"""Policy semantics: statement parsing, unknown-vs-absent, unevaluated reasons,
wildcard targets, NotAction/NotResource, and reorder-stable statement keys."""
import json

from archdiff_extractor.edges import statement_key
from archdiff_extractor.policy import Statement, parse_policy_json
from planbuilder import PlanBuilder, const, edges_of, graph_of, pair, policy, ref

ACCT = "111122223333"
S = f"aws:{ACCT}:us-east-1"


def base():
    return PlanBuilder().provider("aws", allowed_account_ids=const([ACCT]))


def with_policy(text, unknown=None, expressions=None):
    b = base()
    b.resource("aws_iam_policy.p", "aws_iam_policy",
               {"name": "p", "path": "/", "policy": text} if text is not None else {"name": "p", "path": "/"},
               unknown=unknown or {"arn": True, "id": True},
               expressions={"name": const("p"), **(expressions or {})})
    return b


# -- parse_policy_json ------------------------------------------------------------------

def test_parse_string_and_list_forms():
    stmts, warnings = parse_policy_json(policy(
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
        {"Sid": "B", "Effect": "Deny", "Action": ["s3:*", "kms:*"], "Resource": ["a", "b"]}))
    assert not warnings
    assert stmts[0].actions == ["s3:GetObject"] and [r.pattern for r in stmts[0].resources] == ["*"]
    assert stmts[1].sid == "B" and stmts[1].effect == "Deny"
    assert sorted(stmts[1].actions) == ["kms:*", "s3:*"]


def test_parse_single_statement_object_and_principal_forms():
    doc = json.dumps({"Statement": {"Effect": "Allow", "Principal": {"AWS": ["a", "b"], "Service": "ec2.amazonaws.com"},
                                    "Action": "sts:AssumeRole"}})
    (stmt,), _ = parse_policy_json(doc)
    assert [(p.kind, p.value) for p in stmt.principals] == [("AWS", "a"), ("AWS", "b"), ("Service", "ec2.amazonaws.com")]
    (star,), _ = parse_policy_json(json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]}))
    assert star.principals[0].kind == "*"


def test_parse_invalid_json_warns_and_returns_nothing():
    stmts, warnings = parse_policy_json("{not json")
    assert stmts == [] and warnings


# -- grants edges -----------------------------------------------------------------------

def test_resource_star_targets_the_synthetic_wildcard_node():
    g = graph_of(with_policy(policy({"Sid": "All", "Effect": "Allow", "Action": "s3:*", "Resource": "*"})), env={})
    (e,) = edges_of(g, type="grants")
    assert e["target"] == f"{S}/wildcard.all"
    assert e["actions"] == ["s3:*"] and e["resource_patterns"] == ["*"]
    assert e["effect"] == "Allow" and e["unevaluated"] == [] and e["resolution"] == "resolved"
    node = next(n for n in g["nodes"] if n["id"] == e["target"])
    assert node["type"] == "wildcard"


def test_deny_effect_is_preserved():
    g = graph_of(with_policy(policy({"Effect": "Deny", "Action": "iam:*", "Resource": "*"})), env={})
    (e,) = edges_of(g, type="grants")
    assert e["effect"] == "Deny"


def test_condition_marks_unevaluated_but_keeps_edge():
    g = graph_of(with_policy(policy({"Sid": "C", "Effect": "Allow", "Action": "sts:AssumeRole",
                                     "Resource": "arn:aws:iam::111122223333:role/x",
                                     "Condition": {"StringEquals": {"aws:PrincipalTag/team": "x"}}})), env={})
    (e,) = edges_of(g, type="grants")
    assert e["unevaluated"] == ["condition"]
    assert e["actions"] == ["sts:AssumeRole"]


def test_not_action_and_not_resource_are_marked_and_kept():
    g = graph_of(with_policy(policy({"Sid": "N", "Effect": "Allow", "NotAction": "iam:*",
                                     "NotResource": "arn:aws:s3:::secret"})), env={})
    (e,) = edges_of(g, type="grants")
    assert e["unevaluated"] == ["not_action"]
    assert e["actions"] == ["NotAction:iam:*"]
    assert e["resource_patterns"] == ["NotResource:arn:aws:s3:::secret"]
    assert e["target"] == f"{S}/wildcard.all"


def test_one_statement_two_targets_gets_target_qualified_ids():
    b = with_policy(policy({"Sid": "Two", "Effect": "Allow", "Action": "s3:GetObject",
                            "Resource": ["arn:aws:s3:::a/*", "arn:aws:s3:::b/*"]}))
    b.resource("aws_s3_bucket.a", "aws_s3_bucket", {"bucket": "a"}, unknown={"arn": True})
    b.resource("aws_s3_bucket.b", "aws_s3_bucket", {"bucket": "b"}, unknown={"arn": True})
    g = graph_of(b, env={})
    ids = sorted(e["id"] for e in edges_of(g, type="grants"))
    assert ids == [f"{S}/aws_iam_policy.p#stmt:Two@aws_s3_bucket.a", f"{S}/aws_iam_policy.p#stmt:Two@aws_s3_bucket.b"]


def test_single_target_statement_keeps_bare_sid_id():
    b = with_policy(policy({"Sid": "One", "Effect": "Allow", "Action": "s3:GetObject",
                            "Resource": ["arn:aws:s3:::a", "arn:aws:s3:::a/*"]}))
    b.resource("aws_s3_bucket.a", "aws_s3_bucket", {"bucket": "a"}, unknown={"arn": True})
    g = graph_of(b, env={})
    (e,) = edges_of(g, type="grants")
    assert e["id"] == f"{S}/aws_iam_policy.p#stmt:One"
    assert e["target"] == f"{S}/aws_s3_bucket.a"
    assert e["resource_patterns"] == ["arn:aws:s3:::a", "arn:aws:s3:::a/*"]


def test_unknown_policy_body_yields_structural_edge_from_references():
    """policy = jsonencode({... Resource = aws_kms_key.k.arn}) -> body deferred;
    the edge to the key exists from configuration references alone."""
    b = with_policy(None, unknown={"arn": True, "id": True, "policy": True},
                    expressions={"policy": pair("aws_kms_key.k", "arn")})
    b.resource("aws_kms_key.k", "aws_kms_key", {"description": "k"}, unknown={"arn": True, "id": True})
    g = graph_of(b, env={})
    (e,) = edges_of(g, type="grants")
    assert e["id"] == f"{S}/aws_iam_policy.p#stmt:unresolved"
    assert e["target"] == f"{S}/aws_kms_key.k"
    assert e["resolution"] == "unresolved_at_plan"
    assert e["unevaluated"] == ["unresolved_policy_body"]
    assert e["actions"] == [] and e["effect"] is None
    pol = next(n for n in g["nodes"] if n["logical_address"] == "aws_iam_policy.p")
    assert pol["resolution"] == "unresolved_at_plan" and pol["unresolved_attributes"] == ["policy"]


def test_unknown_policy_body_without_references_is_recorded_not_dropped():
    b = with_policy(None, unknown={"arn": True, "id": True, "policy": True},
                    expressions={"policy": ref("local.rendered")})
    g = graph_of(b, env={})
    (e,) = edges_of(g, type="grants")
    assert e["target"] == f"{S}/external.unresolved"
    assert e["unevaluated"] == ["unresolved_policy_body"]
    assert any("local.rendered" in w for w in g["warnings"])


def test_absent_policy_attribute_is_not_treated_as_unknown():
    """null + not in after_unknown -> genuinely absent, never guessed as unknown."""
    b = base()
    b.resource("aws_kms_key.k", "aws_kms_key", {"description": "k", "policy": None},
               unknown={"arn": True, "id": True}, expressions={"description": const("k")})
    g = graph_of(b, env={})
    key = next(n for n in g["nodes"] if n["logical_address"] == "aws_kms_key.k")
    assert key["unresolved_attributes"] == ["arn"]
    assert "resource_policy" not in key["properties"]


def test_kms_resource_policy_is_flagged_not_silently_dropped():
    b = base()
    b.resource("aws_kms_key.k", "aws_kms_key", {"description": "k", "policy": policy({"Effect": "Allow", "Principal": "*", "Action": "kms:*", "Resource": "*"})},
               unknown={"arn": True, "id": True}, expressions={"policy": const("x")})
    g = graph_of(b, env={})
    key = next(n for n in g["nodes"] if n["logical_address"] == "aws_kms_key.k")
    assert len(key["properties"]["resource_policy"]) == 16
    assert any("resource policy" in w for w in g["warnings"])


def test_bucket_policy_edges_carry_resource_policy_reason():
    b = base()
    b.resource("aws_s3_bucket.data", "aws_s3_bucket", {"bucket": "data"}, unknown={"arn": True})
    b.resource("aws_s3_bucket_policy.bp", "aws_s3_bucket_policy",
               {"policy": policy({"Sid": "Pub", "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                                  "Resource": "arn:aws:s3:::data/*"})},
               unknown={"id": True}, expressions={"bucket": pair("aws_s3_bucket.data", "id")})
    g = graph_of(b, env={})
    (e,) = edges_of(g, type="grants")
    assert e["target"] == f"{S}/aws_s3_bucket.data"
    assert e["unevaluated"] == ["resource_policy"]


# -- statement keys ---------------------------------------------------------------------

def test_statement_key_is_sid_or_content_hash_never_position():
    a = Statement(effect="Allow", actions=["s3:GetObject"])
    b = Statement(effect="Allow", actions=["kms:Decrypt"])
    assert statement_key(a) != statement_key(b)
    assert statement_key(a) == statement_key(Statement(effect="Allow", actions=["s3:GetObject"]))
    assert statement_key(Statement(sid="X")) == "X"


def test_reordering_statements_produces_identical_edges_and_digests():
    s1 = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
    s2 = {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": "*"}
    g1 = graph_of(with_policy(policy(s1, s2)), env={})
    g2 = graph_of(with_policy(policy(s2, s1)), env={})
    assert [e["id"] for e in g1["edges"]] == [e["id"] for e in g2["edges"]]
    assert [e["digest"] for e in g1["edges"]] == [e["digest"] for e in g2["edges"]]
    assert g1["modules"][0]["digest"] == g2["modules"][0]["digest"]


def test_two_statements_same_sid_get_deterministic_suffix():
    g = graph_of(with_policy(policy(
        {"Sid": "Dup", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
        {"Sid": "Dup", "Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"})), env={})
    ids = sorted(e["id"] for e in edges_of(g, type="grants"))
    assert ids == [f"{S}/aws_iam_policy.p#stmt:Dup", f"{S}/aws_iam_policy.p#stmt:Dup~2"]
