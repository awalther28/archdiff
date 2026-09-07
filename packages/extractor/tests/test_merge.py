"""Merging N plans: cross-scope resolution through the alias index, external
nodes, never-merge-on-alias, id collisions, unknown trust bodies via
references, module-threaded references, and the module rollup."""
from archdiff_extractor.canonical import module_digest
from planbuilder import PlanBuilder, const, edges_of, graph_of, node_index, pair, policy, ref, trust

ACCT = "111122223333"
S = f"aws:{ACCT}:us-east-1"
MGMT = "999988887777"
M = f"aws:{MGMT}:us-east-1"


def mgmt_plan():
    b = PlanBuilder().provider("aws", allowed_account_ids=const([MGMT]))
    b.resource("aws_iam_role.mgmt_deploy", "aws_iam_role",
               {"name": "mgmt-deploy", "path": "/", "assume_role_policy": trust({"Service": "ec2.amazonaws.com"})},
               unknown={"arn": True})
    return b


def sub_plan():
    b = PlanBuilder().provider("aws", allowed_account_ids=const([ACCT]))
    b.resource("aws_iam_role.app_admin", "aws_iam_role",
               {"name": "app-admin", "path": "/",
                "assume_role_policy": trust({"AWS": f"arn:aws:iam::{MGMT}:role/mgmt-deploy"})},
               unknown={"arn": True})
    return b


def test_cross_root_hop_is_invisible_alone_and_visible_after_merge():
    alone = graph_of(sub_plan(), env={})
    (e,) = edges_of(alone, type="can_assume")
    assert e["source"] == f"{S}/external.arn:aws:iam::{MGMT}:role/mgmt-deploy"

    merged = graph_of(mgmt_plan(), sub_plan(), roots=["live/mgmt/iam", "live/prod/iam"], env={})
    (e,) = edges_of(merged, type="can_assume", target=f"{S}/aws_iam_role.app_admin")
    assert e["source"] == f"{M}/aws_iam_role.mgmt_deploy"
    assert not any(n["type"] == "external" and "mgmt-deploy" in n["id"] for n in merged["nodes"])
    assert [s["key"] for s in merged["scopes"]] == [S, M]


def test_alias_resolves_references_but_never_merges_nodes():
    """Two roots both predict the same ARN (same name, same account). They stay
    two nodes; the reference fans out to both and a warning is recorded."""
    a = PlanBuilder().provider("aws", allowed_account_ids=const([ACCT]))
    a.resource("aws_iam_role.x", "aws_iam_role", {"name": "shared", "path": "/", "assume_role_policy": "{}"},
               unknown={"arn": True})
    b = PlanBuilder().provider("aws", allowed_account_ids=const([ACCT]))
    b.resource("aws_iam_role.y", "aws_iam_role", {"name": "shared", "path": "/", "assume_role_policy": "{}"},
               unknown={"arn": True})
    c = PlanBuilder().provider("aws", allowed_account_ids=const([ACCT]))
    c.resource("aws_iam_role.t", "aws_iam_role",
               {"name": "t", "path": "/", "assume_role_policy": trust({"AWS": f"arn:aws:iam::{ACCT}:role/shared"})},
               unknown={"arn": True})
    g = graph_of(a, b, c, roots=["a", "b", "c"], env={})
    principals = [n for n in g["nodes"] if n["type"] == "principal"]
    assert len(principals) == 3
    sources = sorted(e["source"] for e in edges_of(g, type="can_assume", target=f"{S}/aws_iam_role.t"))
    assert sources == [f"{S}/aws_iam_role.x", f"{S}/aws_iam_role.y"]
    assert any("predicted for 2 nodes" in w for w in g["warnings"])


def test_id_collision_across_plans_is_qualified_and_warned():
    def plan(name):
        b = PlanBuilder().provider("aws", allowed_account_ids=const([ACCT]))
        b.module("module.role")
        b.resource("module.role.aws_iam_role.this", "aws_iam_role",
                   {"name": name, "path": "/", "assume_role_policy": "{}"}, unknown={"arn": True})
        return b
    g = graph_of(plan("ci"), plan("app"), roots=["live/ci", "live/app"], env={})
    ids = sorted(n["id"] for n in g["nodes"] if n["type"] == "principal")
    assert ids == [f"{S}/module.role.aws_iam_role.this@live/app", f"{S}/module.role.aws_iam_role.this@live/ci"]
    assert any("node id collision" in w for w in g["warnings"])


def test_identical_node_from_two_plans_is_kept_once():
    g = graph_of(mgmt_plan(), mgmt_plan(), roots=["x", "y"], env={})
    assert len([n for n in g["nodes"] if n["type"] == "principal"]) == 1
    assert not any("collision" in w for w in g["warnings"])


def test_attachment_by_arn_string_resolves_across_roots():
    """policy_arn = "arn:...:policy/shared" (a constant) in root B resolves to
    the policy managed in root A; an AWS-managed ARN becomes external."""
    a = PlanBuilder().provider("aws", allowed_account_ids=const([ACCT]))
    a.resource("aws_iam_policy.shared", "aws_iam_policy",
               {"name": "shared", "path": "/", "policy": policy({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"})},
               unknown={"arn": True})
    b = PlanBuilder().provider("aws", allowed_account_ids=const([ACCT]))
    b.resource("aws_iam_role.r", "aws_iam_role", {"name": "r", "path": "/", "assume_role_policy": "{}"},
               unknown={"arn": True})
    b.resource("aws_iam_role_policy_attachment.shared", "aws_iam_role_policy_attachment",
               {"role": "r", "policy_arn": f"arn:aws:iam::{ACCT}:policy/shared"}, unknown={"id": True},
               expressions={"role": pair("aws_iam_role.r", "name"),
                            "policy_arn": const(f"arn:aws:iam::{ACCT}:policy/shared")})
    b.resource("aws_iam_role_policy_attachment.admin", "aws_iam_role_policy_attachment",
               {"role": "r", "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"}, unknown={"id": True},
               expressions={"role": pair("aws_iam_role.r", "name"),
                            "policy_arn": const("arn:aws:iam::aws:policy/AdministratorAccess")})
    g = graph_of(a, b, roots=["a", "b"], env={})
    targets = sorted(e["target"] for e in edges_of(g, type="attaches", source=f"{S}/aws_iam_role.r"))
    assert targets == [f"{S}/aws_iam_policy.shared", f"{S}/external.arn:aws:iam::aws:policy/AdministratorAccess"]


def test_attachment_role_by_name_string_resolves_through_predicted_arn():
    b = PlanBuilder().provider("aws", allowed_account_ids=const([ACCT]))
    b.resource("aws_iam_role.r", "aws_iam_role", {"name": "named", "path": "/", "assume_role_policy": "{}"},
               unknown={"arn": True})
    b.resource("aws_iam_policy.p", "aws_iam_policy", {"name": "p", "path": "/", "policy": policy()}, unknown={"arn": True})
    b.resource("aws_iam_role_policy_attachment.a", "aws_iam_role_policy_attachment",
               {"role": "named"}, unknown={"id": True, "policy_arn": True},
               expressions={"role": const("named"), "policy_arn": pair("aws_iam_policy.p", "arn")})
    g = graph_of(b, env={})
    (e,) = edges_of(g, type="attaches")
    assert e["source"] == f"{S}/aws_iam_role.r" and e["target"] == f"{S}/aws_iam_policy.p"


def test_unknown_trust_body_uses_references_and_marks_unresolved():
    b = PlanBuilder().provider("aws", allowed_account_ids=const([ACCT]))
    b.resource("aws_iam_role.a", "aws_iam_role", {"name": "a", "path": "/", "assume_role_policy": "{}"},
               unknown={"arn": True})
    b.resource("aws_iam_role.b", "aws_iam_role", {"name": "b", "path": "/"},
               unknown={"arn": True, "assume_role_policy": True},
               expressions={"assume_role_policy": pair("aws_iam_role.a", "arn")})
    g = graph_of(b, env={})
    (e,) = edges_of(g, type="can_assume")
    assert (e["source"], e["target"]) == (f"{S}/aws_iam_role.a", f"{S}/aws_iam_role.b")
    assert e["resolution"] == "unresolved_at_plan" and e["unevaluated"] == ["unresolved_policy_body"]
    assert node_index(g)[e["target"]]["unresolved_attributes"] == ["assume_role_policy"]


def test_unknown_federated_reference_becomes_trusted_by():
    b = PlanBuilder().provider("aws", allowed_account_ids=const([ACCT]))
    b.resource("aws_iam_openid_connect_provider.gh", "aws_iam_openid_connect_provider",
               {"url": "https://token.actions.githubusercontent.com", "client_id_list": ["sts.amazonaws.com"]},
               unknown={"arn": True})
    b.resource("aws_iam_role.gha", "aws_iam_role", {"name": "gha", "path": "/"},
               unknown={"arn": True, "assume_role_policy": True},
               expressions={"assume_role_policy": pair("aws_iam_openid_connect_provider.gh", "arn")})
    g = graph_of(b, env={})
    (e,) = g["edges"]
    assert e["type"] == "trusted_by"
    assert (e["source"], e["target"]) == (f"{S}/aws_iam_role.gha", f"{S}/aws_iam_openid_connect_provider.gh")


def test_reference_threaded_through_module_variable_and_output():
    """root: module.iam(role_arn = aws_iam_role.root_role.arn); inside the module a
    role trusts var.role_arn; root attaches module.iam.policy_arn output."""
    b = PlanBuilder().provider("aws", allowed_account_ids=const([ACCT]))
    b.module("module.iam", call_expressions={"role_arn": pair("aws_iam_role.root_role", "arn")},
             outputs={"policy_arn": {"expression": pair("aws_iam_policy.inner", "arn")}})
    b.resource("aws_iam_role.root_role", "aws_iam_role", {"name": "root", "path": "/", "assume_role_policy": "{}"},
               unknown={"arn": True})
    b.resource("module.iam.aws_iam_role.inner", "aws_iam_role", {"name": "inner", "path": "/"},
               unknown={"arn": True, "assume_role_policy": True},
               expressions={"assume_role_policy": ref("var.role_arn")}, provider_key="module.iam:aws")
    b.resource("module.iam.aws_iam_policy.inner", "aws_iam_policy",
               {"name": "inner", "path": "/", "policy": policy()}, unknown={"arn": True},
               provider_key="module.iam:aws")
    b.resource("aws_iam_role_policy_attachment.a", "aws_iam_role_policy_attachment", {"role": "root"},
               unknown={"id": True, "policy_arn": True},
               expressions={"role": pair("aws_iam_role.root_role", "name"),
                            "policy_arn": ref("module.iam.policy_arn", "module.iam")})
    g = graph_of(b, env={})
    (ca,) = edges_of(g, type="can_assume")
    assert (ca["source"], ca["target"]) == (f"{S}/aws_iam_role.root_role", f"{S}/module.iam.aws_iam_role.inner")
    (att,) = edges_of(g, type="attaches")
    assert (att["source"], att["target"]) == (f"{S}/aws_iam_role.root_role", f"{S}/module.iam.aws_iam_policy.inner")
    # module rollup: module.iam is a child of the plan root
    plan_root = g["modules"][0]["children"][0]
    assert [c["path"] for c in plan_root["children"]] == ["module.iam"]
    assert plan_root["children"][0]["digest"] == module_digest(
        [n["digest"] for n in g["nodes"] if n["logical_address"].startswith("module.iam.")],
        [ca["digest"]], [])


def test_glob_pattern_resolves_to_every_matching_alias():
    b = PlanBuilder().provider("aws", allowed_account_ids=const([ACCT]))
    for n in ("ci-a", "ci-b", "other"):
        b.resource(f"aws_iam_role.{n.replace('-', '_')}", "aws_iam_role",
                   {"name": n, "path": "/", "assume_role_policy": "{}"}, unknown={"arn": True})
    b.resource("aws_iam_policy.p", "aws_iam_policy",
               {"name": "p", "path": "/", "policy": policy({"Sid": "Pass", "Effect": "Allow", "Action": "iam:PassRole",
                                                            "Resource": f"arn:aws:iam::{ACCT}:role/ci-*"})},
               unknown={"arn": True})
    g = graph_of(b, env={})
    targets = sorted(e["target"] for e in edges_of(g, type="grants"))
    assert targets == [f"{S}/aws_iam_role.ci_a", f"{S}/aws_iam_role.ci_b"]


def test_for_each_instances_are_separate_nodes_and_keyed_references_select_one():
    b = PlanBuilder().provider("aws", allowed_account_ids=const([ACCT]))
    for k in ("a", "b"):
        b.resource(f'aws_iam_role.r["{k}"]', "aws_iam_role", {"name": f"r-{k}", "path": "/", "assume_role_policy": "{}"},
                   unknown={"arn": True}, instance_of="aws_iam_role.r")
    b.resource("aws_iam_policy.p", "aws_iam_policy", {"name": "p", "path": "/", "policy": policy()}, unknown={"arn": True})
    b.resource('aws_iam_role_policy_attachment.a["a"]', "aws_iam_role_policy_attachment", {"role": "r-a"},
               unknown={"id": True, "policy_arn": True}, instance_of="aws_iam_role_policy_attachment.a",
               expressions={"role": ref("aws_iam_role.r", "each.key"), "policy_arn": pair("aws_iam_policy.p", "arn")})
    g = graph_of(b, env={})
    assert sorted(n["logical_address"] for n in g["nodes"] if n["type"] == "principal") == [
        'aws_iam_role.r["a"]', 'aws_iam_role.r["b"]']
    (att,) = edges_of(g, type="attaches")
    assert att["source"] == f'{S}/aws_iam_role.r["a"]'
