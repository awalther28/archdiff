"""can_assume DIRECTION: a trust policy on role B naming principal A produces
the edge A -> B. Tested explicitly in both directions, in one scope and across
two, plus trusted_by (role -> identity provider)."""
from planbuilder import PlanBuilder, const, edges_of, graph_of, node_index, trust

ACCT = "111122223333"
S = f"aws:{ACCT}:us-east-1"
MGMT = "999988887777"
M = f"aws:{MGMT}:us-east-1"


def role(b, name, trust_json, provider_key="aws"):
    b.resource(f"aws_iam_role.{name}", "aws_iam_role",
               {"name": name, "path": "/", "assume_role_policy": trust_json, "permissions_boundary": None},
               unknown={"arn": True, "id": True}, expressions={"name": const(name)}, provider_key=provider_key)


def test_b_trusts_a_gives_edge_a_to_b():
    b = PlanBuilder().provider("aws", allowed_account_ids=const([ACCT]))
    role(b, "a", trust({"Service": "ec2.amazonaws.com"}))
    role(b, "b", trust({"AWS": f"arn:aws:iam::{ACCT}:role/a"}))
    g = graph_of(b, env={})
    (e,) = edges_of(g, type="can_assume", target=f"{S}/aws_iam_role.b")
    assert e["source"] == f"{S}/aws_iam_role.a"
    assert e["id"] == f"{S}/aws_iam_role.b#trust:aws_iam_role.a"
    assert not edges_of(g, type="can_assume", source=f"{S}/aws_iam_role.b", target=f"{S}/aws_iam_role.a")


def test_a_trusts_b_gives_edge_b_to_a():
    """The mirror image: swapping the trust policy must swap the edge."""
    b = PlanBuilder().provider("aws", allowed_account_ids=const([ACCT]))
    role(b, "a", trust({"AWS": f"arn:aws:iam::{ACCT}:role/b"}))
    role(b, "b", trust({"Service": "ec2.amazonaws.com"}))
    g = graph_of(b, env={})
    (e,) = edges_of(g, type="can_assume", target=f"{S}/aws_iam_role.a")
    assert e["source"] == f"{S}/aws_iam_role.b"
    assert not edges_of(g, type="can_assume", source=f"{S}/aws_iam_role.a", target=f"{S}/aws_iam_role.b")


def test_mutual_trust_gives_both_edges():
    b = PlanBuilder().provider("aws", allowed_account_ids=const([ACCT]))
    role(b, "a", trust({"AWS": f"arn:aws:iam::{ACCT}:role/b"}))
    role(b, "b", trust({"AWS": f"arn:aws:iam::{ACCT}:role/a"}))
    g = graph_of(b, env={})
    pairs = {(e["source"], e["target"]) for e in edges_of(g, type="can_assume")}
    assert pairs == {(f"{S}/aws_iam_role.a", f"{S}/aws_iam_role.b"),
                     (f"{S}/aws_iam_role.b", f"{S}/aws_iam_role.a")}


def test_cross_scope_direction_source_is_the_named_principal():
    """mgmt-deploy (account 9999) is named in app_admin's (account 1111) trust
    policy: edge mgmt-deploy -> app_admin, never the reverse."""
    b = PlanBuilder().provider("aws", allowed_account_ids=const([ACCT]))
    b.provider("aws.mgmt", allowed_account_ids=const([MGMT]))
    role(b, "mgmt_deploy", trust({"Service": "ec2.amazonaws.com"}), provider_key="aws.mgmt")
    role(b, "app_admin", trust({"AWS": f"arn:aws:iam::{MGMT}:role/mgmt_deploy"}))
    g = graph_of(b, env={})
    (e,) = edges_of(g, type="can_assume", target=f"{S}/aws_iam_role.app_admin")
    assert e["source"] == f"{M}/aws_iam_role.mgmt_deploy"
    assert e["id"] == f"{S}/aws_iam_role.app_admin#trust:{M}/aws_iam_role.mgmt_deploy"
    assert not edges_of(g, source=f"{S}/aws_iam_role.app_admin", target=f"{M}/aws_iam_role.mgmt_deploy")


def test_unmanaged_principal_becomes_external_source():
    b = PlanBuilder().provider("aws", allowed_account_ids=const([ACCT]))
    role(b, "app_admin", trust({"AWS": "arn:aws:iam::555566667777:role/third-party-audit"},
                               condition={"StringEquals": {"sts:ExternalId": "x"}}))
    g = graph_of(b, env={})
    (e,) = edges_of(g, type="can_assume")
    assert e["source"] == f"{S}/external.arn:aws:iam::555566667777:role/third-party-audit"
    assert e["target"] == f"{S}/aws_iam_role.app_admin"
    assert e["unevaluated"] == ["condition"]
    ext = node_index(g)[e["source"]]
    assert ext["type"] == "external" and ext["resolution"] == "external"
    assert ext["aliases"] == ["arn:aws:iam::555566667777:role/third-party-audit"]


def test_trusted_by_goes_from_role_to_identity_provider():
    b = PlanBuilder().provider("aws", allowed_account_ids=const([ACCT]))
    b.resource("aws_iam_openid_connect_provider.github", "aws_iam_openid_connect_provider",
               {"url": "https://token.actions.githubusercontent.com", "client_id_list": ["sts.amazonaws.com"]},
               unknown={"arn": True, "id": True})
    role(b, "gha", trust({"Federated": f"arn:aws:iam::{ACCT}:oidc-provider/token.actions.githubusercontent.com"},
                         action="sts:AssumeRoleWithWebIdentity"))
    g = graph_of(b, env={})
    (e,) = edges_of(g, type="trusted_by")
    assert e["source"] == f"{S}/aws_iam_role.gha"
    assert e["target"] == f"{S}/aws_iam_openid_connect_provider.github"
    assert e["actions"] == ["sts:AssumeRoleWithWebIdentity"]
    assert not edges_of(g, type="can_assume")


def test_account_root_and_anonymous_principals():
    b = PlanBuilder().provider("aws", allowed_account_ids=const([ACCT]))
    role(b, "r", trust({"AWS": MGMT}))
    role(b, "open", trust("*"))
    g = graph_of(b, env={})
    (root,) = edges_of(g, target=f"{S}/aws_iam_role.r")
    assert root["source"] == f"{S}/external.arn:aws:iam::{MGMT}:root"
    (anon,) = edges_of(g, target=f"{S}/aws_iam_role.open")
    assert anon["source"] == f"{S}/external.*"
    assert node_index(g)[anon["source"]]["name"] == "*"


def test_deny_trust_statement_keeps_effect():
    b = PlanBuilder().provider("aws", allowed_account_ids=const([ACCT]))
    role(b, "r", trust({"AWS": f"arn:aws:iam::{ACCT}:root"}, effect="Deny"))
    g = graph_of(b, env={})
    (e,) = edges_of(g, type="can_assume")
    assert e["effect"] == "Deny"
