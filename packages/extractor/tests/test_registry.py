"""The type registry: every required type produces the right node and aliases;
adding a type is a function; unregistered types referenced by a policy get a
generic resource node rather than being dropped."""
import pytest

from archdiff_extractor.registry import REGISTRY, TypeHandler, register
from planbuilder import PlanBuilder, const, edges_of, graph_of, pair, policy

ACCT = "111122223333"
S = f"aws:{ACCT}:us-east-1"

REQUIRED = ["aws_iam_role", "aws_iam_policy", "aws_iam_role_policy", "aws_iam_role_policy_attachment",
            "aws_iam_openid_connect_provider", "aws_kms_key", "aws_s3_bucket"]


def base():
    return PlanBuilder().provider("aws", allowed_account_ids=const([ACCT]))


def node(g, address):
    return next(n for n in g["nodes"] if n["logical_address"] == address)


@pytest.mark.parametrize("tf_type", REQUIRED)
def test_required_types_are_registered(tf_type):
    assert tf_type in REGISTRY


def test_policy_document_data_source_is_not_a_node():
    assert "aws_iam_policy_document" not in REGISTRY   # folded into the policy that uses it


def test_role_node_aliases_and_properties():
    b = base().resource("aws_iam_role.r", "aws_iam_role",
                        {"name": "ci", "path": "/svc/", "assume_role_policy": "{}", "permissions_boundary": None},
                        unknown={"arn": True})
    n = node(graph_of(b, env={}), "aws_iam_role.r")
    assert n["type"] == "principal" and n["name"] == "ci"
    assert n["aliases"] == [f"arn:aws:iam::{ACCT}:role/svc/ci"]
    assert n["properties"] == {"path": "/svc/", "permissions_boundary": None}


def test_role_with_unknown_name_is_unresolved_and_has_no_alias():
    b = base().resource("aws_iam_role.r", "aws_iam_role", {"path": "/", "assume_role_policy": "{}"},
                        unknown={"arn": True, "name": True})
    n = node(graph_of(b, env={}), "aws_iam_role.r")
    assert n["name"] is None and n["aliases"] == []
    assert n["resolution"] == "unresolved_at_plan" and n["unresolved_attributes"] == ["name"]


def test_permissions_boundary_reference_is_recorded_by_address():
    b = base()
    b.resource("aws_iam_policy.boundary", "aws_iam_policy", {"name": "b", "path": "/", "policy": policy()}, unknown={"arn": True})
    b.resource("aws_iam_role.r", "aws_iam_role", {"name": "r", "path": "/", "assume_role_policy": "{}"},
               unknown={"arn": True, "permissions_boundary": True},
               expressions={"permissions_boundary": pair("aws_iam_policy.boundary", "arn")})
    n = node(graph_of(b, env={}), "aws_iam_role.r")
    assert n["properties"]["permissions_boundary"] == "aws_iam_policy.boundary"
    assert n["resolution"] == "resolved"


def test_policy_and_inline_policy_nodes():
    b = base()
    b.resource("aws_iam_policy.p", "aws_iam_policy", {"name": "p", "path": "/", "policy": policy()}, unknown={"arn": True})
    b.resource("aws_iam_role.r", "aws_iam_role", {"name": "r", "path": "/", "assume_role_policy": "{}"}, unknown={"arn": True})
    b.resource("aws_iam_role_policy.i", "aws_iam_role_policy", {"name": "i", "policy": policy()},
               unknown={"id": True, "role": True}, expressions={"role": pair("aws_iam_role.r", "id")})
    g = graph_of(b, env={})
    assert node(g, "aws_iam_policy.p")["aliases"] == [f"arn:aws:iam::{ACCT}:policy/p"]
    inline = node(g, "aws_iam_role_policy.i")
    assert inline["type"] == "policy" and inline["properties"] == {"inline": True} and inline["aliases"] == []
    (att,) = edges_of(g, type="attaches")
    assert (att["source"], att["target"]) == (f"{S}/aws_iam_role.r", f"{S}/aws_iam_role_policy.i")


def test_attachment_resource_is_an_edge_not_a_node():
    b = base()
    b.resource("aws_iam_policy.p", "aws_iam_policy", {"name": "p", "path": "/", "policy": policy()}, unknown={"arn": True})
    b.resource("aws_iam_role.r", "aws_iam_role", {"name": "r", "path": "/", "assume_role_policy": "{}"}, unknown={"arn": True})
    b.resource("aws_iam_role_policy_attachment.a", "aws_iam_role_policy_attachment", {"role": "r"},
               unknown={"id": True, "policy_arn": True},
               expressions={"role": pair("aws_iam_role.r", "name"), "policy_arn": pair("aws_iam_policy.p", "arn")})
    g = graph_of(b, env={})
    assert not any("attachment" in n["logical_address"] for n in g["nodes"])
    (att,) = edges_of(g, type="attaches")
    assert att["id"] == f"{S}/aws_iam_role.r#attach:aws_iam_policy.p"


def test_oidc_provider_node():
    b = base().resource("aws_iam_openid_connect_provider.gh", "aws_iam_openid_connect_provider",
                        {"url": "https://token.actions.githubusercontent.com", "client_id_list": ["sts.amazonaws.com"]},
                        unknown={"arn": True})
    n = node(graph_of(b, env={}), "aws_iam_openid_connect_provider.gh")
    assert n["type"] == "identity_provider"
    assert n["name"] == "token.actions.githubusercontent.com"
    assert n["aliases"] == [f"arn:aws:iam::{ACCT}:oidc-provider/token.actions.githubusercontent.com"]
    assert n["properties"]["client_id_list"] == ["sts.amazonaws.com"]


def test_kms_key_alias_only_when_arn_known():
    new = base().resource("aws_kms_key.new", "aws_kms_key", {"description": "x"}, unknown={"arn": True, "id": True})
    existing = base().resource("aws_kms_key.old", "aws_kms_key",
                               {"description": "x", "arn": f"arn:aws:kms:us-east-1:{ACCT}:key/abc"}, actions=["no-op"])
    n_new = node(graph_of(new, env={}), "aws_kms_key.new")
    n_old = node(graph_of(existing, env={}), "aws_kms_key.old")
    assert n_new["aliases"] == [] and n_new["resolution"] == "unresolved_at_plan"
    assert n_old["aliases"] == [f"arn:aws:kms:us-east-1:{ACCT}:key/abc"] and n_old["resolution"] == "resolved"


def test_s3_bucket_alias_uses_partition():
    b = PlanBuilder().provider("aws", region="cn-north-1", allowed_account_ids=const([ACCT]))
    b.resource("aws_s3_bucket.d", "aws_s3_bucket", {"bucket": "data"}, unknown={"arn": True})
    n = node(graph_of(b, env={}), "aws_s3_bucket.d")
    assert n["name"] == "data" and n["aliases"] == ["arn:aws-cn:s3:::data"]


def test_unregistered_type_referenced_by_policy_gets_generic_resource_node():
    b = base()
    b.resource("aws_dynamodb_table.t", "aws_dynamodb_table", {"name": "orders"}, unknown={"arn": True, "id": True})
    b.resource("aws_iam_policy.p", "aws_iam_policy", {"name": "p", "path": "/"},
               unknown={"arn": True, "policy": True}, expressions={"policy": pair("aws_dynamodb_table.t", "arn")})
    g = graph_of(b, env={})
    t = node(g, "aws_dynamodb_table.t")
    assert t["type"] == "resource" and t["name"] == "orders" and t["unresolved_attributes"] == ["arn"]
    (e,) = edges_of(g, type="grants")
    assert e["target"] == t["id"]


def test_unregistered_types_are_not_nodes_unless_referenced():
    b = base().resource("aws_instance.i", "aws_instance", {"ami": "x"}, unknown={"arn": True})
    assert graph_of(b, env={})["nodes"] == []


def test_adding_a_type_is_a_function():
    class SqsQueue(TypeHandler):
        tf_type = "aws_sqs_queue_test_only"
        node_type = "resource"

        def build_node(self, ctx):
            name = ctx.value("name")
            arn = f"arn:{ctx.scope.partition}:sqs:{ctx.scope.region}:{ctx.scope.account_id}:{name}"
            return ctx.make_node("resource", name, [arn], {}, ["name"])

    register(SqsQueue)
    try:
        b = base().resource("aws_sqs_queue_test_only.q", "aws_sqs_queue_test_only", {"name": "jobs"}, unknown={"arn": True})
        b.resource("aws_iam_policy.p", "aws_iam_policy",
                   {"name": "p", "path": "/", "policy": policy({"Sid": "Q", "Effect": "Allow", "Action": "sqs:SendMessage",
                                                                "Resource": f"arn:aws:sqs:us-east-1:{ACCT}:jobs"})},
                   unknown={"arn": True})
        g = graph_of(b, env={})
        q = node(g, "aws_sqs_queue_test_only.q")
        assert q["aliases"] == [f"arn:aws:sqs:us-east-1:{ACCT}:jobs"]
        (e,) = edges_of(g, type="grants")
        assert e["target"] == q["id"]
    finally:
        del REGISTRY["aws_sqs_queue_test_only"]


def test_iam_user_types_share_the_role_machinery():
    b = base()
    b.resource("aws_iam_user.u", "aws_iam_user", {"name": "alice", "path": "/"}, unknown={"arn": True})
    b.resource("aws_iam_policy.p", "aws_iam_policy", {"name": "p", "path": "/", "policy": policy()}, unknown={"arn": True})
    b.resource("aws_iam_user_policy_attachment.a", "aws_iam_user_policy_attachment", {"user": "alice"},
               unknown={"id": True, "policy_arn": True},
               expressions={"user": pair("aws_iam_user.u", "name"), "policy_arn": pair("aws_iam_policy.p", "arn")})
    g = graph_of(b, env={})
    assert node(g, "aws_iam_user.u")["aliases"] == [f"arn:aws:iam::{ACCT}:user/alice"]
    (att,) = edges_of(g, type="attaches")
    assert att["source"] == f"{S}/aws_iam_user.u"
