"""The three real plan JSON samples produced by the verified spike, checked
against the seven verified facts about plan JSON."""
import os

from archdiff_extractor.extract import extract_plan
from archdiff_extractor.merge import merge
from archdiff_extractor.plan import Plan, unknown_at
from conftest import FIXTURES

SUB = {"aws": {"account_id": "111122223333"}}


def load(name):
    return Plan.load(os.path.join(FIXTURES, name))


def graph(name, **kw):
    kw.setdefault("env", {})
    return merge([extract_plan(load(name), **kw)])


def by_addr(g, address):
    return next(n for n in g["nodes"] if n["logical_address"] == address)


def edges(g, **match):
    return [e for e in g["edges"] if all(e.get(k) == v for k, v in match.items())]


# -- fact 2: role -> policy edge exists ONLY in configuration ----------------------------

def test_fact2_attachment_edge_exists_although_policy_arn_is_unknown():
    plan = load("plan-poisoned.json")
    assert unknown_at(plan.after_unknown_for("aws_iam_role_policy_attachment.ci"), "policy_arn")
    assert "policy_arn" not in plan.planned["aws_iam_role_policy_attachment.ci"].values
    g = graph("plan-poisoned.json")
    (att,) = edges(g, type="attaches", target="aws:unknown:us-east-1/aws_iam_policy.ci")
    assert att["source"] == "aws:unknown:us-east-1/aws_iam_role.ci"
    assert att["resolution"] == "resolved"


def test_fact2_no_disconnected_policy_node():
    g = graph("plan-clean.json")
    attached = {e["target"] for e in g["edges"] if e["type"] == "attaches"}
    assert "aws:unknown:us-east-1/aws_iam_policy.clean" in attached


# -- fact 3: resolved data sources live in prior_state ----------------------------------

def test_fact3_data_source_in_prior_state_is_used_for_the_policy_body():
    plan = load("plan-clean.json")
    assert "data.aws_iam_policy_document.clean" in plan.prior
    assert "data.aws_iam_policy_document.clean" not in plan.planned
    g = graph("plan-clean.json")
    read = edges(g, sid="ReadBuckets")
    assert len(read) == 1
    assert read[0]["actions"] == ["s3:GetObject", "s3:ListBucket"]
    assert read[0]["resource_patterns"] == ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"]
    assert read[0]["resolution"] == "resolved" and read[0]["unevaluated"] == []
    (cond,) = edges(g, sid="ConditionalAssume")
    assert cond["unevaluated"] == ["condition"]


# -- facts 4/5: after_unknown distinguishes unknown from absent; whole json deferred -------

def test_fact5_poisoned_document_has_json_deferred_but_statements_recoverable():
    plan = load("plan-poisoned.json")
    doc = "data.aws_iam_policy_document.ci"
    assert unknown_at(plan.after_unknown_for(doc), "json")
    assert unknown_at(plan.after_unknown_for(doc), "statement", 1, "resources", 0)
    assert not unknown_at(plan.after_unknown_for(doc), "statement", 0, "resources", 0)
    g = graph("plan-poisoned.json")
    pol = by_addr(g, "aws_iam_policy.ci")
    assert pol["resolution"] == "unresolved_at_plan" and pol["unresolved_attributes"] == ["policy"]
    # Known statement: fully resolved.
    (read,) = edges(g, sid="ReadBuckets")
    assert read["resolution"] == "resolved" and read["unevaluated"] == []
    # Poisoned statement: target known structurally, body marked unresolved.
    (key,) = edges(g, sid="UseKey")
    assert key["target"] == "aws:unknown:us-east-1/aws_kms_key.main"
    assert key["actions"] == ["kms:Decrypt"]
    assert key["resolution"] == "unresolved_at_plan"
    assert key["unevaluated"] == ["unresolved_policy_body"]
    assert key["resource_patterns"] == []


def test_fact4_null_and_not_unknown_is_absent():
    plan = load("plan-poisoned.json")
    role = plan.planned["aws_iam_role.ci"].values
    assert role["permissions_boundary"] is None
    assert not unknown_at(plan.after_unknown_for("aws_iam_role.ci"), "permissions_boundary")
    g = graph("plan-poisoned.json")
    node = by_addr(g, "aws_iam_role.ci")
    assert node["resolution"] == "resolved"
    assert node["properties"]["permissions_boundary"] is None
    kms = by_addr(g, "aws_kms_key.main")
    assert kms["resolution"] == "unresolved_at_plan" and kms["unresolved_attributes"] == ["arn"]


# -- fact 6: reference pairs ----------------------------------------------------------------

def test_fact6_reference_pairs_resolve_to_resource_level_address():
    plan = load("plan-poisoned.json")
    cfg = plan.config_resource("aws_iam_role_policy_attachment.ci")
    assert cfg.expressions["policy_arn"]["references"] == ["aws_iam_policy.ci.arn", "aws_iam_policy.ci"]
    from archdiff_extractor.references import ReferenceResolver, ResourceRef
    targets = ReferenceResolver(plan).resolve_expr(cfg.expressions["policy_arn"], "")
    assert targets == [ResourceRef("aws_iam_policy.ci", None)]


# -- fact 7: provider_config_key, provider_config, variables ---------------------------------

def test_fact7_aliased_provider_and_variables_split_two_accounts():
    plan = load("plan-two-accounts.json")
    assert plan.variables == {"account_id": "111122223333", "environment": "prod"}
    assert plan.config_resource("aws_iam_role.mgmt_deploy").provider_config_key == "aws.mgmt"
    g = graph("plan-two-accounts.json")
    app, mgmt = by_addr(g, "aws_iam_role.app"), by_addr(g, "aws_iam_role.mgmt_deploy")
    assert app["scope"]["key"] == "aws:111122223333:us-east-1"
    assert app["scope"]["source"] == "provider_config" and app["scope"]["confidence"] == "high"
    assert mgmt["scope"]["key"] == "aws:unknown:us-east-1"
    assert mgmt["scope"]["source"] == "fallback"
    assert app["scope"]["key"] != mgmt["scope"]["key"]


def test_errored_plan_reconstructs_config_only_resource_as_unresolved():
    plan = load("plan-two-accounts.json")
    assert plan.errored and "aws_iam_role.app" not in plan.planned
    g = graph("plan-two-accounts.json")
    app = by_addr(g, "aws_iam_role.app")
    assert app["resolution"] == "unresolved_at_plan"
    assert app["unresolved_attributes"] == ["assume_role_policy", "name"]
    assert app["name"] is None
    assert any("errored=true" in w for w in g["warnings"])
    (t,) = edges(g, target=app["id"])
    assert t["type"] == "can_assume" and t["source"].endswith("/external.unresolved")


# -- fact 1: the hybrid approach end to end ---------------------------------------------------

def test_fact1_poisoned_plan_full_shape():
    g = graph("plan-poisoned.json")
    S = "aws:unknown:us-east-1"
    types = {n["logical_address"]: n["type"] for n in g["nodes"]}
    assert types == {
        "aws_iam_policy.ci": "policy",
        "aws_iam_role.ci": "principal",
        "aws_iam_role_policy.admin_inline": "policy",
        "aws_kms_key.main": "resource",
        "external.arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com": "external",
        "external.arn:aws:iam::111122223333:role/deploy": "external",
        "external.arn:aws:s3:::my-bucket": "external",
        "wildcard.all": "wildcard",
    }
    (inline,) = edges(g, source=f"{S}/aws_iam_role_policy.admin_inline")
    assert inline["target"] == f"{S}/wildcard.all" and inline["actions"] == ["s3:*"]
    (trust,) = edges(g, type="trusted_by")
    assert trust["source"] == f"{S}/aws_iam_role.ci"
    assert trust["actions"] == ["sts:AssumeRoleWithWebIdentity"]
    assert len(edges(g, type="attaches", source=f"{S}/aws_iam_role.ci")) == 2


def test_explicit_scope_makes_aliases_predictable_on_real_sample():
    g = graph("plan-poisoned.json", explicit_scopes=SUB)
    role = by_addr(g, "aws_iam_role.ci")
    assert role["aliases"] == ["arn:aws:iam::111122223333:role/ci-role"]
    assert by_addr(g, "aws_iam_policy.ci")["aliases"] == ["arn:aws:iam::111122223333:policy/ci-policy"]
    assert role["scope"]["source"] == "explicit"


def test_merging_all_three_samples_validates():
    from archdiff_extractor.validate import validate
    g = merge([extract_plan(load(n), env={}) for n in
               ("plan-poisoned.json", "plan-clean.json", "plan-two-accounts.json")])
    assert validate(g) == []
    assert [c["path"] for c in g["modules"][0]["children"]] == ["plan[0]", "plan[1]", "plan[2]"]
