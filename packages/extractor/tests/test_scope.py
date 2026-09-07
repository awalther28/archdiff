"""Scope resolution: the precedence chain, variable resolution, aliased-provider
isolation, Terragrunt working dir (never cwd), and the root_module invariant."""
from archdiff_extractor.scope import ScopeResolver
from planbuilder import PlanBuilder, const, graph_of, ref


def resolver(builder, **kw):
    kw.setdefault("env", {})            # never read the real environment in tests
    return ScopeResolver(builder.plan(), **kw)


# -- provider_config -------------------------------------------------------------

def test_allowed_account_ids_via_variable_is_high_confidence():
    b = PlanBuilder(variables={"account_id": "111122223333"})
    b.provider("aws", allowed_account_ids=ref("var.account_id"))
    s = resolver(b).resolve("aws")
    assert (s.key, s.account_id, s.region, s.source, s.confidence) == (
        "aws:111122223333:us-east-1", "111122223333", "us-east-1", "provider_config", "high")


def test_allowed_account_ids_constant_list():
    b = PlanBuilder().provider("aws", allowed_account_ids=const(["999988887777"]))
    assert resolver(b).resolve("aws").account_id == "999988887777"


def test_assume_role_arn_gives_account_and_partition():
    b = PlanBuilder(variables={"deploy_role": "arn:aws-us-gov:iam::444455556666:role/deploy"})
    b.provider("aws", region="us-gov-west-1", assume_role=[{"role_arn": ref("var.deploy_role")}])
    s = resolver(b).resolve("aws")
    assert s.account_id == "444455556666"
    assert s.partition == "aws-us-gov"
    assert s.key == "aws-us-gov:444455556666:us-gov-west-1"
    assert s.source == "provider_config"


def test_profile_only_is_keyed_on_profile_and_not_high_confidence():
    b = PlanBuilder().provider("aws", profile=const("prod"))
    s = resolver(b).resolve("aws")
    assert s.account_id is None
    assert s.key == "aws:profile=prod:us-east-1"
    assert s.source == "provider_config"
    assert s.confidence == "medium"


def test_region_from_variable():
    b = PlanBuilder(variables={"region": "eu-west-1", "account_id": "111122223333"})
    b.provider("aws", region=ref("var.region"), allowed_account_ids=ref("var.account_id"))
    assert resolver(b).resolve("aws").key == "aws:111122223333:eu-west-1"


def test_region_prefix_selects_partition():
    b = PlanBuilder().provider("aws", region="cn-north-1", allowed_account_ids=const(["111122223333"]))
    assert resolver(b).resolve("aws").key == "aws-cn:111122223333:cn-north-1"


# -- aliased providers: the subtle bug ---------------------------------------------

def test_aliased_provider_without_account_does_not_inherit_default_providers_variables():
    """The default provider resolves var.account_id; the aliased mgmt provider has
    no account expression. It targets a DIFFERENT account, so the variable
    heuristic must not apply -- otherwise two accounts collapse into one scope."""
    b = PlanBuilder(variables={"account_id": "111122223333", "environment": "prod"})
    b.provider("aws", allowed_account_ids=ref("var.account_id"))
    b.provider("aws.mgmt")
    r = resolver(b)
    default, mgmt = r.resolve("aws"), r.resolve("aws.mgmt")
    assert default.key == "aws:111122223333:us-east-1"
    assert mgmt.key == "aws:unknown:us-east-1"
    assert mgmt.source == "fallback" and mgmt.confidence == "low"
    assert default.key != mgmt.key


def test_two_aliased_providers_resolve_to_two_scopes():
    b = PlanBuilder().provider("aws", allowed_account_ids=const(["111122223333"]))
    b.provider("aws.mgmt", allowed_account_ids=const(["999988887777"]))
    r = resolver(b)
    assert r.resolve("aws").key == "aws:111122223333:us-east-1"
    assert r.resolve("aws.mgmt").key == "aws:999988887777:us-east-1"


def test_scope_is_per_resource_not_per_plan():
    b = PlanBuilder().provider("aws", allowed_account_ids=const(["111122223333"]))
    b.provider("aws.mgmt", allowed_account_ids=const(["999988887777"]))
    b.resource("aws_iam_role.a", "aws_iam_role", {"name": "a", "assume_role_policy": "{}"})
    b.resource("aws_iam_role.b", "aws_iam_role", {"name": "b", "assume_role_policy": "{}"},
               provider_key="aws.mgmt")
    g = graph_of(b, env={})
    ids = {n["id"] for n in g["nodes"] if n["type"] == "principal"}
    assert ids == {"aws:111122223333:us-east-1/aws_iam_role.a", "aws:999988887777:us-east-1/aws_iam_role.b"}
    assert [s["key"] for s in g["scopes"]] == ["aws:111122223333:us-east-1", "aws:999988887777:us-east-1"]


# -- variable heuristic ------------------------------------------------------------

def test_variable_heuristic_account_id_is_low_confidence():
    b = PlanBuilder(variables={"account_id": "111122223333"}).provider("aws")
    s = resolver(b).resolve("aws")
    assert s.key == "aws:111122223333:us-east-1"
    assert s.source == "variable_heuristic"
    assert s.confidence == "low"


def test_variable_heuristic_environment():
    b = PlanBuilder(variables={"environment": "staging"}).provider("aws")
    s = resolver(b).resolve("aws")
    assert s.key == "aws:env=staging:us-east-1"
    assert s.account_id is None
    assert s.source == "variable_heuristic"


def test_variable_heuristic_ignores_non_account_values():
    b = PlanBuilder(variables={"account_id": "not-an-account"}).provider("aws")
    assert resolver(b).resolve("aws").source == "fallback"


# -- fallback ------------------------------------------------------------------------

def test_fallback_keeps_region_when_known():
    b = PlanBuilder().provider("aws", region="eu-central-1")
    s = resolver(b).resolve("aws")
    assert (s.key, s.source, s.confidence) == ("aws:unknown:eu-central-1", "fallback", "low")


def test_fallback_with_nothing_known():
    s = resolver(PlanBuilder()).resolve("aws")
    assert s.key == "aws:unknown:unknown"
    assert s.account_id is None and s.region is None


# -- explicit -------------------------------------------------------------------------

def test_explicit_override_wins_over_provider_config():
    b = PlanBuilder().provider("aws", allowed_account_ids=const(["111122223333"]))
    s = resolver(b, explicit={"aws": {"account_id": "000000000000", "region": "us-west-2"}}).resolve("aws")
    assert s.key == "aws:000000000000:us-west-2"
    assert (s.source, s.confidence) == ("explicit", "high")


def test_explicit_override_matches_module_local_provider_key():
    b = PlanBuilder().provider("aws.mgmt")
    s = resolver(b, explicit={"aws.mgmt": {"account_id": "999988887777"}}).resolve("module.iam:aws.mgmt")
    assert s.account_id == "999988887777"


# -- terragrunt -------------------------------------------------------------------------

def test_terragrunt_working_dir_from_env_not_cwd(monkeypatch, tmp_path):
    """Terragrunt executes inside .terragrunt-cache/<hash>/; cwd is useless."""
    cache = tmp_path / "live" / "prod" / "111122223333" / "us-west-2" / "iam" / ".terragrunt-cache" / "abc" / "def"
    cache.mkdir(parents=True)
    monkeypatch.chdir(cache)
    unit = str(tmp_path / "live" / "prod" / "111122223333" / "us-west-2" / "iam")
    b = PlanBuilder().provider("aws", region=None)
    s = ScopeResolver(b.plan(), env={"TERRAGRUNT_WORKING_DIR": unit}, repo_root=str(tmp_path)).resolve("aws")
    assert s.account_id == "111122223333"
    assert s.region == "us-west-2"
    assert s.key == "aws:111122223333:us-west-2"
    assert (s.source, s.confidence) == ("terragrunt_unit", "medium")


def test_terragrunt_unit_without_account_in_path_is_keyed_on_unit(tmp_path):
    unit = str(tmp_path / "live" / "prod" / "iam")
    b = PlanBuilder().provider("aws")
    r = ScopeResolver(b.plan(), env={"TERRAGRUNT_WORKING_DIR": unit}, repo_root=str(tmp_path))
    s = r.resolve("aws")
    assert s.key == "aws:unit=live/prod/iam:us-east-1"
    assert s.source == "terragrunt_unit"
    assert r.default_root_module() == "live/prod/iam"


def test_terragrunt_is_below_provider_config_in_precedence(tmp_path):
    unit = str(tmp_path / "live" / "999988887777" / "iam")
    b = PlanBuilder().provider("aws", allowed_account_ids=const(["111122223333"]))
    s = ScopeResolver(b.plan(), env={"TERRAGRUNT_WORKING_DIR": unit}).resolve("aws")
    assert s.account_id == "111122223333" and s.source == "provider_config"


def test_terragrunt_is_above_variable_heuristic(tmp_path):
    unit = str(tmp_path / "live" / "999988887777" / "iam")
    b = PlanBuilder(variables={"account_id": "111122223333"}).provider("aws")
    s = ScopeResolver(b.plan(), env={"TERRAGRUNT_WORKING_DIR": unit}).resolve("aws")
    assert s.account_id == "999988887777" and s.source == "terragrunt_unit"


def test_cwd_is_never_consulted(monkeypatch, tmp_path):
    inside = tmp_path / "live" / "555566667777" / "eu-west-1" / "x"
    inside.mkdir(parents=True)
    monkeypatch.chdir(inside)
    s = ScopeResolver(PlanBuilder().provider("aws").plan(), env={}).resolve("aws")
    assert s.source == "fallback" and s.account_id is None


# -- module provider inheritance ----------------------------------------------------------

def test_child_module_inherits_root_provider_facts():
    b = PlanBuilder().provider("aws", allowed_account_ids=const(["111122223333"]))
    b.provider("module.iam:aws", region=None)          # inherited block without expressions
    s = resolver(b).resolve("module.iam:aws")
    assert s.key == "aws:111122223333:us-east-1"


def test_child_module_provider_key_without_entry_walks_to_root():
    b = PlanBuilder().provider("aws", allowed_account_ids=const(["111122223333"]))
    assert resolver(b).resolve("module.a.module.b:aws").account_id == "111122223333"


# -- root_module invariant ------------------------------------------------------------------

def test_root_module_is_informational_and_never_in_key_or_digest():
    def build(root):
        b = PlanBuilder().provider("aws", allowed_account_ids=const(["111122223333"]))
        b.resource("aws_iam_role.r", "aws_iam_role",
                   {"name": "r", "assume_role_policy": '{"Statement":[]}'})
        return graph_of(b, roots=[root], env={})

    a, c = build("live/prod/iam"), build("live/prod/identity/roles")
    na = {n["id"]: n for n in a["nodes"]}
    nc = {n["id"]: n for n in c["nodes"]}
    assert set(na) == set(nc)
    for nid in na:
        assert na[nid]["digest"] == nc[nid]["digest"]
        assert na[nid]["scope"]["root_module"] == "live/prod/iam"
        assert nc[nid]["scope"]["root_module"] == "live/prod/identity/roles"
        assert "live/prod" not in na[nid]["scope"]["key"]
    assert a["modules"][0]["digest"] == c["modules"][0]["digest"]


def test_scope_with_multiple_allowed_accounts_warns_and_uses_first():
    b = PlanBuilder().provider("aws", allowed_account_ids=const(["111122223333", "999988887777"]))
    r = resolver(b)
    assert r.resolve("aws").account_id == "111122223333"
    assert any("allowed_account_ids lists 2 accounts" in w for w in r.warnings)
