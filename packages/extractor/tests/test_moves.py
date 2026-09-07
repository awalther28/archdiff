"""``moved {}`` blocks (SCHEMA.md 6.1): parsed from HCL (they are absent from
plan JSON without prior state), prefix semantics, transitive chains, cycle
detection, per-scope attribution, and no effect on any digest."""
import json

from archdiff_extractor.extract import extract_plan
from archdiff_extractor.merge import merge
from archdiff_extractor.moves import (load_moves_from_dir, parse_moved_blocks, parse_moved_json,
                                      prefix_matches, resolve_chains, rewrite)
from archdiff_extractor.validate import validate
from planbuilder import PlanBuilder, const, policy

ACCT = "111122223333"
S = f"aws:{ACCT}:us-east-1"
MGMT = "999988887777"
M = f"aws:{MGMT}:us-east-1"


# -- HCL parsing --------------------------------------------------------------------

def test_parse_moved_blocks_in_either_order_with_comments_and_keys():
    text = '''
    resource "aws_iam_role" "ci" { name = "ci" } # not a moved block
    moved {
      # comment with a brace }
      to   = module.deployer.aws_iam_role.this   // trailing comment
      from = aws_iam_role.deployer
    }
    moved {
      from = module.app["x"]
      to   = module.workload["x"]
    }
    moved {
      from = aws_iam_role.r["a"]
      to   = aws_iam_role.r["b"]  # key contains a quote and a bracket
    }
    '''
    assert parse_moved_blocks(text) == [
        ("aws_iam_role.deployer", "module.deployer.aws_iam_role.this"),
        ('module.app["x"]', 'module.workload["x"]'),
        ('aws_iam_role.r["a"]', 'aws_iam_role.r["b"]'),
    ]


def test_parse_moved_blocks_one_per_line_form():
    text = 'moved {\n  from = module.app\n  to   = module.workload\n}\n'
    assert parse_moved_blocks(text) == [("module.app", "module.workload")]


def test_parse_moved_blocks_ignores_strings_containing_braces():
    text = 'locals { x = "}" }\nmoved {\n from = a.b\n to = c.d\n}\n'
    assert parse_moved_blocks(text) == [("a.b", "c.d")]


def test_parse_moved_json():
    assert parse_moved_json({"moved": [{"from": "a.b", "to": "c.d"}]}) == [("a.b", "c.d")]
    assert parse_moved_json({"moved": {"from": "a.b", "to": "c.d"}}) == [("a.b", "c.d")]
    assert parse_moved_json({"resource": {}}) == []


def test_load_moves_walks_local_child_modules_with_prefix(tmp_path):
    root = tmp_path / "root"
    child = tmp_path / "modules" / "role"
    child.mkdir(parents=True)
    root.mkdir()
    (root / "main.tf").write_text('module "role" {\n  source = "../modules/role"\n}\nmoved {\n from = aws_iam_role.old\n to = module.role.aws_iam_role.this\n}\n')
    (root / "extra.tf.json").write_text(json.dumps({"moved": [{"from": "aws_iam_policy.a", "to": "aws_iam_policy.b"}]}))
    (child / "moves.tf").write_text('moved {\n from = aws_iam_role.legacy\n to = aws_iam_role.this\n}\n')
    moves, warnings = load_moves_from_dir(str(root))
    assert warnings == []
    assert sorted(moves) == [
        ("aws_iam_policy.a", "aws_iam_policy.b"),
        ("aws_iam_role.old", "module.role.aws_iam_role.this"),
        ("module.role.aws_iam_role.legacy", "module.role.aws_iam_role.this"),
    ]


def test_load_moves_uses_plan_module_sources_when_given(tmp_path):
    root = tmp_path / "root"
    child = tmp_path / "mods" / "x"
    root.mkdir(); child.mkdir(parents=True)
    (root / "main.tf").write_text("")
    (child / "m.tf").write_text('moved {\n from = a.b\n to = a.c\n}\n')
    moves, _ = load_moves_from_dir(str(root), {"x": "../mods/x", "remote": "git::https://example.invalid/x"})
    assert moves == [("module.x.a.b", "module.x.a.c")]


def test_missing_source_dir_warns_not_raises(tmp_path):
    moves, warnings = load_moves_from_dir(str(tmp_path / "nope"))
    assert moves == [] and any("not found" in w for w in warnings)


# -- semantics ------------------------------------------------------------------------

def test_prefix_match_semantics():
    assert prefix_matches("module.app", "module.app")
    assert prefix_matches("module.app", "module.app.aws_iam_role.this")
    assert prefix_matches("module.app", 'module.app["x"].aws_iam_role.this')
    assert not prefix_matches("module.app", "module.application.aws_iam_role.this")
    assert rewrite("module.app.aws_iam_role.this", [("module.app", "module.workload")]) == "module.workload.aws_iam_role.this"
    assert rewrite("aws_iam_role.x", [("module.app", "module.workload")]) == "aws_iam_role.x"


def test_chains_resolve_transitively():
    composed, warnings = resolve_chains([("a.x", "b.x"), ("b.x", "c.x")])
    assert warnings == []
    assert ("a.x", "c.x") in composed and ("b.x", "c.x") in composed
    assert not any(t == "b.x" for _, t in composed)


def test_chains_resolve_through_prefix_moves():
    composed, _ = resolve_chains([("module.app", "module.workload"),
                                  ("module.workload.aws_iam_role.this", "aws_iam_role.deployer")])
    assert ("module.app", "module.workload") in composed
    assert ("module.workload.aws_iam_role.this", "aws_iam_role.deployer") in composed


def test_cycles_are_detected_and_dropped_with_warning():
    composed, warnings = resolve_chains([("a.x", "b.x"), ("b.x", "a.x")])
    assert composed == []
    assert warnings and all("cycle" in w for w in warnings)
    composed, warnings = resolve_chains([("a.x", "b.x"), ("b.x", "c.x"), ("c.x", "a.x")])
    assert composed == [] and warnings


def test_self_move_and_duplicates_are_ignored():
    composed, warnings = resolve_chains([("a.x", "a.x"), ("a.y", "b.y"), ("a.y", "b.y")])
    assert composed == [("a.y", "b.y")] and warnings == []


# -- extraction -------------------------------------------------------------------------

def two_scope_plan():
    b = PlanBuilder().provider("aws", allowed_account_ids=const([ACCT]))
    b.provider("aws.mgmt", allowed_account_ids=const([MGMT]))
    b.module("module.workload")
    b.resource("module.workload.aws_iam_role.a", "aws_iam_role", {"name": "a", "path": "/", "assume_role_policy": "{}"},
               unknown={"arn": True}, provider_key="module.workload:aws")
    b.resource("module.workload.aws_iam_role.m", "aws_iam_role", {"name": "m", "path": "/", "assume_role_policy": "{}"},
               unknown={"arn": True}, provider_key="module.workload:aws.mgmt")
    b.resource("aws_iam_policy.p", "aws_iam_policy", {"name": "p", "path": "/", "policy": policy()}, unknown={"arn": True})
    return b


def test_moves_are_attributed_to_every_scope_under_the_target(tmp_path):
    (tmp_path / "moves.tf").write_text(
        'moved {\n from = module.app\n to = module.workload\n}\n'
        'moved {\n from = aws_iam_policy.old\n to = aws_iam_policy.p\n}\n')
    g = merge([extract_plan(two_scope_plan().plan(), source_dir=str(tmp_path), env={})])
    assert g["moves"] == [
        {"scope_key": S, "from": "aws_iam_policy.old", "to": "aws_iam_policy.p"},
        {"scope_key": S, "from": "module.app", "to": "module.workload"},
        {"scope_key": M, "from": "module.app", "to": "module.workload"},
    ]
    assert validate(g) == []


def test_move_to_unknown_target_is_recorded_for_all_scopes_with_warning(tmp_path):
    (tmp_path / "moves.tf").write_text('moved {\n from = aws_iam_role.x\n to = aws_iam_role.y\n}\n')
    g = merge([extract_plan(two_scope_plan().plan(), source_dir=str(tmp_path), env={})])
    assert [m["scope_key"] for m in g["moves"]] == [S, M]
    assert any("no node under the target address" in w for w in g["warnings"])


def test_previous_address_and_hcl_moves_are_merged_and_deduplicated(tmp_path):
    (tmp_path / "m.tf").write_text('moved {\n from = aws_iam_policy.old\n to = aws_iam_policy.p\n}\n')
    b = two_scope_plan().moved("aws_iam_policy.old", "aws_iam_policy.p")
    g = merge([extract_plan(b.plan(), source_dir=str(tmp_path), env={})])
    assert g["moves"] == [{"scope_key": S, "from": "aws_iam_policy.old", "to": "aws_iam_policy.p"}]


def test_moves_do_not_affect_any_digest(tmp_path):
    (tmp_path / "m.tf").write_text('moved {\n from = aws_iam_policy.old\n to = aws_iam_policy.p\n}\n')
    with_moves = merge([extract_plan(two_scope_plan().plan(), source_dir=str(tmp_path), env={})])
    without = merge([extract_plan(two_scope_plan().plan(), env={})])
    assert with_moves["moves"] and without["moves"] == []
    assert [n["digest"] for n in with_moves["nodes"]] == [n["digest"] for n in without["nodes"]]
    assert with_moves["modules"][0]["digest"] == without["modules"][0]["digest"]


def test_moves_are_sorted_and_merged_across_plans(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir(); b.mkdir()
    (a / "m.tf").write_text('moved {\n from = aws_iam_policy.z\n to = aws_iam_policy.p\n}\n')
    (b / "m.tf").write_text('moved {\n from = aws_iam_policy.a\n to = aws_iam_policy.p\n}\n')
    g = merge([extract_plan(two_scope_plan().plan(), source_dir=str(a), root_module="a", env={}),
               extract_plan(two_scope_plan().plan(), source_dir=str(b), root_module="b", env={})])
    assert [m["from"] for m in g["moves"]] == ["aws_iam_policy.a", "aws_iam_policy.z"]
