"""Byte-reproducibility: identical input -> identical bytes. Also the section-8
null results: statement reorder, root_module change, plan order."""
import json
import os

from archdiff_extractor.cli import build_graph, dumps
from archdiff_extractor.extract import extract_plan
from archdiff_extractor.merge import merge
from archdiff_extractor.plan import Plan
from conftest import FIXTURES

SAMPLES = ["plan-poisoned.json", "plan-clean.json", "plan-two-accounts.json"]


def paths():
    return [os.path.join(FIXTURES, n) for n in SAMPLES]


def test_extraction_twice_is_byte_identical():
    first = dumps(build_graph(paths(), roots=["a", "b", "c"]))
    second = dumps(build_graph(paths(), roots=["a", "b", "c"]))
    assert first == second
    assert first.encode("utf-8") == second.encode("utf-8")


def test_reload_from_disk_between_runs_is_byte_identical(tmp_path):
    out1, out2 = tmp_path / "1.json", tmp_path / "2.json"
    for out in (out1, out2):
        out.write_text(dumps(build_graph(paths(), roots=["a", "b", "c"])), encoding="utf-8")
    assert out1.read_bytes() == out2.read_bytes()


def test_nodes_and_edges_are_sorted_by_id():
    g = build_graph(paths(), roots=["a", "b", "c"])
    assert [n["id"] for n in g["nodes"]] == sorted(n["id"] for n in g["nodes"])
    assert [e["id"] for e in g["edges"]] == sorted(e["id"] for e in g["edges"])
    assert g["warnings"] == sorted(set(g["warnings"]))
    assert [s["key"] for s in g["scopes"]] == sorted(s["key"] for s in g["scopes"])


def test_plan_order_does_not_change_digests_when_roots_are_labelled():
    a = build_graph(paths(), roots=["a", "b", "c"])
    b = build_graph(list(reversed(paths())), roots=["c", "b", "a"])
    assert a["modules"][0]["digest"] == b["modules"][0]["digest"]
    assert [n["digest"] for n in a["nodes"]] == [n["digest"] for n in b["nodes"]]
    assert [e["id"] for e in a["edges"]] == [e["id"] for e in b["edges"]]


def test_serialised_form_is_canonical_json_with_sorted_keys():
    text = dumps(build_graph(paths()[:1], roots=["a"]))
    assert text.endswith("\n")
    doc = json.loads(text)
    assert text == json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    assert "timestamp" not in text          # no clock leaks into the artifact


def test_no_timestamp_or_terraform_version_in_output():
    g = build_graph(paths(), roots=["a", "b", "c"])
    assert set(g) == {"schema_version", "generated_by", "scopes", "modules", "moves", "nodes", "edges", "warnings"}
    assert g["generated_by"] == {"tool_version": "0.1.0", "extractor_version": "1"}


def test_root_module_relabel_is_a_null_diff():
    plan = Plan.load(paths()[0])
    a = merge([extract_plan(plan, root_module="live/prod/iam", env={})])
    b = merge([extract_plan(plan, root_module="live/prod/identity/roles", env={})])
    assert {n["id"]: n["digest"] for n in a["nodes"]} == {n["id"]: n["digest"] for n in b["nodes"]}
    assert {e["id"]: e["digest"] for e in a["edges"]} == {e["id"]: e["digest"] for e in b["edges"]}
    assert a["modules"][0]["digest"] == b["modules"][0]["digest"]
    assert a["modules"][0]["children"][0]["path"] != b["modules"][0]["children"][0]["path"]
