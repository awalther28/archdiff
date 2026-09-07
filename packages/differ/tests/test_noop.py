"""THE MOST IMPORTANT TEST (SCHEMA.md section 8).

base.graph.json vs refactor-noop.graph.json differ only in scope.root_module,
which is excluded from every digest.  The diff must be completely empty --
every array, both stages -- and must say so affirmatively.
"""
import pytest

from archdiff_differ import Graph, diff_graphs, dumps
from archdiff_differ.differ import is_empty_doc
from archdiff_differ.render import render_markdown
from conftest import all_arrays


@pytest.fixture(scope="module")
def noop(base_doc, noop_doc):
    return diff_graphs(Graph(base_doc, "base"), Graph(noop_doc, "head"))


def test_inputs_really_differ_only_in_root_module(base_doc, noop_doc):
    assert base_doc != noop_doc
    b_roots = {n["scope"]["root_module"] for n in base_doc["nodes"]}
    h_roots = {n["scope"]["root_module"] for n in noop_doc["nodes"]}
    assert b_roots != h_roots


def test_every_array_in_the_diff_is_empty(noop):
    non_empty = [p for p, arr in all_arrays(noop.doc) if arr]
    assert non_empty == [], f"non-empty arrays in a no-op diff: {non_empty}"


def test_structural_stage_empty(noop):
    s = noop.doc["structural"]
    for kind in ("nodes", "edges"):
        for op in ("added", "removed", "changed"):
            assert s[kind][op] == []


def test_semantic_stage_empty(noop):
    m = noop.doc["semantic"]
    assert m["capabilities"] == {"added": [], "removed": []}
    assert m["paths"] == {"added": [], "removed": []}
    assert noop.doc["findings"] == []
    assert noop.doc["unevaluated"] == []


def test_empty_is_affirmative(noop):
    assert noop.doc["empty"] is True
    assert is_empty_doc(noop.doc)
    assert noop.is_empty
    md = render_markdown(noop.doc)
    assert "No permission changes" in md.splitlines()[0]


def test_graph_digests_identical(noop):
    assert noop.doc["base"]["graph_digest"] == noop.doc["head"]["graph_digest"]


def test_merkle_actually_pruned(noop):
    s = noop.doc["stats"]
    assert s["modules_skipped"] == 1 == s["modules_total"]
    assert s["nodes_compared"] == 0 and s["edges_compared"] == 0
    assert s["merkle"]["prune_points"] == 1
    assert s["semantic"]["principals_evaluated"] == 0


def test_noop_also_empty_without_merkle_and_with_full_semantic(base_doc, noop_doc):
    res = diff_graphs(Graph(base_doc), Graph(noop_doc), use_merkle=False, full_semantic=True)
    assert res.doc["empty"] is True
    assert [p for p, arr in all_arrays(res.doc) if arr] == []
    assert res.doc["stats"]["nodes_compared"] == 10
    assert res.doc["stats"]["modules_skipped"] == 0


def test_noop_is_symmetric(base_doc, noop_doc):
    a = dumps(diff_graphs(Graph(base_doc), Graph(noop_doc)).doc)
    b = dumps(diff_graphs(Graph(noop_doc), Graph(base_doc)).doc)
    assert a == b
