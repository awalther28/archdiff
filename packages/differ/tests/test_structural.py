"""Stage 1: hash-set comparison + Merkle prune, in isolation from Stage 2."""
import json

import pytest

from archdiff_differ import Graph
from archdiff_differ.address import (UNASSIGNED_KEY, module_key_of_address, module_key_of_path,
                              split_address)
from archdiff_differ.builder import GraphBuilder, scope
from archdiff_differ.structural import full_compare, structural_diff, verify_all_digests

SC = scope("111122223333")


def _tree(n_mods=4, per=3):
    """root -> module.m{i} -> module.leaf{j}; each leaf has a role, policy, bucket, 2 edges."""
    b = GraphBuilder()
    for i in range(n_mods):
        for j in range(per):
            pre = f"module.m{i}.module.leaf{j}."
            r = b.principal(SC, pre + "aws_iam_role.r")
            p = b.policy(SC, pre + "aws_iam_policy.p")
            s = b.resource(SC, pre + "aws_s3_bucket.b", "b", f"arn:aws:s3:::b-{i}-{j}")
            b.attaches(r, p)
            b.grants(p, s, ["s3:GetObject"], [f"arn:aws:s3:::b-{i}-{j}/*"], "Read")
    b.principal(SC, "aws_iam_role.top")  # lives directly in root
    return b


# --- address parsing -------------------------------------------------------

def test_split_address_respects_brackets_and_quotes():
    assert split_address('module.a["x.y"].aws_iam_role.r') == ["module", 'a["x.y"]', "aws_iam_role", "r"]
    assert split_address("module.a[0].module.b.aws_iam_role.r[1]") == \
        ["module", "a[0]", "module", "b", "aws_iam_role", "r[1]"]


def test_module_key_of_address():
    assert module_key_of_address("aws_iam_role.r") == ()
    assert module_key_of_address("module.a.module.b.aws_iam_role.r") == ("a", "b")
    assert module_key_of_address('module.a["k"].aws_iam_role.r') == ('a["k"]',)


@pytest.mark.parametrize("path", ["root", "", "root/", "."])
def test_module_key_of_root_spellings(path):
    assert module_key_of_path(path) == ()


@pytest.mark.parametrize("path", ["module.a.module.b", "root/module.a/module.b", "a/b",
                                  "root/a/b", "module.a/module.b"])
def test_module_key_of_nested_spellings(path):
    assert module_key_of_path(path) == ("a", "b")


# --- comparison ------------------------------------------------------------

def test_builder_graphs_verify_against_canonical():
    g = Graph(_tree().build())
    assert verify_all_digests(g) == []


def test_identical_trees_prune_everything():
    doc = _tree().build()
    res = structural_diff(Graph(doc), Graph(json.loads(json.dumps(doc))))
    assert res.is_empty
    assert res.stats["modules_skipped"] == res.stats["modules_total"] == 1 + 4 + 12
    assert res.stats["merkle"]["prune_points"] == 1
    assert res.stats["nodes_compared"] == 0


def test_one_leaf_change_compares_only_its_ancestors():
    base = _tree()
    head = base.clone()
    pol = "aws:111122223333:us-east-1/module.m2.module.leaf1.aws_iam_policy.p"
    head.grants(pol, "aws:111122223333:us-east-1/module.m2.module.leaf1.aws_s3_bucket.b",
                ["s3:*"], ["*"], "Read")
    res = structural_diff(Graph(base.build()), Graph(head.build()))
    assert res.edges["changed"][0]["id"] == pol + "#stmt:Read"
    assert res.nodes == {"added": [], "removed": [], "changed": []}
    # compared: root (1 node), m2 (0 nodes), leaf1 (3 nodes) -> 4 nodes, 2 edges
    assert res.stats["nodes_compared"] == 4
    assert res.stats["edges_compared"] == 2
    assert res.stats["modules_compared"] == 3
    # skipped: 3 other top modules with 3 leaves each (12) + 2 sibling leaves = 14
    assert res.stats["modules_skipped"] == 14
    assert res.stats["merkle"]["prune_points"] == 3 + 2
    assert res.stats["merkle"]["verified"] is True
    assert res.field_deltas[pol + "#stmt:Read"] == ["target", "actions", "resource_patterns"] or \
        set(res.field_deltas[pol + "#stmt:Read"]) == {"actions", "resource_patterns"}


def test_merkle_result_equals_full_compare():
    base = _tree()
    head = base.clone()
    head.principal(SC, "module.m0.module.leaf0.aws_iam_role.extra")
    head.remove_node("aws:111122223333:us-east-1/module.m3.module.leaf2.aws_s3_bucket.b")
    head.remove_edge("aws:111122223333:us-east-1/module.m3.module.leaf2.aws_iam_policy.p#stmt:Read")
    head.node(SC, "module.m1.module.leaf1.aws_iam_role.r", "principal", "renamed",
              ["arn:aws:iam::111122223333:role/renamed"])
    gb, gh = Graph(base.build()), Graph(head.build())
    m = structural_diff(gb, gh)
    f = full_compare(gb, gh)
    assert m.as_doc() == f.as_doc()
    assert m.stats["modules_skipped"] > 0 and f.stats["modules_skipped"] == 0
    assert m.field_deltas == f.field_deltas
    assert m.field_deltas["aws:111122223333:us-east-1/module.m1.module.leaf1.aws_iam_role.r"] == ["name", "aliases"]


def test_added_and_removed_modules():
    base = _tree(n_mods=2)
    head = _tree(n_mods=3)
    res = structural_diff(Graph(base.build()), Graph(head.build()))
    assert len(res.nodes["added"]) == 9 and len(res.edges["added"]) == 6
    assert res.stats["modules_skipped"] == 2 * (1 + 3)
    back = structural_diff(Graph(head.build()), Graph(base.build()))
    assert len(back.nodes["removed"]) == 9


def test_changed_entry_shape_matches_section_7_fixture():
    base = _tree(1, 1)
    head = base.clone()
    head.node(SC, "module.m0.module.leaf0.aws_iam_role.r", "principal", "other-name")
    res = structural_diff(Graph(base.build()), Graph(head.build()))
    (c,) = res.nodes["changed"]
    assert set(c) == {"id", "before_digest", "after_digest"}
    assert c["before_digest"] != c["after_digest"]


def test_tampered_module_digest_falls_back_to_full_compare():
    """If the module tree lies about a compared module, the prune is not
    trusted: full comparison, modules_skipped = 0, reason recorded."""
    base = _tree(2, 2)
    head = base.clone()
    head.principal(SC, "module.m0.module.leaf0.aws_iam_role.extra")
    hd = head.build()
    # corrupt the *changed* module's digest so recomputation cannot match
    hd["modules"][0]["children"][0]["children"][0]["digest"] = "f" * 16
    res = structural_diff(Graph(base.build()), Graph(hd))
    assert res.stats["merkle"]["enabled"] is False
    assert "verification failed" in res.stats["merkle"]["fallback_reason"]
    assert res.stats["modules_skipped"] == 0
    assert len(res.nodes["added"]) == 1


def test_misbucketed_node_cannot_hide_a_change():
    """A node whose address says module X but which the extractor rolled into
    module Y: the prune must never skip its change.  We simulate this by
    moving a node's digest between module rollups in the document."""
    base = _tree(2, 1)
    head = base.clone()
    head.node(SC, "module.m1.module.leaf0.aws_iam_role.r", "principal", "changed")
    bd, hd = base.build(), head.build()
    from archdiff_differ.canonical import module_digest
    # In both documents, pretend m1/leaf0's role belongs to m0/leaf0's rollup
    for doc in (bd, hd):
        nodes = {n["id"]: n for n in doc["nodes"]}
        edges = {e["id"]: e for e in doc["edges"]}
        r1 = nodes["aws:111122223333:us-east-1/module.m1.module.leaf0.aws_iam_role.r"]["digest"]
        def leaf(i):
            ids_n = [d for k, d in ((k, v["digest"]) for k, v in nodes.items()) if f"module.m{i}." in k]
            ids_e = [d for k, d in ((k, v["digest"]) for k, v in edges.items()) if f"module.m{i}." in k]
            return ids_n, ids_e
        n0, e0 = leaf(0); n1, e1 = leaf(1)
        n0 = n0 + [r1]; n1 = [d for d in n1 if d != r1]
        m0l = module_digest(n0, e0, []); m1l = module_digest(n1, e1, [])
        m0 = module_digest([], [], [m0l]); m1 = module_digest([], [], [m1l])
        top = nodes["aws:111122223333:us-east-1/aws_iam_role.top"]["digest"]
        doc["modules"] = [{"path": "root", "digest": module_digest([top], [], [m0, m1]), "children": [
            {"path": "module.m0", "digest": m0, "children": [{"path": "module.m0.module.leaf0", "digest": m0l}]},
            {"path": "module.m1", "digest": m1, "children": [{"path": "module.m1.module.leaf0", "digest": m1l}]}]}]
    res = structural_diff(Graph(bd), Graph(hd))
    assert [c["id"] for c in res.nodes["changed"]] == \
        ["aws:111122223333:us-east-1/module.m1.module.leaf0.aws_iam_role.r"]
    assert res.stats["merkle"]["enabled"] is False  # detected, fell back


def test_unmappable_module_paths_are_compared_not_skipped():
    base = _tree(1, 1)
    head = base.clone()
    head.node(SC, "module.m0.module.leaf0.aws_iam_role.r", "principal", "changed")
    bd, hd = base.build(), head.build()
    for doc in (bd, hd):
        doc["modules"][0]["children"][0]["children"][0]["path"] = "live/prod/something"   # unrecognisable
    gb, gh = Graph(bd), Graph(hd)
    assert gb.node_bucket(UNASSIGNED_KEY)
    res = structural_diff(gb, gh)
    assert len(res.nodes["changed"]) == 1


def test_duplicate_module_paths_disable_merkle():
    doc = _tree(1, 1).build()
    doc["modules"][0]["children"].append(dict(doc["modules"][0]["children"][0]))
    g = Graph(doc)
    assert not g.merkle_ok
    res = structural_diff(g, Graph(doc))
    assert res.stats["merkle"]["enabled"] is False and res.is_empty


def test_no_module_tree_still_diffs():
    doc = _tree(1, 1).build()
    doc["modules"] = []
    res = structural_diff(Graph(doc), Graph(doc))
    assert res.is_empty and res.stats["merkle"]["enabled"] is False
    assert Graph(doc).graph_digest  # rollup over everything, still deterministic
