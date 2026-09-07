"""Cost scales with the size of the CHANGE, not the repo.

Synthesises a >=100k-node graph across 500 modules, changes ONE leaf, and
checks (a) the Merkle prune skipped nearly every module, (b) the comparison
work done is bounded by the changed leaf, (c) the structural stage with the
prune is far cheaper than without it and (d) the semantic stage only touched
the affected principals.  Absolute times are printed for the report, not
asserted (CI machines vary); the ratios are asserted.
"""
import json
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bench"))

from archdiff_differ import Graph, diff_graphs  # noqa: E402
from archdiff_differ.structural import full_compare, structural_diff, verify_all_digests  # noqa: E402
from synth import generate, mutate  # noqa: E402

GROUPS, LEAVES, ROLES = 20, 25, 80   # 20*25*(2*80+40+1) = 100,500 nodes + 2


@pytest.fixture(scope="module")
def big():
    t0 = time.perf_counter()
    base = generate(GROUPS, LEAVES, ROLES)
    head = mutate(json.loads(json.dumps(base)), "7/3")
    gen = time.perf_counter() - t0
    return base, head, gen


def test_generator_output_is_schema_honest(big):
    base, head, _ = big
    assert len(base["nodes"]) >= 100_000
    g = Graph(head)
    assert verify_all_digests(g) == []   # every digest + rollup recomputes with canonical.py


def test_one_leaf_change_scales_with_change(big, capsys):
    base, head, gen = big
    gb, gh = Graph(base, "base"), Graph(head, "head")
    gb._bucket(); gh._bucket()   # measured separately below

    t0 = time.perf_counter(); res = structural_diff(gb, gh); t_merkle = time.perf_counter() - t0
    t0 = time.perf_counter(); full = full_compare(gb, gh); t_full = time.perf_counter() - t0
    t0 = time.perf_counter(); gb._bucket(); gh._bucket(); t_bucket = time.perf_counter() - t0
    t0 = time.perf_counter(); d = diff_graphs(gb, gh); t_diff = time.perf_counter() - t0

    assert res.as_doc() == full.as_doc()
    assert len(res.edges["changed"]) == 1 and not res.nodes["changed"]
    s = res.stats
    # 1 + 20 + 500 modules; compared: root, g7, l3  -> skipped 518
    assert s["modules_total"] == 521
    assert s["modules_compared"] == 3
    assert s["modules_skipped"] == 518
    assert s["merkle"]["prune_points"] == 19 + 24
    assert s["merkle"]["verified"] is True
    leaf_nodes = 2 * ROLES + ROLES // 2 + 1
    assert s["nodes_compared"] == leaf_nodes + 2          # leaf + 2 root wildcards
    assert s["nodes_compared"] < len(gb.nodes) / 100
    assert t_merkle * 5 < t_full, f"merkle {t_merkle:.4f}s vs full {t_full:.4f}s"
    sem = d.doc["stats"]["semantic"]
    assert sem["principals_evaluated"] == 1
    assert d.doc["findings"][0]["kind"] == "wildcard_capability_added"
    with capsys.disabled():
        print(f"\n[perf] nodes={len(gb.nodes):,} edges={len(gb.edges):,} modules={s['modules_total']} "
              f"generate={gen:.2f}s bucket={t_bucket:.3f}s "
              f"structural(merkle)={t_merkle*1000:.1f}ms structural(full)={t_full*1000:.1f}ms "
              f"whole_diff={t_diff*1000:.1f}ms modules_skipped={s['modules_skipped']} "
              f"nodes_compared={s['nodes_compared']} principals_evaluated={sem['principals_evaluated']}")


def test_unchanged_big_graph_is_o1(big):
    base, _, _ = big
    gb, gh = Graph(base), Graph(json.loads(json.dumps(base)))
    t0 = time.perf_counter(); res = structural_diff(gb, gh); t = time.perf_counter() - t0
    assert res.is_empty and res.stats["nodes_compared"] == 0
    assert res.stats["modules_skipped"] == 521 and res.stats["merkle"]["prune_points"] == 1
    # root digest equal: no bucket is even built
    assert gb._node_buckets is None
    assert t < 0.05
