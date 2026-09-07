"""Reproducible performance measurement.

    python bench/run.py                # default ladder, prints a markdown table
    python bench/run.py --sizes 40,80  # roles per leaf; 20 groups x 25 leaves each

For each size: build base, apply the one-leaf mutation, then time
  * json.loads of both documents          (O(repo), unavoidable)
  * Graph indexing                        (O(repo), dict building)
  * structural diff WITH the Merkle prune (should be ~flat)
  * structural diff WITHOUT it            (O(repo))
  * full diff (structural + semantic + findings), incremental semantic
Each timing is the best of `--repeat` runs.  Numbers are wall-clock
(time.perf_counter) on whatever machine runs this; rerun rather than quote.
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from permdiff import Graph, diff_graphs  # noqa: E402
from permdiff.structural import full_compare, structural_diff  # noqa: E402
from synth import generate, mutate  # noqa: E402


def best(fn, repeat):
    t = float("inf")
    out = None
    for _ in range(repeat):
        t0 = time.perf_counter()
        out = fn()
        t = min(t, time.perf_counter() - t0)
    return t, out


def measure(groups, leaves, roles, repeat, leaf="7/3"):
    base = generate(groups, leaves, roles)
    head = mutate(json.loads(json.dumps(base)), leaf)
    bt, ht = json.dumps(base, sort_keys=True, separators=(",", ":")), \
        json.dumps(head, sort_keys=True, separators=(",", ":"))
    t_load, (bdoc, hdoc) = best(lambda: (json.loads(bt), json.loads(ht)), repeat)
    t_index, (gb, gh) = best(lambda: (Graph(bdoc), Graph(hdoc)), repeat)
    # Bucketing (address -> module) is lazy and O(V+E); it is part of the honest
    # cost of the first structural diff, so it is measured on its own here and
    # the structural timings below are taken with warm buckets.
    t_bucket, _ = best(lambda: (gb._bucket(), gh._bucket()), repeat)
    t_merkle, res = best(lambda: structural_diff(gb, gh), repeat)
    t_full, _ = best(lambda: full_compare(gb, gh), repeat)
    t_diff, dres = best(lambda: diff_graphs(gb, gh), repeat)
    return {
        "nodes": len(gb.nodes), "edges": len(gb.edges), "modules": gb.modules_total,
        "bytes": len(bt),
        "t_json_load": t_load, "t_index": t_index, "t_bucket": t_bucket,
        "t_struct_merkle": t_merkle, "t_struct_full": t_full, "t_diff_total": t_diff,
        "modules_skipped": res.stats["modules_skipped"],
        "prune_points": res.stats["merkle"]["prune_points"],
        "nodes_compared": res.stats["nodes_compared"],
        "verified": res.stats["merkle"]["verified"],
        "changed_edges": len(res.edges["changed"]),
        "principals_evaluated": dres.doc["stats"]["semantic"]["principals_evaluated"],
        "findings": len(dres.doc["findings"]),
        "sem_timings": dres.timings,
    }


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", default="10,20,40,80", help="roles per leaf")
    ap.add_argument("--groups", type=int, default=20)
    ap.add_argument("--leaves", type=int, default=25)
    ap.add_argument("--repeat", type=int, default=3)
    ap.add_argument("--json", help="write raw numbers here")
    a = ap.parse_args(argv)
    rows = []
    print("| nodes | edges | modules | json load (s) | index (s) | bucket (s) | structural, Merkle (s) | structural, full (s) | whole diff (s) | modules skipped | nodes compared | principals evaluated |")
    print("|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for roles in (int(x) for x in a.sizes.split(",")):
        r = measure(a.groups, a.leaves, roles, a.repeat)
        rows.append(r)
        print(f"| {r['nodes']:,} | {r['edges']:,} | {r['modules']} | {r['t_json_load']:.3f} | "
              f"{r['t_index']:.3f} | {r['t_bucket']:.3f} | {r['t_struct_merkle']:.4f} | "
              f"{r['t_struct_full']:.4f} | {r['t_diff_total']:.4f} | "
              f"{r['modules_skipped']}/{r['modules']} | {r['nodes_compared']} | "
              f"{r['principals_evaluated']} |", flush=True)
        assert r["verified"] and r["changed_edges"] == 1 and r["findings"] >= 1
    if a.json:
        with open(a.json, "w") as f:
            json.dump(rows, f, indent=2)


if __name__ == "__main__":
    main()
