"""Synthetic large-graph generator for the performance test.

    python bench/synth.py generate --groups 20 --leaves 25 --roles 40 --out base.graph.json
    python bench/synth.py mutate   --in base.graph.json --out head.graph.json --leaf 7/3

Shape: root -> module.g{i} -> module.g{i}.module.l{j}.  Each leaf module holds
``roles`` principals, one policy per principal, ``roles // 2`` buckets, one
wildcard node, an attaches edge and a grants edge per principal, and a short
can_assume chain, spread over two scopes.  Node count per leaf is
2*roles + roles//2 + 1, so 20 x 25 x 40 gives 20 x 25 x 101 = 50,500 nodes;
``--roles 80`` gives ~100k.  Every digest and every module rollup comes from
``archdiff_differ.canonical``; ``archdiff_differ verify`` passes on the output.

``mutate`` changes exactly ONE grants edge in one leaf (widening it to s3:*)
and recomputes the rollups on that leaf's root path -- the minimal PR.
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from archdiff_differ.address import module_key_of_path  # noqa: E402
from archdiff_differ.builder import GraphBuilder, scope  # noqa: E402
from archdiff_differ.canonical import edge_digest  # noqa: E402
from archdiff_differ.graph import Graph  # noqa: E402

PROD = scope("111122223333", root_module="live/prod")
MGMT = scope("999988887777", root_module="live/mgmt")


def generate(groups: int, leaves: int, roles: int, seed: int = 0) -> dict:
    b = GraphBuilder()
    # one wildcard per scope at root so grants have a shared target
    root_w = {s["key"]: b.wildcard(s) for s in (PROD, MGMT)}
    for i in range(groups):
        for j in range(leaves):
            sc = PROD if (i + j) % 2 == 0 else MGMT
            pre = f"module.g{i}.module.l{j}."
            w = b.wildcard(sc, pre + "wildcard.all")
            buckets = [b.resource(sc, pre + f"aws_s3_bucket.b{k}", f"b{k}",
                                  f"arn:aws:s3:::g{i}-l{j}-b{k}") for k in range(roles // 2)]
            prev = None
            for k in range(roles):
                r = b.principal(sc, pre + f"aws_iam_role.r{k}", f"g{i}-l{j}-r{k}")
                p = b.policy(sc, pre + f"aws_iam_policy.p{k}", f"g{i}-l{j}-p{k}")
                b.attaches(r, p)
                tgt = buckets[k % len(buckets)] if buckets else w
                pat = f"arn:aws:s3:::g{i}-l{j}-b{k % max(1, len(buckets))}/*"
                b.grants(p, tgt, ["s3:GetObject", "s3:ListBucket"], [pat], "Read")
                if k % 7 == 0:
                    b.grants(p, root_w[sc["key"]], ["kms:Decrypt"], ["*"], "Kms",
                             unevaluated=["condition"] if k % 14 == 0 else None)
                if prev is not None and k % 5 != 0:
                    b.can_assume(prev, r)
                prev = r
    return b.build()


def mutate(doc: dict, leaf: str) -> dict:
    """Widen one statement in module ``g{i}.l{j}`` (leaf = "i/j") and recompute
    the module rollups (SCHEMA.md section 5) so the document stays honest.
    An extractor that emitted stale rollups here would defeat the prune --
    ``archdiff_differ verify`` exists to catch exactly that."""
    i, j = (int(x) for x in leaf.split("/"))
    pre = f"module.g{i}.module.l{j}."
    target_eid = None
    for e in doc["edges"]:
        if e["type"] == "grants" and pre + "aws_iam_policy.p0#stmt:Read" in e["id"]:
            target_eid = e["id"]
            e["actions"] = ["s3:*"]
            e["resource_patterns"] = ["*"]
            e["digest"] = edge_digest(e)
            break
    assert target_eid, "leaf not found"
    g = Graph(doc)

    def fix(m: dict) -> str:
        child_digests = [fix(c) for c in m.get("children", [])]
        m["digest"] = g.recompute_module_digest(module_key_of_path(m["path"]), child_digests)
        return m["digest"]

    for root in doc["modules"]:
        fix(root)
    return doc


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate")
    g.add_argument("--groups", type=int, default=20)
    g.add_argument("--leaves", type=int, default=25)
    g.add_argument("--roles", type=int, default=40)
    g.add_argument("--out", required=True)
    m = sub.add_parser("mutate")
    m.add_argument("--in", dest="inp", required=True)
    m.add_argument("--out", required=True)
    m.add_argument("--leaf", default="7/3")
    a = ap.parse_args(argv)
    t0 = time.perf_counter()
    if a.cmd == "generate":
        doc = generate(a.groups, a.leaves, a.roles)
    else:
        with open(a.inp, encoding="utf-8") as f:
            doc = json.load(f)
        doc = mutate(doc, a.leaf)
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(doc, f, sort_keys=True, separators=(",", ":"))
        f.write("\n")
    print(f"{a.cmd}: {len(doc['nodes'])} nodes, {len(doc['edges'])} edges -> {a.out} "
          f"({time.perf_counter() - t0:.2f}s)")


if __name__ == "__main__":
    main()
