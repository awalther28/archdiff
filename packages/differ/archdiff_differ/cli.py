"""Command line interface.

    archdiff_differ diff   --base base.graph.json --head head.graph.json --out diff.json
    archdiff_differ render --diff diff.json --out comment.md
    archdiff_differ verify graph.json
"""
import argparse
import json
import sys
from typing import List, Optional

from .differ import diff_graphs, dumps
from .graph import GraphError, load_graph
from .render import render_markdown
from .structural import verify_all_digests

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _cmd_diff(a: argparse.Namespace) -> int:
    try:
        base = load_graph(a.base, "base")
        head = load_graph(a.head, "head")
        res = diff_graphs(base, head, base_ref=a.base_ref, head_ref=a.head_ref,
                          use_merkle=not a.no_merkle, full_semantic=a.full_semantic,
                          max_hops=a.max_hops, allow_version_mismatch=a.allow_version_mismatch)
    except (GraphError, OSError, KeyError, json.JSONDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    text = dumps(res.doc)
    if a.out == "-":
        sys.stdout.write(text)
    else:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(text)
    if a.markdown:
        with open(a.markdown, "w", encoding="utf-8") as f:
            f.write(render_markdown(res.doc))
    if a.stats:
        s = res.doc["stats"]
        print(f"empty={res.doc['empty']} nodes_compared={s['nodes_compared']} "
              f"modules_skipped={s['modules_skipped']}/{s['modules_total']} "
              f"merkle={'on' if s['merkle']['enabled'] else 'off'} "
              f"semantic={s['semantic']['mode']} "
              f"timings(s): " + " ".join(f"{k}={v:.4f}" for k, v in res.timings.items()),
              file=sys.stderr)
    if a.fail_on:
        worst = min((_SEV_RANK[f["severity"]] for f in res.doc["findings"]), default=99)
        if worst <= _SEV_RANK[a.fail_on]:
            return 3
    return 0


def _cmd_render(a: argparse.Namespace) -> int:
    with open(a.diff, "r", encoding="utf-8") as f:
        doc = json.load(f)
    md = render_markdown(doc)
    if a.out == "-":
        sys.stdout.write(md)
    else:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(md)
    return 0


def _cmd_verify(a: argparse.Namespace) -> int:
    rc = 0
    for path in a.graph:
        try:
            g = load_graph(path)
        except (GraphError, OSError, KeyError, json.JSONDecodeError) as e:
            print(f"{path}: error: {e}")
            rc = 2
            continue
        problems = verify_all_digests(g)
        if problems:
            rc = 1
            print(f"{path}: {len(problems)} problem(s)")
            for p in problems[:50]:
                print("  " + p)
        else:
            print(f"{path}: ok ({len(g.nodes)} nodes, {len(g.edges)} edges, "
                  f"{g.modules_total} modules, graph_digest {g.graph_digest})")
    return rc


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="archdiff_differ", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("diff", help="diff two Permission Graph v1 documents")
    d.add_argument("--base", required=True)
    d.add_argument("--head", required=True)
    d.add_argument("--out", required=True, help="diff.json path, or - for stdout")
    d.add_argument("--base-ref", default="base")
    d.add_argument("--head-ref", default="head")
    d.add_argument("--markdown", help="also write the PR-comment markdown here")
    d.add_argument("--no-merkle", action="store_true", help="disable the module-tree prune")
    d.add_argument("--full-semantic", action="store_true",
                   help="evaluate every principal/path instead of only the affected ones")
    d.add_argument("--max-hops", type=int, default=4)
    d.add_argument("--allow-version-mismatch", action="store_true")
    d.add_argument("--stats", action="store_true", help="print timings to stderr")
    d.add_argument("--fail-on", choices=list(_SEV_RANK), help="exit 3 if any finding is at least this severe")
    d.set_defaults(func=_cmd_diff)

    r = sub.add_parser("render", help="render a diff document as markdown")
    r.add_argument("--diff", required=True)
    r.add_argument("--out", default="-")
    r.set_defaults(func=_cmd_render)

    v = sub.add_parser("verify", help="audit a graph's digests against canonical.py")
    v.add_argument("graph", nargs="+")
    v.set_defaults(func=_cmd_verify)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
