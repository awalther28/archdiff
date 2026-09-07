"""``extract --plan a.json --plan b.json --out graph.json``"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from typing import Any, Dict, List, Optional

from .extract import extract_plan
from .merge import merge
from .plan import Plan
from .validate import validate


def dumps(doc: Dict[str, Any]) -> str:
    """The committed form: indented, keys sorted, trailing newline. Stable."""
    return json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def default_root_label(plan_path: str) -> Optional[str]:
    """Informational label: the plan's directory relative to cwd, when inside it."""
    parent = os.path.dirname(os.path.abspath(plan_path))
    try:
        rel = os.path.relpath(parent, os.getcwd())
    except ValueError:
        return None
    if rel == "." or rel.startswith(".."):
        return None
    return rel.replace(os.sep, "/")


def default_source_dir(plan_path: str) -> Optional[str]:
    """The plan's own directory, when it holds Terraform source (moved {} blocks)."""
    parent = os.path.dirname(os.path.abspath(plan_path))
    if glob.glob(os.path.join(parent, "*.tf")) or glob.glob(os.path.join(parent, "*.tf.json")):
        return parent
    return None


def build_graph(plan_paths: List[str], roots: Optional[List[str]] = None,
                explicit_scopes: Optional[Dict[str, Dict[str, Any]]] = None,
                repo_root: Optional[str] = None, sources: Optional[List[Optional[str]]] = None) -> Dict[str, Any]:
    extracts = []
    env_root = os.environ.get("TERRAGRUNT_WORKING_DIR")
    for i, path in enumerate(plan_paths):
        plan = Plan.load(path)
        root = roots[i] if roots and i < len(roots) and roots[i] else None
        if root is None and not env_root:
            root = default_root_label(path)
        src = sources[i] if sources and i < len(sources) and sources[i] else None
        if src is None:
            src = env_root or default_source_dir(path)
        extracts.append(extract_plan(plan, root_module=root, explicit_scopes=explicit_scopes,
                                     repo_root=repo_root, source_dir=src))
    return merge(extracts)


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="extract",
                                description="OpenTofu plan JSON -> Permission Graph v1")
    p.add_argument("--plan", action="append", required=True, metavar="PLAN_JSON",
                   help="plan JSON (tofu show -json tfplan); repeat to merge several roots")
    p.add_argument("--root", action="append", metavar="LABEL",
                   help="informational root_module label for the corresponding --plan "
                        "(never affects digests)")
    p.add_argument("--out", required=True, metavar="GRAPH_JSON", help="output path, or - for stdout")
    p.add_argument("--scope-overrides", metavar="JSON",
                   help='explicit scopes: {"aws.mgmt": {"account_id": "9999...", "region": "us-east-1"}}')
    p.add_argument("--repo-root", metavar="DIR", help="repo root for relative Terragrunt unit labels")
    p.add_argument("--src", action="append", metavar="DIR",
                   help="root module source directory for the corresponding --plan, used to parse "
                        "moved {} blocks (default: TERRAGRUNT_WORKING_DIR, else the plan's directory)")
    p.add_argument("--no-validate", action="store_true", help="skip schema validation of the output")
    args = p.parse_args(argv)

    explicit = None
    if args.scope_overrides:
        with open(args.scope_overrides, "r", encoding="utf-8") as fh:
            explicit = json.load(fh)

    if args.root and len(args.root) != len(args.plan):
        p.error("--root must be given once per --plan, or not at all")
    if args.src and len(args.src) != len(args.plan):
        p.error("--src must be given once per --plan, or not at all")

    graph = build_graph(args.plan, args.root, explicit, args.repo_root, args.src)

    if not args.no_validate:
        errors = validate(graph)
        if errors:
            for e in errors:
                print(f"schema violation: {e}", file=sys.stderr)
            return 2

    text = dumps(graph)
    if args.out == "-":
        sys.stdout.write(text)
    else:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)

    n, e, w = len(graph["nodes"]), len(graph["edges"]), len(graph["warnings"])
    print(f"extract: {n} nodes, {e} edges, {len(graph['scopes'])} scopes, {len(graph['moves'])} moves, "
          f"{w} warnings -> {args.out}", file=sys.stderr)
    for wmsg in graph["warnings"]:
        print(f"  warning: {wmsg}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
