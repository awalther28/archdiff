"""Emit one TSV line per root declared in the archdiff config: label, dir, plan args.

Kept out of action.yml so the workflow never has to embed multi-line Python in a
YAML block scalar.
"""
import json
import shlex
import sys

cfg = json.load(open(sys.argv[1]))
for label, root in cfg["roots"].items():
    args = " ".join(
        "-var " + shlex.quote(f"{k}={v}")
        for k, v in (root.get("vars") or {}).items()
    )
    print("\t".join([label, root["dir"], args]))
