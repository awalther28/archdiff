"""Identical inputs -> byte-identical output, across processes, hash seeds and
input ordering."""
import json
import os
import random
import subprocess
import sys

import pytest

from archdiff_differ import Graph, diff_graphs, dumps
from conftest import FIXTURES, PKG


def _run_cli(base, head, out, seed, extra=()):
    env = dict(os.environ, PYTHONHASHSEED=str(seed))
    subprocess.run([sys.executable, "-m", "archdiff_differ", "diff", "--base", base, "--head", head,
                    "--out", out, "--base-ref", "main", "--head-ref", "pr-1", *extra],
                   cwd=PKG, env=env, check=True)
    with open(out, "rb") as f:
        return f.read()


@pytest.mark.parametrize("head_name", ["head.graph.json", "refactor-noop.graph.json"])
def test_cli_output_is_byte_identical_across_hash_seeds(tmp_path, head_name):
    base = os.path.join(FIXTURES, "base.graph.json")
    head = os.path.join(FIXTURES, head_name)
    outs = [_run_cli(base, head, str(tmp_path / f"d{s}.json"), s) for s in (0, 1, 12345)]
    assert outs[0] == outs[1] == outs[2]
    assert outs[0].endswith(b"\n")


def test_in_process_repeat_is_byte_identical(base_doc, head_doc):
    a = dumps(diff_graphs(Graph(base_doc), Graph(head_doc)).doc)
    b = dumps(diff_graphs(Graph(base_doc), Graph(head_doc)).doc)
    assert a == b


def test_input_order_does_not_matter(base_doc, head_doc):
    """Nodes/edges MUST be sorted in a valid document (section 6), but the
    differ must not depend on it."""
    ref = dumps(diff_graphs(Graph(base_doc), Graph(head_doc)).doc)
    rng = random.Random(7)
    for _ in range(5):
        b = json.loads(json.dumps(base_doc))
        h = json.loads(json.dumps(head_doc))
        for d in (b, h):
            rng.shuffle(d["nodes"])
            rng.shuffle(d["edges"])
        assert dumps(diff_graphs(Graph(b), Graph(h)).doc) == ref


def test_full_and_incremental_modes_agree_on_fixtures(base_doc, head_doc):
    inc = diff_graphs(Graph(base_doc), Graph(head_doc)).doc
    full = diff_graphs(Graph(base_doc), Graph(head_doc), full_semantic=True).doc
    for k in ("structural", "semantic", "findings", "unevaluated", "empty"):
        assert inc[k] == full[k], k
