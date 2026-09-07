import json
import os
import subprocess
import sys

import pytest

from permdiff.builder import GraphBuilder, scope
from permdiff.cli import main
from permdiff.render import render_markdown
from permdiff import Graph, diff_graphs
from conftest import FIXTURES, PKG


def test_cli_diff_writes_doc_and_markdown(tmp_path):
    out = tmp_path / "diff.json"
    md = tmp_path / "diff.md"
    rc = main(["diff", "--base", os.path.join(FIXTURES, "base.graph.json"),
               "--head", os.path.join(FIXTURES, "head.graph.json"),
               "--out", str(out), "--markdown", str(md)])
    assert rc == 0
    doc = json.loads(out.read_text())
    assert doc["findings"][0]["kind"] == "wildcard_capability_added"
    text = md.read_text()
    assert text.splitlines()[0].startswith("**HIGH**")
    assert "### New capabilities" in text
    assert "### Unevaluated (2 of 2 in head)" in text
    assert "<details>" in text and "</details>" in text
    assert "changed edge" in text
    # the conditional trust edge is called out explicitly
    assert "app_admin#trust:audit" in text and "condition" in text


def test_cli_render_subcommand(tmp_path):
    out = tmp_path / "diff.json"
    main(["diff", "--base", os.path.join(FIXTURES, "base.graph.json"),
          "--head", os.path.join(FIXTURES, "refactor-noop.graph.json"), "--out", str(out)])
    r = subprocess.run([sys.executable, "-m", "permdiff", "render", "--diff", str(out)],
                       cwd=PKG, capture_output=True, text=True, check=True)
    assert r.stdout.startswith("**No permission changes**")
    assert "1 of 1 module(s) skipped by Merkle rollup (verified)" in r.stdout


def test_cli_fail_on(tmp_path):
    args = ["diff", "--base", os.path.join(FIXTURES, "base.graph.json"),
            "--head", os.path.join(FIXTURES, "head.graph.json"), "--out", str(tmp_path / "d.json")]
    assert main(args + ["--fail-on", "high"]) == 3
    assert main(args + ["--fail-on", "critical"]) == 0


def test_cli_version_mismatch_is_reported_not_diffed(tmp_path):
    b = GraphBuilder(extractor_version="1")
    sc = scope("111122223333")
    b.principal(sc, "aws_iam_role.a")
    h = GraphBuilder(extractor_version="2")
    h.principal(sc, "aws_iam_role.a")
    pb, ph = tmp_path / "b.json", tmp_path / "h.json"
    pb.write_text(json.dumps(b.build()))
    ph.write_text(json.dumps(h.build()))
    out = tmp_path / "d.json"
    assert main(["diff", "--base", str(pb), "--head", str(ph), "--out", str(out)]) == 2
    assert not out.exists()
    assert main(["diff", "--base", str(pb), "--head", str(ph), "--out", str(out),
                 "--allow-version-mismatch"]) == 0
    doc = json.loads(out.read_text())
    assert any("extractor_version mismatch" in w for w in doc["warnings"])


def test_cli_verify_fixtures():
    rc = main(["verify", os.path.join(FIXTURES, "base.graph.json"),
               os.path.join(FIXTURES, "head.graph.json")])
    assert rc == 0


def test_cli_verify_detects_tampered_digest(tmp_path, base_doc):
    doc = json.loads(json.dumps(base_doc))
    doc["nodes"][0]["digest"] = "0" * 16
    p = tmp_path / "bad.json"
    p.write_text(json.dumps(doc))
    assert main(["verify", str(p)]) == 1


def test_render_orders_sections_and_marks_conditional():
    sc_a, sc_b = scope("111122223333"), scope("999988887777")
    base = GraphBuilder()
    a = base.principal(sc_a, "aws_iam_role.a")
    bb = base.principal(sc_b, "aws_iam_role.b")
    c = base.principal(sc_b, "aws_iam_role.c")
    base.can_assume(bb, c, unevaluated=["condition"])
    head = base.clone()
    head.can_assume(a, bb)                       # new cross-scope entry into b
    pol = head.policy(sc_b, "aws_iam_policy.p")
    head.attaches(c, pol)
    head.grants(pol, head.wildcard(sc_b), ["iam:*"], ["*"], "Admin")
    doc = diff_graphs(Graph(base.build()), Graph(head.build())).doc
    md = render_markdown(doc)
    i_paths = md.index("### New privilege paths")
    i_caps = md.index("### New capabilities")
    i_unev = md.index("### Unevaluated")
    i_churn = md.index("<details>")
    assert md.index("**CRITICAL**") == 0
    assert i_paths < i_caps < i_unev < i_churn
    assert "[conditional -- not confirmed]" in md
    assert "(cross-scope)" in md
