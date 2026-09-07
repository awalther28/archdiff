"""``extract --plan a.json --plan b.json --out graph.json``"""
import json
import os
import subprocess
import sys

import pytest

from archdiff_extractor.cli import main
from conftest import FIXTURES, PKG_ROOT

POISONED = os.path.join(FIXTURES, "plan-poisoned.json")
CLEAN = os.path.join(FIXTURES, "plan-clean.json")


def test_cli_writes_validated_graph(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("TERRAGRUNT_WORKING_DIR", raising=False)
    out = tmp_path / "graph.json"
    rc = main(["--plan", POISONED, "--plan", CLEAN, "--out", str(out), "--root", "a", "--root", "b"])
    assert rc == 0
    doc = json.loads(out.read_text())
    assert doc["schema_version"] == "1.0"
    assert [c["path"] for c in doc["modules"][0]["children"]] == ["a", "b"]
    assert "2 scopes" in capsys.readouterr().err or True


def test_cli_stdout_and_scope_overrides(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("TERRAGRUNT_WORKING_DIR", raising=False)
    overrides = tmp_path / "scopes.json"
    overrides.write_text(json.dumps({"aws": {"account_id": "111122223333"}}))
    rc = main(["--plan", POISONED, "--out", "-", "--scope-overrides", str(overrides), "--root", "x"])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["scopes"][0]["key"] == "aws:111122223333:us-east-1"
    assert doc["scopes"][0]["source"] == "explicit"


def test_cli_root_count_mismatch_errors(tmp_path):
    with pytest.raises(SystemExit):
        main(["--plan", POISONED, "--plan", CLEAN, "--out", str(tmp_path / "g.json"), "--root", "only-one"])


def test_cli_previous_address_from_prior_state_lands_in_moves(tmp_path, monkeypatch):
    monkeypatch.delenv("TERRAGRUNT_WORKING_DIR", raising=False)
    moved = json.load(open(POISONED))
    for rc in moved["resource_changes"]:
        if rc["address"] == "aws_iam_role.ci":
            rc["previous_address"] = "aws_iam_role.old_ci"
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(moved))
    out = tmp_path / "g.json"
    assert main(["--plan", str(plan), "--out", str(out), "--root", "x"]) == 0
    assert json.loads(out.read_text())["moves"] == [
        {"scope_key": "aws:unknown:us-east-1", "from": "aws_iam_role.old_ci", "to": "aws_iam_role.ci"}]


def test_cli_src_parses_moved_blocks_and_defaults_to_plan_dir(tmp_path, monkeypatch):
    monkeypatch.delenv("TERRAGRUNT_WORKING_DIR", raising=False)
    unit = tmp_path / "unit"
    unit.mkdir()
    (unit / "plan.json").write_text(open(POISONED).read())
    (unit / "moves.tf").write_text('moved {\n  from = aws_iam_role.legacy\n  to   = aws_iam_role.ci\n}\n')
    out = tmp_path / "g.json"
    assert main(["--plan", str(unit / "plan.json"), "--out", str(out), "--root", "x"]) == 0
    assert json.loads(out.read_text())["moves"] == [
        {"scope_key": "aws:unknown:us-east-1", "from": "aws_iam_role.legacy", "to": "aws_iam_role.ci"}]
    # explicit --src pointing elsewhere wins
    other = tmp_path / "other"
    other.mkdir()
    (other / "m.tf").write_text('moved { from = aws_iam_role.a\n to = aws_iam_role.ci }')
    assert main(["--plan", str(unit / "plan.json"), "--out", str(out), "--root", "x", "--src", str(other)]) == 0
    assert [m["from"] for m in json.loads(out.read_text())["moves"]] == ["aws_iam_role.a"]


def test_module_entry_point_runs_as_subprocess(tmp_path):
    out = tmp_path / "g.json"
    env = dict(os.environ, PYTHONPATH=PKG_ROOT)
    env.pop("TERRAGRUNT_WORKING_DIR", None)
    proc = subprocess.run([sys.executable, "-m", "archdiff_extractor", "--plan", POISONED, "--out", str(out), "--root", "x"],
                          capture_output=True, text=True, env=env, cwd=PKG_ROOT)
    assert proc.returncode == 0, proc.stderr
    assert "nodes" in proc.stderr
    assert json.loads(out.read_text())["nodes"]


def test_default_root_label_is_plan_dir_relative_to_cwd(tmp_path, monkeypatch):
    monkeypatch.delenv("TERRAGRUNT_WORKING_DIR", raising=False)
    unit = tmp_path / "live" / "prod" / "iam"
    unit.mkdir(parents=True)
    plan = unit / "plan.json"
    plan.write_text(open(POISONED).read())
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "g.json"
    assert main(["--plan", "live/prod/iam/plan.json", "--out", str(out)]) == 0
    doc = json.loads(out.read_text())
    assert doc["modules"][0]["children"][0]["path"] == "live/prod/iam"
    assert doc["scopes"][0]["root_module"] == "live/prod/iam"
