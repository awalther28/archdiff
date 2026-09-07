"""Every output validates against graph.schema.json -- with the real jsonschema
package when available and always with the bundled dependency-free validator,
which is itself cross-checked against jsonschema on the golden fixtures."""
import copy
import json
import os

import pytest

from archdiff_extractor.cli import build_graph
from archdiff_extractor.validate import load_schema, validate
from conftest import FIXTURES, SCHEMA_DIR

try:
    import jsonschema  # type: ignore
except ImportError:  # pragma: no cover
    jsonschema = None

SAMPLES = [os.path.join(FIXTURES, n) for n in ("plan-poisoned.json", "plan-clean.json", "plan-two-accounts.json")]


def _jsonschema_errors(doc):
    v = jsonschema.Draft202012Validator(load_schema())
    return [e.message for e in v.iter_errors(doc)]


@pytest.mark.parametrize("path", SAMPLES)
def test_each_sample_validates(path):
    g = build_graph([path], roots=["x"])
    assert validate(g) == []
    if jsonschema:
        assert _jsonschema_errors(g) == []


def test_merged_output_validates():
    g = build_graph(SAMPLES, roots=["a", "b", "c"], explicit_scopes={"aws": {"account_id": "111122223333"}})
    assert validate(g) == []
    if jsonschema:
        assert _jsonschema_errors(g) == []


@pytest.mark.parametrize("name", ["base.graph.json", "head.graph.json", "refactor-noop.graph.json"])
def test_builtin_validator_accepts_golden_fixtures(name):
    with open(os.path.join(SCHEMA_DIR, "fixtures", name)) as fh:
        doc = json.load(fh)
    assert validate(doc) == []
    if jsonschema:
        assert _jsonschema_errors(doc) == []


def test_builtin_validator_rejects_what_jsonschema_rejects():
    with open(os.path.join(SCHEMA_DIR, "fixtures", "base.graph.json")) as fh:
        good = json.load(fh)
    broken = []
    d = copy.deepcopy(good); d["nodes"][0]["type"] = "user"; broken.append(d)
    d = copy.deepcopy(good); d["nodes"][0]["digest"] = "nothex"; broken.append(d)
    d = copy.deepcopy(good); d["nodes"][0]["extra"] = 1; broken.append(d)
    d = copy.deepcopy(good); del d["edges"][0]["source"]; broken.append(d)
    d = copy.deepcopy(good); d["edges"][0]["unevaluated"] = ["maybe"]; broken.append(d)
    d = copy.deepcopy(good); d["schema_version"] = "2.0"; broken.append(d)
    d = copy.deepcopy(good); d["scopes"][0]["confidence"] = "certain"; broken.append(d)
    for doc in broken:
        assert validate(doc) != []
        if jsonschema:
            assert _jsonschema_errors(doc) != []
