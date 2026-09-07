"""The digest implementation is copied UNMODIFIED from schema/. A divergence
produces phantom diffs -- the exact failure mode this project exists to
prevent -- so the copy must be byte-identical."""
import os

import archdiff_extractor.canonical as canonical
from archdiff_extractor.canonical import edge_digest, module_digest, node_digest
from conftest import SCHEMA_DIR

PKG_DIR = os.path.dirname(canonical.__file__)


def _bytes(path):
    with open(path, "rb") as fh:
        return fh.read()


def test_canonical_py_is_byte_identical_to_schema_original():
    original = os.path.join(SCHEMA_DIR, "canonical.py")
    assert os.path.exists(original), "schema/canonical.py must exist next to the package"
    assert _bytes(canonical.__file__) == _bytes(original)


def test_graph_schema_json_is_byte_identical_to_schema_original():
    original = os.path.join(SCHEMA_DIR, "graph.schema.json")
    assert _bytes(os.path.join(PKG_DIR, "graph.schema.json")) == _bytes(original)


def test_golden_fixture_digests_recompute_with_our_copy():
    """Every digest in the golden fixtures must recompute identically."""
    import json
    for name in ("base.graph.json", "head.graph.json", "refactor-noop.graph.json"):
        with open(os.path.join(SCHEMA_DIR, "fixtures", name)) as fh:
            doc = json.load(fh)
        for n in doc["nodes"]:
            assert node_digest(n) == n["digest"], n["id"]
        for e in doc["edges"]:
            assert edge_digest(e) == e["digest"], e["id"]
        root = doc["modules"][0]
        assert module_digest([n["digest"] for n in doc["nodes"]],
                             [e["digest"] for e in doc["edges"]], []) == root["digest"]
