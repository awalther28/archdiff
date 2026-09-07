"""The digest implementation is copied, not reimplemented (SCHEMA.md section 5)."""
import os

import archdiff_differ.canonical as ours
from conftest import PKG, SCHEMA_DIR


def test_canonical_is_byte_identical_to_schema_original():
    with open(os.path.join(SCHEMA_DIR, "canonical.py"), "rb") as f:
        original = f.read()
    with open(os.path.join(PKG, "archdiff_differ", "canonical.py"), "rb") as f:
        copy = f.read()
    assert copy == original, "archdiff_differ/canonical.py must be byte-identical to schema/canonical.py"


def test_fixture_digests_recompute_with_our_copy(base_doc, head_doc, noop_doc):
    for doc in (base_doc, head_doc, noop_doc):
        for n in doc["nodes"]:
            assert ours.node_digest(n) == n["digest"]
        for e in doc["edges"]:
            assert ours.edge_digest(e) == e["digest"]
        root = ours.module_digest([n["digest"] for n in doc["nodes"]],
                                  [e["digest"] for e in doc["edges"]], [])
        assert root == doc["modules"][0]["digest"]


def test_no_other_digest_implementation_in_package():
    """Nothing but canonical.py may call hashlib."""
    pkg = os.path.join(PKG, "archdiff_differ")
    for fn in os.listdir(pkg):
        if fn.endswith(".py") and fn != "canonical.py":
            with open(os.path.join(pkg, fn), encoding="utf-8") as f:
                assert "hashlib" not in f.read(), f"{fn} must not hash on its own"
