import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.dirname(HERE)
SCHEMA_DIR = os.path.normpath(os.path.join(PKG, "..", "..", "schema"))
FIXTURES = os.path.join(SCHEMA_DIR, "fixtures")
if PKG not in sys.path:
    sys.path.insert(0, PKG)


def _load(name):
    with open(os.path.join(FIXTURES, name), "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="session")
def fixtures_dir():
    return FIXTURES


@pytest.fixture(scope="session")
def schema_dir():
    return SCHEMA_DIR


@pytest.fixture(scope="session")
def base_doc():
    return _load("base.graph.json")


@pytest.fixture(scope="session")
def head_doc():
    return _load("head.graph.json")


@pytest.fixture(scope="session")
def noop_doc():
    return _load("refactor-noop.graph.json")


@pytest.fixture(scope="session")
def expected_diff():
    return _load("expected.diff.json")


def all_arrays(obj, path=""):
    """Yield (path, list) for every list anywhere in a JSON document."""
    if isinstance(obj, list):
        yield path, obj
        for i, v in enumerate(obj):
            yield from all_arrays(v, f"{path}[{i}]")
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from all_arrays(v, f"{path}/{k}")
