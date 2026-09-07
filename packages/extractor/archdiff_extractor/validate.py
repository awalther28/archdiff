"""Minimal, dependency-free validator for graph.schema.json.

Supports exactly the JSON Schema subset the schema uses: type (incl. unions),
required, additionalProperties: false, properties, enum, const, pattern,
items, $ref into $defs. Tests cross-check it against the ``jsonschema``
package when that is installed; at runtime nothing is required.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List

SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "graph.schema.json")

_TYPES = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "null": lambda v: v is None,
    "boolean": lambda v: isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
}


def load_schema() -> Dict[str, Any]:
    with open(SCHEMA_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def validate(doc: Any, schema: Dict[str, Any] = None) -> List[str]:
    """Return a list of error strings; empty means valid."""
    schema = schema or load_schema()
    errors: List[str] = []
    _check(doc, schema, schema, "$", errors)
    return errors


def _deref(node: Dict[str, Any], root: Dict[str, Any]) -> Dict[str, Any]:
    ref = node.get("$ref")
    if not ref:
        return node
    assert ref.startswith("#/"), ref
    cur: Any = root
    for part in ref[2:].split("/"):
        cur = cur[part]
    return cur


def _check(value: Any, node: Dict[str, Any], root: Dict[str, Any], path: str, errors: List[str]) -> None:
    node = _deref(node, root)
    if "const" in node and value != node["const"]:
        errors.append(f"{path}: expected const {node['const']!r}, got {value!r}")
    if "enum" in node and value not in node["enum"]:
        errors.append(f"{path}: {value!r} not in enum {node['enum']!r}")
    if "type" in node:
        types = node["type"] if isinstance(node["type"], list) else [node["type"]]
        if not any(_TYPES[t](value) for t in types):
            errors.append(f"{path}: expected type {types}, got {type(value).__name__}")
            return
    if "pattern" in node and isinstance(value, str) and not re.search(node["pattern"], value):
        errors.append(f"{path}: {value!r} does not match {node['pattern']!r}")
    if isinstance(value, dict):
        for req in node.get("required", []):
            if req not in value:
                errors.append(f"{path}: missing required property {req!r}")
        props = node.get("properties", {})
        for k, v in value.items():
            if k in props:
                _check(v, props[k], root, f"{path}.{k}", errors)
            elif node.get("additionalProperties") is False:
                errors.append(f"{path}: additional property {k!r} not allowed")
    if isinstance(value, list) and "items" in node:
        for i, item in enumerate(value):
            _check(item, node["items"], root, f"{path}[{i}]", errors)
