"""Normative canonicalisation and digest implementation for Permission Graph v1.

Every component MUST use these functions. A divergence here produces phantom
diffs, which is the one failure mode the whole design exists to prevent.
"""
import hashlib
import json

DIGEST_LEN = 16


def canonical_json(obj) -> str:
    """Canonical form: sorted keys, no insignificant whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(obj) -> str:
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()[:DIGEST_LEN]


def node_digest(node: dict) -> str:
    """Excludes `id` (derivable) and `scope.root_module` (churns on refactor)."""
    return digest({
        "type": node["type"],
        "scope_key": node["scope"]["key"],
        "logical_address": node["logical_address"],
        "name": node.get("name"),
        "aliases": sorted(node.get("aliases", [])),
        "resolution": node.get("resolution", "resolved"),
        "unresolved_attributes": sorted(node.get("unresolved_attributes", [])),
        "properties": node.get("properties", {}),
    })


def edge_digest(edge: dict) -> str:
    return digest({
        "type": edge["type"],
        "source": edge["source"],
        "target": edge["target"],
        "effect": edge.get("effect"),
        "actions": sorted(edge.get("actions", [])),
        "resource_patterns": sorted(edge.get("resource_patterns", [])),
        "sid": edge.get("sid"),
        "resolution": edge.get("resolution", "resolved"),
        "unevaluated": sorted(edge.get("unevaluated", [])),
    })


def module_digest(child_node_digests, child_edge_digests, child_module_digests) -> str:
    """Rollup over the MODULE TREE, not the graph -- acyclic by construction.

    Lets an unchanged module compare in O(1) regardless of node count.
    """
    return digest({
        "nodes": sorted(child_node_digests),
        "edges": sorted(child_edge_digests),
        "modules": sorted(child_module_digests),
    })


def node_id(scope_key: str, logical_address: str) -> str:
    return f"{scope_key}/{logical_address}"
