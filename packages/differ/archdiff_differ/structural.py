"""Stage 1 -- structural diff.

Node ids are stable and digests are content hashes (SCHEMA.md sections 2, 5),
so this is a hash-set comparison, not graph matching:

    added   = ids in head but not base
    removed = ids in base but not head
    changed = shared ids whose digests differ

On top of that sits the Merkle prune over the *module tree*: a module whose
digest is identical on both sides is skipped in O(1) together with its whole
subtree.  ``stats.modules_skipped`` counts every module not descended into
(prune point plus its descendants); ``stats.merkle.prune_points`` counts the
O(1) cut-offs themselves.

Safety net.  Module membership of nodes/edges is derived from Terraform
addresses (see ``archdiff_differ.address``) because the schema does not state it.
Any mis-assignment that could hide a change necessarily involves a module we
*did* compare, so every compared module is re-hashed from its buckets and
checked against the document digest.  If that check fails the result is thrown
away and a full comparison is returned instead, with the reason recorded in
``stats.merkle.fallback_reason``.  Pruned modules are never wrong as long as the
extractor's digests are honest, which is the contract section 5 establishes.
"""
from typing import Dict, List, Optional, Set, Tuple

from .address import ModuleKey, UNASSIGNED_KEY
from .graph import Graph

CHANGE_FIELDS_NODE = ("type", "name", "aliases", "resolution", "unresolved_attributes",
                      "properties", "logical_address")
CHANGE_FIELDS_EDGE = ("type", "source", "target", "effect", "actions",
                      "resource_patterns", "sid", "resolution", "unevaluated")


class StructuralResult:
    """``structural`` section + ``stats`` + the per-element field deltas that
    the findings/renderer use but which the section-7 ``changed`` entry does
    not carry (see README: "property_deltas")."""

    def __init__(self) -> None:
        self.nodes = {"added": [], "removed": [], "changed": []}  # type: Dict[str, list]
        self.edges = {"added": [], "removed": [], "changed": []}  # type: Dict[str, list]
        self.stats: Dict[str, object] = {}
        self.field_deltas: Dict[str, List[str]] = {}

    def as_doc(self) -> dict:
        return {"nodes": self.nodes, "edges": self.edges}

    @property
    def is_empty(self) -> bool:
        return not any(self.nodes.values()) and not any(self.edges.values())

    @property
    def dirty_node_ids(self) -> Set[str]:
        return set(self.nodes["added"]) | set(self.nodes["removed"]) | \
            {c["id"] for c in self.nodes["changed"]}

    @property
    def dirty_edge_ids(self) -> Set[str]:
        return set(self.edges["added"]) | set(self.edges["removed"]) | \
            {c["id"] for c in self.edges["changed"]}


def _field_deltas(a: dict, b: dict, fields: Tuple[str, ...]) -> List[str]:
    out = []
    for f in fields:
        va, vb = a.get(f), b.get(f)
        if isinstance(va, list) and isinstance(vb, list):
            try:
                if sorted(va) == sorted(vb):
                    continue
            except TypeError:
                pass
        if va != vb:
            out.append(f)
    return out


def _compare_ids(base_items: Dict[str, dict], head_items: Dict[str, dict],
                 base_ids: List[str], head_ids: List[str], fields: Tuple[str, ...],
                 sink: Dict[str, list], deltas: Dict[str, List[str]]) -> int:
    bset, hset = set(base_ids), set(head_ids)
    for i in hset - bset:
        sink["added"].append(i)
    for i in bset - hset:
        sink["removed"].append(i)
    for i in bset & hset:
        bd, hd = base_items[i]["digest"], head_items[i]["digest"]
        if bd != hd:
            sink["changed"].append({"id": i, "before_digest": bd, "after_digest": hd})
            deltas[i] = _field_deltas(base_items[i], head_items[i], fields)
    return len(bset | hset)


def _finalise(res: StructuralResult) -> StructuralResult:
    for sec in (res.nodes, res.edges):
        sec["added"].sort()
        sec["removed"].sort()
        sec["changed"].sort(key=lambda c: c["id"])
    return res


def full_compare(base: Graph, head: Graph, reason: str = "disabled") -> StructuralResult:
    """Plain O(V+E) hash-set comparison, no pruning."""
    res = StructuralResult()
    n = _compare_ids(base.nodes, head.nodes, list(base.nodes), list(head.nodes),
                     CHANGE_FIELDS_NODE, res.nodes, res.field_deltas)
    e = _compare_ids(base.edges, head.edges, list(base.edges), list(head.edges),
                     CHANGE_FIELDS_EDGE, res.edges, res.field_deltas)
    res.stats = {
        "nodes_compared": n,
        "edges_compared": e,
        "modules_total": head.modules_total,
        "modules_compared": head.modules_total,
        "modules_skipped": 0,
        "merkle": {"enabled": False, "verified": False, "prune_points": 0,
                   "fallback_reason": reason},
    }
    return _finalise(res)


def _merkle_compare(base: Graph, head: Graph) -> Tuple[StructuralResult, bool, str]:
    """Returns (result, verified, reason).  ``verified`` False means the result
    must not be used."""
    res = StructuralResult()
    compared: List[ModuleKey] = []
    skipped = 0
    prune_points = 0
    nodes_compared = edges_compared = 0
    # recomputed digests for compared modules, per side, filled post-order
    recomputed: Dict[ModuleKey, Tuple[Optional[str], Optional[str]]] = {}

    def walk(key: ModuleKey) -> Tuple[Optional[str], Optional[str]]:
        nonlocal skipped, prune_points, nodes_compared, edges_compared
        bm, hm = base.modules.get(key), head.modules.get(key)
        if bm is not None and hm is not None and bm.digest == hm.digest:
            # Merkle prune: identical rollup => identical subtree.  O(1).
            prune_points += 1
            skipped += hm.subtree_size
            return bm.digest, hm.digest
        compared.append(key)
        nodes_compared += _compare_ids(base.nodes, head.nodes, base.node_bucket(key),
                                       head.node_bucket(key), CHANGE_FIELDS_NODE,
                                       res.nodes, res.field_deltas)
        edges_compared += _compare_ids(base.edges, head.edges, base.edge_bucket(key),
                                       head.edge_bucket(key), CHANGE_FIELDS_EDGE,
                                       res.edges, res.field_deltas)
        child_keys = sorted({c.key for c in (bm.children if bm else [])} |
                            {c.key for c in (hm.children if hm else [])})
        b_children: List[str] = []
        h_children: List[str] = []
        for ck in child_keys:
            bd, hd = walk(ck)
            if bd is not None:
                b_children.append(bd)
            if hd is not None:
                h_children.append(hd)
        bd = base.recompute_module_digest(key, b_children) if bm is not None else None
        hd = head.recompute_module_digest(key, h_children) if hm is not None else None
        recomputed[key] = (bd, hd)
        return bd, hd

    root_keys = sorted({r.key for r in base.module_roots} | {r.key for r in head.module_roots})
    for rk in root_keys:
        walk(rk)
    # Elements the address heuristic could not place: always compared -- but
    # only when something was compared at all.  If every root digest matched,
    # section 5 guarantees the documents are identical and we must not touch
    # the buckets (that would make the empty diff O(V) instead of O(1)).
    if compared and (base.node_bucket(UNASSIGNED_KEY) or head.node_bucket(UNASSIGNED_KEY) or
                     base.edge_bucket(UNASSIGNED_KEY) or head.edge_bucket(UNASSIGNED_KEY)):
        compared.append(UNASSIGNED_KEY)
        nodes_compared += _compare_ids(base.nodes, head.nodes,
                                       base.node_bucket(UNASSIGNED_KEY),
                                       head.node_bucket(UNASSIGNED_KEY),
                                       CHANGE_FIELDS_NODE, res.nodes, res.field_deltas)
        edges_compared += _compare_ids(base.edges, head.edges,
                                       base.edge_bucket(UNASSIGNED_KEY),
                                       head.edge_bucket(UNASSIGNED_KEY),
                                       CHANGE_FIELDS_EDGE, res.edges, res.field_deltas)

    # --- verification of every compared module (cost: size of the change) ---
    for key, (bd, hd) in recomputed.items():
        if bd is not None and bd != base.modules[key].digest:
            return res, False, (f"base module {base.modules[key].path!r}: recomputed "
                                f"digest {bd} != document digest {base.modules[key].digest}")
        if hd is not None and hd != head.modules[key].digest:
            return res, False, (f"head module {head.modules[key].path!r}: recomputed "
                                f"digest {hd} != document digest {head.modules[key].digest}")

    res.stats = {
        "nodes_compared": nodes_compared,
        "edges_compared": edges_compared,
        "modules_total": head.modules_total,
        "modules_compared": len([k for k in compared if k != UNASSIGNED_KEY]),
        "modules_skipped": skipped,
        "merkle": {"enabled": True, "verified": True, "prune_points": prune_points,
                   "fallback_reason": None},
    }
    return _finalise(res), True, ""


def structural_diff(base: Graph, head: Graph, use_merkle: bool = True) -> StructuralResult:
    if not use_merkle:
        return full_compare(base, head, "disabled by caller")
    if not base.merkle_ok:
        return full_compare(base, head, f"base: {base.merkle_reason}")
    if not head.merkle_ok:
        return full_compare(base, head, f"head: {head.merkle_reason}")
    res, verified, reason = _merkle_compare(base, head)
    if not verified:
        return full_compare(base, head, "merkle verification failed: " + reason)
    return res


def verify_all_digests(g: Graph) -> List[str]:
    """Full O(V+E) audit of a document against canonical.py: node digests, edge
    digests and the module rollup under this package's membership rule.  Not
    used by the diff itself (it would defeat the prune); used by tests and by
    ``archdiff_differ verify``."""
    from .canonical import edge_digest, node_digest
    problems: List[str] = []
    for nid, n in g.nodes.items():
        if node_digest(n) != n["digest"]:
            problems.append(f"node {nid}: digest {n['digest']} != {node_digest(n)}")
    for eid, e in g.edges.items():
        if edge_digest(e) != e["digest"]:
            problems.append(f"edge {eid}: digest {e['digest']} != {edge_digest(e)}")

    def walk(m) -> str:
        d = g.recompute_module_digest(m.key, [walk(c) for c in m.children])
        if d != m.digest:
            problems.append(f"module {m.path!r}: rollup {m.digest} != {d}")
        return d

    for r in g.module_roots:
        walk(r)
    if g.node_bucket(UNASSIGNED_KEY):
        problems.append(f"{len(g.node_bucket(UNASSIGNED_KEY))} node(s) not mappable to the module tree")
    if g.edge_bucket(UNASSIGNED_KEY):
        problems.append(f"{len(g.edge_bucket(UNASSIGNED_KEY))} edge(s) not mappable to the module tree")
    return problems
