"""Findings (ranked, human-readable) and the `unevaluated` section.

Ranking (SCHEMA.md section 7):
  new cross-scope confirmed paths > new confirmed paths > new wildcard
  capabilities > new capabilities > removals > structural churn.
Conditional items sort directly after the confirmed items of the same tier
and carry one notch lower severity.  Within a tier the order is deterministic
(cross-scope first, confirmed first, then title).
"""
from typing import Dict, List, Optional, Set, Tuple

from .graph import Graph
from .semantic import (CONDITIONAL, CONFIRMED, Capability, Path, SemanticResult,
                       capabilities_of, involved_edges_for_principal, restrict_delta,
                       superseding)
from .structural import StructuralResult

TIER_PATH_CROSS = 1      # new cross-scope confirmed paths
TIER_PATH = 2            # new confirmed paths
TIER_PATH_COND = 3       # new conditional paths (cross-scope first) -- not "confirmed", so
                         # below every confirmed path but above capabilities
TIER_WILDCARD = 4        # new wildcard capabilities (confirmed, then conditional)
TIER_CAP = 5             # new capabilities (confirmed, then conditional)
TIER_REMOVAL = 6         # removals (paths and capabilities)
TIER_CHURN = 7           # structural churn with no permission effect
NEW_ACTIONS_SAMPLE = 20

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_DOWNGRADE = {"critical": "high", "high": "medium", "medium": "low", "low": "info", "info": "info"}

REASON_NOTES = {
    "condition": "Statement carries a Condition block; its effect was not evaluated.",
    "unresolved_policy_body": "Policy document was unresolved at plan time; actions and "
                              "resources are unknown.",
    "not_action": "Statement uses NotAction/NotResource; not evaluated.",
    "resource_policy": "Resource-based policy; not evaluated in v1.",
}


def _short(g: Graph, nid: str) -> str:
    n = g.nodes.get(nid)
    if n is None:
        return nid
    return n.get("name") or n["logical_address"]


def _addr(g: Graph, nid: str) -> str:
    n = g.nodes.get(nid)
    return n["logical_address"] if n else nid


def _fmt_actions(actions: Tuple[str, ...]) -> str:
    if len(actions) <= 4:
        return "[" + ", ".join(actions) + "]"
    return "[" + ", ".join(actions[:3]) + f", ... +{len(actions) - 3} more]"


def _fmt_resources(pats: Tuple[str, ...]) -> str:
    if not pats:
        return "(no resource pattern)"
    if pats == ("*",):
        return "all resources (*)"
    if len(pats) == 1:
        return pats[0]
    return ", ".join(pats)


class _F:
    __slots__ = ("tier", "sev", "cross", "conf", "kind", "title", "detail", "node_ids",
                 "edge_ids", "extra")

    def __init__(self, tier: int, sev: str, kind: str, title: str, detail: str,
                 node_ids: List[str], edge_ids: List[str], cross: bool = False,
                 conf: str = CONFIRMED, extra: Optional[dict] = None) -> None:
        self.tier, self.sev, self.kind = tier, sev, kind
        self.title, self.detail = title, detail
        self.node_ids = sorted(set(node_ids))
        self.edge_ids = sorted(set(edge_ids))
        self.cross, self.conf, self.extra = cross, conf, extra or {}

    def sort_key(self) -> tuple:
        return (self.tier, 0 if self.cross else 1, 0 if self.conf == CONFIRMED else 1,
                _SEV_ORDER[self.sev], self.title, tuple(self.node_ids))

    def as_doc(self, rank: int) -> dict:
        d = {"rank": rank, "severity": self.sev, "kind": self.kind, "title": self.title,
             "detail": self.detail, "node_ids": self.node_ids, "edge_ids": self.edge_ids,
             "confidence": self.conf}
        d.update(self.extra)
        return d


def _path_finding(g: Graph, p: Path, added: bool, became_confirmed: bool,
                  term_caps: Tuple[List[str], List[str]]) -> _F:
    cross = len({n.split("/", 1)[0] for n in p.nodes}) > 1
    hops = len(p.nodes) - 1
    src, dst = p.nodes[0], p.nodes[-1]
    chain = " -> ".join(_short(g, n) for n in p.nodes)
    scopes = sorted({n.split("/", 1)[0] for n in p.nodes})
    if added:
        tier = TIER_PATH_CROSS if cross else TIER_PATH
        sev = "critical" if cross else "high"
        if p.confidence != CONFIRMED:
            tier = TIER_PATH_COND
            sev = _DOWNGRADE[sev]
        verb = "can now reach" if not became_confirmed else "can now unconditionally reach"
        title = f"{_short(g, src)} {verb} {_short(g, dst)}"
        title += f" ({hops} hop{'s' if hops != 1 else ''}"
        title += ", cross-scope)" if cross else ")"
        if p.confidence != CONFIRMED:
            title += " [conditional]"
        detail = f"New privilege path {chain}"
        if cross:
            detail += f" spanning scopes {', '.join(scopes)}; no single plan sees this path"
        detail += "."
        if became_confirmed:
            detail += " The path existed before but was conditional."
        if p.reasons:
            detail += f" Conditional on unevaluated: {', '.join(p.reasons)}."
        confirmed_caps, cond_caps = term_caps
        if confirmed_caps:
            detail += f" Terminal capabilities: {_fmt_actions(tuple(confirmed_caps))}."
        if cond_caps:
            detail += f" Conditional terminal capabilities: {_fmt_actions(tuple(cond_caps))}."
        kind = "path_confirmed" if became_confirmed else "path_added"
    else:
        tier, sev = TIER_REMOVAL, "info"
        title = f"{_short(g, src)} can no longer reach {_short(g, dst)} ({hops} hop{'s' if hops != 1 else ''}"
        title += ", cross-scope)" if cross else ")"
        detail = f"Removed privilege path {chain}."
        kind = "path_removed"
    return _F(tier, sev, kind, title, detail, list(p.nodes), list(p.edge_ids), cross,
              p.confidence, {"path": list(p.nodes), "hops": hops, "crosses_scopes": cross})


def _cap_group_key(c: Capability) -> tuple:
    return (c.actions, c.denied_actions, c.resource_patterns, c.confidence)


def _dirty_context(base: Graph, head: Graph, struct: StructuralResult,
                   principals: List[str]) -> Tuple[Set[str], Set[str]]:
    """Dirty edges/nodes in the attach/grant neighbourhood of these principals,
    on either side: the structural changes that *explain* a capability delta."""
    edges: Set[str] = set()
    nodes: Set[str] = set()
    for p in principals:
        for g in (base, head):
            for e in involved_edges_for_principal(g, p):
                if e["type"] in ("attaches", "grants") and e["id"] in struct.dirty_edge_ids:
                    edges.add(e["id"])
                    for n in (e["source"], e["target"]):
                        if n in struct.dirty_node_ids:
                            nodes.add(n)
    return edges, nodes


def _cap_findings(base: Graph, head: Graph, sem: SemanticResult,
                  struct: StructuralResult) -> List[_F]:
    """Capability findings are driven by the action-level delta, not by grant
    identities: an added grant that gives the principal nothing new (e.g. an
    explicit Deny narrowing s3:*) is not a "new capability", and a removed
    grant whose actions are still covered elsewhere is a widening, not a loss."""
    out: List[_F] = []
    groups: Dict[tuple, List[Capability]] = {}
    for c in sem.caps_added:
        groups.setdefault(_cap_group_key(c), []).append(c)
    for key, caps in sorted(groups.items()):
        c0 = caps[0]
        gained_by_p = {c.principal: restrict_delta(sem.actions_gained.get(c.principal, []), c)
                       for c in caps}
        principals = sorted(p for p, g in gained_by_p.items() if g)
        if not principals:
            continue  # nothing actually new for anyone: narrowing or reshuffle
        widened_from: List[Capability] = []
        for r in sem.caps_removed:
            if r.principal in principals and superseding(r, caps) is not None:
                widened_from.append(r)
        wildcard = c0.wildcard
        tier = TIER_WILDCARD if wildcard else TIER_CAP
        if c0.actions == ("*",) and c0.resource_patterns == ("*",):
            sev = "critical"
        elif wildcard:
            sev = "high"
        else:
            sev = "medium"
        if c0.confidence != CONFIRMED:
            sev = _DOWNGRADE[sev]
        kind = "wildcard_capability_added" if wildcard else "capability_added"
        who = _short(head, principals[0]) if len(principals) == 1 else f"{len(principals)} principals"
        confirmed_only = bool(widened_from) and all(
            w.actions == c0.actions and w.resource_patterns == c0.resource_patterns
            for w in widened_from)
        if confirmed_only:
            title = (f"{who} now confirmed for {_fmt_actions(c0.actions)} on "
                     f"{_fmt_resources(c0.resource_patterns)} (was conditional)")
        else:
            verb = "widened to" if widened_from else "gained"
            title = f"{who} {verb} {_fmt_actions(c0.actions)} on {_fmt_resources(c0.resource_patterns)}"
        if c0.confidence != CONFIRMED:
            title += " [conditional]"
        pol = sorted({p for c in caps for p in c.via_policies})
        pol_txt = ", ".join(_addr(head, p) for p in pol)
        sids = sorted({s for c in caps for s in c.sids})
        stmt = f" statement {', '.join(sids)}" if sids else ""
        if confirmed_only:
            detail = (f"{pol_txt}{stmt} grants {_fmt_actions(c0.actions)} on "
                      f"{_fmt_resources(c0.resource_patterns)}; the unevaluated condition that "
                      f"made it conditional is gone.")
        elif widened_from:
            w = widened_from[0]
            detail = (f"{pol_txt}{stmt} widened from {_fmt_actions(w.actions)} on "
                      f"{_fmt_resources(w.resource_patterns)} to {_fmt_actions(c0.actions)} on "
                      f"{_fmt_resources(c0.resource_patterns)}.")
        else:
            detail = (f"{pol_txt}{stmt} grants {_fmt_actions(c0.actions)} on "
                      f"{_fmt_resources(c0.resource_patterns)} to "
                      f"{', '.join(_short(head, p) for p in principals)}.")
        if c0.denied_actions:
            detail += f" Explicit denies carve out {_fmt_actions(c0.denied_actions)}."
        if c0.wildcard_actions:
            n = len([t for t in c0.expanded if "*" not in t and "?" not in t])
            detail += f" Wildcard expands to {n} catalogued action{'s' if n != 1 else ''}."
        if c0.unexpandable:
            detail += (f" Not expanded (service outside bundled catalog): "
                       f"{', '.join(c0.unexpandable)}.")
        if c0.unevaluated:
            detail += f" Conditional on unevaluated: {', '.join(c0.unevaluated)}."
        gained = sorted({t for p in principals for (t, _, _) in gained_by_p[p]})
        d_edges, d_nodes = _dirty_context(base, head, struct, principals)
        targets = sorted({t for c in caps for t in c.targets})
        out.append(_F(tier, sev, kind, title, detail,
                      principals + pol + targets + sorted(d_nodes),
                      sorted({e for c in caps for e in c.edge_ids} | d_edges),
                      False, c0.confidence,
                      {"principals": principals, "actions": list(c0.actions),
                       "resource_patterns": list(c0.resource_patterns),
                       "wildcard": wildcard, "new_actions_count": len(gained),
                       "new_actions_sample": gained[:NEW_ACTIONS_SAMPLE]}))

    # removals: only what was actually lost at the action level
    rgroups: Dict[tuple, List[Tuple[Capability, List[str]]]] = {}
    for r in sem.caps_removed:
        lost = sorted({t for t, _, _ in restrict_delta(sem.actions_lost.get(r.principal, []), r)})
        if not lost:
            continue  # superseded / still covered: a widening, reported above
        rgroups.setdefault((r.actions, r.resource_patterns, r.confidence, tuple(lost)), []).append((r, lost))
    for key, items in sorted(rgroups.items()):
        c0, lost = items[0]
        principals = sorted(c.principal for c, _ in items)
        who = _short(base, principals[0]) if len(principals) == 1 else f"{len(principals)} principals"
        lost_t = tuple(lost)
        title = f"{who} lost {_fmt_actions(lost_t)} on {_fmt_resources(c0.resource_patterns)}"
        pol = sorted({p for c, _ in items for p in c.via_policies})
        detail = (f"{', '.join(_addr(base, p) for p in pol)} granted {_fmt_actions(c0.actions)} on "
                  f"{_fmt_resources(c0.resource_patterns)}; {', '.join(_short(base, p) for p in principals)} "
                  f"no longer {'has' if len(principals) == 1 else 'have'} {_fmt_actions(lost_t)} there.")
        d_edges, d_nodes = _dirty_context(base, head, struct, principals)
        head_denies = sorted({e for p in principals for c in capabilities_of(head, p)
                              for e in c.deny_edge_ids})
        if head_denies:
            detail += " Carved out by an explicit Deny."
        targets = sorted({t for c, _ in items for t in c.targets})
        out.append(_F(TIER_REMOVAL, "info", "capability_removed", title, detail,
                      principals + pol + targets + sorted(d_nodes),
                      sorted({e for c, _ in items for e in c.edge_ids} | d_edges | set(head_denies)),
                      False, c0.confidence,
                      {"principals": principals, "actions": list(c0.actions),
                       "resource_patterns": list(c0.resource_patterns),
                       "lost_actions": list(lost_t)}))
    return out


def build_findings(base: Graph, head: Graph, struct: StructuralResult,
                   sem: SemanticResult) -> List[dict]:
    fs: List[_F] = []
    removed_idx = {p.nodes: p for p in sem.paths_removed}
    added_idx = {p.nodes: p for p in sem.paths_added}
    for p in sem.paths_added:
        prev = removed_idx.get(p.nodes)
        became_confirmed = prev is not None and prev.confidence == CONDITIONAL and p.confidence == CONFIRMED
        fs.append(_path_finding(head, p, True, became_confirmed,
                                sem.terminal_caps.get(p.identity, ([], []))))
    for p in sem.paths_removed:
        if p.nodes in added_idx:
            continue  # confidence change, reported on the added side
        fs.append(_path_finding(base, p, False, False, ([], [])))
    fs.extend(_cap_findings(base, head, sem, struct))

    # structural churn: everything not already explained by a semantic finding
    explained_edges = {e for f in fs for e in f.edge_ids}
    explained_nodes = {n for f in fs for n in f.node_ids}
    churn_nodes = sorted(struct.dirty_node_ids - explained_nodes)
    churn_edges = sorted(struct.dirty_edge_ids - explained_edges)
    if churn_nodes or churn_edges:
        parts = []
        for label, sec in (("nodes", struct.nodes), ("edges", struct.edges)):
            a, r, c = len(sec["added"]), len(sec["removed"]), len(sec["changed"])
            parts.append(f"{label}: +{a} -{r} ~{c}")
        items = []
        for nid in churn_nodes[:20]:
            fields = struct.field_deltas.get(nid)
            items.append(nid + (f" ({', '.join(fields)})" if fields else ""))
        for eid in churn_edges[:20]:
            fields = struct.field_deltas.get(eid)
            items.append(eid + (f" ({', '.join(fields)})" if fields else ""))
        more = len(churn_nodes) + len(churn_edges) - len(items)
        detail = "Structural changes with no capability or path effect: " + "; ".join(items)
        if more > 0:
            detail += f"; ... +{more} more"
        detail += "."
        fs.append(_F(TIER_CHURN, "info", "structural_churn",
                     f"Structural churn without permission effect ({'; '.join(parts)})",
                     detail, churn_nodes, churn_edges, False, CONFIRMED,
                     {"nodes": churn_nodes, "edges": churn_edges}))

    fs.sort(key=_F.sort_key)
    return [f.as_doc(i + 1) for i, f in enumerate(fs)]


def build_unevaluated(base: Graph, head: Graph, struct: StructuralResult,
                      sem: SemanticResult) -> List[dict]:
    """Unevaluated edges that bear on this diff: dirty themselves, or within
    the trust/capability neighbourhood of any principal or node the diff
    touched.  Nothing touched -> nothing listed (section 8: the empty diff is
    empty everywhere)."""
    # principals whose trust/capability neighbourhood matters for this diff
    principals: Set[str] = set()
    for c in sem.caps_added + sem.caps_removed:
        principals.add(c.principal)
    for p in sem.paths_added + sem.paths_removed:
        for n in p.nodes:
            if head.node_type(n) == "principal":
                principals.add(n)
    for eid in struct.dirty_edge_ids:
        for g in (base, head):
            e = g.edges.get(eid)
            if e:
                for n in (e["source"], e["target"]):
                    if head.node_type(n) == "principal":
                        principals.add(n)
    for n in struct.dirty_node_ids:
        if head.node_type(n) == "principal":
            principals.add(n)
    # nodes whose own content changed (not merely endpoints of a dirty edge --
    # a shared wildcard target must not drag in every statement aimed at it)
    involved_nodes: Set[str] = set(struct.dirty_node_ids)

    relevant: Dict[str, Tuple[dict, str]] = {}
    for eid in struct.dirty_edge_ids:
        e = head.edges.get(eid)
        if e is not None and e.get("unevaluated"):
            relevant[eid] = (e, "changed in this diff")
    for p in sorted(principals):
        for e in involved_edges_for_principal(head, p):
            if e.get("unevaluated") and e["id"] not in relevant:
                relevant[e["id"]] = (e, f"affects {_short(head, p)}")
    for n in sorted(involved_nodes):
        for e in head.incident_edges(n):
            if e.get("unevaluated") and e["id"] not in relevant:
                relevant[e["id"]] = (e, "incident to a changed node")

    out = []
    for eid in sorted(relevant):
        e, why = relevant[eid]
        reasons = sorted(e.get("unevaluated") or [])
        notes = [REASON_NOTES.get(r, f"Unevaluated: {r}.") for r in reasons]
        if "unresolved_policy_body" in reasons:
            tgt = head.nodes.get(e["target"])
            if tgt and tgt.get("unresolved_attributes"):
                notes.append(f"Target {tgt['logical_address']} has unresolved attributes: "
                             f"{', '.join(sorted(tgt['unresolved_attributes']))}.")
        out.append({
            "edge_id": eid,
            "edge_type": e["type"],
            "source": e["source"],
            "target": e["target"],
            "reasons": reasons,
            "note": " ".join(notes),
            "relevance": why,
        })
    return out
