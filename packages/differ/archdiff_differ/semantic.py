"""Stage 2 -- semantic diff.

a) Effective capabilities per principal: principal -attaches-> policy -grants->
   target, Allow/Deny resolved with explicit-deny-wins, wildcards expanded
   against ``archdiff_differ.catalog`` (five services only).
b) Privilege paths: simple paths over ``can_assume`` edges from entry
   principals, at most MAX_HOPS hops; ``crosses_scopes`` when the path touches
   more than one ``scope.key``.
c) Confidence: ``confirmed`` only when no edge involved carries a non-empty
   ``unevaluated``; otherwise ``conditional``.  An unevaluated edge is never a
   confirmed capability.

Incrementality.  The semantic layer is derived from the structural delta:
only principals whose attach/grant neighbourhood contains a dirty element are
re-evaluated, and only privilege paths that traverse a dirty ``can_assume``
pair are enumerated.  An untouched principal has byte-identical policies and
edges on both sides (that is what identical digests mean), so its capabilities
cannot differ.  ``semantic_diff(..., full=True)`` computes everything globally
and is used by tests to prove the incremental result equals the full one.
"""
from collections import defaultdict
from fnmatch import fnmatchcase
from typing import Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

from .catalog import CATALOG_VERSION, action_matches, expand_actions, is_wildcard
from .graph import Graph

CONFIRMED = "confirmed"
CONDITIONAL = "conditional"
MAX_HOPS = 4


def _conf(*edges: dict) -> str:
    return CONFIRMED if all(not e.get("unevaluated") for e in edges) else CONDITIONAL


def _reasons(*edges: dict) -> List[str]:
    out: Set[str] = set()
    for e in edges:
        out.update(e.get("unevaluated") or [])
    return sorted(out)


def resource_covers(cover: str, pattern: str) -> bool:
    """Does resource pattern ``cover`` subsume resource pattern ``pattern``?
    Conservative: exact match, ``*``, or glob match of the literal pattern."""
    if cover == "*" or cover == pattern:
        return True
    return fnmatchcase(pattern, cover)


def _all_covered(covers: Iterable[str], patterns: Iterable[str]) -> bool:
    covers = list(covers)
    pats = list(patterns)
    if not covers:
        return False
    if not pats:  # no resource pattern (e.g. unresolved): only "*" covers it
        return "*" in covers
    return all(any(resource_covers(c, p) for c in covers) for p in pats)


# ---------------------------------------------------------------------------
# a) capabilities
# ---------------------------------------------------------------------------

class Capability:
    """One effective grant of a principal.  Identity (what the added/removed
    diff is computed over) deliberately excludes provenance: a statement moved
    between policies is not a semantic change."""
    __slots__ = ("principal", "actions", "denied_actions", "resource_patterns",
                 "confidence", "targets", "via_policies", "edge_ids", "unevaluated",
                 "wildcard_actions", "wildcard_resources", "expanded", "unexpandable",
                 "sids", "deny_edge_ids")

    def __init__(self, principal: str) -> None:
        self.principal = principal
        self.actions: Tuple[str, ...] = ()
        self.denied_actions: Tuple[str, ...] = ()
        self.resource_patterns: Tuple[str, ...] = ()
        self.confidence = CONFIRMED
        self.targets: Tuple[str, ...] = ()
        self.via_policies: Tuple[str, ...] = ()
        self.edge_ids: Tuple[str, ...] = ()
        self.unevaluated: Tuple[str, ...] = ()
        self.wildcard_actions = False
        self.wildcard_resources = False
        self.expanded: Tuple[str, ...] = ()   # concrete tokens after deny carving
        self.unexpandable: Tuple[str, ...] = ()
        self.sids: Tuple[str, ...] = ()
        self.deny_edge_ids: Tuple[str, ...] = ()   # explicit denies that carved this grant

    @property
    def identity(self) -> tuple:
        return (self.principal, self.actions, self.denied_actions,
                self.resource_patterns, self.confidence)

    @property
    def wildcard(self) -> bool:
        return self.wildcard_actions or self.wildcard_resources

    def as_doc(self) -> dict:
        d = {
            "principal": self.principal,
            "actions": list(self.actions),
            "resource_patterns": list(self.resource_patterns),
            "confidence": self.confidence,
            "wildcard": self.wildcard,
            "targets": list(self.targets),
            "via_policies": list(self.via_policies),
            "edge_ids": list(self.edge_ids),
            "expanded_action_count": len([t for t in self.expanded if not is_wildcard(t)]),
        }
        if self.denied_actions:
            d["denied_actions"] = list(self.denied_actions)
        if self.unevaluated:
            d["unevaluated"] = list(self.unevaluated)
        if self.unexpandable:
            d["unexpandable"] = list(self.unexpandable)
        return d


def _grants_of(graph: Graph, principal: str) -> List[Tuple[dict, dict]]:
    """(attaches_edge, grants_edge) pairs reachable from a principal."""
    out = []
    for att in graph.out_edges(principal, "attaches"):
        for g in graph.out_edges(att["target"], "grants"):
            out.append((att, g))
    return out


def capabilities_of(graph: Graph, principal: str) -> List[Capability]:
    pairs = _grants_of(graph, principal)
    allows = [(a, g) for a, g in pairs if (g.get("effect") or "Allow") == "Allow"]
    # Explicit deny wins -- but only a deny we could evaluate.  A deny that
    # carries `unevaluated` might not apply, so it must not hide an allow;
    # it is surfaced in the diff's `unevaluated` section instead.
    denies = [(a, g) for a, g in pairs if g.get("effect") == "Deny"
              and not g.get("unevaluated") and not a.get("unevaluated")]

    caps: Dict[tuple, Capability] = {}
    for att, g in allows:
        actions = sorted(set(g.get("actions") or []))
        patterns = tuple(sorted(set(g.get("resource_patterns") or [])))
        tokens, unexpandable = expand_actions(actions)
        carved: Set[str] = set()
        deny_ids: Set[str] = set()
        for datt, d in denies:
            if not _all_covered(d.get("resource_patterns") or [], patterns):
                continue
            for t in tokens:
                if any(action_matches(t, p) for p in (d.get("actions") or [])):
                    carved.add(t)
                    deny_ids.update((datt["id"], d["id"]))
        cap = Capability(principal)
        cap.deny_edge_ids = tuple(sorted(deny_ids))
        if carved:
            remaining = [t for t in tokens if t not in carved]
            cap.actions = tuple(remaining)
            cap.denied_actions = tuple(sorted(carved))
            cap.expanded = tuple(remaining)
        else:
            cap.actions = tuple(actions)
            cap.expanded = tuple(tokens)
        cap.resource_patterns = patterns
        cap.confidence = _conf(att, g)
        cap.unevaluated = tuple(_reasons(att, g))
        cap.wildcard_actions = any(is_wildcard(a) for a in actions)
        cap.wildcard_resources = "*" in patterns
        cap.unexpandable = tuple(unexpandable)
        key = cap.identity
        if key in caps:
            prev = caps[key]
            prev.targets = tuple(sorted(set(prev.targets) | {g["target"]}))
            prev.via_policies = tuple(sorted(set(prev.via_policies) | {g["source"]}))
            prev.edge_ids = tuple(sorted(set(prev.edge_ids) | {att["id"], g["id"]} | deny_ids))
            prev.sids = tuple(sorted(set(prev.sids) | ({g["sid"]} if g.get("sid") else set())))
        else:
            cap.targets = (g["target"],)
            cap.via_policies = (g["source"],)
            cap.edge_ids = tuple(sorted({att["id"], g["id"]} | deny_ids))
            cap.sids = (g["sid"],) if g.get("sid") else ()
            caps[key] = cap
    return [caps[k] for k in sorted(caps)]


def all_principals(graph: Graph) -> List[str]:
    return sorted(nid for nid, n in graph.nodes.items() if n["type"] == "principal")


# ---------------------------------------------------------------------------
# b) privilege paths
# ---------------------------------------------------------------------------

class Hop:
    __slots__ = ("source", "target", "confidence", "edge_ids", "reasons")

    def __init__(self, source: str, target: str, edges: List[dict]) -> None:
        self.source, self.target = source, target
        good = [e for e in edges if not e.get("unevaluated")]
        self.confidence = CONFIRMED if good else CONDITIONAL
        self.edge_ids = tuple(sorted(e["id"] for e in edges))
        self.reasons = () if good else tuple(_reasons(*edges))


class TrustGraph:
    """Lazy view of the ``can_assume`` relation: one Hop per (source, target)
    pair, materialised on demand so the incremental diff touches only the
    neighbourhood of a change.

    * Parallel edges collapse into one hop; if any is confirmed the hop is.
    * A confirmed explicit Deny on a pair removes the hop (deny wins); a
      conditional Deny does not (it may not apply) and stays in `unevaluated`.
    * Entry nodes are where reported paths start: a node with outgoing hops and
      no incoming hop.  A region reachable from no such node (trust cycles
      only) gets the smallest id of its backward closure as its entry so the
      cycle is still reported.  Both rules are local to the node's backward
      closure, and the check stops as soon as a real entry is found.
    """

    def __init__(self, graph: Graph) -> None:
        self.graph = graph
        self._succ: Dict[str, Dict[str, Hop]] = {}
        self._pred: Dict[str, List[str]] = {}
        self._entry: Dict[str, bool] = {}
        self._real_reach: Dict[str, bool] = {}

    def succ(self, u: str) -> Dict[str, Hop]:
        h = self._succ.get(u)
        if h is None:
            by_target: Dict[str, List[dict]] = {}
            denied: Set[str] = set()
            for e in self.graph.out_edges(u, "can_assume"):
                if e.get("effect") == "Deny":
                    if not e.get("unevaluated"):
                        denied.add(e["target"])
                    continue
                by_target.setdefault(e["target"], []).append(e)
            h = {v: Hop(u, v, edges) for v, edges in by_target.items() if v not in denied}
            self._succ[u] = h
        return h

    def pred(self, v: str) -> List[str]:
        p = self._pred.get(v)
        if p is None:
            p = sorted({e["source"] for e in self.graph.in_edges(v, "can_assume")
                        if v in self.succ(e["source"])})
            self._pred[v] = p
        return p

    def hop(self, u: str, v: str) -> Optional[Hop]:
        return self.succ(u).get(v)

    def _reachable_from_real_entry(self, n: str) -> Tuple[bool, Set[str]]:
        """(True, partial closure) as soon as a real entry is found in the
        backward closure of n; otherwise (False, full backward closure)."""
        seen: Set[str] = set()
        stack = [n]
        while stack:
            m = stack.pop()
            if m in seen:
                continue
            seen.add(m)
            preds = self.pred(m)
            if not preds and self.succ(m):
                return True, seen
            stack.extend(preds)
        return False, seen

    def is_entry(self, n: str) -> bool:
        r = self._entry.get(n)
        if r is None:
            if not self.succ(n):
                r = False
            elif not self.pred(n):
                r = True
            else:
                reach, closure = self._reachable_from_real_entry(n)
                r = (not reach) and n == min(closure)
            self._entry[n] = r
        return r

    def reachable_from_real_entry(self, n: str) -> bool:
        r = self._real_reach.get(n)
        if r is None:
            r = self._reachable_from_real_entry(n)[0]
            self._real_reach[n] = r
        return r

    def all_sources(self) -> List[str]:
        return sorted({e["source"] for e in self.graph.edges.values()
                       if e["type"] == "can_assume"})

    def all_entries(self) -> List[str]:
        """Global enumeration -- O(trust graph); used by the full mode only."""
        return [s for s in self.all_sources() if self.is_entry(s)]

    def pairs_touching(self, edge_ids: Set[str]) -> Set[Tuple[str, str]]:
        out: Set[Tuple[str, str]] = set()
        for eid in edge_ids:
            e = self.graph.edges.get(eid)
            if e is not None and e["type"] == "can_assume":
                out.add((e["source"], e["target"]))
        return out


class Path:
    __slots__ = ("nodes", "hops", "confidence", "edge_ids", "reasons")

    def __init__(self, nodes: Tuple[str, ...], hops: List[Hop]) -> None:
        self.nodes = nodes
        self.hops = hops
        self.confidence = CONFIRMED if all(h.confidence == CONFIRMED for h in hops) else CONDITIONAL
        self.edge_ids = tuple(sorted({eid for h in hops for eid in h.edge_ids}))
        self.reasons = tuple(sorted({r for h in hops for r in h.reasons}))

    @property
    def identity(self) -> tuple:
        return (self.nodes, self.confidence)


def _forward(tg: TrustGraph, start: str, max_hops: int) -> List[Path]:
    """All simple paths from ``start`` with 1..max_hops hops (every prefix is
    itself a path)."""
    out: List[Path] = []

    def dfs(node: str, visited: Tuple[str, ...], hops: List[Hop]) -> None:
        if len(hops) >= max_hops:
            return
        for nxt in sorted(tg.succ(node)):
            if nxt in visited:
                continue
            h = tg.hop(node, nxt)
            p = visited + (nxt,)
            out.append(Path(p, hops + [h]))
            dfs(nxt, p, hops + [h])

    dfs(start, (start,), [])
    return out


def enumerate_paths(tg: TrustGraph, max_hops: int = MAX_HOPS) -> List[Path]:
    """Every reported path in the graph.  O(trust graph): full mode only."""
    paths: List[Path] = []
    for s in tg.all_entries():
        paths.extend(_forward(tg, s, max_hops))
    return paths


def paths_through(tg: TrustGraph, pairs: Set[Tuple[str, str]],
                  max_hops: int = MAX_HOPS) -> List[Path]:
    """Exactly the subset of ``enumerate_paths`` whose hops include at least one
    of ``pairs``, found without enumerating the rest of the graph: backward
    simple paths from the pair's source to an entry, joined with forward simple
    paths from its target, total length <= max_hops."""
    found: Dict[tuple, Path] = {}
    for (u, v) in sorted(pairs):
        hop = tg.hop(u, v)
        if hop is None:
            continue
        prefixes: List[Tuple[Tuple[str, ...], List[Hop]]] = []

        def back(node: str, chain: Tuple[str, ...], hops: List[Hop]) -> None:
            if tg.is_entry(node):
                prefixes.append((chain, hops))
            if len(hops) >= max_hops - 1:
                return
            for prev in tg.pred(node):
                if prev in chain:
                    continue
                back(prev, (prev,) + chain, [tg.hop(prev, node)] + hops)

        back(u, (u,), [])
        for chain, hops in prefixes:
            if v in chain:
                continue
            base_nodes = chain + (v,)
            base_hops = hops + [hop]
            p = Path(base_nodes, base_hops)
            found[p.identity] = p
            remaining = max_hops - len(base_hops)

            def fwd(node: str, visited: Tuple[str, ...], hs: List[Hop], budget: int) -> None:
                if budget <= 0:
                    return
                for nxt in sorted(tg.succ(node)):
                    if nxt in visited:
                        continue
                    h = tg.hop(node, nxt)
                    q = Path(visited + (nxt,), hs + [h])
                    found[q.identity] = q
                    fwd(nxt, visited + (nxt,), hs + [h], budget - 1)

            fwd(v, base_nodes, base_hops, remaining)
    return [found[k] for k in sorted(found)]


def flipped_entries(tg_b: TrustGraph, tg_h: TrustGraph,
                    pairs: Set[Tuple[str, str]]) -> Tuple[List[str], List[str]]:
    """Nodes whose entry status differs between the sides, given that only
    ``pairs`` changed.  Candidates are the pair endpoints plus, forward from the
    pair targets, any node not reachable from a real entry on both sides (a
    node that *is* reachable from a real entry on both sides is a non-entry on
    both, and so is everything downstream of it -- the search prunes there).
    Returns (entries only in base, entries only in head)."""
    cand: List[str] = []
    seen: Set[str] = set()
    stack = sorted({n for pr in pairs for n in pr})
    while stack:
        n = stack.pop()
        if n in seen:
            continue
        seen.add(n)
        cand.append(n)
        if tg_b.reachable_from_real_entry(n) and tg_h.reachable_from_real_entry(n):
            continue
        stack.extend(sorted(set(tg_b.succ(n)) | set(tg_h.succ(n))))
    only_b = sorted(n for n in cand if tg_b.is_entry(n) and not tg_h.is_entry(n))
    only_h = sorted(n for n in cand if tg_h.is_entry(n) and not tg_b.is_entry(n))
    return only_b, only_h


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------

class SemanticResult:
    def __init__(self) -> None:
        self.caps_added: List[Capability] = []
        self.caps_removed: List[Capability] = []
        self.paths_added: List[Path] = []
        self.paths_removed: List[Path] = []
        self.principals_evaluated: List[str] = []
        self.paths_enumerated = 0
        self.mode = "incremental"
        # per-path terminal capabilities, keyed by path identity
        self.terminal_caps: Dict[tuple, Tuple[List[str], List[str]]] = {}
        # granular action-level delta used by findings: principal -> ...
        self.actions_gained: Dict[str, List[Tuple[str, str, str]]] = {}
        self.actions_lost: Dict[str, List[Tuple[str, str, str]]] = {}

    @property
    def is_empty(self) -> bool:
        return not (self.caps_added or self.caps_removed or
                    self.paths_added or self.paths_removed)

    def as_doc(self) -> dict:
        def cap_doc(c: Capability, superseded_by: Optional[Capability], added: bool) -> dict:
            d = c.as_doc()
            if added:
                gained = restrict_delta(self.actions_gained.get(c.principal, []), c)
                d["gained_action_count"] = len(gained)
            else:
                lost = restrict_delta(self.actions_lost.get(c.principal, []), c)
                d["lost_actions"] = sorted({t for t, _, _ in lost})
                if superseded_by is not None:
                    d["superseded_by"] = {"actions": list(superseded_by.actions),
                                          "resource_patterns": list(superseded_by.resource_patterns),
                                          "confidence": superseded_by.confidence}
            return d

        def path_doc(p: Path) -> dict:
            term, cond = self.terminal_caps.get(p.identity, ([], []))
            d = {
                "path": list(p.nodes),
                "hops": len(p.nodes) - 1,
                "crosses_scopes": _crosses_scopes(p.nodes),
                "terminal_capabilities": term,
                "confidence": p.confidence,
                "edge_ids": list(p.edge_ids),
            }
            if cond:
                d["terminal_conditional_capabilities"] = cond
            if p.reasons:
                d["unevaluated"] = list(p.reasons)
            return d

        return {
            "capabilities": {
                "added": [cap_doc(c, None, True) for c in self.caps_added],
                "removed": [cap_doc(c, superseding(c, self.caps_added), False)
                            for c in self.caps_removed],
            },
            "paths": {
                "added": [path_doc(p) for p in self.paths_added],
                "removed": [path_doc(p) for p in self.paths_removed],
            },
        }


def _crosses_scopes(nodes: Iterable[str]) -> bool:
    return len({n.split("/", 1)[0] for n in nodes}) > 1


def superseding(removed: Capability, added: List[Capability]) -> Optional[Capability]:
    """The added capability (same principal) that strictly covers a removed one:
    every concrete action still allowed, every resource pattern still covered,
    confidence not weaker.  Used to tell "widened" from "lost"."""
    order = {CONFIRMED: 1, CONDITIONAL: 0}
    for a in added:
        if a.principal != removed.principal:
            continue
        if order[a.confidence] < order[removed.confidence]:
            continue
        if not _all_covered(a.resource_patterns, removed.resource_patterns):
            continue
        a_tokens = set(a.expanded)
        if all(t in a_tokens or any(action_matches(t, pat) for pat in a.actions
                                     if is_wildcard(pat) and pat not in a.denied_actions)
               for t in removed.expanded):
            return a
    return None


def affected_principals(base: Graph, head: Graph, dirty_nodes: Set[str],
                        dirty_edges: Set[str]) -> Set[str]:
    """Principals whose capability computation touches a dirty node or edge, on
    either side."""
    out: Set[str] = set()
    for g in (base, head):
        for eid in dirty_edges:
            e = g.edges.get(eid)
            if e is None:
                continue
            if e["type"] == "attaches":
                out.add(e["source"])
            elif e["type"] == "grants":
                for att in g.in_edges(e["source"], "attaches"):
                    out.add(att["source"])
        for nid in dirty_nodes:
            n = g.nodes.get(nid)
            if n is None:
                continue
            if n["type"] == "principal":
                out.add(nid)
            elif n["type"] == "policy":
                for att in g.in_edges(nid, "attaches"):
                    out.add(att["source"])
            else:
                for gr in g.in_edges(nid, "grants"):
                    for att in g.in_edges(gr["source"], "attaches"):
                        out.add(att["source"])
    return out


def _granular(caps: List[Capability]) -> Dict[str, Dict[str, Set[str]]]:
    """confidence -> action token -> set of resource patterns ('' for none)."""
    out: Dict[str, Dict[str, Set[str]]] = {CONFIRMED: defaultdict(set), "any": defaultdict(set)}
    for c in caps:
        pats = c.resource_patterns or ("",)
        for t in c.expanded:
            for p in pats:
                out["any"][t].add(p)
                if c.confidence == CONFIRMED:
                    out[CONFIRMED][t].add(p)
    return out


def _covered(index: Dict[str, Set[str]], token: str, pattern: str) -> bool:
    want = [pattern] if pattern else []
    pats = index.get(token)
    if pats and _all_covered(pats, want):
        return True
    # a token may also be covered by a retained wildcard token (e.g. "*" or an
    # unexpandable "ec2:*") on a covering resource pattern
    for t, ps in index.items():
        if t != token and is_wildcard(t) and action_matches(token, t) and _all_covered(ps, want):
            return True
    return False


def action_delta(before: List[Capability], after: List[Capability]
                 ) -> Tuple[List[Tuple[str, str, str]], List[Tuple[str, str, str]]]:
    """Action-level (token, resource_pattern, confidence) triples gained and
    lost, honouring resource coverage.  'confirmed' triples are those new/lost
    at confirmed strength; 'conditional' triples are new/lost at any strength."""
    b, a = _granular(before), _granular(after)
    gained: List[Tuple[str, str, str]] = []
    lost: List[Tuple[str, str, str]] = []
    for t, pats in a[CONFIRMED].items():
        for p in pats:
            if not _covered(b[CONFIRMED], t, p):
                gained.append((t, p, CONFIRMED))
    for t, pats in a["any"].items():
        for p in pats:
            if not _covered(b["any"], t, p) and (t, p, CONFIRMED) not in gained:
                gained.append((t, p, CONDITIONAL))
    for t, pats in b[CONFIRMED].items():
        for p in pats:
            if not _covered(a[CONFIRMED], t, p):
                lost.append((t, p, CONFIRMED))
    for t, pats in b["any"].items():
        for p in pats:
            if not _covered(a["any"], t, p) and (t, p, CONFIRMED) not in lost:
                lost.append((t, p, CONDITIONAL))
    return sorted(gained), sorted(lost)


def restrict_delta(triples: Iterable[Tuple[str, str, str]], cap: Capability
                   ) -> List[Tuple[str, str, str]]:
    """The (token, pattern, confidence) triples of a principal-level delta that
    fall under one capability entry."""
    out = []
    pats = cap.resource_patterns or ("",)
    expanded = set(cap.expanded)
    wild = [a for a in cap.actions if is_wildcard(a)]
    for t, p, conf in triples:
        if p not in pats:
            continue
        if t in expanded or any(action_matches(t, a) for a in wild):
            out.append((t, p, conf))
    return out


def semantic_diff(base: Graph, head: Graph, dirty_nodes: Set[str], dirty_edges: Set[str],
                  full: bool = False, max_hops: int = MAX_HOPS) -> SemanticResult:
    res = SemanticResult()
    res.mode = "full" if full else "incremental"

    # ---- capabilities ----
    if full:
        principals = sorted(set(all_principals(base)) | set(all_principals(head)))
    else:
        principals = sorted(affected_principals(base, head, dirty_nodes, dirty_edges))
    res.principals_evaluated = principals
    cap_cache: Dict[Tuple[int, str], List[Capability]] = {}

    def caps(g: Graph, p: str) -> List[Capability]:
        k = (id(g), p)
        if k not in cap_cache:
            cap_cache[k] = capabilities_of(g, p)
        return cap_cache[k]

    for p in principals:
        b_caps = {c.identity: c for c in caps(base, p)}
        h_caps = {c.identity: c for c in caps(head, p)}
        for k in sorted(set(h_caps) - set(b_caps)):
            res.caps_added.append(h_caps[k])
        for k in sorted(set(b_caps) - set(h_caps)):
            res.caps_removed.append(b_caps[k])
        if set(h_caps) != set(b_caps):
            gained, lost = action_delta(list(b_caps.values()), list(h_caps.values()))
            if gained:
                res.actions_gained[p] = gained
            if lost:
                res.actions_lost[p] = lost

    # ---- paths ----
    tg_b, tg_h = TrustGraph(base), TrustGraph(head)
    if full:
        b_paths = enumerate_paths(tg_b, max_hops)
        h_paths = enumerate_paths(tg_h, max_hops)
    else:
        pairs = tg_b.pairs_touching(dirty_edges) | tg_h.pairs_touching(dirty_edges)
        # A path can differ between the sides only if (1) one of its hops is
        # dirty, or (2) its start node is an entry on one side but not the
        # other (an edge removal can promote a node to entry, making every
        # path from it "new").  A dirty *node* on its own changes nothing:
        # ids are stable, and its can_assume edges are in the dirty edge set.
        b_paths = paths_through(tg_b, pairs, max_hops)
        h_paths = paths_through(tg_h, pairs, max_hops)
        only_b, only_h = flipped_entries(tg_b, tg_h, pairs)
        for s in only_b:
            b_paths.extend(_forward(tg_b, s, max_hops))
        for s in only_h:
            h_paths.extend(_forward(tg_h, s, max_hops))
    res.paths_enumerated = len(b_paths) + len(h_paths)
    b_idx = {p.identity: p for p in b_paths}
    h_idx = {p.identity: p for p in h_paths}
    for k in sorted(set(h_idx) - set(b_idx)):
        res.paths_added.append(h_idx[k])
    for k in sorted(set(b_idx) - set(h_idx)):
        res.paths_removed.append(b_idx[k])
    for p, g in [(p, head) for p in res.paths_added] + [(p, base) for p in res.paths_removed]:
        term = p.nodes[-1]
        tc = caps(g, term)
        confirmed = sorted({a for c in tc if c.confidence == CONFIRMED for a in c.actions})
        conditional = sorted({a for c in tc if c.confidence != CONFIRMED for a in c.actions}
                             - set(confirmed))
        res.terminal_caps[p.identity] = (confirmed, conditional)
    return res


def involved_edges_for_principal(g: Graph, principal: str) -> List[dict]:
    """Edges whose `unevaluated` could affect this principal's capabilities or
    trust: its attaches, the grants of its policies, and can_assume /
    trusted_by edges in or out of it."""
    out: List[dict] = []
    for att in g.out_edges(principal, "attaches"):
        out.append(att)
        out.extend(g.out_edges(att["target"], "grants"))
    for t in ("can_assume", "trusted_by"):
        out.extend(g.out_edges(principal, t))
        out.extend(g.in_edges(principal, t))
    return out


CATALOG_NOTE = ("wildcard expansion covers only the bundled catalog "
                f"({CATALOG_VERSION}: s3, sts, iam, kms, secretsmanager)")
