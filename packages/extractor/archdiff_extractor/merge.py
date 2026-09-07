"""Merge N plan extracts into ONE Permission Graph v1 document.

This is where cross-root edges become visible: an ARN string referenced in
one plan is resolved through the alias index built from EVERY plan's
predicted ARNs. Aliases resolve references only -- two nodes are never merged
on alias match.

The output is byte-reproducible: nodes, edges, scopes, warnings and module
children are sorted, and every id is derived from content, never from
position.
"""
from __future__ import annotations

import fnmatch
from dataclasses import replace
from typing import Any, Dict, List, Optional, Tuple

from . import __version__
from .canonical import edge_digest, module_digest, node_digest
from .model import (AnonymousEndpoint, ArnEndpoint, Endpoint, ExternalEndpoint, Node, NodeEndpoint,
                    PendingEdge, PlanExtract, ServiceEndpoint, UNRESOLVED_ADDRESS, UnresolvedEndpoint,
                    WILDCARD_ADDRESS, WildcardEndpoint)
from .scope import Scope, parse_arn

EXTRACTOR_VERSION = "1"
CONFIDENCE_RANK = {"high": 0, "medium": 1, "low": 2}


class Merger:
    def __init__(self, extracts: List[PlanExtract]):
        self.extracts = extracts
        self.nodes: Dict[str, Node] = {}
        self.node_plan: Dict[str, int] = {}
        self.warnings: List[str] = []
        self.alias_index: Dict[str, List[str]] = {}
        self.synthetic_ids: set = set()

    # -- entry ----------------------------------------------------------------

    def run(self) -> Dict[str, Any]:
        for ex in self.extracts:
            self.warnings.extend(ex.warnings)
        pending = self._collect_nodes()
        self._build_alias_index()
        edges = self._resolve_edges(pending)
        return self._assemble(edges)

    # -- nodes --------------------------------------------------------------

    def _collect_nodes(self) -> List[Tuple[int, PendingEdge]]:
        """Collect nodes from every plan; disambiguate genuine id collisions."""
        by_id: Dict[str, List[Tuple[int, Node]]] = {}
        for i, ex in enumerate(self.extracts):
            for node in ex.nodes.values():
                by_id.setdefault(node.id, []).append((i, node))
        renames: Dict[Tuple[int, str], str] = {}
        for node_id, owners in by_id.items():
            if len(owners) == 1:
                i, node = owners[0]
                self._put(node, i)
                continue
            digests = {node_digest(n.to_dict()) for _, n in owners}
            if len(digests) == 1:
                # Identical node from several plans (e.g. run-all re-planning the
                # same unit). Keep one, attributed to the plan whose label sorts
                # first so plan ORDER never changes the rollup.
                i, node = min(owners, key=lambda o: (self._label_of(o[0]), o[0]))
                self._put(node, i)
                continue
            labels = [self.extracts[i].root_label or f"plan[{i}]" for i, _ in owners]
            self.warnings.append(
                f"node id collision across plans: {node_id} is defined by "
                f"{', '.join(sorted(labels))} with different content; logical addresses were "
                f"qualified with the root label. SCHEMA.md gives no disambiguator for this case.")
            for (i, node), label in zip(owners, labels):
                qualified = replace(node, logical_address=f"{node.logical_address}@{label}")
                renames[(i, node_id)] = qualified.id
                self._put(qualified, i)
        pending: List[Tuple[int, PendingEdge]] = []
        for i, ex in enumerate(self.extracts):
            for e in ex.edges:
                pending.append((i, _rename_edge(e, i, renames)))
        return pending

    def _label_of(self, plan_index: int) -> str:
        return self.extracts[plan_index].root_label or f"plan[{plan_index}]"

    def _put(self, node: Node, plan_index: int) -> None:
        self.nodes[node.id] = node
        self.node_plan[node.id] = plan_index

    def _build_alias_index(self) -> None:
        for node in self.nodes.values():
            if node.type in ("external", "wildcard"):
                continue
            for alias in node.aliases:
                self.alias_index.setdefault(alias, []).append(node.id)
        for alias, ids in self.alias_index.items():
            ids.sort()
            if len(ids) > 1:
                self.warnings.append(
                    f"alias {alias} is predicted for {len(ids)} nodes ({', '.join(ids)}); "
                    f"references resolve to all of them")

    # -- endpoint resolution --------------------------------------------------

    def _resolve(self, ep: Endpoint, plan_index: int) -> List[str]:
        if isinstance(ep, NodeEndpoint):
            return [ep.node_id]
        if isinstance(ep, WildcardEndpoint):
            return [self._synthetic(ep.scope, WILDCARD_ADDRESS, "wildcard", None, [], "resolved", plan_index)]
        if isinstance(ep, UnresolvedEndpoint):
            return [self._synthetic(ep.scope, UNRESOLVED_ADDRESS, "external", None, [],
                                    "unresolved_at_plan", plan_index)]
        if isinstance(ep, AnonymousEndpoint):
            return [self._synthetic(ep.scope, "external.*", "external", "*", ["*"], "external", plan_index)]
        if isinstance(ep, ServiceEndpoint):
            return [self._synthetic(ep.scope, f"external.{ep.name}", "external", None, [ep.name],
                                    "external", plan_index)]
        if isinstance(ep, ExternalEndpoint):
            aliases = [ep.alias] if ep.alias else []
            return [self._synthetic(ep.scope, f"external.{ep.label}", "external", None, aliases,
                                    "external", plan_index)]
        if isinstance(ep, ArnEndpoint):
            matched = self._match_alias(ep.pattern)
            if matched:
                return matched
            base = external_base(ep.pattern)
            return [self._synthetic(ep.scope, f"external.{base}", "external", None, [base],
                                    "external", plan_index)]
        raise TypeError(f"unknown endpoint {ep!r}")

    def _match_alias(self, pattern: str) -> List[str]:
        exact = self.alias_index.get(pattern)
        if exact:
            return list(exact)
        prefixed: List[str] = []
        for alias, ids in self.alias_index.items():
            if pattern.startswith(alias + "/") or pattern.startswith(alias + ":"):
                prefixed.extend(ids)
        if prefixed:
            return sorted(set(prefixed))
        if any(c in pattern for c in "*?"):
            globbed: List[str] = []
            for alias, ids in self.alias_index.items():
                if fnmatch.fnmatchcase(alias, pattern):
                    globbed.extend(ids)
            return sorted(set(globbed))
        return []

    def _synthetic(self, scope: Scope, logical_address: str, node_type: str, name: Optional[str],
                   aliases: List[str], resolution: str, plan_index: int) -> str:
        node = Node(type=node_type, scope=scope, logical_address=logical_address, name=name,
                    aliases=aliases, resolution=resolution, module_path="")
        if node.id not in self.nodes:
            self._put(node, plan_index)
            self.synthetic_ids.add(node.id)
        return node.id

    # -- edges ------------------------------------------------------------------

    def _resolve_edges(self, pending: List[Tuple[int, PendingEdge]]) -> List[Tuple[Dict[str, Any], int, str]]:
        expanded: List[Tuple[PendingEdge, str, str, int]] = []
        for i, e in pending:
            for s in self._resolve(e.source, i):
                for t in self._resolve(e.target, i):
                    expanded.append((e, s, t, i))
        expanded = _coalesce_statement_edges(expanded)

        # Statement edges only carry their target in the id when one statement
        # resolves to several targets -- so a widened statement diffs as
        # "changed", not "removed + added" (see schema/fixtures/expected.diff.json).
        stmt_targets: Dict[Tuple[str, str], set] = {}
        for e, s, t, _ in expanded:
            if e.kind == "stmt":
                stmt_targets.setdefault((e.anchor.node_id, e.key or ""), set()).add(t)

        edges: List[Tuple[Dict[str, Any], int, str]] = []
        for e, s, t, i in expanded:
            anchor_id = e.anchor.node_id
            other_id = t if s == anchor_id else s
            label = self._label(anchor_id, other_id)
            if e.kind == "attach":
                eid = f"{anchor_id}#attach:{label}"
            elif e.kind == "trust":
                eid = f"{anchor_id}#trust:{label}"
            else:
                eid = f"{anchor_id}#stmt:{e.key}"
                if len(stmt_targets[(anchor_id, e.key or "")]) > 1:
                    eid += f"@{label}"
            doc = {
                "id": eid, "type": e.type, "source": s, "target": t, "effect": e.effect,
                "actions": sorted(set(e.actions)), "resource_patterns": sorted(set(e.resource_patterns)),
                "sid": e.sid, "resolution": e.resolution, "unevaluated": sorted(set(e.unevaluated)),
            }
            doc["digest"] = edge_digest(doc)
            edges.append((doc, i, e.module_path))
        return _dedupe_edge_ids(edges)

    def _label(self, anchor_id: str, other_id: str) -> str:
        anchor, other = self.nodes[anchor_id], self.nodes[other_id]
        return other.logical_address if other.scope.key == anchor.scope.key else other_id

    # -- assembly -----------------------------------------------------------------

    def _assemble(self, edges: List[Tuple[Dict[str, Any], int, str]]) -> Dict[str, Any]:
        node_docs = []
        for node in self.nodes.values():
            d = node.to_dict()
            d["digest"] = node_digest(d)
            node_docs.append(d)
        node_docs.sort(key=lambda d: d["id"])
        edge_docs = sorted((d for d, _, _ in edges), key=lambda d: d["id"])
        modules = self._module_tree(node_docs, edges)
        return {
            "schema_version": "1.0",
            "generated_by": {"tool_version": __version__, "extractor_version": EXTRACTOR_VERSION},
            "scopes": self._scopes(),
            "modules": modules,
            "moves": self._moves(),
            "nodes": node_docs,
            "edges": edge_docs,
            "warnings": sorted(set(self.warnings)),
        }

    def _moves(self) -> List[Dict[str, Any]]:
        seen = set()
        out = []
        for ex in self.extracts:
            for m in ex.moves:
                key = (m["scope_key"], m["from"], m["to"])
                if key not in seen:
                    seen.add(key)
                    out.append({"scope_key": key[0], "from": key[1], "to": key[2]})
        return sorted(out, key=lambda m: (m["scope_key"], m["from"], m["to"]))

    def _scopes(self) -> List[Dict[str, Any]]:
        by_key: Dict[str, List[Scope]] = {}
        for node in self.nodes.values():
            by_key.setdefault(node.scope.key, []).append(node.scope)
        out = []
        for key in sorted(by_key):
            candidates = by_key[key]
            best = sorted(candidates, key=lambda s: (CONFIDENCE_RANK[s.confidence], s.source))[0]
            roots = {s.root_module for s in candidates}
            out.append(replace(best, root_module=roots.pop() if len(roots) == 1 else None).to_dict())
        return out

    def _module_tree(self, node_docs, edges) -> List[Dict[str, Any]]:
        by_node_id = {d["id"]: d for d in node_docs}
        plan_trees: List[Dict[str, Any]] = []
        for i, ex in enumerate(self.extracts):
            label = self._label_of(i)
            tree = _ModuleNode(label)
            for node_id, node in self.nodes.items():
                if self.node_plan[node_id] == i and node_id not in self.synthetic_ids:
                    tree.at(node.module_path).nodes.append(by_node_id[node_id]["digest"])
            for doc, plan_index, module_path in edges:
                if plan_index == i:
                    tree.at(module_path).edges.append(doc["digest"])
            plan_trees.append(tree.to_doc())
        plan_trees.sort(key=lambda m: m["path"])
        # Synthetic nodes (external / wildcard / unresolved) are owned by no
        # plan: they hang off the top-level root, independent of plan order.
        synthetic = [by_node_id[n]["digest"] for n in self.synthetic_ids]
        root_digest = module_digest(synthetic, [], [m["digest"] for m in plan_trees])
        return [{"path": "root", "digest": root_digest, "children": plan_trees}]


class _ModuleNode:
    def __init__(self, path: str):
        self.path = path
        self.nodes: List[str] = []
        self.edges: List[str] = []
        self.children: Dict[str, "_ModuleNode"] = {}

    def at(self, module_path: str) -> "_ModuleNode":
        if not module_path:
            return self
        from .plan import _split_dotted
        parts = _split_dotted(module_path)
        cur = self
        for j in range(0, len(parts), 2):
            seg = ".".join(parts[j:j + 2])
            cur = cur.children.setdefault(seg, _ModuleNode(seg))
        return cur

    def to_doc(self) -> Dict[str, Any]:
        children = sorted((c.to_doc() for c in self.children.values()), key=lambda m: m["path"])
        return {"path": self.path,
                "digest": module_digest(self.nodes, self.edges, [c["digest"] for c in children]),
                "children": children}


def _rename_edge(e: PendingEdge, plan_index: int, renames: Dict[Tuple[int, str], str]) -> PendingEdge:
    def fix(ep: Endpoint) -> Endpoint:
        if isinstance(ep, NodeEndpoint) and (plan_index, ep.node_id) in renames:
            return NodeEndpoint(renames[(plan_index, ep.node_id)])
        return ep
    if not renames:
        return e
    return replace(e, source=fix(e.source), target=fix(e.target), anchor=fix(e.anchor))


def _coalesce_statement_edges(expanded):
    """Two resource patterns of one statement (``bucket`` and ``bucket/*``) may
    resolve to the same node; they are one edge carrying both patterns."""
    groups: Dict[Tuple[str, str, str, str, int], PendingEdge] = {}
    order: List[Tuple[str, str, str, str, int]] = []
    out = []
    for e, s, t, i in expanded:
        if e.kind != "stmt":
            out.append((e, s, t, i))
            continue
        key = (e.anchor.node_id, e.key or "", e.effect, tuple(sorted(e.actions)), e.sid, s, t, i)
        if key not in groups:
            groups[key] = replace(e, actions=list(e.actions), resource_patterns=list(e.resource_patterns),
                                  unevaluated=list(e.unevaluated))
            order.append(key)
            continue
        g = groups[key]
        g.resource_patterns = sorted(set(g.resource_patterns) | set(e.resource_patterns))
        g.unevaluated = sorted(set(g.unevaluated) | set(e.unevaluated))
        if e.resolution == "unresolved_at_plan":
            g.resolution = e.resolution
    for key in order:
        out.append((groups[key], key[5], key[6], key[7]))
    return out


def _dedupe_edge_ids(edges: List[Tuple[Dict[str, Any], int, str]]) -> List[Tuple[Dict[str, Any], int, str]]:
    """Identical ids (e.g. two trust statements naming the same principal) get a
    deterministic ``~n`` suffix ordered by digest; exact duplicates collapse."""
    groups: Dict[str, List[Tuple[Dict[str, Any], int, str]]] = {}
    for item in edges:
        groups.setdefault(item[0]["id"], []).append(item)
    out: List[Tuple[Dict[str, Any], int, str]] = []
    for eid, items in groups.items():
        unique: Dict[str, Tuple[Dict[str, Any], int, str]] = {}
        for item in items:
            unique.setdefault(item[0]["digest"], item)
        ordered = [unique[d] for d in sorted(unique)]
        for n, item in enumerate(ordered):
            if n:
                item[0]["id"] = f"{eid}~{n + 1}"
            out.append(item)
    return out


def external_base(pattern: str) -> str:
    """The node label for an unmanaged ARN: S3 object patterns collapse onto
    their bucket so ``bucket`` and ``bucket/*`` share one external node."""
    arn = parse_arn(pattern)
    if arn and arn["service"] == "s3" and "/" in arn["rest"]:
        return pattern[: pattern.index("/", len("arn:") + len(arn["partition"]) + len(":s3:::"))]
    return pattern


def merge(extracts: List[PlanExtract]) -> Dict[str, Any]:
    return Merger(extracts).run()
