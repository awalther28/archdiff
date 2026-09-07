"""In-memory model of a Permission Graph v1 document.

Only what the differ needs: id-indexed nodes/edges, the module tree, the
module-membership buckets used by the Merkle prune, and lazy adjacency indexes
used by the semantic layer.  Inputs are assumed to conform to
``schema/graph.schema.json``; the light validation here exists so that a
malformed document fails loudly instead of producing a misleading diff.
"""
import json
from collections import defaultdict
from typing import Dict, Iterable, List, Optional, Tuple

from .address import (ModuleKey, ROOT_KEY, UNASSIGNED_KEY, module_key_of_address,
                      module_key_of_path)
from .canonical import module_digest

SCHEMA_VERSION = "1.0"


class GraphError(ValueError):
    pass


class ModuleNode:
    __slots__ = ("path", "digest", "key", "children", "subtree_size")

    def __init__(self, path: str, digest: str, key: ModuleKey):
        self.path = path
        self.digest = digest
        self.key = key
        self.children: List["ModuleNode"] = []
        self.subtree_size = 1


class Graph:
    def __init__(self, doc: dict, name: str = "graph"):
        self.name = name
        self.doc = doc
        if not isinstance(doc, dict):
            raise GraphError(f"{name}: document is not a JSON object")
        if doc.get("schema_version") != SCHEMA_VERSION:
            raise GraphError(f"{name}: schema_version {doc.get('schema_version')!r} "
                             f"is not {SCHEMA_VERSION!r}")
        gb = doc.get("generated_by") or {}
        self.extractor_version: Optional[str] = gb.get("extractor_version")
        self.tool_version: Optional[str] = gb.get("tool_version")

        self.nodes: Dict[str, dict] = {}
        for n in doc.get("nodes", []):
            nid = n["id"]
            if nid in self.nodes:
                raise GraphError(f"{name}: duplicate node id {nid}")
            self.nodes[nid] = n
        self.edges: Dict[str, dict] = {}
        # Per-node incidence lists (edge ids), built in the same pass that
        # indexes the edges: this is the only whole-graph adjacency work and it
        # happens at load time, so every later lookup is O(degree).
        self._out_ids: Dict[str, List[str]] = {}
        self._in_ids: Dict[str, List[str]] = {}
        self.unevaluated_edge_count = 0
        out_ids, in_ids = self._out_ids, self._in_ids
        for e in doc.get("edges", []):
            eid = e["id"]
            if eid in self.edges:
                raise GraphError(f"{name}: duplicate edge id {eid}")
            self.edges[eid] = e
            src, tgt = e["source"], e["target"]
            lst = out_ids.get(src)
            if lst is None:
                out_ids[src] = [eid]
            else:
                lst.append(eid)
            lst = in_ids.get(tgt)
            if lst is None:
                in_ids[tgt] = [eid]
            else:
                lst.append(eid)
            if e.get("unevaluated"):
                self.unevaluated_edge_count += 1

        # --- module tree -------------------------------------------------
        self.module_roots: List[ModuleNode] = []
        self.modules: Dict[ModuleKey, ModuleNode] = {}
        self.merkle_ok = True
        self.merkle_reason = ""
        dup: List[str] = []

        def build(m: dict) -> ModuleNode:
            node = ModuleNode(m["path"], m["digest"], module_key_of_path(m["path"]))
            if node.key in self.modules:
                dup.append(m["path"])
            self.modules[node.key] = node
            for c in m.get("children", []) or []:
                child = build(c)
                node.children.append(child)
                node.subtree_size += child.subtree_size
            return node

        for m in doc.get("modules", []) or []:
            self.module_roots.append(build(m))
        if dup:
            self.merkle_ok = False
            self.merkle_reason = "ambiguous module paths: " + ", ".join(sorted(dup)[:5])
        if not self.modules:
            self.merkle_ok = False
            self.merkle_reason = "document has no module tree"
        self.modules_total = sum(r.subtree_size for r in self.module_roots)

        self._node_buckets: Optional[Dict[ModuleKey, List[str]]] = None
        self._edge_buckets: Optional[Dict[ModuleKey, List[str]]] = None

    # --- digests ---------------------------------------------------------
    @property
    def graph_digest(self) -> str:
        """Root-of-tree digest.  One root module -> its digest (this is what the
        golden fixture uses).  Several roots -> a rollup over them.  No module
        tree -> rollup over every node and edge (still deterministic)."""
        if len(self.module_roots) == 1:
            return self.module_roots[0].digest
        if self.module_roots:
            return module_digest([], [], [r.digest for r in self.module_roots])
        return module_digest([n["digest"] for n in self.nodes.values()],
                             [e["digest"] for e in self.edges.values()], [])

    # --- module membership ----------------------------------------------
    def module_key_of_node(self, nid: str) -> ModuleKey:
        node = self.nodes[nid]
        key = module_key_of_address(node["logical_address"])
        return key if key in self.modules else UNASSIGNED_KEY

    def module_key_of_edge(self, eid: str) -> ModuleKey:
        """An edge lives with the Terraform resource whose configuration produced
        it.  Edge ids in the fixtures are ``{node_id}#{qualifier}``, so that node
        is tried first; otherwise the source node; otherwise unassigned."""
        edge = self.edges[eid]
        owner = eid.split("#", 1)[0]
        if owner in self.nodes:
            return self.module_key_of_node(owner)
        if edge["source"] in self.nodes:
            return self.module_key_of_node(edge["source"])
        if edge["target"] in self.nodes:
            return self.module_key_of_node(edge["target"])
        return UNASSIGNED_KEY

    def _bucket(self) -> None:
        nb: Dict[ModuleKey, List[str]] = defaultdict(list)
        eb: Dict[ModuleKey, List[str]] = defaultdict(list)
        for nid in self.nodes:
            nb[self.module_key_of_node(nid)].append(nid)
        for eid in self.edges:
            eb[self.module_key_of_edge(eid)].append(eid)
        self._node_buckets, self._edge_buckets = dict(nb), dict(eb)

    def node_bucket(self, key: ModuleKey) -> List[str]:
        if self._node_buckets is None:
            self._bucket()
        return self._node_buckets.get(key, [])  # type: ignore[union-attr]

    def edge_bucket(self, key: ModuleKey) -> List[str]:
        if self._edge_buckets is None:
            self._bucket()
        return self._edge_buckets.get(key, [])  # type: ignore[union-attr]

    def recompute_module_digest(self, key: ModuleKey,
                                child_digests: Iterable[str]) -> str:
        """Re-hash one module from its bucketed contents (SCHEMA.md section 5)."""
        return module_digest([self.nodes[i]["digest"] for i in self.node_bucket(key)],
                             [self.edges[i]["digest"] for i in self.edge_bucket(key)],
                             list(child_digests))

    # --- adjacency (semantic layer) --------------------------------------
    def out_edges(self, nid: str, etype: str) -> List[dict]:
        """Edges of one type leaving ``nid``, sorted by id.  O(out-degree)."""
        ids = self._out_ids.get(nid)
        if not ids:
            return []
        edges = self.edges
        return sorted((edges[i] for i in ids if edges[i]["type"] == etype), key=lambda e: e["id"])

    def in_edges(self, nid: str, etype: str) -> List[dict]:
        ids = self._in_ids.get(nid)
        if not ids:
            return []
        edges = self.edges
        return sorted((edges[i] for i in ids if edges[i]["type"] == etype), key=lambda e: e["id"])

    def incident_edges(self, nid: str) -> List[dict]:
        ids = set(self._out_ids.get(nid, ())) | set(self._in_ids.get(nid, ()))
        return [self.edges[i] for i in sorted(ids)]

    def has_out_edges(self, nid: str, etype: str) -> bool:
        edges = self.edges
        return any(edges[i]["type"] == etype for i in self._out_ids.get(nid, ()))

    def scope_key(self, nid: str) -> str:
        n = self.nodes.get(nid)
        if n is not None:
            return n["scope"]["key"]
        return nid.split("/", 1)[0]

    def display_name(self, nid: str) -> str:
        n = self.nodes.get(nid)
        if n is None:
            return nid
        return n.get("name") or n["logical_address"]

    def node_type(self, nid: str) -> Optional[str]:
        n = self.nodes.get(nid)
        return n["type"] if n else None


def load_graph(path: str, name: Optional[str] = None) -> Graph:
    with open(path, "r", encoding="utf-8") as f:
        return Graph(json.load(f), name=name or path)


def check_compatible(base: Graph, head: Graph) -> Tuple[bool, str]:
    """SCHEMA.md section 6: an extractor version mismatch must be reported, not
    rendered as a code change."""
    if base.extractor_version != head.extractor_version:
        return False, (f"extractor_version mismatch: base={base.extractor_version!r} "
                       f"head={head.extractor_version!r}")
    return True, ""
