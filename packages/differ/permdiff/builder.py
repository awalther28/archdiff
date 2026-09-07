"""Small builder for schema-conformant Permission Graph v1 documents.

Used by the test-suite and by ``bench/synth.py``.  It is the *only* producer
of graphs inside this package and it uses ``permdiff.canonical`` for every
digest, so a graph it builds is exactly what SCHEMA.md section 5 prescribes
(``permdiff verify`` confirms this for every generated graph in the tests).
It is not the extractor and knows nothing about Terraform.
"""
import copy
from typing import Dict, List, Optional

from .address import module_key_of_address
from .canonical import edge_digest, module_digest, node_digest, node_id


def scope(account: str, region: str = "us-east-1", root_module: Optional[str] = None,
          source: str = "provider_config", confidence: str = "high") -> dict:
    return {"key": f"aws:{account}:{region}", "partition": "aws", "account_id": account,
            "region": region, "source": source, "confidence": confidence,
            "root_module": root_module}


class GraphBuilder:
    def __init__(self, extractor_version: str = "1", tool_version: str = "0.1.0") -> None:
        self.nodes: Dict[str, dict] = {}
        self.edges: Dict[str, dict] = {}
        self.scopes: Dict[str, dict] = {}
        self.extractor_version = extractor_version
        self.tool_version = tool_version
        self.module_paths: List[str] = []   # explicit module paths (parents auto-added)

    # --- nodes -----------------------------------------------------------
    def node(self, sc: dict, address: str, typ: str, name: Optional[str] = None,
             aliases: Optional[List[str]] = None, resolution: str = "resolved",
             unresolved: Optional[List[str]] = None, props: Optional[dict] = None) -> str:
        self.scopes.setdefault(sc["key"], sc)
        nid = node_id(sc["key"], address)
        n = {"id": nid, "type": typ, "scope": sc, "logical_address": address, "name": name,
             "aliases": list(aliases or []), "resolution": resolution,
             "unresolved_attributes": list(unresolved or []), "properties": props or {}}
        n["digest"] = node_digest(n)
        self.nodes[nid] = n
        return nid

    def principal(self, sc: dict, address: str, name: Optional[str] = None) -> str:
        name = name or address.split(".")[-1]
        return self.node(sc, address, "principal", name,
                         [f"arn:aws:iam::{sc['account_id']}:role/{name}"])

    def policy(self, sc: dict, address: str, name: Optional[str] = None) -> str:
        name = name or address.split(".")[-1]
        return self.node(sc, address, "policy", name,
                         [f"arn:aws:iam::{sc['account_id']}:policy/{name}"])

    def resource(self, sc: dict, address: str, name: Optional[str] = None,
                 arn: Optional[str] = None) -> str:
        return self.node(sc, address, "resource", name, [arn] if arn else [])

    def wildcard(self, sc: dict, address: str = "wildcard.all") -> str:
        return self.node(sc, address, "wildcard")

    def external(self, sc: dict, address: str, arn: str) -> str:
        return self.node(sc, address, "external", None, [arn], "external")

    # --- edges -----------------------------------------------------------
    def edge(self, eid: str, typ: str, source: str, target: str, effect: Optional[str] = None,
             actions: Optional[List[str]] = None, resource_patterns: Optional[List[str]] = None,
             sid: Optional[str] = None, resolution: str = "resolved",
             unevaluated: Optional[List[str]] = None) -> str:
        e = {"id": eid, "type": typ, "source": source, "target": target, "effect": effect,
             "actions": list(actions or []), "resource_patterns": list(resource_patterns or []),
             "sid": sid, "resolution": resolution, "unevaluated": list(unevaluated or [])}
        e["digest"] = edge_digest(e)
        self.edges[eid] = e
        return eid

    def attaches(self, principal: str, policy: str, unevaluated=None) -> str:
        return self.edge(f"{principal}#attach:{policy.rsplit('.', 1)[-1]}", "attaches",
                         principal, policy, unevaluated=unevaluated)

    def grants(self, policy: str, target: str, actions: List[str], patterns: List[str],
               sid: str, effect: str = "Allow", unevaluated=None, resolution="resolved") -> str:
        return self.edge(f"{policy}#stmt:{sid}", "grants", policy, target, effect, actions,
                         patterns, sid, resolution, unevaluated)

    def can_assume(self, source: str, target: str, unevaluated=None, effect="Allow",
                   qualifier: Optional[str] = None) -> str:
        q = qualifier or source.rsplit(".", 1)[-1]
        return self.edge(f"{target}#trust:{q}", "can_assume", source, target, effect,
                         ["sts:AssumeRole"], unevaluated=unevaluated)

    def trusted_by(self, principal: str, idp: str) -> str:
        return self.edge(f"{principal}#trust", "trusted_by", principal, idp, "Allow",
                         ["sts:AssumeRoleWithWebIdentity"])

    # --- document --------------------------------------------------------
    def remove_node(self, nid: str) -> None:
        del self.nodes[nid]

    def remove_edge(self, eid: str) -> None:
        del self.edges[eid]

    def build(self, warnings: Optional[List[str]] = None) -> dict:
        """Assemble the document with a module tree derived from addresses:
        every ``module.a.module.b`` prefix becomes a nested module under
        ``root``; rollup digests are computed bottom-up per section 5."""
        by_key: Dict[tuple, dict] = {(): {"nodes": [], "edges": [], "children": {}}}

        def ensure(key: tuple) -> dict:
            if key not in by_key:
                by_key[key] = {"nodes": [], "edges": [], "children": {}}
                parent = ensure(key[:-1])
                parent["children"][key[-1]] = by_key[key]
            return by_key[key]

        for nid, n in self.nodes.items():
            ensure(module_key_of_address(n["logical_address"]))["nodes"].append(n["digest"])
        for eid, e in self.edges.items():
            owner = eid.split("#", 1)[0]
            ref = self.nodes.get(owner) or self.nodes.get(e["source"]) or self.nodes.get(e["target"])
            key = module_key_of_address(ref["logical_address"]) if ref else ()
            ensure(key)["edges"].append(e["digest"])
        for p in self.module_paths:
            ensure(tuple(p.split(".")))

        def emit(key: tuple, entry: dict) -> dict:
            children = [emit(key + (name,), c) for name, c in sorted(entry["children"].items())]
            d = module_digest(entry["nodes"], entry["edges"], [c["digest"] for c in children])
            path = "root" if not key else ".".join(f"module.{k}" for k in key)
            m = {"path": path, "digest": d}
            if children:
                m["children"] = children
            return m

        root = emit((), by_key[()])
        return {
            "schema_version": "1.0",
            "generated_by": {"tool_version": self.tool_version,
                             "extractor_version": self.extractor_version},
            "scopes": [self.scopes[k] for k in sorted(self.scopes)],
            "modules": [root],
            "nodes": [self.nodes[k] for k in sorted(self.nodes)],
            "edges": [self.edges[k] for k in sorted(self.edges)],
            "warnings": list(warnings or []),
        }

    def clone(self) -> "GraphBuilder":
        return copy.deepcopy(self)
