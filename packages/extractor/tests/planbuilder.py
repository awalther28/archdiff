"""Tiny builder for synthetic plan JSON documents shaped like real
``tofu show -json`` output (see tests/fixtures for the real thing)."""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from archdiff_extractor.extract import extract_plan
from archdiff_extractor.merge import merge
from archdiff_extractor.plan import Plan


def const(value: Any) -> Dict[str, Any]:
    return {"constant_value": value}


def ref(*refs: str) -> Dict[str, Any]:
    return {"references": list(refs)}


def pair(address: str, attr: str) -> Dict[str, Any]:
    """The reference pair Terraform emits for ``address.attr``."""
    return ref(f"{address}.{attr}", address)


def trust(principal: Dict[str, Any], action: str = "sts:AssumeRole", condition=None,
          effect: str = "Allow") -> str:
    stmt: Dict[str, Any] = {"Effect": effect, "Principal": principal, "Action": action}
    if condition:
        stmt["Condition"] = condition
    return json.dumps({"Version": "2012-10-17", "Statement": [stmt]})


def policy(*statements: Dict[str, Any]) -> str:
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


class PlanBuilder:
    def __init__(self, variables: Optional[Dict[str, Any]] = None, errored: bool = False):
        self.variables = variables or {}
        self.errored = errored
        self.providers: Dict[str, Dict[str, Any]] = {}
        self.planned: Dict[str, List[Dict[str, Any]]] = {"": []}
        self.prior: Dict[str, List[Dict[str, Any]]] = {"": []}
        self.changes: List[Dict[str, Any]] = []
        self.config: Dict[str, Dict[str, Any]] = {"": {"resources": [], "module_calls": {}, "outputs": {}, "variables": {}}}

    # -- providers ----------------------------------------------------------

    def provider(self, key: str = "aws", *, region: Any = "us-east-1", **exprs: Any) -> "PlanBuilder":
        name = key.split(":")[-1].split(".")[0]
        entry: Dict[str, Any] = {"name": name, "full_name": f"registry.opentofu.org/hashicorp/{name}",
                                 "expressions": {}}
        if "." in key.split(":")[-1]:
            entry["alias"] = key.split(":")[-1].split(".", 1)[1]
        if ":" in key:
            entry["module_address"] = key.split(":")[0]
        if region is not None:
            entry["expressions"]["region"] = region if isinstance(region, dict) else const(region)
        for k, v in exprs.items():
            entry["expressions"][k] = v
        self.providers[key] = entry
        return self

    # -- modules --------------------------------------------------------------

    def module(self, path: str, *, call_expressions: Optional[Dict[str, Any]] = None,
               outputs: Optional[Dict[str, Any]] = None) -> "PlanBuilder":
        """Declare ``module.x`` (one level) with its call expressions and outputs."""
        self.config[path] = {"resources": [], "module_calls": {}, "outputs": outputs or {},
                             "variables": {}, "_call": call_expressions or {}}
        self.planned.setdefault(path, [])
        self.prior.setdefault(path, [])
        return self

    # -- resources ------------------------------------------------------------

    def resource(self, address: str, tf_type: str, values: Optional[Dict[str, Any]] = None,
                 unknown: Optional[Dict[str, Any]] = None, expressions: Optional[Dict[str, Any]] = None,
                 provider_key: str = "aws", mode: str = "managed", planned: bool = True,
                 prior: bool = False, config: bool = True, instance_of: Optional[str] = None,
                 actions: Optional[List[str]] = None) -> "PlanBuilder":
        module_path, rel = _split(address)
        name = rel.split(".")[-1].split("[")[0]
        vals = values or {}
        if config:
            cfg_addr = instance_of or address
            _, cfg_rel = _split(cfg_addr)
            if not any(r["address"] == cfg_rel for r in self.config[module_path]["resources"]):
                self.config[module_path]["resources"].append({
                    "address": cfg_rel, "mode": mode, "type": tf_type,
                    "name": cfg_rel.split(".")[-1].split("[")[0],
                    "provider_config_key": provider_key, "expressions": expressions or {},
                    "schema_version": 0})
        entry = {"address": address, "mode": mode, "type": tf_type, "name": name,
                 "provider_name": "registry.opentofu.org/hashicorp/aws", "schema_version": 0,
                 "values": vals, "sensitive_values": {}}
        if planned:
            self.planned[module_path].append(entry)
        if prior:
            self.prior[module_path].append(entry)
        if planned or unknown is not None:
            self.changes.append({"address": address, "mode": mode, "type": tf_type, "name": name,
                                 "provider_name": "registry.opentofu.org/hashicorp/aws",
                                 "change": {"actions": actions or (["read"] if mode == "data" else ["create"]),
                                            "before": None, "after": vals,
                                            "after_unknown": unknown or {},
                                            "before_sensitive": False, "after_sensitive": {}}})
        return self

    def moved(self, previous: str, address: str) -> "PlanBuilder":
        for ch in self.changes:
            if ch["address"] == address:
                ch["previous_address"] = previous
        return self

    # -- output ---------------------------------------------------------------

    def build(self) -> Dict[str, Any]:
        def values_tree(store: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
            root: Dict[str, Any] = {"resources": list(store.get("", []))}
            children = []
            for path, resources in store.items():
                if path:
                    children.append({"address": path, "resources": resources})
            if children:
                root["child_modules"] = children
            return root

        root_cfg = {"resources": self.config[""]["resources"], "module_calls": {},
                    "outputs": self.config[""]["outputs"],
                    "variables": {k: {"type": "string"} for k in self.variables}}
        for path, cfg in self.config.items():
            if not path:
                continue
            name = path.split(".")[-1]
            root_cfg["module_calls"][name] = {
                "source": f"./modules/{name}", "expressions": cfg["_call"],
                "module": {"resources": cfg["resources"], "module_calls": {},
                           "outputs": cfg["outputs"], "variables": {}}}
        doc: Dict[str, Any] = {
            "format_version": "1.2",
            "terraform_version": "1.12.6",
            "planned_values": {"root_module": values_tree(self.planned)},
            "resource_changes": self.changes,
            "configuration": {"provider_config": self.providers, "root_module": root_cfg},
            "timestamp": "2026-01-01T00:00:00Z",
            "errored": self.errored,
        }
        if self.variables:
            doc["variables"] = {k: {"value": v} for k, v in self.variables.items()}
        if any(self.prior.values()):
            doc["prior_state"] = {"format_version": "1.0", "terraform_version": "1.12.6",
                                  "values": {"root_module": values_tree(self.prior)}}
        return doc

    def plan(self) -> Plan:
        return Plan.from_dict(json.loads(json.dumps(self.build())))


def _split(address: str):
    parts = address.split(".")
    if parts[0] == "module":
        return ".".join(parts[:2]), ".".join(parts[2:])
    return "", address


def graph_of(*builders: PlanBuilder, roots: Optional[List[Optional[str]]] = None,
             **kwargs: Any) -> Dict[str, Any]:
    extracts = []
    for i, b in enumerate(builders):
        root = roots[i] if roots else None
        extracts.append(extract_plan(b.plan(), root_module=root, **kwargs))
    return merge(extracts)


def edge_index(graph: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {e["id"]: e for e in graph["edges"]}


def node_index(graph: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {n["id"]: n for n in graph["nodes"]}


def edges_of(graph: Dict[str, Any], **match: Any) -> List[Dict[str, Any]]:
    out = []
    for e in graph["edges"]:
        if all(e.get(k) == v for k, v in match.items()):
            out.append(e)
    return out
