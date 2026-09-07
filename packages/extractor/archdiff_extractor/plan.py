"""Plan JSON model.

Reads the three *different* parts of an OpenTofu/Terraform plan JSON that the
extractor needs, each walked recursively through ``child_modules``:

* ``planned_values``   - resolved values of managed resources (and deferred
                         data sources) as they will exist after apply.
* ``prior_state``      - where FULLY resolved data sources live. They are NOT
                         in ``planned_values``.
* ``configuration``    - the structural layer: ``expressions.<attr>.references``
                         and ``provider_config_key`` per resource.
* ``resource_changes`` - ``change.after_unknown`` is the explicit map of
                         deferred attributes. It is the only way to tell
                         "unknown" from "absent".

Nothing in this module interprets resource semantics.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Address helpers
# ---------------------------------------------------------------------------

_INDEX_RE = re.compile(r'\[(?:"(?:[^"\\]|\\.)*"|[^\]]*)\]')


def strip_indexes(address: str) -> str:
    """``module.m["a"].aws_iam_role.r[0]`` -> ``module.m.aws_iam_role.r``."""
    return _INDEX_RE.sub("", address)


def split_module_path(address: str) -> Tuple[str, str]:
    """Split a full address into (module path, resource-relative address).

    ``module.a["x"].module.b.aws_iam_role.r`` -> (``module.a["x"].module.b``,
    ``aws_iam_role.r``). Root resources return ``""`` for the module path.
    """
    parts = _split_dotted(address)
    i = 0
    mod: List[str] = []
    while i + 1 < len(parts) and parts[i].startswith("module"):
        mod.append(parts[i])
        mod.append(parts[i + 1])
        i += 2
    return ".".join(mod), ".".join(parts[i:])


def _split_dotted(address: str) -> List[str]:
    """Split on dots that are not inside ``[...]``."""
    out: List[str] = []
    buf = []
    depth = 0
    for ch in address:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        if ch == "." and depth == 0:
            out.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    out.append("".join(buf))
    return out


def join_module(module_path: str, relative: str) -> str:
    return f"{module_path}.{relative}" if module_path else relative


def module_parent_chain(module_path: str) -> List[str]:
    """``module.a.module.b`` -> [``module.a.module.b``, ``module.a``, ``""``]."""
    chain = [module_path]
    while module_path:
        parts = _split_dotted(module_path)
        module_path = ".".join(parts[:-2])
        chain.append(module_path)
    return chain


# ---------------------------------------------------------------------------
# after_unknown helpers
# ---------------------------------------------------------------------------

def contains_true(obj: Any) -> bool:
    if obj is True:
        return True
    if isinstance(obj, dict):
        return any(contains_true(v) for v in obj.values())
    if isinstance(obj, list):
        return any(contains_true(v) for v in obj)
    return False


def unknown_at(after_unknown: Any, *path: Any) -> bool:
    """True if the attribute at ``path`` is (wholly or partially) unknown.

    ``after_unknown`` mirrors the value structure with ``true`` leaves. A
    ``true`` at any ancestor means everything below is unknown. A missing key
    means known/absent -- never guess.
    """
    cur = after_unknown
    for p in path:
        if cur is True:
            return True
        if isinstance(cur, dict):
            if p not in cur:
                return False
            cur = cur[p]
        elif isinstance(cur, list):
            if not isinstance(p, int) or p >= len(cur):
                return False
            cur = cur[p]
        else:
            return False
    return contains_true(cur)


# ---------------------------------------------------------------------------
# Configuration layer
# ---------------------------------------------------------------------------

@dataclass
class ConfigResource:
    address: str            # full address incl. module path, no instance keys
    module_path: str        # "" for root
    mode: str               # "managed" | "data"
    type: str
    name: str
    provider_config_key: str
    expressions: Dict[str, Any]
    raw: Dict[str, Any]


@dataclass
class ConfigModule:
    path: str                                  # "" for root
    resources: Dict[str, ConfigResource]       # keyed by RELATIVE address
    module_calls: Dict[str, "ModuleCall"]
    outputs: Dict[str, Dict[str, Any]]         # name -> {"expression": {...}}
    variables: Dict[str, Dict[str, Any]]

    def all_resources(self) -> Iterator[ConfigResource]:
        for r in self.resources.values():
            yield r
        for call in self.module_calls.values():
            yield from call.module.all_resources()

    def find_module(self, module_path: str) -> Optional["ConfigModule"]:
        if strip_indexes(module_path) == strip_indexes(self.path):
            return self
        for call in self.module_calls.values():
            if strip_indexes(module_path).startswith(strip_indexes(call.module.path)):
                found = call.module.find_module(module_path)
                if found is not None:
                    return found
        return None


@dataclass
class ModuleCall:
    name: str
    expressions: Dict[str, Any]     # variable name -> expression (in parent ctx)
    module: ConfigModule
    raw: Dict[str, Any]


def _parse_config_module(raw: Dict[str, Any], path: str) -> ConfigModule:
    resources: Dict[str, ConfigResource] = {}
    for r in raw.get("resources", []) or []:
        rel = r["address"]
        resources[rel] = ConfigResource(
            address=join_module(path, rel),
            module_path=path,
            mode=r.get("mode", "managed"),
            type=r["type"],
            name=r["name"],
            provider_config_key=r.get("provider_config_key", ""),
            expressions=r.get("expressions", {}) or {},
            raw=r,
        )
    calls: Dict[str, ModuleCall] = {}
    for name, call in (raw.get("module_calls", {}) or {}).items():
        child_path = join_module(path, f"module.{name}")
        child = _parse_config_module(call.get("module", {}) or {}, child_path)
        calls[name] = ModuleCall(name=name, expressions=call.get("expressions", {}) or {},
                                 module=child, raw=call)
    return ConfigModule(path=path, resources=resources, module_calls=calls,
                        outputs=raw.get("outputs", {}) or {},
                        variables=raw.get("variables", {}) or {})


# ---------------------------------------------------------------------------
# Values layer (planned_values / prior_state)
# ---------------------------------------------------------------------------

@dataclass
class ValuesResource:
    address: str
    mode: str
    type: str
    name: str
    values: Dict[str, Any]
    raw: Dict[str, Any]


def _walk_values_module(mod: Dict[str, Any]) -> Iterator[ValuesResource]:
    for r in mod.get("resources", []) or []:
        yield ValuesResource(address=r["address"], mode=r.get("mode", "managed"),
                             type=r["type"], name=r["name"],
                             values=r.get("values", {}) or {}, raw=r)
    for child in mod.get("child_modules", []) or []:
        yield from _walk_values_module(child)


# ---------------------------------------------------------------------------
# The plan
# ---------------------------------------------------------------------------

@dataclass
class ResourceChange:
    address: str
    actions: List[str]
    after_unknown: Any
    previous_address: Optional[str]
    raw: Dict[str, Any]


@dataclass
class Plan:
    doc: Dict[str, Any]
    variables: Dict[str, Any] = field(default_factory=dict)
    planned: Dict[str, ValuesResource] = field(default_factory=dict)
    prior: Dict[str, ValuesResource] = field(default_factory=dict)
    changes: Dict[str, ResourceChange] = field(default_factory=dict)
    config: ConfigModule = field(default_factory=lambda: _parse_config_module({}, ""))
    provider_config: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    errored: bool = False
    _config_index: Dict[str, ConfigResource] = field(default_factory=dict, repr=False)
    _instance_index: Dict[str, List[str]] = field(default_factory=dict, repr=False)

    # -- construction -------------------------------------------------------

    @classmethod
    def from_dict(cls, doc: Dict[str, Any]) -> "Plan":
        plan = cls(doc=doc)
        plan.variables = {k: (v or {}).get("value") for k, v in (doc.get("variables") or {}).items()}
        pv = (doc.get("planned_values") or {}).get("root_module") or {}
        plan.planned = {r.address: r for r in _walk_values_module(pv)}
        ps = ((doc.get("prior_state") or {}).get("values") or {}).get("root_module") or {}
        plan.prior = {r.address: r for r in _walk_values_module(ps)}
        for rc in doc.get("resource_changes") or []:
            ch = rc.get("change") or {}
            plan.changes[rc["address"]] = ResourceChange(
                address=rc["address"], actions=list(ch.get("actions") or []),
                after_unknown=ch.get("after_unknown", {}),
                previous_address=rc.get("previous_address"), raw=rc)
        cfg = doc.get("configuration") or {}
        plan.config = _parse_config_module(cfg.get("root_module") or {}, "")
        plan.provider_config = cfg.get("provider_config") or {}
        plan.errored = bool(doc.get("errored", False))
        plan._config_index = {r.address: r for r in plan.config.all_resources()}
        for addr in list(plan.planned) + [a for a in plan.prior if a not in plan.planned]:
            plan._instance_index.setdefault(strip_indexes(addr), []).append(addr)
        for addrs in plan._instance_index.values():
            addrs.sort()
        return plan

    @classmethod
    def load(cls, path: str) -> "Plan":
        with open(path, "r", encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))

    # -- lookups ------------------------------------------------------------

    def config_resource(self, address: str) -> Optional[ConfigResource]:
        """Look up by full address; instance keys are ignored."""
        return self._config_index.get(strip_indexes(address))

    def instances_of(self, config_address: str) -> List[str]:
        """Instance addresses (planned or prior) of a config-level address."""
        return list(self._instance_index.get(strip_indexes(config_address), []))

    def values_for(self, address: str) -> Optional[ValuesResource]:
        """planned_values first, then prior_state (resolved data sources)."""
        if address in self.planned:
            return self.planned[address]
        return self.prior.get(address)

    def after_unknown_for(self, address: str) -> Any:
        ch = self.changes.get(address)
        return ch.after_unknown if ch else {}

    def is_unknown(self, address: str, *path: Any) -> bool:
        return unknown_at(self.after_unknown_for(address), *path)

    def moves(self) -> List[Tuple[str, str]]:
        """(previous_address, address) pairs declared via ``moved {}`` blocks."""
        return sorted((c.previous_address, c.address)
                      for c in self.changes.values() if c.previous_address)
