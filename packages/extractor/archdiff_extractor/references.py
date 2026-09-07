"""Resolution of ``expressions.<attr>.references`` to concrete targets.

References arrive in pairs (``["aws_iam_policy.x.arn", "aws_iam_policy.x"]``);
the resource-level address is the one we keep. ``var.*`` inside a child module
is followed through the parent's ``module_calls[...].expressions`` and
``module.x.output`` through the child's ``outputs`` so a role ARN threaded
through a module boundary still resolves to the resource that produces it.

Locals are NOT expanded in plan JSON, so a reference through ``local.*`` is a
dead end and the caller must treat the value as unresolvable.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, Optional, Set, Tuple, Union

from .plan import ConfigModule, Plan, _split_dotted, join_module, module_parent_chain, strip_indexes

IGNORED_PREFIXES = ("local.", "each.", "count.", "path.", "terraform.", "self.")


@dataclass(frozen=True)
class ResourceRef:
    address: str                    # full config address, no instance keys
    instance_key: Optional[str]     # '"a"' / '0' when the reference is instance-specific


@dataclass(frozen=True)
class DataRef:
    address: str                    # full config address of a data source


@dataclass(frozen=True)
class ValueRef:
    value: Any                      # a resolved variable value (string, list, ...)


@dataclass(frozen=True)
class DeadEndRef:
    ref: str                        # local.*, unknown module output, ...


Target = Union[ResourceRef, DataRef, ValueRef, DeadEndRef]


def collapse_pairs(refs: List[str]) -> List[str]:
    """Drop references that extend another reference (``x.arn`` when ``x`` is present)."""
    out = []
    for r in refs:
        if any(s != r and not _is_bare_module(s) and (r.startswith(s + ".") or r.startswith(s + "[")) for s in refs):
            continue
        if _is_bare_module(r) and any(s != r and s.startswith(r + ".") for s in refs):
            continue          # "module.x" alone says nothing; "module.x.output" does
        if r not in out:
            out.append(r)
    return out


def _is_bare_module(ref: str) -> bool:
    parts = _split_dotted(strip_indexes(ref))
    return len(parts) == 2 and parts[0] == "module"


def collect_references(expr: Any) -> List[str]:
    """All ``references`` anywhere inside an expression tree, in document order."""
    out: List[str] = []
    if isinstance(expr, dict):
        for r in expr.get("references", []) or []:
            if r not in out:
                out.append(r)
        for k, v in expr.items():
            if k == "references":
                continue
            for r in collect_references(v):
                if r not in out:
                    out.append(r)
    elif isinstance(expr, list):
        for v in expr:
            for r in collect_references(v):
                if r not in out:
                    out.append(r)
    return out


def constant_of(expr: Any) -> Tuple[bool, Any]:
    """(has_constant, value) for an expression object."""
    if isinstance(expr, dict) and "constant_value" in expr:
        return True, expr["constant_value"]
    return False, None


def _parse_address(ref: str) -> Tuple[str, Optional[str]]:
    """``module.m.aws_iam_role.r["a"]`` -> (``module.m.aws_iam_role.r``, ``"a"``)."""
    parts = _split_dotted(ref)
    key = None
    last = parts[-1]
    if "[" in last and last.endswith("]"):
        key = last[last.index("[") + 1:-1]
    return strip_indexes(ref), key


class ReferenceResolver:
    def __init__(self, plan: Plan):
        self.plan = plan

    def resolve_expr(self, expr: Any, module_path: str) -> List[Target]:
        """Resolve every reference inside ``expr`` evaluated in ``module_path``."""
        out: List[Target] = []
        for ref in collapse_pairs(collect_references(expr)):
            for t in self.resolve_ref(ref, module_path, set()):
                if t not in out:
                    out.append(t)
        return out

    def resolve_ref(self, ref: str, module_path: str, seen: Set[Tuple[str, str]]) -> List[Target]:
        if (ref, module_path) in seen:
            return []
        seen = seen | {(ref, module_path)}
        if ref.startswith(IGNORED_PREFIXES):
            return [DeadEndRef(ref)]
        if ref.startswith("var."):
            return self._resolve_var(ref[4:].split(".")[0].split("[")[0], module_path, seen)
        if ref.startswith("module."):
            return self._resolve_module_output(ref, module_path, seen)
        if ref.startswith("data."):
            addr, _ = _parse_address(ref)
            return [DataRef(join_module(module_path, addr))]
        addr, key = _parse_address(ref)
        # A bare traversal like "aws_iam_role.r.name" without its pair: keep
        # only the first two components as the resource address.
        parts = _split_dotted(addr)
        if len(parts) >= 2:
            addr = ".".join(parts[:2])
        return [ResourceRef(join_module(module_path, addr), key)]

    # -- variables ----------------------------------------------------------

    def _resolve_var(self, name: str, module_path: str, seen) -> List[Target]:
        if not module_path:
            if name in self.plan.variables:
                return [ValueRef(_freeze(self.plan.variables[name]))]
            default = (self.plan.config.variables.get(name) or {}).get("default")
            if default is not None:
                return [ValueRef(_freeze(default))]
            return [DeadEndRef(f"var.{name}")]
        parent_path = module_parent_chain(module_path)[1]
        parent = self.plan.config.find_module(parent_path)
        call_name = _split_dotted(strip_indexes(module_path))[-1]
        if parent is None or call_name not in parent.module_calls:
            return [DeadEndRef(f"var.{name}")]
        call = parent.module_calls[call_name]
        expr = call.expressions.get(name)
        if expr is None:
            default = (call.module.variables.get(name) or {}).get("default")
            if default is not None:
                return [ValueRef(_freeze(default))]
            return [DeadEndRef(f"var.{name}")]
        has_const, value = constant_of(expr)
        if has_const:
            return [ValueRef(_freeze(value))]
        out: List[Target] = []
        for r in collapse_pairs(collect_references(expr)):
            out.extend(self.resolve_ref(r, parent_path, seen))
        return out or [DeadEndRef(f"var.{name}")]

    # -- module outputs -----------------------------------------------------

    def _resolve_module_output(self, ref: str, module_path: str, seen) -> List[Target]:
        parts = _split_dotted(ref)
        if len(parts) < 3:
            return [DeadEndRef(ref)]          # "module.x" alone carries no attribute
        call_name = strip_indexes(parts[1])
        child_path = join_module(module_path, f"module.{call_name}")
        here = self.plan.config.find_module(module_path)
        if here is None or call_name not in here.module_calls:
            return [DeadEndRef(ref)]
        child = here.module_calls[call_name].module
        output = child.outputs.get(parts[2])
        if output is None:
            return [DeadEndRef(ref)]
        expr = output.get("expression") or {}
        has_const, value = constant_of(expr)
        if has_const:
            return [ValueRef(_freeze(value))]
        out: List[Target] = []
        for r in collapse_pairs(collect_references(expr)):
            out.extend(self.resolve_ref(r, child_path, seen))
        return out or [DeadEndRef(ref)]


def _freeze(value: Any) -> Any:
    """Make variable values hashable so Targets can be deduplicated."""
    if isinstance(value, list):
        return tuple(_freeze(v) for v in value)
    if isinstance(value, dict):
        return tuple(sorted((k, _freeze(v)) for k, v in value.items()))
    return value


def module_of(config: ConfigModule, module_path: str) -> Optional[ConfigModule]:
    return config.find_module(module_path)
