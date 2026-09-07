"""IAM policy semantics: statements from rendered JSON or from the structured
``statement`` blocks of ``data.aws_iam_policy_document``.

Two sources, one model:

* A rendered policy string (``aws_iam_policy.policy``, ``aws_iam_role.
  assume_role_policy``) that is KNOWN at plan time is parsed as IAM JSON.
* A policy document with ANY unknown reference has its entire ``.json``
  deferred to null (verified fact 5). The structured ``statement`` values of
  the data source are still present in ``planned_values``, with the unknown
  leaves set to null and marked in ``after_unknown``. We recover every
  statement from there and use ``configuration`` references to name the
  resource behind each unknown leaf.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, List, Optional, Sequence, Tuple

from .plan import Plan, contains_true, split_module_path
from .references import DataRef, ReferenceResolver, Target, ValueRef

POLICY_DOCUMENT_TYPE = "aws_iam_policy_document"


@dataclass(frozen=True)
class ResourceSpec:
    pattern: Optional[str]                   # None -> unknown at plan time
    refs: Tuple[Target, ...] = ()            # what the unknown value references


@dataclass(frozen=True)
class PrincipalSpec:
    kind: str                                # "AWS" | "Service" | "Federated" | "*" | other
    value: Optional[str]                     # None -> unknown at plan time
    refs: Tuple[Target, ...] = ()


@dataclass
class Statement:
    sid: Optional[str] = None
    effect: Optional[str] = None
    actions: List[str] = field(default_factory=list)
    not_action: bool = False
    resources: List[ResourceSpec] = field(default_factory=list)
    not_resource: bool = False
    principals: List[PrincipalSpec] = field(default_factory=list)
    not_principal: bool = False
    has_condition: bool = False
    unknown_fields: List[str] = field(default_factory=list)   # "actions", "effect", ...


@dataclass
class PolicyBody:
    statements: List[Statement]
    resolved: bool                       # the rendered body was known at plan time
    coarse_targets: List[Target] = field(default_factory=list)  # refs when no statements
    warnings: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Rendered IAM JSON
# ---------------------------------------------------------------------------

def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def parse_policy_json(text: str) -> Tuple[List[Statement], List[str]]:
    warnings: List[str] = []
    try:
        doc = json.loads(text)
    except (TypeError, ValueError) as exc:
        return [], [f"policy body is not valid JSON: {exc}"]
    if not isinstance(doc, dict):
        return [], ["policy body is not a JSON object"]
    statements: List[Statement] = []
    for raw in _as_list(doc.get("Statement")):
        if not isinstance(raw, dict):
            warnings.append("statement is not an object; ignored")
            continue
        stmt = Statement(sid=raw.get("Sid"), effect=raw.get("Effect"))
        if "Action" in raw:
            stmt.actions = [str(a) for a in _as_list(raw["Action"])]
        elif "NotAction" in raw:
            stmt.actions = [str(a) for a in _as_list(raw["NotAction"])]
            stmt.not_action = True
        if "Resource" in raw:
            stmt.resources = [ResourceSpec(str(r)) for r in _as_list(raw["Resource"])]
        elif "NotResource" in raw:
            stmt.resources = [ResourceSpec(str(r)) for r in _as_list(raw["NotResource"])]
            stmt.not_resource = True
        if "Principal" in raw:
            stmt.principals = _parse_principal(raw["Principal"])
        elif "NotPrincipal" in raw:
            stmt.principals = _parse_principal(raw["NotPrincipal"])
            stmt.not_principal = True
        stmt.has_condition = bool(raw.get("Condition"))
        if stmt.effect not in ("Allow", "Deny"):
            warnings.append(f"statement {stmt.sid or '<no sid>'} has invalid Effect {stmt.effect!r}")
        statements.append(stmt)
    return statements, warnings


def _parse_principal(raw: Any) -> List[PrincipalSpec]:
    if raw == "*":
        return [PrincipalSpec("*", "*")]
    out: List[PrincipalSpec] = []
    if isinstance(raw, dict):
        for kind, values in raw.items():
            for v in _as_list(values):
                out.append(PrincipalSpec(str(kind), str(v)))
    elif isinstance(raw, str):
        out.append(PrincipalSpec("AWS", raw))
    return out


# ---------------------------------------------------------------------------
# Structured statements from data.aws_iam_policy_document
# ---------------------------------------------------------------------------

def parse_structured_statements(values_statements: Sequence[Any], after_unknown: Any,
                                config_statements: Any, resolver: ReferenceResolver,
                                module_path: str) -> Tuple[List[Statement], List[str]]:
    """``after_unknown`` is the ``statement`` subtree of the change's after_unknown;
    ``config_statements`` the ``statement`` subtree of the config expressions."""
    warnings: List[str] = []
    out: List[Statement] = []
    cfg_list = config_statements if isinstance(config_statements, list) else []
    if cfg_list and len(cfg_list) != len(values_statements):
        warnings.append("policy document statement blocks do not align with configuration "
                        "(dynamic blocks?); references resolved per document, not per statement")
        merged = {"references": []}
        for c in cfg_list:
            merged["references"].extend(_all_refs(c))
        cfg_list = [merged] * len(values_statements)
    for i, raw in enumerate(values_statements):
        raw = raw or {}
        au = after_unknown[i] if isinstance(after_unknown, list) and i < len(after_unknown) else (
            True if after_unknown is True else {})
        cfg = cfg_list[i] if i < len(cfg_list) else {}
        stmt = Statement(sid=raw.get("sid") or None, effect=raw.get("effect") or "Allow")

        def unknown(fld: str) -> bool:
            if au is True:
                return True
            return isinstance(au, dict) and contains_true(au.get(fld))

        if unknown("effect"):
            stmt.effect = None
            stmt.unknown_fields.append("effect")

        actions = raw.get("actions")
        not_actions = raw.get("not_actions")
        if not_actions:
            stmt.not_action = True
            stmt.actions = [a for a in not_actions if a is not None]
            if unknown("not_actions") or any(a is None for a in not_actions):
                stmt.unknown_fields.append("actions")
        else:
            stmt.actions = [a for a in (actions or []) if a is not None]
            if unknown("actions") or any(a is None for a in (actions or [])):
                stmt.unknown_fields.append("actions")

        resources = raw.get("resources")
        not_resources = raw.get("not_resources")
        if not_resources:
            stmt.not_resource = True
            stmt.resources = _resource_specs(not_resources, unknown("not_resources"),
                                             cfg.get("not_resources") if isinstance(cfg, dict) else None,
                                             resolver, module_path)
        else:
            stmt.resources = _resource_specs(resources or [], unknown("resources"),
                                             cfg.get("resources") if isinstance(cfg, dict) else None,
                                             resolver, module_path)

        principals = raw.get("principals") or []
        not_principals = raw.get("not_principals") or []
        cfg_principals = cfg.get("principals") if isinstance(cfg, dict) else None
        cfg_not_principals = cfg.get("not_principals") if isinstance(cfg, dict) else None
        au_principals = au.get("principals") if isinstance(au, dict) else au
        au_not_principals = au.get("not_principals") if isinstance(au, dict) else au
        if not_principals:
            stmt.not_principal = True
            stmt.principals = _principal_specs(not_principals, au_not_principals, cfg_not_principals,
                                               resolver, module_path)
        else:
            stmt.principals = _principal_specs(principals, au_principals, cfg_principals,
                                               resolver, module_path)

        cond = raw.get("condition") or []
        stmt.has_condition = bool(cond) or unknown("condition")
        out.append(stmt)
    return out, warnings


def _all_refs(expr: Any) -> List[str]:
    from .references import collect_references
    return collect_references(expr)


def _resource_specs(values: Sequence[Any], any_unknown: bool, cfg_expr: Any,
                    resolver: ReferenceResolver, module_path: str) -> List[ResourceSpec]:
    specs = [ResourceSpec(str(v)) for v in values if v is not None]
    if any_unknown or any(v is None for v in values):
        refs = tuple(resolver.resolve_expr(cfg_expr, module_path)) if cfg_expr is not None else ()
        specs.append(ResourceSpec(None, refs))
    return specs


def _principal_specs(blocks: Sequence[Any], au_blocks: Any, cfg_blocks: Any,
                     resolver: ReferenceResolver, module_path: str) -> List[PrincipalSpec]:
    out: List[PrincipalSpec] = []
    cfg_list = cfg_blocks if isinstance(cfg_blocks, list) else []
    for i, block in enumerate(blocks):
        block = block or {}
        kind = block.get("type") or "AWS"
        identifiers = block.get("identifiers") or []
        au = au_blocks[i] if isinstance(au_blocks, list) and i < len(au_blocks) else (
            True if au_blocks is True else {})
        unknown = au is True or (isinstance(au, dict) and contains_true(au.get("identifiers")))
        for ident in identifiers:
            if ident is not None:
                out.append(PrincipalSpec(kind, str(ident)))
        if unknown or any(v is None for v in identifiers):
            cfg = cfg_list[i] if i < len(cfg_list) and isinstance(cfg_list[i], dict) else {}
            refs = tuple(resolver.resolve_expr(cfg.get("identifiers"), module_path)) if cfg else ()
            out.append(PrincipalSpec(kind, None, refs))
    return out


# ---------------------------------------------------------------------------
# Loading a policy body for an attribute of a resource
# ---------------------------------------------------------------------------

def load_policy_document(plan: Plan, resolver: ReferenceResolver, address: str,
                         _depth: int = 0) -> PolicyBody:
    """Statements of ``data.aws_iam_policy_document.X`` (instance address)."""
    warnings: List[str] = []
    if _depth > 4:
        return PolicyBody([], False, [], ["policy document nesting too deep"])
    vr = plan.values_for(address)
    if vr is None:
        return PolicyBody([], False, [], [f"{address}: not present in planned_values or prior_state"])
    values = vr.values
    module_path, _ = split_module_path(address)
    cfg = plan.config_resource(address)
    exprs = cfg.expressions if cfg else {}

    # Fully resolved (prior_state) -> the rendered JSON is authoritative.
    if isinstance(values.get("json"), str) and not plan.is_unknown(address, "json"):
        statements, w = parse_policy_json(values["json"])
        return PolicyBody(statements, True, [], [f"{address}: {x}" for x in w])

    statements: List[Statement] = []
    coarse: List[Target] = []

    # Composition: source docs first, then this document's blocks, then overrides by sid.
    for attr in ("source_json", "source_policy_documents"):
        s, c, w = _composed_docs(plan, resolver, address, values, exprs, attr, module_path, _depth)
        statements.extend(s)
        coarse.extend(c)
        warnings.extend(w)

    own, w = parse_structured_statements(
        values.get("statement") or [],
        (plan.after_unknown_for(address) or {}).get("statement") if isinstance(plan.after_unknown_for(address), dict) else plan.after_unknown_for(address),
        exprs.get("statement"), resolver, module_path)
    statements.extend(own)
    warnings.extend(f"{address}: {x}" for x in w)

    for attr in ("override_json", "override_policy_documents"):
        s, c, w = _composed_docs(plan, resolver, address, values, exprs, attr, module_path, _depth)
        for stmt in s:
            if stmt.sid:
                statements = [x for x in statements if x.sid != stmt.sid]
            statements.append(stmt)
        coarse.extend(c)
        warnings.extend(w)

    return PolicyBody(statements, False, coarse, warnings)


def _composed_docs(plan, resolver, address, values, exprs, attr, module_path, depth):
    statements: List[Statement] = []
    coarse: List[Target] = []
    warnings: List[str] = []
    value = values.get(attr)
    if value is None and not plan.is_unknown(address, attr):
        return statements, coarse, warnings
    if not plan.is_unknown(address, attr):
        for text in _as_list(value):
            if isinstance(text, str):
                s, w = parse_policy_json(text)
                statements.extend(s)
                warnings.extend(f"{address}.{attr}: {x}" for x in w)
        return statements, coarse, warnings
    # Unknown: follow references to other policy documents.
    for target in resolver.resolve_expr(exprs.get(attr), module_path):
        if isinstance(target, DataRef) and target.address.split(".")[1] == POLICY_DOCUMENT_TYPE:
            for inst in plan.instances_of(target.address) or [target.address]:
                body = load_policy_document(plan, resolver, inst, depth + 1)
                statements.extend(body.statements)
                coarse.extend(body.coarse_targets)
                warnings.extend(body.warnings)
        else:
            coarse.append(target)
    if not statements and not coarse:
        warnings.append(f"{address}.{attr}: unknown at plan time and not traceable to a document")
    return statements, coarse, warnings


def load_policy_attribute(plan: Plan, resolver: ReferenceResolver, address: str,
                          attr: str) -> PolicyBody:
    """Policy body for ``<address>.<attr>`` using the hybrid strategy."""
    vr = plan.values_for(address)
    values = vr.values if vr else {}
    module_path, _ = split_module_path(address)
    cfg = plan.config_resource(address)
    expr = (cfg.expressions if cfg else {}).get(attr)
    value = values.get(attr)

    if isinstance(value, str) and not plan.is_unknown(address, attr):
        statements, w = parse_policy_json(value)
        return PolicyBody(statements, True, [], [f"{address}.{attr}: {x}" for x in w])

    statements: List[Statement] = []
    coarse: List[Target] = []
    warnings: List[str] = []
    if not plan.is_unknown(address, attr) and value is None and expr is None:
        # Genuinely absent (e.g. a role without assume_role_policy in config -- invalid
        # for AWS but possible in a partial plan).
        return PolicyBody([], True, [], [])

    for target in resolver.resolve_expr(expr, module_path):
        if isinstance(target, DataRef) and target.address.split(".")[1] == POLICY_DOCUMENT_TYPE:
            for inst in plan.instances_of(target.address) or [target.address]:
                body = load_policy_document(plan, resolver, inst)
                statements.extend(body.statements)
                coarse.extend(body.coarse_targets)
                warnings.extend(body.warnings)
        elif isinstance(target, ValueRef) and isinstance(target.value, str):
            s, w = parse_policy_json(target.value)
            if s:
                statements.extend(s)
                warnings.extend(f"{address}.{attr}: {x}" for x in w)
            else:
                coarse.append(target)
        else:
            coarse.append(target)
    return PolicyBody(statements, False, coarse, warnings)
