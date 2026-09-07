"""Edge semantics: policy statements -> ``grants``; trust policies ->
``can_assume`` / ``trusted_by``; attachments -> ``attaches``.

DIRECTION of ``can_assume``: the trust policy on role B naming principal A
produces the edge A -> B (source can assume target). ``trusted_by`` goes the
other way round: role -> identity provider (the federated entry point).
"""
from __future__ import annotations

import hashlib
import json
from typing import Dict, List, Optional, Sequence, Tuple

from .model import (AnonymousEndpoint, ArnEndpoint, Endpoint, ExternalEndpoint, Node,
                    NodeEndpoint, PendingEdge, ServiceEndpoint, UnresolvedEndpoint,
                    WildcardEndpoint)
from .policy import PolicyBody, Statement
from .scope import ACCOUNT_RE

STS_FEDERATED_ACTIONS = ("sts:AssumeRoleWithWebIdentity", "sts:AssumeRoleWithSAML")


def statement_key(stmt: Statement) -> str:
    """``sid`` when present, else a content hash. Never a positional index --
    reordering statements MUST produce an empty diff (SCHEMA.md section 8)."""
    if stmt.sid:
        return stmt.sid
    material = {
        "effect": stmt.effect,
        "actions": sorted(stmt.actions),
        "not_action": stmt.not_action,
        "resources": sorted(r.pattern or f"ref:{sorted(repr(x) for x in r.refs)}" for r in stmt.resources),
        "not_resource": stmt.not_resource,
        "principals": sorted(f"{p.kind}:{p.value}" for p in stmt.principals),
        "condition": stmt.has_condition,
    }
    h = hashlib.sha256(json.dumps(material, sort_keys=True).encode("utf-8")).hexdigest()[:8]
    return f"_{h}"


def _unevaluated_for(stmt: Statement, body_unresolved: bool, resource_policy: bool) -> List[str]:
    out: List[str] = []
    if stmt.has_condition:
        out.append("condition")
    if stmt.not_action or stmt.not_resource or stmt.not_principal:
        out.append("not_action")
    if body_unresolved or stmt.unknown_fields:
        out.append("unresolved_policy_body")
    if resource_policy:
        out.append("resource_policy")
    return sorted(set(out))


# ---------------------------------------------------------------------------
# grants
# ---------------------------------------------------------------------------

def grants_edges(ctx, policy: Node, body: PolicyBody, *, resource_policy: bool = False) -> List[PendingEdge]:
    anchor = NodeEndpoint(policy.id)
    edges: List[PendingEdge] = []

    if not body.statements:
        # The whole body is deferred: keep the structural edges from references.
        targets = ctx.endpoints(body.coarse_targets)
        if not targets and (body.coarse_targets or not body.resolved):
            targets = [UnresolvedEndpoint(policy.scope)]
            ctx.warn(f"{policy.logical_address}: policy body unknown at plan time and not "
                     f"traceable to any resource; edge target recorded as unresolved")
        for t in targets:
            edges.append(PendingEdge(
                type="grants", source=anchor, target=t, anchor=anchor, kind="stmt",
                key="unresolved", effect=None, actions=[], resource_patterns=[], sid=None,
                resolution="unresolved_at_plan",
                unevaluated=sorted({"unresolved_policy_body"} | ({"resource_policy"} if resource_policy else set())),
                module_path=policy.module_path))
        return edges

    for stmt in body.statements:
        key = statement_key(stmt)
        actions = list(stmt.actions)
        if stmt.not_action:
            actions = [f"NotAction:{a}" for a in actions]
        per_target: Dict[Endpoint, List[str]] = {}
        order: List[Endpoint] = []
        unresolved_any = False

        def add(ep: Endpoint, pattern: Optional[str]):
            if ep not in per_target:
                per_target[ep] = []
                order.append(ep)
            if pattern is not None and pattern not in per_target[ep]:
                per_target[ep].append(pattern)

        for spec in stmt.resources:
            if spec.pattern is None:
                unresolved_any = True
                eps = ctx.endpoints(list(spec.refs))
                if not eps:
                    eps = [UnresolvedEndpoint(policy.scope)]
                    ctx.warn(f"{policy.logical_address} statement {key}: resource unknown at plan "
                             f"time and not traceable to any resource")
                for ep in eps:
                    add(ep, None)
                continue
            pattern = spec.pattern
            label = f"NotResource:{pattern}" if stmt.not_resource else pattern
            if stmt.not_resource:
                add(WildcardEndpoint(policy.scope), label)
            elif pattern == "*":
                add(WildcardEndpoint(policy.scope), "*")
            else:
                add(ArnEndpoint(pattern, policy.scope), label)

        if not order:
            add(UnresolvedEndpoint(policy.scope), None)
            ctx.warn(f"{policy.logical_address} statement {key}: no Resource element")

        unevaluated = _unevaluated_for(stmt, unresolved_any or bool(stmt.unknown_fields), resource_policy)
        resolution = "unresolved_at_plan" if (unresolved_any or stmt.unknown_fields) else "resolved"
        for ep in order:
            edges.append(PendingEdge(
                type="grants", source=anchor, target=ep, anchor=anchor, kind="stmt", key=key,
                effect=stmt.effect, actions=actions, resource_patterns=per_target[ep],
                sid=stmt.sid, resolution=resolution, unevaluated=unevaluated,
                module_path=policy.module_path))
    return edges


# ---------------------------------------------------------------------------
# trust policies
# ---------------------------------------------------------------------------

def principal_endpoint(ctx, spec, scope) -> Tuple[List[Endpoint], str]:
    """(endpoints, edge type) for one principal of a trust statement."""
    kind = spec.kind
    value = spec.value
    if value is None:
        eps = ctx.endpoints(list(spec.refs))
        if not eps:
            eps = [UnresolvedEndpoint(scope)]
        edge_type = "trusted_by" if kind == "Federated" else "can_assume"
        return eps, edge_type
    if kind == "*" or value == "*":
        return [AnonymousEndpoint(scope)], "can_assume"
    if kind == "AWS":
        if ACCOUNT_RE.match(value):
            value = f"arn:{scope.partition}:iam::{value}:root"
        return [ArnEndpoint(value, scope)], "can_assume"
    if kind == "Service":
        return [ServiceEndpoint(value, scope)], "can_assume"
    if kind == "Federated":
        if value.startswith("arn:"):
            return [ArnEndpoint(value, scope)], "trusted_by"
        return [ServiceEndpoint(value, scope)], "trusted_by"
    return [ExternalEndpoint(f"{kind}:{value}", scope)], "can_assume"


def trust_edges(ctx, role: Node, body: PolicyBody) -> List[PendingEdge]:
    anchor = NodeEndpoint(role.id)
    edges: List[PendingEdge] = []

    if not body.statements:
        targets = ctx.endpoints(body.coarse_targets)
        if not targets and (body.coarse_targets or not body.resolved):
            targets = [UnresolvedEndpoint(role.scope)]
            ctx.warn(f"{role.logical_address}: trust policy unknown at plan time and not "
                     f"traceable to any principal; edge source recorded as unresolved")
        for t in targets:
            edge_type = "trusted_by" if ctx.endpoint_node_type(t) == "identity_provider" else "can_assume"
            edges.append(_trust_edge(anchor, t, edge_type, None, [], None, "unresolved_at_plan",
                                     ["unresolved_policy_body"], role.module_path))
        return edges

    for stmt in body.statements:
        unevaluated = _unevaluated_for(stmt, bool(stmt.unknown_fields), False)
        resolution = "unresolved_at_plan" if stmt.unknown_fields else "resolved"
        if stmt.not_principal:
            ctx.warn(f"{role.logical_address}: NotPrincipal in trust policy; recorded as anonymous "
                     f"principal with unevaluated=not_action")
            specs = [type(stmt.principals[0])("*", "*")] if stmt.principals else []
        else:
            specs = stmt.principals
        if not specs:
            ctx.warn(f"{role.logical_address} statement {statement_key(stmt)}: no Principal element")
            edges.append(_trust_edge(anchor, UnresolvedEndpoint(role.scope), "can_assume", stmt.effect,
                                     stmt.actions, stmt.sid, "unresolved_at_plan",
                                     sorted(set(unevaluated) | {"unresolved_policy_body"}), role.module_path))
            continue
        for spec in specs:
            eps, edge_type = principal_endpoint(ctx, spec, role.scope)
            stmt_res = resolution
            stmt_unev = unevaluated
            if spec.value is None:
                stmt_res = "unresolved_at_plan"
                stmt_unev = sorted(set(unevaluated) | {"unresolved_policy_body"})
            for ep in eps:
                et = edge_type
                if spec.value is None:
                    et = "trusted_by" if ctx.endpoint_node_type(ep) == "identity_provider" else "can_assume"
                edges.append(_trust_edge(anchor, ep, et, stmt.effect, stmt.actions, stmt.sid,
                                         stmt_res, stmt_unev, role.module_path))
    return edges


def _trust_edge(role: NodeEndpoint, other: Endpoint, edge_type: str, effect, actions, sid,
                resolution, unevaluated, module_path) -> PendingEdge:
    if edge_type == "trusted_by":
        source, target = role, other          # role -> identity provider
    else:
        source, target = other, role          # principal -> role  (A can assume B)
    return PendingEdge(type=edge_type, source=source, target=target, anchor=role, kind="trust",
                       effect=effect, actions=list(actions), resource_patterns=[], sid=sid,
                       resolution=resolution, unevaluated=list(unevaluated), module_path=module_path)


# ---------------------------------------------------------------------------
# attachments
# ---------------------------------------------------------------------------

def attach_edges(ctx, principals: Sequence[Endpoint], policies: Sequence[Endpoint],
                 module_path: str, resolution: str = "resolved") -> List[PendingEdge]:
    edges: List[PendingEdge] = []
    for p in principals:
        if not isinstance(p, NodeEndpoint):
            # A principal we do not manage cannot anchor an edge id; we still
            # keep the edge, anchored on the policy instead.
            for pol in policies:
                anchor = pol if isinstance(pol, NodeEndpoint) else None
                if anchor is None:
                    ctx.warn("attachment between two unmanaged endpoints; dropped from graph "
                             "(neither side is a repo-managed node)")
                    continue
                edges.append(PendingEdge(type="attaches", source=p, target=pol, anchor=anchor,
                                         kind="attach", resolution=resolution, module_path=module_path))
            continue
        for pol in policies:
            edges.append(PendingEdge(type="attaches", source=p, target=pol, anchor=p, kind="attach",
                                     resolution=resolution, module_path=module_path))
    return edges
