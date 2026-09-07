"""Per-plan extraction: plan JSON -> nodes + pending edges.

Two passes over different parts of the document (verified fact 1):

1. every registered resource instance becomes a node, built from RESOLVED
   values (``planned_values`` / ``prior_state``) with ``after_unknown``
   deciding unknown-vs-absent;
2. every handler then emits edges, whose structure comes from
   ``configuration.*.expressions.<attr>.references`` and whose policy bodies
   come from the resolved values.

Cross-plan references (ARN strings) stay pending until ``merge``.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Set

from .model import (ArnEndpoint, Endpoint, ExternalEndpoint, Node, NodeEndpoint, PendingEdge,
                    PlanExtract, UnresolvedEndpoint)
from .moves import load_moves_from_dir, prefix_matches, resolve_chains
from .plan import Plan, split_module_path, strip_indexes
from .policy import POLICY_DOCUMENT_TYPE
from .references import DataRef, DeadEndRef, ReferenceResolver, ResourceRef, Target, ValueRef
from .registry import GenericResource, ResourceContext, handler_for
from .scope import Scope, ScopeResolver


class PlanExtractor:
    def __init__(self, plan: Plan, *, root_module: Optional[str] = None,
                 explicit_scopes: Optional[Dict[str, Dict[str, Any]]] = None,
                 terragrunt_working_dir: Optional[str] = None, repo_root: Optional[str] = None,
                 env: Optional[Dict[str, str]] = None, source_dir: Optional[str] = None,
                 extra_moves: Optional[List[Any]] = None):
        self.plan = plan
        self.source_dir = source_dir
        self.extra_moves = list(extra_moves or [])
        self.resolver = ReferenceResolver(plan)
        self.scope_resolver = ScopeResolver(
            plan, explicit=explicit_scopes, terragrunt_working_dir=terragrunt_working_dir,
            repo_root=repo_root, env=env)
        self.root_module = root_module or self.scope_resolver.default_root_module()
        self.scope_resolver.root_module = self.root_module
        self.nodes: Dict[str, Node] = {}
        self.edges: List[PendingEdge] = []
        self.warnings: List[str] = []
        self._warned_once: Set[str] = set()
        self._by_config_address: Dict[str, List[str]] = {}
        self._contexts: List[ResourceContext] = []

    # -- public -------------------------------------------------------------

    def run(self) -> PlanExtract:
        if self.plan.errored:
            self.warn("plan reports errored=true; resources missing from planned_values were "
                      "reconstructed from configuration and are unresolved")
        self._build_nodes()
        for ctx, handler, node in list(self._pending_edges):
            self.edges.extend(handler.build_edges(ctx, node))
        self.warnings.extend(self.scope_resolver.warnings)
        scopes = sorted({n.scope for n in self.nodes.values()}, key=lambda s: s.key)
        moves = self._moves(scopes)            # may add warnings: compute before freezing them
        return PlanExtract(nodes=dict(self.nodes), edges=list(self.edges), scopes=scopes,
                           warnings=sorted(set(self.warnings)), root_label=self.root_module,
                           moves=moves)

    # -- moved {} blocks ------------------------------------------------------

    def _moves(self, scopes: List[Scope]) -> List[Dict[str, str]]:
        raw: List[Any] = []
        if self.source_dir:
            sources = {name: (call.raw.get("source") or "")
                       for name, call in self.plan.config.module_calls.items()}
            found, w = load_moves_from_dir(self.source_dir, sources)
            raw.extend(found)
            self.warnings.extend(w)
        raw.extend(self.plan.moves())            # previous_address, when prior state exists
        raw.extend(tuple(m) for m in self.extra_moves)
        composed, w = resolve_chains(raw)
        self.warnings.extend(w)
        out: List[Dict[str, str]] = []
        for frm, to in composed:
            keys = sorted({n.scope.key for n in self.nodes.values()
                           if prefix_matches(to, n.logical_address)})
            if not keys:
                keys = [s.key for s in scopes]
                if not keys:
                    self.warn(f"moved {frm} -> {to}: no node under the target address and no "
                              f"scope in this plan; move dropped")
                    continue
                self.warn(f"moved {frm} -> {to}: no node under the target address; "
                          f"recorded for every scope in this plan")
            for key in keys:
                out.append({"scope_key": key, "from": frm, "to": to})
        return out

    def warn(self, message: str) -> None:
        self.warnings.append(message)

    def warn_once(self, message: str) -> None:
        if message not in self._warned_once:
            self._warned_once.add(message)
            self.warnings.append(message)

    # -- pass 1: nodes --------------------------------------------------------

    def _build_nodes(self) -> None:
        self._pending_edges = []
        for cfg in sorted(self.plan.config.all_resources(), key=lambda r: r.address):
            if cfg.mode != "managed":
                continue
            handler = handler_for(cfg.type)
            if handler is None:
                continue
            instances = [a for a in self.plan.instances_of(cfg.address) if a in self.plan.planned]
            config_only = False
            if not instances:
                if not self.plan.errored:
                    continue                      # count = 0 / for_each = {} : nothing to deploy
                instances = [cfg.address]
                config_only = True
            for address in instances:
                ctx = self._context(address, cfg.type, config_only)
                node = handler.build_node(ctx) if handler.node_type else None
                if node is not None:
                    self._add_node(node, cfg.address)
                self._pending_edges.append((ctx, handler, node))
        # Managed resources present in planned_values but absent from configuration
        # (should not happen; be defensive rather than silent).
        for address, vr in sorted(self.plan.planned.items()):
            if vr.mode != "managed" or self.plan.config_resource(address) is not None:
                continue
            handler = handler_for(vr.type)
            if handler is None or not handler.node_type:
                continue
            self.warn(f"{address}: present in planned_values but not in configuration")
            ctx = self._context(address, vr.type, False)
            node = handler.build_node(ctx)
            if node is not None:
                self._add_node(node, strip_indexes(address))
                self._pending_edges.append((ctx, handler, node))

    def _context(self, address: str, tf_type: str, config_only: bool) -> ResourceContext:
        cfg = self.plan.config_resource(address)
        scope = self.scope_resolver.resolve(cfg.provider_config_key if cfg else "")
        ctx = ResourceContext(self, address, tf_type, cfg, self.plan.values_for(address), scope, config_only)
        self._contexts.append(ctx)
        return ctx

    def _add_node(self, node: Node, config_address: str) -> None:
        if node.id in self.nodes:
            self.warn(f"duplicate node id within one plan: {node.id}")
            return
        self.nodes[node.id] = node
        self._by_config_address.setdefault(strip_indexes(config_address), []).append(node.id)

    # -- reference targets -> endpoints ------------------------------------

    def endpoints_for(self, targets: Sequence[Target], scope: Scope,
                      hint: Optional[str] = None) -> List[Endpoint]:
        out: List[Endpoint] = []

        def add(ep: Endpoint) -> None:
            if ep not in out:
                out.append(ep)

        for t in targets:
            if isinstance(t, ResourceRef):
                for node_id in self._resource_node_ids(t):
                    add(NodeEndpoint(node_id))
            elif isinstance(t, DataRef):
                for ep in self._data_endpoints(t, scope):
                    add(ep)
            elif isinstance(t, ValueRef):
                for ep in self._value_endpoints(t.value, scope, hint):
                    add(ep)
            elif isinstance(t, DeadEndRef):
                self.warn(f"reference through {t.ref} cannot be followed in plan JSON "
                          f"(locals are not expanded); recorded as unresolved")
                add(UnresolvedEndpoint(scope))
        return out

    def endpoint_node_type(self, ep: Endpoint) -> Optional[str]:
        if isinstance(ep, NodeEndpoint) and ep.node_id in self.nodes:
            return self.nodes[ep.node_id].type
        return None

    def _resource_node_ids(self, ref: ResourceRef) -> List[str]:
        ids = self._by_config_address.get(ref.address)
        if ids is None:
            ids = self._materialise_generic(ref.address)
        if ref.instance_key is not None:
            keyed = [i for i in ids if self.nodes[i].logical_address.endswith(f"[{ref.instance_key}]")]
            if keyed:
                ids = keyed
        if not ids:
            self.warn(f"reference to {ref.address} has no planned instances; edge dropped "
                      f"(count = 0, or the plan errored before expansion)")
        return sorted(ids)

    def _materialise_generic(self, config_address: str) -> List[str]:
        """A managed resource of an unregistered type, referenced by a policy."""
        cfg = self.plan.config_resource(config_address)
        if cfg is None or cfg.mode != "managed":
            self._by_config_address[config_address] = []
            return []
        handler = GenericResource(cfg.type)
        ids: List[str] = []
        instances = [a for a in self.plan.instances_of(cfg.address) if a in self.plan.planned]
        config_only = False
        if not instances and self.plan.errored:
            instances, config_only = [cfg.address], True
        for address in instances:
            ctx = self._context(address, cfg.type, config_only)
            node = handler.build_node(ctx)
            if node is not None:
                self._add_node(node, cfg.address)
                ids.append(node.id)
        self._by_config_address.setdefault(config_address, ids)
        return ids

    def _data_endpoints(self, ref: DataRef, scope: Scope) -> List[Endpoint]:
        _, rel = split_module_path(ref.address)
        tf_type = rel.split(".")[1]
        if tf_type == POLICY_DOCUMENT_TYPE:
            return []          # folded into the policy that references it
        out: List[Endpoint] = []
        for inst in self.plan.instances_of(ref.address) or [ref.address]:
            vr = self.plan.values_for(inst)
            arn = vr.values.get("arn") if vr else None
            if isinstance(arn, str) and not self.plan.is_unknown(inst, "arn"):
                out.append(ArnEndpoint(arn, scope))
            else:
                out.append(ExternalEndpoint(inst, scope))
        return out

    def _value_endpoints(self, value: Any, scope: Scope, hint: Optional[str]) -> List[Endpoint]:
        if isinstance(value, (list, tuple)):
            out: List[Endpoint] = []
            for v in value:
                out.extend(self._value_endpoints(v, scope, hint))
            return out
        if not isinstance(value, str) or not value:
            return []
        if value.startswith("arn:"):
            return [ArnEndpoint(value, scope)]
        if hint in ("role", "user"):
            if scope.account_id:
                return [ArnEndpoint(f"arn:{scope.partition}:iam::{scope.account_id}:{hint}/{value}", scope)]
            return [ExternalEndpoint(f"{hint}/{value}", scope)]
        return [ExternalEndpoint(value, scope)]


def extract_plan(plan: Plan, **kwargs: Any) -> PlanExtract:
    return PlanExtractor(plan, **kwargs).run()
