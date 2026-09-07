"""Intermediate graph model shared by extraction and merge.

Nodes are final as soon as they are built (their ids are known: scope key +
logical address). Edges are *pending* until merge, because their endpoints
may be ARN strings that only resolve once every plan's alias index is known.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

from .canonical import node_id
from .scope import Scope

NODE_TYPES = ("principal", "policy", "resource", "identity_provider", "external", "wildcard")
EDGE_TYPES = ("attaches", "can_assume", "trusted_by", "grants")
RESOLUTIONS = ("resolved", "unresolved_at_plan", "external")
UNEVALUATED = ("condition", "unresolved_policy_body", "not_action", "resource_policy")

WILDCARD_ADDRESS = "wildcard.all"
UNRESOLVED_ADDRESS = "external.unresolved"


@dataclass
class Node:
    type: str
    scope: Scope
    logical_address: str
    name: Optional[str] = None
    aliases: List[str] = field(default_factory=list)
    resolution: str = "resolved"
    unresolved_attributes: List[str] = field(default_factory=list)
    properties: Dict[str, Any] = field(default_factory=dict)
    module_path: str = ""          # for the module rollup; not persisted
    tf_type: Optional[str] = None  # not persisted

    @property
    def id(self) -> str:
        return node_id(self.scope.key, self.logical_address)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "scope": self.scope.to_dict(),
            "logical_address": self.logical_address,
            "name": self.name,
            "aliases": sorted(set(self.aliases)),
            "resolution": self.resolution,
            "unresolved_attributes": sorted(set(self.unresolved_attributes)),
            "properties": self.properties,
        }


# ---------------------------------------------------------------------------
# Endpoints: what an edge end refers to before merge-time resolution
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class NodeEndpoint:
    """A node that exists in the plan being extracted."""
    node_id: str


@dataclass(frozen=True)
class ArnEndpoint:
    """An ARN or ARN glob. Resolved through the alias index; otherwise external."""
    pattern: str
    scope: Scope


@dataclass(frozen=True)
class WildcardEndpoint:
    """``Resource: "*"``."""
    scope: Scope


@dataclass(frozen=True)
class ServiceEndpoint:
    """``Principal: {Service: ...}`` or a non-ARN federated provider."""
    name: str
    scope: Scope


@dataclass(frozen=True)
class AnonymousEndpoint:
    """``Principal: "*"``."""
    scope: Scope


@dataclass(frozen=True)
class UnresolvedEndpoint:
    """We know an edge exists but cannot determine the other end."""
    scope: Scope


@dataclass(frozen=True)
class ExternalEndpoint:
    """Something outside the repo with a stable label (e.g. a data source)."""
    label: str
    scope: Scope
    alias: Optional[str] = None


Endpoint = Union[NodeEndpoint, ArnEndpoint, WildcardEndpoint, ServiceEndpoint,
                 AnonymousEndpoint, UnresolvedEndpoint, ExternalEndpoint]


@dataclass
class PendingEdge:
    type: str
    source: Endpoint
    target: Endpoint
    anchor: NodeEndpoint          # the node whose id prefixes the edge id
    kind: str                     # "attach" | "trust" | "stmt"
    key: Optional[str] = None     # statement key for kind == "stmt"
    effect: Optional[str] = None
    actions: List[str] = field(default_factory=list)
    resource_patterns: List[str] = field(default_factory=list)
    sid: Optional[str] = None
    resolution: str = "resolved"
    unevaluated: List[str] = field(default_factory=list)
    module_path: str = ""


@dataclass
class PlanExtract:
    """Everything one plan contributes, before cross-plan resolution."""
    nodes: Dict[str, Node]
    edges: List[PendingEdge]
    scopes: List[Scope]
    warnings: List[str]
    root_label: Optional[str]
    moves: List[Any] = field(default_factory=list)
