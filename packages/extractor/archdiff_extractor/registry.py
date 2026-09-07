"""Resource-type registry keyed on the Terraform type.

Adding a type is a function: subclass ``TypeHandler``, set ``tf_type``, and
decorate with ``@register``. Nothing else needs to change.

Each handler sees a ``ResourceContext`` that already knows the resource's
scope, its resolved values, its ``after_unknown`` map and how to resolve
configuration references to endpoints.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional, Sequence, Type

from .edges import attach_edges, grants_edges, trust_edges
from .model import (ArnEndpoint, Endpoint, Node, NodeEndpoint, PendingEdge, UnresolvedEndpoint)
from .plan import ConfigResource, Plan, ValuesResource, split_module_path
from .policy import PolicyBody, load_policy_attribute
from .references import ReferenceResolver, ResourceRef, Target, ValueRef, constant_of
from .scope import Scope


class ResourceContext:
    """Everything a handler needs about one resource INSTANCE."""

    def __init__(self, extractor, address: str, tf_type: str, config: Optional[ConfigResource],
                 values: Optional[ValuesResource], scope: Scope, config_only: bool):
        self.extractor = extractor
        self.plan: Plan = extractor.plan
        self.resolver: ReferenceResolver = extractor.resolver
        self.address = address
        self.tf_type = tf_type
        self.config = config
        self.values: Dict[str, Any] = values.values if values else {}
        self.scope = scope
        self.config_only = config_only
        self.module_path, _ = split_module_path(address)

    # -- values / unknowns --------------------------------------------------

    def value(self, attr: str) -> Any:
        if attr in self.values and self.values[attr] is not None:
            return self.values[attr]
        has_const, const = constant_of(self.expr(attr))
        if has_const:
            return const
        return self.values.get(attr)

    def unknown(self, attr: str, *path: Any) -> bool:
        if self.config_only:
            has_const, _ = constant_of(self.expr(attr))
            return not has_const
        return self.plan.is_unknown(self.address, attr, *path)

    def configured(self, attr: str) -> bool:
        """Set in configuration, or carrying a non-null resolved value. A null
        that is not in after_unknown is ABSENT, not configured."""
        return self.expr(attr) is not None or self.values.get(attr) is not None

    def expr(self, attr: str) -> Any:
        return (self.config.expressions if self.config else {}).get(attr)

    def targets(self, attr: str) -> List[Target]:
        return self.resolver.resolve_expr(self.expr(attr), self.module_path)

    def endpoints(self, targets: Sequence[Target], hint: Optional[str] = None) -> List[Endpoint]:
        return self.extractor.endpoints_for(targets, self.scope, hint)

    def endpoint_node_type(self, ep: Endpoint) -> Optional[str]:
        return self.extractor.endpoint_node_type(ep)

    def policy(self, attr: str) -> PolicyBody:
        body = load_policy_attribute(self.plan, self.resolver, self.address, attr)
        for w in body.warnings:
            self.warn(w)
        return body

    def warn(self, message: str) -> None:
        self.extractor.warn(message)

    # -- node construction --------------------------------------------------

    def make_node(self, node_type: str, name: Optional[str], aliases: Sequence[str],
                  properties: Dict[str, Any], tracked: Sequence[str]) -> Node:
        unresolved = sorted(a for a in tracked if self.unknown(a))
        return Node(type=node_type, scope=self.scope, logical_address=self.address, name=name,
                    aliases=[a for a in aliases if a], resolution="unresolved_at_plan" if unresolved else "resolved",
                    unresolved_attributes=unresolved, properties=properties,
                    module_path=self.module_path, tf_type=self.tf_type)

    def iam_arn(self, kind: str, name: Optional[str], path: Optional[str] = "/") -> Optional[str]:
        """Predicted IAM ARN, or None when the account is unknown or the name is."""
        if not name or not self.scope.account_id:
            return None
        path = path or "/"
        return f"arn:{self.scope.partition}:iam::{self.scope.account_id}:{kind}{path}{name}"

    def digest_of(self, value: Any) -> str:
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()[:16]


class TypeHandler:
    tf_type: str = ""
    node_type: Optional[str] = None

    def build_node(self, ctx: ResourceContext) -> Optional[Node]:
        return None

    def build_edges(self, ctx: ResourceContext, node: Optional[Node]) -> List[PendingEdge]:
        return []


REGISTRY: Dict[str, TypeHandler] = {}


def register(cls: Type[TypeHandler]) -> Type[TypeHandler]:
    REGISTRY[cls.tf_type] = cls()
    return cls


def handler_for(tf_type: str) -> Optional[TypeHandler]:
    return REGISTRY.get(tf_type)


# ---------------------------------------------------------------------------
# Principals
# ---------------------------------------------------------------------------

@register
class IamRole(TypeHandler):
    tf_type = "aws_iam_role"
    node_type = "principal"

    def build_node(self, ctx):
        name = ctx.value("name") if not ctx.unknown("name") else None
        path = ctx.value("path") if not ctx.unknown("path") else "/"
        boundary = _arn_or_ref(ctx, "permissions_boundary")
        props = {"path": path or "/", "permissions_boundary": boundary}
        node = ctx.make_node("principal", name, [ctx.iam_arn("role", name, path)], props,
                             ["name", "assume_role_policy"])
        if ctx.unknown("permissions_boundary") and boundary is None and ctx.configured("permissions_boundary"):
            node.unresolved_attributes = sorted(set(node.unresolved_attributes) | {"permissions_boundary"})
            node.resolution = "unresolved_at_plan"
        _warn_missing_alias(ctx, node)
        return node

    def build_edges(self, ctx, node):
        edges = trust_edges(ctx, node, ctx.policy("assume_role_policy"))
        # Deprecated exclusive attribute, still common in the wild.
        if ctx.configured("managed_policy_arns"):
            policies = _policy_endpoints(ctx, "managed_policy_arns")
            edges += attach_edges(ctx, [NodeEndpoint(node.id)], policies, node.module_path)
        if ctx.expr("inline_policy") is not None:
            ctx.warn(f"{ctx.address}: inline_policy blocks are not modelled in v1; "
                     f"use aws_iam_role_policy")
        return edges


@register
class IamUser(TypeHandler):
    tf_type = "aws_iam_user"
    node_type = "principal"

    def build_node(self, ctx):
        name = ctx.value("name") if not ctx.unknown("name") else None
        path = ctx.value("path") if not ctx.unknown("path") else "/"
        props = {"path": path or "/", "permissions_boundary": _arn_or_ref(ctx, "permissions_boundary")}
        node = ctx.make_node("principal", name, [ctx.iam_arn("user", name, path)], props, ["name"])
        _warn_missing_alias(ctx, node)
        return node


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------

@register
class IamPolicy(TypeHandler):
    tf_type = "aws_iam_policy"
    node_type = "policy"

    def build_node(self, ctx):
        name = ctx.value("name") if not ctx.unknown("name") else None
        path = ctx.value("path") if not ctx.unknown("path") else "/"
        node = ctx.make_node("policy", name, [ctx.iam_arn("policy", name, path)],
                             {"path": path or "/"}, ["name", "policy"])
        _warn_missing_alias(ctx, node)
        return node

    def build_edges(self, ctx, node):
        return grants_edges(ctx, node, ctx.policy("policy"))


class _InlinePolicy(TypeHandler):
    node_type = "policy"
    principal_attr = "role"
    principal_hint = "role"

    def build_node(self, ctx):
        name = ctx.value("name") if not ctx.unknown("name") else None
        return ctx.make_node("policy", name, [], {"inline": True}, ["name", "policy"])

    def build_edges(self, ctx, node):
        edges = grants_edges(ctx, node, ctx.policy("policy"))
        principals = _principal_endpoints(ctx, self.principal_attr, self.principal_hint)
        edges += attach_edges(ctx, principals, [NodeEndpoint(node.id)], node.module_path)
        return edges


@register
class IamRolePolicy(_InlinePolicy):
    tf_type = "aws_iam_role_policy"


@register
class IamUserPolicy(_InlinePolicy):
    tf_type = "aws_iam_user_policy"
    principal_attr = "user"
    principal_hint = "user"


class _Attachment(TypeHandler):
    node_type = None
    principal_attr = "role"
    principal_hint = "role"

    def build_edges(self, ctx, node):
        principals = _principal_endpoints(ctx, self.principal_attr, self.principal_hint)
        policies = _policy_endpoints(ctx, "policy_arn")
        return attach_edges(ctx, principals, policies, ctx.module_path)


@register
class IamRolePolicyAttachment(_Attachment):
    tf_type = "aws_iam_role_policy_attachment"


@register
class IamUserPolicyAttachment(_Attachment):
    tf_type = "aws_iam_user_policy_attachment"
    principal_attr = "user"
    principal_hint = "user"


# ---------------------------------------------------------------------------
# Identity providers
# ---------------------------------------------------------------------------

@register
class OidcProvider(TypeHandler):
    tf_type = "aws_iam_openid_connect_provider"
    node_type = "identity_provider"

    def build_node(self, ctx):
        url = ctx.value("url") if not ctx.unknown("url") else None
        host = url.split("://", 1)[-1] if isinstance(url, str) else None
        clients = ctx.value("client_id_list") if not ctx.unknown("client_id_list") else None
        props = {"url": url, "client_id_list": sorted(clients) if isinstance(clients, list) else None}
        aliases = [ctx.iam_arn("oidc-provider", host, "/")] if host else []
        node = ctx.make_node("identity_provider", host, aliases, props, ["url"])
        _warn_missing_alias(ctx, node)
        return node


@register
class SamlProvider(TypeHandler):
    tf_type = "aws_iam_saml_provider"
    node_type = "identity_provider"

    def build_node(self, ctx):
        name = ctx.value("name") if not ctx.unknown("name") else None
        node = ctx.make_node("identity_provider", name, [ctx.iam_arn("saml-provider", name, "/")], {}, ["name"])
        _warn_missing_alias(ctx, node)
        return node


# ---------------------------------------------------------------------------
# Permission targets
# ---------------------------------------------------------------------------

@register
class KmsKey(TypeHandler):
    tf_type = "aws_kms_key"
    node_type = "resource"

    def build_node(self, ctx):
        # The key id is server-generated: the ARN is only predictable once the
        # key exists (update / no-op plans carry it in planned values).
        arn = ctx.value("arn") if not ctx.unknown("arn") else None
        props: Dict[str, Any] = {}
        if ctx.configured("policy"):
            if ctx.unknown("policy"):
                props["resource_policy"] = "unresolved"
            else:
                props["resource_policy"] = ctx.digest_of(ctx.value("policy"))
            ctx.warn(f"{ctx.address}: KMS key policy is a resource policy; not evaluated in v1 "
                     f"(digest tracked in properties.resource_policy)")
        return ctx.make_node("resource", None, [arn] if arn else [], props, ["arn"])


@register
class S3Bucket(TypeHandler):
    tf_type = "aws_s3_bucket"
    node_type = "resource"

    def build_node(self, ctx):
        bucket = ctx.value("bucket") if not ctx.unknown("bucket") else None
        arn = f"arn:{ctx.scope.partition}:s3:::{bucket}" if bucket else None
        return ctx.make_node("resource", bucket, [arn] if arn else [], {}, ["bucket"])


@register
class S3BucketPolicy(TypeHandler):
    tf_type = "aws_s3_bucket_policy"
    node_type = "policy"

    def build_node(self, ctx):
        return ctx.make_node("policy", None, [], {"resource_policy": True}, ["policy"])

    def build_edges(self, ctx, node):
        body = ctx.policy("policy")
        if not body.statements and not body.coarse_targets:
            # Body unknown and untraceable: fall back to the bucket reference
            # so the policy is at least attached to what it governs.
            body.coarse_targets = ctx.targets("bucket")
        return grants_edges(ctx, node, body, resource_policy=True)


class GenericResource(TypeHandler):
    """Fallback for any managed type referenced by a policy but not registered."""
    node_type = "resource"

    def __init__(self, tf_type: str):
        self.tf_type = tf_type

    def build_node(self, ctx):
        arn = ctx.value("arn") if not ctx.unknown("arn") else None
        name = ctx.value("name") if not ctx.unknown("name") and isinstance(ctx.value("name"), str) else None
        return ctx.make_node("resource", name, [arn] if isinstance(arn, str) else [], {}, ["arn"])


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _principal_endpoints(ctx: ResourceContext, attr: str, hint: str) -> List[Endpoint]:
    targets = ctx.targets(attr)
    eps = ctx.endpoints(targets, hint)
    if eps:
        if len(eps) > 1 and not ctx.unknown(attr):
            # Reference fans out over instances (for_each); the resolved value
            # names exactly one of them.
            eps = _filter_by_name(ctx, eps, ctx.value(attr)) or eps
        if len(eps) > 1:
            ctx.warn(f"{ctx.address}.{attr}: reference fans out to {len(eps)} instances; "
                     f"edges over-approximated")
        return eps
    value = ctx.value(attr)
    if isinstance(value, str) and not ctx.unknown(attr):
        return ctx.endpoints([ValueRef(value)], hint)
    ctx.warn(f"{ctx.address}.{attr}: unknown at plan time and not traceable to a resource")
    return [UnresolvedEndpoint(ctx.scope)]


def _policy_endpoints(ctx: ResourceContext, attr: str) -> List[Endpoint]:
    targets = ctx.targets(attr)
    eps = ctx.endpoints(targets, "policy")
    value = ctx.value(attr)
    if not ctx.unknown(attr) and value is not None:
        for v in (value if isinstance(value, list) else [value]):
            if isinstance(v, str) and v.startswith("arn:"):
                ep = ArnEndpoint(v, ctx.scope)
                if ep not in eps and not any(isinstance(e, NodeEndpoint) for e in eps):
                    eps.append(ep)
    if len(eps) > 1 and len([e for e in eps if isinstance(e, NodeEndpoint)]) > 1 and not isinstance(value, list):
        ctx.warn(f"{ctx.address}.{attr}: reference fans out to {len(eps)} instances; edges over-approximated")
    if not eps:
        ctx.warn(f"{ctx.address}.{attr}: unknown at plan time and not traceable to a resource")
        eps = [UnresolvedEndpoint(ctx.scope)]
    return eps


def _filter_by_name(ctx: ResourceContext, eps: List[Endpoint], value: Any) -> List[Endpoint]:
    if not isinstance(value, str):
        return eps
    out = []
    for ep in eps:
        if isinstance(ep, NodeEndpoint):
            node = ctx.extractor.nodes.get(ep.node_id)
            if node and (node.name == value or value in node.aliases):
                out.append(ep)
    return out


def _arn_or_ref(ctx: ResourceContext, attr: str) -> Optional[str]:
    """A known ARN string, or the address of the resource it references."""
    if not ctx.configured(attr):
        return None
    if not ctx.unknown(attr):
        v = ctx.value(attr)
        return v if isinstance(v, str) else None
    refs = [t.address for t in ctx.targets(attr) if isinstance(t, ResourceRef)]
    return refs[0] if refs else None


def _warn_missing_alias(ctx: ResourceContext, node: Node) -> None:
    if node.name and not node.aliases and not ctx.scope.account_id:
        ctx.extractor.warn_once(
            f"scope {ctx.scope.key}: account id unknown; ARN aliases cannot be predicted, so "
            f"cross-root references into this scope will not resolve "
            f"(scope source={ctx.scope.source}, confidence={ctx.scope.confidence})")
