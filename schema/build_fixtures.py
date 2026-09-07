"""Generates the golden fixtures with real digests. Re-run after any schema edit."""
import json, copy, os
from canonical import node_digest, edge_digest, module_digest, node_id

MGMT = {"key": "aws:999988887777:us-east-1", "partition": "aws",
        "account_id": "999988887777", "region": "us-east-1",
        "source": "provider_config", "confidence": "high", "root_module": "live/mgmt/iam"}
SUB = {"key": "aws:111122223333:us-east-1", "partition": "aws",
       "account_id": "111122223333", "region": "us-east-1",
       "source": "provider_config", "confidence": "high", "root_module": "live/prod/iam"}


def n(scope, addr, typ, name=None, aliases=None, resolution="resolved",
      unresolved=None, props=None):
    node = {"id": node_id(scope["key"], addr), "type": typ, "scope": scope,
            "logical_address": addr, "name": name, "aliases": aliases or [],
            "resolution": resolution, "unresolved_attributes": unresolved or [],
            "properties": props or {}}
    node["digest"] = node_digest(node)
    return node


def e(eid, typ, src, tgt, **kw):
    edge = {"id": eid, "type": typ, "source": src, "target": tgt,
            "effect": kw.get("effect"), "actions": kw.get("actions", []),
            "resource_patterns": kw.get("resource_patterns", []),
            "sid": kw.get("sid"), "resolution": kw.get("resolution", "resolved"),
            "unevaluated": kw.get("unevaluated", [])}
    edge["digest"] = edge_digest(edge)
    return edge


def build(star: bool):
    """star=False -> base branch. star=True -> the two-character PR."""
    M, S = MGMT["key"], SUB["key"]
    nodes = [
        n(MGMT, "aws_iam_openid_connect_provider.github", "identity_provider",
          "token.actions.githubusercontent.com",
          ["arn:aws:iam::999988887777:oidc-provider/token.actions.githubusercontent.com"]),
        n(MGMT, "aws_iam_role.gha", "principal", "gha-role",
          ["arn:aws:iam::999988887777:role/gha-role"]),
        n(MGMT, "aws_iam_role.mgmt_deploy", "principal", "mgmt-deploy",
          ["arn:aws:iam::999988887777:role/mgmt-deploy"]),
        n(SUB, "aws_iam_role.app_admin", "principal", "app-admin",
          ["arn:aws:iam::111122223333:role/app-admin"]),
        n(SUB, "aws_iam_policy.app_data", "policy", "app-data-policy",
          ["arn:aws:iam::111122223333:policy/app-data-policy"]),
        # deliberately poisoned: body references aws_kms_key.main.arn
        n(SUB, "aws_iam_policy.kms_use", "policy", "kms-use-policy",
          [], "unresolved_at_plan", ["policy"]),
        n(SUB, "aws_kms_key.main", "resource", None, [], "unresolved_at_plan", ["arn"]),
        n(SUB, "aws_s3_bucket.data", "resource", "app-data",
          ["arn:aws:s3:::app-data"]),
        n(SUB, "external.audit_role", "external", None,
          ["arn:aws:iam::555566667777:role/third-party-audit"], "external"),
        n(SUB, "wildcard.all", "wildcard", None),
    ]
    edges = [
        e(f"{M}/aws_iam_role.gha#trust", "trusted_by",
          node_id(M, "aws_iam_role.gha"),
          node_id(M, "aws_iam_openid_connect_provider.github"), effect="Allow",
          actions=["sts:AssumeRoleWithWebIdentity"]),
        e(f"{M}/aws_iam_role.mgmt_deploy#trust:gha", "can_assume",
          node_id(M, "aws_iam_role.gha"), node_id(M, "aws_iam_role.mgmt_deploy"),
          effect="Allow", actions=["sts:AssumeRole"]),
        # the cross-scope hop -- invisible to either plan in isolation
        e(f"{S}/aws_iam_role.app_admin#trust:mgmt", "can_assume",
          node_id(M, "aws_iam_role.mgmt_deploy"), node_id(S, "aws_iam_role.app_admin"),
          effect="Allow", actions=["sts:AssumeRole"]),
        # third party with a Condition -> must never count as confirmed
        e(f"{S}/aws_iam_role.app_admin#trust:audit", "can_assume",
          node_id(S, "external.audit_role"), node_id(S, "aws_iam_role.app_admin"),
          effect="Allow", actions=["sts:AssumeRole"], unevaluated=["condition"]),
        e(f"{S}/aws_iam_role.app_admin#attach:app_data", "attaches",
          node_id(S, "aws_iam_role.app_admin"), node_id(S, "aws_iam_policy.app_data")),
        e(f"{S}/aws_iam_role.app_admin#attach:kms_use", "attaches",
          node_id(S, "aws_iam_role.app_admin"), node_id(S, "aws_iam_policy.kms_use")),
        e(f"{S}/aws_iam_policy.kms_use#stmt:unresolved", "grants",
          node_id(S, "aws_iam_policy.kms_use"), node_id(S, "aws_kms_key.main"),
          effect="Allow", actions=[], resolution="unresolved_at_plan",
          unevaluated=["unresolved_policy_body"]),
    ]
    if star:
        edges.append(e(f"{S}/aws_iam_policy.app_data#stmt:ReadData", "grants",
                       node_id(S, "aws_iam_policy.app_data"), node_id(S, "wildcard.all"),
                       effect="Allow", actions=["s3:*"], resource_patterns=["*"],
                       sid="ReadData"))
    else:
        edges.append(e(f"{S}/aws_iam_policy.app_data#stmt:ReadData", "grants",
                       node_id(S, "aws_iam_policy.app_data"), node_id(S, "aws_s3_bucket.data"),
                       effect="Allow", actions=["s3:GetObject", "s3:ListBucket"],
                       resource_patterns=["arn:aws:s3:::app-data/*"], sid="ReadData"))

    nodes.sort(key=lambda x: x["id"])
    edges.sort(key=lambda x: x["id"])
    root = module_digest([x["digest"] for x in nodes], [x["digest"] for x in edges], [])
    return {"schema_version": "1.0",
            "generated_by": {"tool_version": "0.1.0", "extractor_version": "1"},
            "scopes": [MGMT, SUB],
            "modules": [{"path": "root", "digest": root, "children": []}],
            "nodes": nodes, "edges": edges, "warnings": []}


def structural_diff(base, head):
    def index(items): return {i["id"]: i for i in items}
    out = {}
    for kind in ("nodes", "edges"):
        b, h = index(base[kind]), index(head[kind])
        added = sorted(set(h) - set(b))
        removed = sorted(set(b) - set(h))
        changed = sorted(i for i in (set(b) & set(h)) if b[i]["digest"] != h[i]["digest"])
        out[kind] = {
            "added": added, "removed": removed,
            "changed": [{"id": i, "before_digest": b[i]["digest"],
                         "after_digest": h[i]["digest"]} for i in changed]}
    return out


base, head = build(False), build(True)
diff = {
    "schema_version": "1.0",
    "base": {"ref": "main", "graph_digest": base["modules"][0]["digest"]},
    "head": {"ref": "pr-1-star-policy", "graph_digest": head["modules"][0]["digest"]},
    "structural": structural_diff(base, head),
    "semantic": {
        "capabilities": {
            "added": [{"principal": node_id(SUB["key"], "aws_iam_role.app_admin"),
                       "actions": ["s3:*"], "resource_patterns": ["*"],
                       "confidence": "confirmed"}],
            "removed": [{"principal": node_id(SUB["key"], "aws_iam_role.app_admin"),
                         "actions": ["s3:GetObject", "s3:ListBucket"],
                         "resource_patterns": ["arn:aws:s3:::app-data/*"],
                         "confidence": "confirmed"}]},
        "paths": {"added": [], "removed": []}},
    "findings": [{
        "rank": 1, "severity": "high", "kind": "wildcard_capability_added",
        "title": "app-admin role gained s3:* on all resources",
        "detail": "aws_iam_policy.app_data statement ReadData widened from "
                  "[s3:GetObject, s3:ListBucket] on one bucket to s3:* on *.",
        "node_ids": [node_id(SUB["key"], "aws_iam_policy.app_data")]}],
    "unevaluated": [
        {"edge_id": f"{SUB['key']}/aws_iam_role.app_admin#trust:audit",
         "reasons": ["condition"],
         "note": "Third-party trust guarded by a Condition; not evaluated."},
        {"edge_id": f"{SUB['key']}/aws_iam_policy.kms_use#stmt:unresolved",
         "reasons": ["unresolved_policy_body"],
         "note": "Policy body references aws_kms_key.main.arn, unknown at plan time."}],
    "stats": {"nodes_compared": len(base["nodes"]), "modules_skipped": 0}}

# The null-result fixture: same graph, different root_module paths.
refactored = copy.deepcopy(base)
for nd in refactored["nodes"]:
    nd["scope"] = dict(nd["scope"], root_module="live/prod/identity/roles")
for sc in refactored["scopes"]:
    sc["root_module"] = "live/prod/identity/roles"
empty = structural_diff(base, refactored)

os.makedirs("fixtures", exist_ok=True)
for name, doc in [("base.graph.json", base), ("head.graph.json", head),
                  ("refactor-noop.graph.json", refactored),
                  ("expected.diff.json", diff)]:
    with open(f"fixtures/{name}", "w") as f:
        json.dump(doc, f, indent=2, sort_keys=True)
        f.write("\n")

assert base["modules"][0]["digest"] != head["modules"][0]["digest"], "star PR must change digest"
assert refactored["modules"][0]["digest"] == base["modules"][0]["digest"], \
    "REFACTOR MUST NOT CHANGE THE ROOT DIGEST"
assert all(not v["added"] and not v["removed"] and not v["changed"]
           for v in empty.values()), "refactor must produce an empty diff"
print("base root digest      :", base["modules"][0]["digest"])
print("head root digest      :", head["modules"][0]["digest"])
print("refactor root digest  :", refactored["modules"][0]["digest"], "(== base)")
print("structural node deltas:", diff["structural"]["nodes"])
print("structural edge deltas:", diff["structural"]["edges"])
print("\nall invariants hold")
