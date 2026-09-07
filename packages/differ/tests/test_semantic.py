"""Stage 2: effective capabilities, privilege paths, confidence, findings."""
import random

import pytest

from permdiff import Graph, diff_graphs
from permdiff.builder import GraphBuilder, scope
from permdiff.catalog import CATALOG, expand_action, expand_actions
from permdiff.semantic import (CONDITIONAL, CONFIRMED, TrustGraph, capabilities_of,
                               enumerate_paths, paths_through, semantic_diff)

MGMT = scope("999988887777")
PROD = scope("111122223333")


def _diff(base: GraphBuilder, head: GraphBuilder, **kw):
    return diff_graphs(Graph(base.build(), "base"), Graph(head.build(), "head"), **kw).doc


def _caps(doc, op="added"):
    return [(c["principal"].split("/", 1)[1], tuple(c["actions"]), tuple(c["resource_patterns"]),
             c["confidence"]) for c in doc["semantic"]["capabilities"][op]]


# --- catalog -----------------------------------------------------------------

def test_catalog_covers_exactly_five_services():
    assert set(CATALOG) == {"s3", "sts", "iam", "kms", "secretsmanager"}


def test_expand_service_wildcard():
    tokens, ok = expand_action("s3:*")
    assert ok and len(tokens) == len(CATALOG["s3"]) and "s3:GetObject" in tokens
    tokens, ok = expand_action("kms:Decrypt*")
    assert ok and tokens == ["kms:Decrypt"]
    tokens, ok = expand_action("iam:Pass*")
    assert tokens == ["iam:PassRole"]


def test_expand_unknown_service_is_flagged():
    tokens, ok = expand_action("ec2:*")
    assert tokens == ["ec2:*"] and not ok
    tokens, unexpandable = expand_actions(["s3:Get*", "ec2:Run*"])
    assert unexpandable == ["ec2:Run*"] and "ec2:Run*" in tokens


def test_expand_star_keeps_literal_star():
    tokens, ok = expand_action("*")
    assert ok and "*" in tokens and "iam:PassRole" in tokens


def test_case_insensitive_actions():
    assert expand_action("S3:getobject")[0] == ["s3:GetObject"]


# --- capabilities ------------------------------------------------------------

def _role_with_policy(b, sc, role="aws_iam_role.r", pol="aws_iam_policy.p"):
    r = b.principal(sc, role)
    p = b.policy(sc, pol)
    b.attaches(r, p)
    return r, p


def test_capability_added_and_provenance():
    base = GraphBuilder()
    r, p = _role_with_policy(base, PROD)
    head = base.clone()
    bucket = head.resource(PROD, "aws_s3_bucket.b", "b", "arn:aws:s3:::b")
    head.grants(p, bucket, ["s3:GetObject"], ["arn:aws:s3:::b/*"], "Read")
    doc = _diff(base, head)
    assert _caps(doc) == [("aws_iam_role.r", ("s3:GetObject",), ("arn:aws:s3:::b/*",), CONFIRMED)]
    assert doc["semantic"]["capabilities"]["removed"] == []
    assert doc["findings"][0]["kind"] == "capability_added"
    assert doc["findings"][0]["severity"] == "medium"
    # the added bucket node is explained by the finding -> no churn finding
    assert [f["kind"] for f in doc["findings"]] == ["capability_added"]


def test_explicit_deny_wins():
    b = GraphBuilder()
    r, p = _role_with_policy(b, PROD)
    w = b.wildcard(PROD)
    b.grants(p, w, ["s3:*"], ["*"], "All")
    deny = b.policy(PROD, "aws_iam_policy.deny")
    b.attaches(r, deny)
    b.grants(deny, w, ["s3:DeleteObject", "s3:DeleteBucket*"], ["*"], "NoDelete", effect="Deny")
    (cap,) = capabilities_of(Graph(b.build()), r)
    assert "s3:DeleteObject" not in cap.actions
    assert "s3:DeleteBucket" not in cap.actions and "s3:DeleteBucketPolicy" not in cap.actions
    assert "s3:GetObject" in cap.actions
    assert set(cap.denied_actions) >= {"s3:DeleteObject", "s3:DeleteBucket", "s3:DeleteBucketPolicy"}


def test_conditional_deny_does_not_hide_allow():
    b = GraphBuilder()
    r, p = _role_with_policy(b, PROD)
    w = b.wildcard(PROD)
    b.grants(p, w, ["s3:GetObject"], ["*"], "Get")
    b.grants(p, w, ["s3:GetObject"], ["*"], "DenyMaybe", effect="Deny", unevaluated=["condition"])
    (cap,) = capabilities_of(Graph(b.build()), r)
    assert cap.actions == ("s3:GetObject",) and cap.confidence == CONFIRMED


def test_deny_on_narrower_resource_does_not_carve():
    b = GraphBuilder()
    r, p = _role_with_policy(b, PROD)
    w = b.wildcard(PROD)
    b.grants(p, w, ["s3:GetObject"], ["*"], "Get")
    b.grants(p, w, ["s3:GetObject"], ["arn:aws:s3:::one/*"], "DenyOne", effect="Deny")
    (cap,) = capabilities_of(Graph(b.build()), r)
    assert cap.actions == ("s3:GetObject",) and not cap.denied_actions


def test_adding_a_deny_is_a_removal_not_a_widening():
    base = GraphBuilder()
    r, p = _role_with_policy(base, PROD)
    w = base.wildcard(PROD)
    base.grants(p, w, ["s3:*"], ["*"], "All")
    head = base.clone()
    head.grants(p, w, ["s3:DeleteObject"], ["*"], "NoDel", effect="Deny")
    doc = _diff(base, head)
    kinds = [f["kind"] for f in doc["findings"]]
    assert kinds == ["capability_removed"], kinds
    f = doc["findings"][0]
    assert f["lost_actions"] == ["s3:DeleteObject"] and "s3:DeleteObject" in f["title"]
    assert "explicit Deny" in f["detail"]
    added = doc["semantic"]["capabilities"]["added"][0]
    assert added["denied_actions"] == ["s3:DeleteObject"] and added["gained_action_count"] == 0
    removed = doc["semantic"]["capabilities"]["removed"][0]
    assert removed.get("superseded_by") is None and removed["lost_actions"] == ["s3:DeleteObject"]


def test_unevaluated_edge_is_never_confirmed():
    for where in ("attaches", "grants"):
        b = GraphBuilder()
        r = b.principal(PROD, "aws_iam_role.r")
        p = b.policy(PROD, "aws_iam_policy.p")
        b.attaches(r, p, unevaluated=["condition"] if where == "attaches" else None)
        b.grants(p, b.wildcard(PROD), ["iam:*"], ["*"], "Admin",
                 unevaluated=["not_action"] if where == "grants" else None)
        (cap,) = capabilities_of(Graph(b.build()), r)
        assert cap.confidence == CONDITIONAL
        doc = diff_graphs(Graph(GraphBuilder().build()), Graph(b.build())).doc
        (added,) = doc["semantic"]["capabilities"]["added"]
        assert added["confidence"] == CONDITIONAL
        assert doc["findings"][0]["confidence"] == CONDITIONAL
        assert "[conditional]" in doc["findings"][0]["title"]
        assert doc["findings"][0]["severity"] == "medium"   # downgraded from high
        assert any(u["edge_id"] for u in doc["unevaluated"])


def test_condition_removed_becomes_confirmed_capability():
    base = GraphBuilder()
    r, p = _role_with_policy(base, PROD)
    w = base.wildcard(PROD)
    base.grants(p, w, ["kms:Decrypt"], ["*"], "Dec", unevaluated=["condition"])
    head = base.clone()
    head.grants(p, w, ["kms:Decrypt"], ["*"], "Dec")
    doc = _diff(base, head)
    assert _caps(doc, "added") == [("aws_iam_role.r", ("kms:Decrypt",), ("*",), CONFIRMED)]
    assert _caps(doc, "removed") == [("aws_iam_role.r", ("kms:Decrypt",), ("*",), CONDITIONAL)]
    assert doc["semantic"]["capabilities"]["removed"][0]["superseded_by"]["confidence"] == CONFIRMED
    assert [f["kind"] for f in doc["findings"]] == ["wildcard_capability_added"]  # resource "*"
    assert "was conditional" in doc["findings"][0]["title"]


def test_statement_moved_between_policies_is_not_semantic():
    base = GraphBuilder()
    r = base.principal(PROD, "aws_iam_role.r")
    p1 = base.policy(PROD, "aws_iam_policy.p1")
    p2 = base.policy(PROD, "aws_iam_policy.p2")
    base.attaches(r, p1)
    base.attaches(r, p2)
    w = base.wildcard(PROD)
    base.grants(p1, w, ["sts:GetCallerIdentity"], ["*"], "Who")
    head = base.clone()
    head.remove_edge(f"{p1}#stmt:Who")
    head.grants(p2, w, ["sts:GetCallerIdentity"], ["*"], "Who")
    doc = _diff(base, head)
    assert doc["semantic"]["capabilities"] == {"added": [], "removed": []}
    assert [f["kind"] for f in doc["findings"]] == ["structural_churn"]
    assert doc["empty"] is False


def test_policy_attached_to_many_principals_yields_one_grouped_finding():
    base = GraphBuilder()
    p = base.policy(PROD, "aws_iam_policy.shared")
    roles = [base.principal(PROD, f"aws_iam_role.r{i}") for i in range(5)]
    for r in roles:
        base.attaches(r, p)
    head = base.clone()
    head.grants(p, head.wildcard(PROD), ["secretsmanager:GetSecretValue"], ["*"], "Read")
    doc = _diff(base, head)
    assert len(doc["semantic"]["capabilities"]["added"]) == 5
    caps_findings = [f for f in doc["findings"] if f["kind"].endswith("capability_added")]
    assert len(caps_findings) == 1 and len(caps_findings[0]["principals"]) == 5
    assert caps_findings[0]["title"].startswith("5 principals gained")


def test_admin_star_on_star_is_critical():
    base = GraphBuilder()
    r, p = _role_with_policy(base, PROD)
    head = base.clone()
    head.grants(p, head.wildcard(PROD), ["*"], ["*"], "Admin")
    doc = _diff(base, head)
    assert doc["findings"][0]["severity"] == "critical"
    assert doc["findings"][0]["kind"] == "wildcard_capability_added"


def test_unexpandable_service_is_surfaced():
    base = GraphBuilder()
    r, p = _role_with_policy(base, PROD)
    head = base.clone()
    head.grants(p, head.wildcard(PROD), ["ec2:*"], ["*"], "Ec2")
    doc = _diff(base, head)
    (c,) = doc["semantic"]["capabilities"]["added"]
    assert c["unexpandable"] == ["ec2:*"] and c["wildcard"] is True
    assert "outside bundled catalog" in doc["findings"][0]["detail"]


# --- paths -------------------------------------------------------------------

def _chain(b, unevaluated_last=None):
    gha = b.principal(MGMT, "aws_iam_role.gha", "gha-role")
    dep = b.principal(MGMT, "aws_iam_role.mgmt_deploy", "mgmt-deploy")
    adm = b.principal(PROD, "aws_iam_role.app_admin", "app-admin")
    b.can_assume(gha, dep)
    b.can_assume(dep, adm, unevaluated=unevaluated_last)
    return gha, dep, adm


def test_cross_scope_path_added_ranks_first():
    base = GraphBuilder()
    gha, dep, adm = _chain(base)
    pol = base.policy(PROD, "aws_iam_policy.p")
    base.attaches(adm, pol)
    base.grants(pol, base.wildcard(PROD), ["s3:*", "iam:PassRole"], ["*"], "X")
    head = base.clone()
    root = head.principal(PROD, "aws_iam_role.prod_root", "prod-root")
    head.can_assume(adm, root)
    # also a same-scope wildcard capability, which must rank *below* the path
    p2 = head.policy(PROD, "aws_iam_policy.p2")
    head.attaches(root, p2)
    head.grants(p2, "aws:111122223333:us-east-1/wildcard.all", ["kms:*"], ["*"], "K")
    doc = _diff(base, head)
    added = doc["semantic"]["paths"]["added"]
    paths = [tuple(n.split("/", 1)[1] for n in p["path"]) for p in added]
    assert paths == [("aws_iam_role.gha", "aws_iam_role.mgmt_deploy", "aws_iam_role.app_admin",
                      "aws_iam_role.prod_root")]
    assert added[0]["hops"] == 3 and added[0]["crosses_scopes"] is True
    assert added[0]["confidence"] == CONFIRMED
    assert added[0]["terminal_capabilities"] == ["kms:*"]
    assert doc["findings"][0]["kind"] == "path_added"
    assert doc["findings"][0]["severity"] == "critical"
    assert doc["findings"][0]["crosses_scopes"] is True
    assert doc["findings"][1]["kind"] == "wildcard_capability_added"


def test_conditional_path_is_never_confirmed_and_ranks_below_confirmed():
    base = GraphBuilder()
    _chain(base, unevaluated_last=["condition"])
    head = base.clone()
    a = head.principal(MGMT, "aws_iam_role.other")
    b2 = head.principal(MGMT, "aws_iam_role.target")
    head.can_assume(a, b2)  # confirmed, single-scope
    x = head.principal(PROD, "aws_iam_role.x")
    head.can_assume("aws:111122223333:us-east-1/aws_iam_role.app_admin", x)  # extends conditional
    doc = _diff(base, head)
    kinds = [(f["kind"], f["confidence"], f["crosses_scopes"]) for f in doc["findings"] if f["kind"] == "path_added"]
    assert kinds[0] == ("path_added", CONFIRMED, False)
    assert kinds[1] == ("path_added", CONDITIONAL, True)
    cond = [p for p in doc["semantic"]["paths"]["added"] if p["crosses_scopes"]]
    assert all(p["confidence"] == CONDITIONAL and p["unevaluated"] == ["condition"] for p in cond)


def test_path_becomes_confirmed_when_condition_is_removed():
    base = GraphBuilder()
    _chain(base, unevaluated_last=["condition"])
    head = GraphBuilder()
    _chain(head)
    doc = _diff(base, head)
    assert [f["kind"] for f in doc["findings"]] == ["path_confirmed"]
    assert doc["findings"][0]["severity"] == "critical"   # cross-scope, now confirmed
    assert "was conditional" in doc["findings"][0]["detail"]
    assert len(doc["semantic"]["paths"]["removed"]) == 1
    assert doc["semantic"]["paths"]["removed"][0]["confidence"] == CONDITIONAL


def test_path_removed_is_low_priority():
    base = GraphBuilder()
    gha, dep, adm = _chain(base)
    head = base.clone()
    head.remove_edge(f"{adm}#trust:mgmt_deploy")
    doc = _diff(base, head)
    assert [f["kind"] for f in doc["findings"]] == ["path_removed"]
    assert doc["findings"][0]["severity"] == "info"


def test_confirmed_deny_trust_blocks_path_conditional_deny_does_not():
    b = GraphBuilder()
    gha, dep, adm = _chain(b)
    b.can_assume(dep, adm, effect="Deny", qualifier="deny")
    assert not [p for p in enumerate_paths(TrustGraph(Graph(b.build()))) if len(p.nodes) == 3]
    b2 = GraphBuilder()
    _chain(b2)
    dep2 = "aws:999988887777:us-east-1/aws_iam_role.mgmt_deploy"
    adm2 = "aws:111122223333:us-east-1/aws_iam_role.app_admin"
    b2.can_assume(dep2, adm2, effect="Deny", qualifier="deny", unevaluated=["condition"])
    assert [p for p in enumerate_paths(TrustGraph(Graph(b2.build()))) if len(p.nodes) == 3]


def test_depth_bound():
    b = GraphBuilder()
    roles = [b.principal(PROD, f"aws_iam_role.r{i}") for i in range(7)]
    for i in range(6):
        b.can_assume(roles[i], roles[i + 1])
    paths = enumerate_paths(TrustGraph(Graph(b.build())), max_hops=4)
    assert max(len(p.nodes) - 1 for p in paths) == 4
    assert len(paths) == 4  # r0->r1, r0->..->r2, ->r3, ->r4 ; only r0 is an entry


def test_cycle_still_gets_an_entry():
    b = GraphBuilder()
    a = b.principal(PROD, "aws_iam_role.a")
    c = b.principal(PROD, "aws_iam_role.c")
    b.can_assume(a, c)
    b.can_assume(c, a)
    tg = TrustGraph(Graph(b.build()))
    assert tg.all_entries() == [a]
    assert [tuple(p.nodes) for p in enumerate_paths(tg)] == [(a, c)]


def test_paths_through_equals_filtered_full_enumeration():
    rng = random.Random(42)
    for trial in range(30):
        b = GraphBuilder()
        n = rng.randint(3, 9)
        roles = [b.principal(rng.choice([PROD, MGMT]), f"aws_iam_role.r{i}") for i in range(n)]
        pairs = set()
        for _ in range(rng.randint(2, 14)):
            s, t = rng.sample(roles, 2)
            if (s, t) in pairs:
                continue
            pairs.add((s, t))
            b.can_assume(s, t, unevaluated=["condition"] if rng.random() < 0.2 else None)
        tg = TrustGraph(Graph(b.build()))
        full = enumerate_paths(tg)
        chosen = set(rng.sample(sorted(pairs), min(len(pairs), 3)))
        want = sorted(p.identity for p in full
                      if any((p.nodes[i], p.nodes[i + 1]) in chosen for i in range(len(p.nodes) - 1)))
        got = sorted(p.identity for p in paths_through(tg, chosen))
        assert got == want, trial


# --- incremental == full ---------------------------------------------------------

def _random_graph(rng, n_roles=8):
    b = GraphBuilder()
    scopes = [PROD, MGMT]
    roles = [b.principal(rng.choice(scopes), f"aws_iam_role.r{i}") for i in range(n_roles)]
    pols = [b.policy(rng.choice(scopes), f"aws_iam_policy.p{i}") for i in range(n_roles)]
    w = {s["key"]: b.wildcard(s) for s in scopes}
    buckets = [b.resource(rng.choice(scopes), f"aws_s3_bucket.b{i}", f"b{i}", f"arn:aws:s3:::b{i}")
               for i in range(3)]
    for r in roles:
        for p in rng.sample(pols, rng.randint(0, 3)):
            b.attaches(r, p, unevaluated=["condition"] if rng.random() < 0.1 else None)
    actions_pool = ["s3:*", "s3:GetObject", "s3:Put*", "iam:PassRole", "kms:Decrypt", "*",
                    "sts:AssumeRole", "ec2:*", "secretsmanager:GetSecretValue"]
    for p in pols:
        for j in range(rng.randint(0, 3)):
            tgt = rng.choice(buckets + list(w.values()))
            pats = ["*"] if tgt.endswith("wildcard.all") else [f"arn:aws:s3:::{tgt.split('.')[-1]}/*"]
            b.grants(p, tgt, rng.sample(actions_pool, rng.randint(1, 3)), pats, f"S{j}",
                     effect="Deny" if rng.random() < 0.2 else "Allow",
                     unevaluated=["condition"] if rng.random() < 0.15 else None)
    for _ in range(rng.randint(2, 10)):
        s, t = rng.sample(roles, 2)
        b.can_assume(s, t, unevaluated=["condition"] if rng.random() < 0.2 else None,
                     qualifier=s.rsplit(".", 1)[-1])
    return b


def _mutate(rng, b: GraphBuilder):
    h = b.clone()
    for _ in range(rng.randint(1, 3)):
        op = rng.choice(["add_grant", "del_edge", "add_trust", "cond_flip", "rename"])
        if op == "add_grant":
            p = rng.choice([n for n in h.nodes.values() if n["type"] == "policy"])["id"]
            w = [n for n in h.nodes.values() if n["type"] == "wildcard"][0]["id"]
            h.grants(p, w, rng.choice([["s3:*"], ["*"], ["iam:*"], ["kms:Decrypt"]]), ["*"],
                     f"New{rng.randint(0, 99)}", effect=rng.choice(["Allow", "Allow", "Deny"]))
        elif op == "del_edge" and h.edges:
            h.remove_edge(rng.choice(sorted(h.edges)))
        elif op == "add_trust":
            roles = [n["id"] for n in h.nodes.values() if n["type"] == "principal"]
            s, t = rng.sample(roles, 2)
            h.can_assume(s, t, qualifier=s.rsplit(".", 1)[-1] + "x")
        elif op == "cond_flip" and h.edges:
            eid = rng.choice(sorted(h.edges))
            e = dict(h.edges[eid])
            e["unevaluated"] = [] if e["unevaluated"] else ["condition"]
            h.edge(eid, e["type"], e["source"], e["target"], e["effect"], e["actions"],
                   e["resource_patterns"], e["sid"], e["resolution"], e["unevaluated"])
        elif op == "rename":
            n = rng.choice([n for n in h.nodes.values() if n["type"] == "principal"])
            h.node(n["scope"], n["logical_address"], "principal", n["name"] + "-x", n["aliases"])
    return h


@pytest.mark.parametrize("seed", range(40))
def test_incremental_semantic_equals_full(seed):
    rng = random.Random(seed)
    base = _random_graph(rng)
    head = _mutate(rng, base)
    gb, gh = Graph(base.build()), Graph(head.build())
    inc = diff_graphs(gb, gh).doc
    full = diff_graphs(gb, gh, full_semantic=True).doc
    assert inc["semantic"] == full["semantic"]
    assert inc["findings"] == full["findings"]
    assert inc["unevaluated"] == full["unevaluated"]
    assert inc["stats"]["semantic"]["principals_evaluated"] <= full["stats"]["semantic"]["principals_evaluated"]


@pytest.mark.parametrize("seed", range(10))
def test_random_graph_vs_itself_is_empty(seed):
    rng = random.Random(100 + seed)
    b = _random_graph(rng)
    doc = b.build()
    res = diff_graphs(Graph(doc), Graph(doc), full_semantic=True)
    assert res.doc["empty"] is True


def test_unevaluated_section_lists_only_relevant_edges():
    base = GraphBuilder()
    r1, p1 = _role_with_policy(base, PROD, "aws_iam_role.r1", "aws_iam_policy.p1")
    r2, p2 = _role_with_policy(base, PROD, "aws_iam_role.r2", "aws_iam_policy.p2")
    w = base.wildcard(PROD)
    base.grants(p1, w, ["s3:GetObject"], ["*"], "Cond", unevaluated=["condition"])
    base.grants(p2, w, ["s3:GetObject"], ["*"], "Cond", unevaluated=["condition"])
    head = base.clone()
    head.grants(p1, w, ["kms:Decrypt"], ["*"], "New")
    doc = _diff(base, head)
    assert [u["edge_id"].rsplit("/", 1)[1] for u in doc["unevaluated"]] == ["aws_iam_policy.p1#stmt:Cond"]
    assert doc["stats"]["unevaluated_edges_in_head"] == 2


# --- entry flips (lazy trust graph must find paths that touch no dirty edge) ---

def test_edge_removal_promotes_new_entry_and_its_paths_are_reported():
    base = GraphBuilder()
    x = base.principal(PROD, "aws_iam_role.x")
    r6 = base.principal(PROD, "aws_iam_role.r6")
    m = base.principal(MGMT, "aws_iam_role.m")
    base.can_assume(x, r6)
    base.can_assume(r6, m)
    head = base.clone()
    head.remove_edge(f"{r6}#trust:x")
    doc = _diff(base, head)
    removed = sorted(tuple(n.rsplit(".", 1)[1] for n in p["path"]) for p in doc["semantic"]["paths"]["removed"])
    added = sorted(tuple(n.rsplit(".", 1)[1] for n in p["path"]) for p in doc["semantic"]["paths"]["added"])
    assert removed == [("x", "r6"), ("x", "r6", "m")]
    assert added == [("r6", "m")]          # r6 -> m touches no dirty edge; r6 is a new entry
    full = diff_graphs(Graph(base.build()), Graph(head.build()), full_semantic=True).doc
    assert full["semantic"] == doc["semantic"]


def test_cycle_region_entry_moves_to_non_endpoint():
    """u -> v, v -> w, w -> v.  Removing u -> v leaves {v, w} with no real
    entry; the smallest id (v) becomes the entry.  Here we name them so the
    smallest id is *w*, i.e. a node that is not an endpoint of the dirty pair."""
    base = GraphBuilder()
    u = base.principal(PROD, "aws_iam_role.u")
    v = base.principal(PROD, "aws_iam_role.v")
    w = base.principal(PROD, "aws_iam_role.a")   # sorts before "v"
    base.can_assume(u, v)
    base.can_assume(v, w, qualifier="v")
    base.can_assume(w, v, qualifier="a")
    head = base.clone()
    head.remove_edge(f"{v}#trust:u")
    inc = _diff(base, head)
    full = diff_graphs(Graph(base.build()), Graph(head.build()), full_semantic=True).doc
    assert inc["semantic"] == full["semantic"]
    added = sorted(tuple(n.rsplit(".", 1)[1] for n in p["path"]) for p in inc["semantic"]["paths"]["added"])
    assert added == [("a", "v")]
