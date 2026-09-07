"""Apply Terraform ``moved {}`` blocks to the base graph (SCHEMA.md section 6.1).

A refactor that relocates resources between modules changes their Terraform
addresses, and therefore their node ids -- ``id = {scope.key}/{logical_address}``.
Without this pass such a refactor reads as a large added/removed churn, which is
exactly the false positive section 8 exists to prevent.

The head graph's ``moves`` describe the base->head renames, so they are applied
to the *base* document before comparison.

Both node and edge digests DO change under a move -- ``node_digest`` covers
``logical_address`` and ``edge_digest`` covers ``source``/``target`` (SCHEMA.md
section 5) -- so this pass recomputes them and rolls the module tree back up.
Recomputation is what makes a moved element compare equal to its head twin.
"""
from typing import Dict, List, Tuple

from .address import module_key_of_address, module_key_of_path
from .canonical import edge_digest, module_digest, node_digest

MAX_CHAIN = 64


def _matches(address: str, frm: str) -> bool:
    """Prefix match, per section 6.1 -- ``module.app`` matches ``module.app`` and
    ``module.app.aws_iam_role.this``, but NOT ``module.application``."""
    return address == frm or address.startswith(frm + ".")


def _rewrite(address: str, frm: str, to: str) -> str:
    return to + address[len(frm):]


def resolve_chains(moves: List[dict]) -> Tuple[List[dict], List[str]]:
    """Compose transitive moves (A->B, B->C  =>  A->C) and detect cycles."""
    warnings: List[str] = []
    resolved: List[dict] = []
    for mv in moves:
        scope, frm, to = mv.get("scope_key"), mv["from"], mv["to"]
        seen = {to}
        for _ in range(MAX_CHAIN):
            nxt = None
            for other in moves:
                if other is mv or other.get("scope_key") != scope:
                    continue
                if _matches(to, other["from"]):
                    nxt = _rewrite(to, other["from"], other["to"])
                    break
            if nxt is None:
                break
            if nxt in seen:
                warnings.append(
                    f"cyclic moved chain involving {frm!r}; left at {to!r}")
                break
            seen.add(nxt)
            to = nxt
        resolved.append({"scope_key": scope, "from": frm, "to": to})
    return resolved, warnings


def _remap_address(address: str, scope_key: str, moves: List[dict]):
    """Longest matching ``from`` wins, so a nested move beats its parent."""
    best = None
    for mv in moves:
        if mv.get("scope_key") not in (None, scope_key):
            continue
        if _matches(address, mv["from"]) and (best is None or len(mv["from"]) > len(best["from"])):
            best = mv
    if best is None:
        return address, None
    return _rewrite(address, best["from"], best["to"]), best


def apply_moves(base_doc: dict, head_moves: List[dict]):
    """Return ``(rewritten_base_doc, applied, warnings)``.

    ``applied`` lists only the moves that actually matched something, so
    ``moves_applied`` in the diff reports what happened rather than what was
    declared.  A declared move that matches nothing is reported as a warning:
    silence there would hide a stale or misspelled ``moved`` block.
    """
    resolved, warnings = resolve_chains(head_moves)
    if not resolved:
        return base_doc, [], warnings

    doc = {k: (list(v) if isinstance(v, list) else v) for k, v in base_doc.items()}
    id_map: Dict[str, str] = {}
    hit: Dict[Tuple[str, str, str], dict] = {}

    new_nodes = []
    for node in base_doc.get("nodes", []):
        node = dict(node)
        scope_key = (node.get("scope") or {}).get("key", "")
        new_addr, mv = _remap_address(node["logical_address"], scope_key, resolved)
        if mv is not None:
            old_id = node["id"]
            node["logical_address"] = new_addr
            node["id"] = f"{scope_key}/{new_addr}"
            # A move relocates the node between modules, so the declared
            # membership (SCHEMA.md 6.2) has to follow the new address.
            if node.get("module"):
                node["module"] = _remap_module(node["module"], new_addr)
            # node_digest covers logical_address (SCHEMA.md section 5), so a move
            # DOES invalidate the stored digest and it has to be recomputed here.
            node["digest"] = node_digest(node)
            id_map[old_id] = node["id"]
            hit[(mv.get("scope_key") or "", mv["from"], mv["to"])] = mv
        new_nodes.append(node)
    doc["nodes"] = sorted(new_nodes, key=lambda n: n["id"])

    def remap_edge_id(eid: str, scope_key: str) -> str:
        """Edge ids embed addresses in several shapes, and every one has to be
        remapped or the edge reads as removed+added:

            {owner}#attach:{address}
            {owner}#stmt:{Sid}@{address}
            {owner}#stmt:{Sid}@{scope}/{address}   (cross-scope: a full node id)

        The owner prefix alone is not enough.
        """
        owner, sep, qual = eid.partition("#")
        owner = id_map.get(owner, owner)
        if not sep:
            return owner

        def remap_operand(operand: str) -> str:
            if operand in id_map:            # a full node id
                return id_map[operand]
            if "/" in operand:               # a node id in another scope
                osc, _, oaddr = operand.partition("/")
                remapped, mv = _remap_address(oaddr, osc, resolved)
                return osc + "/" + remapped if mv is not None else operand
            remapped, mv = _remap_address(operand, scope_key, resolved)
            return remapped if mv is not None else operand

        head_part, at, operand = qual.partition("@")
        if at:
            qual = head_part + at + remap_operand(operand)
        else:
            kind, colon, rest = qual.partition(":")
            if colon:
                qual = kind + ":" + remap_operand(rest)
        return owner + sep + qual

    new_edges = []
    for edge in base_doc.get("edges", []):
        edge = dict(edge)
        scope_key = edge["id"].split("/", 1)[0] if "/" in edge["id"] else ""
        moved_endpoint = edge["source"] in id_map or edge["target"] in id_map
        edge["id"] = remap_edge_id(edge["id"], scope_key)
        edge["source"] = id_map.get(edge["source"], edge["source"])
        edge["target"] = id_map.get(edge["target"], edge["target"])
        if moved_endpoint:
            # edge_digest covers source and target (SCHEMA.md section 5), so a
            # moved endpoint invalidates the stored digest.  Recomputing here is
            # what makes a moved edge compare equal to its head counterpart.
            edge["digest"] = edge_digest(edge)
        new_edges.append(edge)
    doc["edges"] = sorted(new_edges, key=lambda e: e["id"])

    # Edge membership follows the owning node (see the extractor's note), so it
    # is resolved from the rewritten nodes rather than guessed from the move.
    new_by_id = {n["id"]: n for n in doc["nodes"]}
    for edge in doc["edges"]:
        if not edge.get("module"):
            continue
        owner = new_by_id.get(edge["id"].partition("#")[0]) or new_by_id.get(edge["source"])
        if owner is not None and owner.get("module"):
            edge["module"] = owner["module"]

    # Module tree paths are addresses too; rewriting them keeps module keys
    # aligned with the rewritten node addresses.  Digests are unchanged because
    # a renamed module keeps exactly the same children.
    def remap_modules(mods):
        out = []
        for m in mods or []:
            m = dict(m)
            path = m.get("path", "")
            if path not in ("", "root", "."):
                new_path, mv = _remap_address(path, "", resolved)
                if mv is None:
                    for r in resolved:
                        if _matches(path, r["from"]):
                            new_path = _rewrite(path, r["from"], r["to"])
                            break
                m["path"] = new_path
            if m.get("children"):
                m["children"] = remap_modules(m["children"])
            out.append(m)
        return out
    if doc.get("modules"):
        doc["modules"] = remap_modules(doc["modules"])

    _recompute_module_digests(doc)

    applied = [dict(m) for m in resolved
               if (m.get("scope_key") or "", m["from"], m["to"]) in hit]
    for m in resolved:
        if (m.get("scope_key") or "", m["from"], m["to"]) not in hit:
            warnings.append(
                f"moved block {m['from']!r} -> {m['to']!r} matched no node in the base graph")
    return doc, applied, warnings


def _recompute_module_digests(doc: dict) -> None:
    """Rebuild the base module tree after a move.

    Relabelling the existing tree is not enough: a move can relocate a node into
    a module that does not exist on the base side at all (``aws_iam_role.deployer``
    -> ``module.deployer.aws_iam_role.this``).  The node then lands in the
    unassigned bucket on one side and a real module on the other, and the *same*
    id is reported as both added and removed.

    So the tree is rebuilt from the declared ``module`` paths (SCHEMA.md 6.2),
    which by construction produces exactly the modules the rewritten nodes claim.
    Documents without declared membership keep the old address-derived rollup.
    """
    nodes = doc.get("nodes", [])
    edges = doc.get("edges", [])
    if not any(n.get("module") for n in nodes):
        _recompute_module_digests_by_address(doc)
        return

    nodes_by_id = {n["id"]: n for n in nodes}
    members: Dict[Tuple[str, ...], Dict[str, List[str]]] = {}

    def bucket(path: str) -> Dict[str, List[str]]:
        segs = tuple(p for p in (path or "root").split("/") if p)
        return members.setdefault(segs, {"nodes": [], "edges": []})

    for n in nodes:
        bucket(n.get("module") or "root")["nodes"].append(n["digest"])
    for e in edges:
        path = e.get("module")
        if not path:
            owner = e["id"].partition("#")[0]
            ref = nodes_by_id.get(owner) or nodes_by_id.get(e["source"])
            path = (ref or {}).get("module") or "root"
        bucket(path)["edges"].append(e["digest"])

    # every ancestor must exist even if it holds nothing itself
    all_paths = set(members)
    for segs in list(all_paths):
        for i in range(1, len(segs)):
            all_paths.add(segs[:i])

    def build(segs: Tuple[str, ...]) -> dict:
        kids = sorted(p for p in all_paths if len(p) == len(segs) + 1 and p[:len(segs)] == segs)
        children = [build(k) for k in kids]
        mine = members.get(segs, {"nodes": [], "edges": []})
        return {"path": segs[-1] if segs else "root",
                "digest": module_digest(sorted(mine["nodes"]), sorted(mine["edges"]),
                                        [c["digest"] for c in children]),
                "children": children}

    roots = sorted(p for p in all_paths if len(p) == 1)
    doc["modules"] = [build(r) for r in roots] if roots else doc.get("modules", [])


def _recompute_module_digests_by_address(doc: dict) -> None:
    """Fallback rollup for documents that predate declared module membership."""
    node_d: Dict[tuple, List[str]] = {}
    edge_d: Dict[tuple, List[str]] = {}
    nodes_by_id = {n["id"]: n for n in doc.get("nodes", [])}
    for n in doc.get("nodes", []):
        node_d.setdefault(module_key_of_address(n["logical_address"]), []).append(n["digest"])
    for e in doc.get("edges", []):
        owner = e["id"].partition("#")[0]
        ref = nodes_by_id.get(owner) or nodes_by_id.get(e["source"]) or nodes_by_id.get(e["target"])
        key = module_key_of_address(ref["logical_address"]) if ref else ()
        edge_d.setdefault(key, []).append(e["digest"])

    def walk(mod: dict, parent_key: tuple = ()) -> str:
        own = module_key_of_path(mod.get("path", ""))
        key = own if own[:len(parent_key)] == parent_key and len(own) > len(parent_key) \
            else parent_key + own
        children = [walk(c, key) for c in (mod.get("children") or [])]
        mod["digest"] = module_digest(node_d.get(key, []), edge_d.get(key, []), children)
        return mod["digest"]

    for root in doc.get("modules", []) or []:
        walk(root)


def _remap_module(old_module: str, new_address: str) -> str:
    """Keep the ``root/<label>`` prefix, replace the module tail from the new address."""
    parts = old_module.split("/") if old_module else ["root"]
    base = parts[:2]
    segs = new_address.split(".")
    mods, i = [], 0
    while i + 1 < len(segs) and segs[i] == "module":
        mods.append("module." + segs[i + 1])
        i += 2
    return "/".join(base + mods)
