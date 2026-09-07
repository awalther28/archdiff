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
    """Roll module digests back up after a move.

    Node digests are unaffected by a move, but edge digests are not (they cover
    source and target), so a module containing a moved edge has a stale rollup.
    Left stale, the differ's Merkle verification correctly refuses to prune and
    falls back to full comparison -- right answer, wrong reason, and a warning
    the reader should never see for a clean refactor.
    """
    node_d: Dict[tuple, List[str]] = {}
    edge_d: Dict[tuple, List[str]] = {}
    for n in doc.get("nodes", []):
        node_d.setdefault(module_key_of_address(n["logical_address"]), []).append(n["digest"])
    nodes_by_id = {n["id"]: n for n in doc.get("nodes", [])}
    for e in doc.get("edges", []):
        owner = e["id"].partition("#")[0]
        ref = nodes_by_id.get(owner) or nodes_by_id.get(e["source"]) or nodes_by_id.get(e["target"])
        key = module_key_of_address(ref["logical_address"]) if ref else ()
        edge_d.setdefault(key, []).append(e["digest"])

    def walk(mod: dict) -> str:
        children = [walk(c) for c in (mod.get("children") or [])]
        key = module_key_of_path(mod.get("path", ""))
        mod["digest"] = module_digest(node_d.get(key, []), edge_d.get(key, []), children)
        return mod["digest"]

    for root in doc.get("modules", []) or []:
        walk(root)
