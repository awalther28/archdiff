"""Markdown renderer for the diff document (the PR comment).

Order: one-line verdict, new paths, new capabilities, removals, the
`unevaluated` section, and a collapsed <details> block for structural churn.
An empty diff is stated affirmatively (SCHEMA.md section 8).
"""
from typing import List

from .differ import is_empty_doc

_SEV_ICON = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW",
             "info": "INFO"}


def _code(s: str) -> str:
    return "`" + s.replace("`", "'") + "`"


def _short(nid: str) -> str:
    return nid.split("/", 1)[1] if "/" in nid else nid


def _scope(nid: str) -> str:
    return nid.split("/", 1)[0]


def _actions(a: List[str]) -> str:
    if len(a) <= 6:
        return ", ".join(_code(x) for x in a)
    return ", ".join(_code(x) for x in a[:5]) + f", ... (+{len(a) - 5} more)"


def _conf_tag(conf: str) -> str:
    return "" if conf == "confirmed" else " **[conditional -- not confirmed]**"


def render_markdown(doc: dict) -> str:
    out: List[str] = []
    stats = doc.get("stats", {})
    base, head = doc["base"], doc["head"]
    empty = doc.get("empty", is_empty_doc(doc))
    findings = doc["findings"]
    sem = doc["semantic"]
    struct = doc["structural"]

    # ---- verdict --------------------------------------------------------
    if empty:
        out.append(f"**No permission changes** between {_code(base['ref'])} and "
                   f"{_code(head['ref'])} -- the permission graphs are semantically identical.")
    else:
        top = findings[0] if findings else None
        n_paths = len(sem["paths"]["added"])
        n_caps = len(sem["capabilities"]["added"])
        sev = top["severity"].upper() if top else "INFO"
        parts = []
        if n_paths:
            parts.append(f"{n_paths} new privilege path{'s' if n_paths != 1 else ''}")
        if n_caps:
            parts.append(f"{n_caps} new capabilit{'ies' if n_caps != 1 else 'y'}")
        real_losses = [c for c in sem["capabilities"]["removed"] if c.get("lost_actions")]
        rem = len(sem["paths"]["removed"]) + len(real_losses)
        if rem:
            parts.append(f"{rem} removal{'s' if rem != 1 else ''}")
        superseded = len(sem["capabilities"]["removed"]) - len(real_losses)
        if superseded:
            parts.append(f"{superseded} grant{'s' if superseded != 1 else ''} superseded")
        if not parts:
            parts.append("structural changes only")
        out.append(f"**{sev}**: {', '.join(parts)} between {_code(base['ref'])} and "
                   f"{_code(head['ref'])}" + (f" -- {top['title']}" if top else "") + ".")
    out.append("")

    if empty:
        merkle = stats.get("merkle", {})
        out.append(f"Compared {stats.get('nodes_compared', 0)} node(s) and "
                   f"{stats.get('edges_compared', 0)} edge(s); "
                   f"{stats.get('modules_skipped', 0)} of {stats.get('modules_total', 0)} "
                   f"module(s) skipped by Merkle rollup"
                   + (" (verified)" if merkle.get("verified") else "") + ".")
        out.append("")
        _footer(out, doc)
        return "\n".join(out) + "\n"

    # ---- new paths ------------------------------------------------------
    paths = sem["paths"]["added"]
    if paths:
        out.append("### New privilege paths")
        out.append("")
        for p in paths:
            chain = " -> ".join(_code(_short(n)) for n in p["path"])
            tag = " (cross-scope)" if p["crosses_scopes"] else ""
            out.append(f"- {chain}{tag}{_conf_tag(p['confidence'])}")
            scopes = sorted({_scope(n) for n in p["path"]})
            out.append(f"  - hops: {p['hops']}; scopes: {', '.join(_code(s) for s in scopes)}")
            if p.get("terminal_capabilities"):
                out.append(f"  - terminal capabilities: {_actions(p['terminal_capabilities'])}")
            if p.get("terminal_conditional_capabilities"):
                out.append(f"  - conditional terminal capabilities: "
                           f"{_actions(p['terminal_conditional_capabilities'])}")
            if p.get("unevaluated"):
                out.append(f"  - unevaluated: {', '.join(p['unevaluated'])}")
        out.append("")

    # ---- new capabilities ----------------------------------------------
    caps = sem["capabilities"]["added"]
    if caps:
        out.append("### New capabilities")
        out.append("")
        for c in caps:
            wc = " **wildcard**" if c.get("wildcard") else ""
            out.append(f"- {_code(_short(c['principal']))}: {_actions(c['actions'])} on "
                       f"{_actions(c['resource_patterns']) or '(none)'}{wc}{_conf_tag(c['confidence'])}")
            via = c.get("via_policies") or []
            if via:
                out.append(f"  - via: {', '.join(_code(_short(v)) for v in via)}")
            if c.get("denied_actions"):
                out.append(f"  - carved out by explicit deny: {_actions(c['denied_actions'])}")
            if c.get("unexpandable"):
                out.append(f"  - not expanded (outside bundled catalog): {_actions(c['unexpandable'])}")
            if c.get("unevaluated"):
                out.append(f"  - unevaluated: {', '.join(c['unevaluated'])}")
        out.append("")

    # ---- removals -------------------------------------------------------
    rcaps = sem["capabilities"]["removed"]
    rpaths = sem["paths"]["removed"]
    if rcaps or rpaths:
        out.append("### Removed or superseded")
        out.append("")
        for p in rpaths:
            chain = " -> ".join(_code(_short(n)) for n in p["path"])
            out.append(f"- path {chain}{_conf_tag(p['confidence'])}")
        for c in rcaps:
            sup = c.get("superseded_by")
            note = (f" -- superseded by {_actions(sup['actions'])} on "
                    f"{_actions(sup['resource_patterns'])}") if sup else ""
            out.append(f"- {_code(_short(c['principal']))}: {_actions(c['actions'])} on "
                       f"{_actions(c['resource_patterns']) or '(none)'}{_conf_tag(c['confidence'])}{note}")
        out.append("")

    # ---- findings table -------------------------------------------------
    if findings:
        out.append("### Findings")
        out.append("")
        out.append("| # | severity | kind | finding |")
        out.append("|---|---|---|---|")
        for f in findings:
            out.append(f"| {f['rank']} | {_SEV_ICON.get(f['severity'], f['severity'])} | "
                       f"{f['kind']} | {f['title']} -- {f['detail']} |")
        out.append("")

    # ---- unevaluated ----------------------------------------------------
    _unevaluated(out, doc)

    # ---- structural churn (collapsed) -----------------------------------
    n_add = len(struct["nodes"]["added"]) + len(struct["edges"]["added"])
    n_rem = len(struct["nodes"]["removed"]) + len(struct["edges"]["removed"])
    n_chg = len(struct["nodes"]["changed"]) + len(struct["edges"]["changed"])
    out.append("<details>")
    out.append(f"<summary>Structural changes: +{n_add} -{n_rem} ~{n_chg} "
               f"(nodes {len(struct['nodes']['added'])}/{len(struct['nodes']['removed'])}/"
               f"{len(struct['nodes']['changed'])}, edges {len(struct['edges']['added'])}/"
               f"{len(struct['edges']['removed'])}/{len(struct['edges']['changed'])})</summary>")
    out.append("")
    for kind in ("nodes", "edges"):
        for op in ("added", "removed"):
            for i in struct[kind][op]:
                out.append(f"- {op} {kind[:-1]} {_code(i)}")
        for c in struct[kind]["changed"]:
            out.append(f"- changed {kind[:-1]} {_code(c['id'])} "
                       f"({c['before_digest']} -> {c['after_digest']})")
    out.append("")
    out.append(f"Compared {stats.get('nodes_compared', 0)} node(s), "
               f"{stats.get('edges_compared', 0)} edge(s); {stats.get('modules_skipped', 0)} of "
               f"{stats.get('modules_total', 0)} module(s) skipped by Merkle rollup.")
    out.append("")
    out.append("</details>")
    out.append("")
    _footer(out, doc)
    return "\n".join(out) + "\n"


def _unevaluated(out: List[str], doc: dict) -> None:
    items = doc.get("unevaluated", [])
    total = doc.get("stats", {}).get("unevaluated_edges_in_head")
    out.append(f"### Unevaluated ({len(items)}" +
               (f" of {total} in head" if total is not None else "") + ")")
    out.append("")
    if not items:
        out.append("Nothing relevant to this change was left unevaluated.")
    else:
        out.append("These edges could not be fully evaluated and are **never** counted as "
                   "confirmed capabilities or paths:")
        out.append("")
        for u in items:
            out.append(f"- {_code(u['edge_id'])} ({u.get('edge_type', 'edge')}): "
                       f"{', '.join(u['reasons'])} -- {u['note']}"
                       + (f" _({u['relevance']})_" if u.get("relevance") else ""))
    out.append("")


def _footer(out: List[str], doc: dict) -> None:
    lim = (doc.get("tool") or {}).get("limits")
    warn = doc.get("warnings") or []
    if warn:
        out.append("**Warnings:** " + "; ".join(warn))
        out.append("")
    if lim:
        out.append("<sub>Limits: " + lim + ".</sub>")
    out.append(f"<sub>base {doc['base']['graph_digest']} -> head {doc['head']['graph_digest']}</sub>")
