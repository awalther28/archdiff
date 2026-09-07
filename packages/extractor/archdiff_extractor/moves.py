"""Terraform ``moved {}`` blocks (SCHEMA.md section 6.1).

They do NOT appear anywhere in ``tofu show -json`` when there is no prior
state, so they are parsed from the HCL source of the root module and of every
local child module (addresses inside a child module are prefixed with
``module.<name>.``). When prior state exists, ``resource_changes[].
previous_address`` carries the same information and is merged in.

Semantics emitted for the differ:

* prefix match -- ``from = module.app`` also renames everything beneath it;
* chains resolved transitively (A->B, B->C  =>  A->C), cycles detected;
* one entry per scope the ``to`` address lands in.
"""
from __future__ import annotations

import glob
import json
import os
import re
from typing import Dict, List, Optional, Sequence, Tuple

Move = Tuple[str, str]   # (from, to)

_ASSIGN_RE = re.compile(r'^\s*(from|to)\s*=\s*(.+?)\s*$')


def parse_moved_blocks(text: str) -> List[Move]:
    """All ``moved { from = ... to = ... }`` blocks in one HCL document."""
    moves: List[Move] = []
    for body in _blocks(text, "moved"):
        fields: Dict[str, str] = {}
        for line in body.splitlines():
            line = _strip_comment(line)
            m = _ASSIGN_RE.match(line)
            if m:
                fields[m.group(1)] = m.group(2).strip()
        if "from" in fields and "to" in fields:
            moves.append((fields["from"], fields["to"]))
    return moves


def parse_moved_json(doc: object) -> List[Move]:
    """``.tf.json`` form: ``{"moved": [{"from": ..., "to": ...}, ...]}``."""
    out: List[Move] = []
    if isinstance(doc, dict):
        blocks = doc.get("moved") or []
        if isinstance(blocks, dict):
            blocks = [blocks]
        for b in blocks:
            if isinstance(b, dict) and "from" in b and "to" in b:
                out.append((str(b["from"]), str(b["to"])))
    return out


def load_moves_from_dir(root_dir: str, module_sources: Optional[Dict[str, str]] = None,
                        _prefix: str = "", _seen: Optional[set] = None) -> Tuple[List[Move], List[str]]:
    """Moves declared in ``root_dir`` and, recursively, in its local child modules.

    ``module_sources`` maps a module-call name to its ``source`` string (only
    local paths are followed); nested modules are discovered from their own
    ``module`` blocks' ``source`` when they are local.
    """
    warnings: List[str] = []
    seen = _seen if _seen is not None else set()
    real = os.path.realpath(root_dir)
    if real in seen:
        return [], warnings
    seen.add(real)
    if not os.path.isdir(root_dir):
        return [], [f"moved-block source directory not found: {root_dir}"]
    moves: List[Move] = []
    for path in sorted(glob.glob(os.path.join(root_dir, "*.tf"))):
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
        moves.extend((_prefix + f, _prefix + t) for f, t in parse_moved_blocks(text))
    for path in sorted(glob.glob(os.path.join(root_dir, "*.tf.json"))):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                moves.extend((_prefix + f, _prefix + t) for f, t in parse_moved_json(json.load(fh)))
        except ValueError as exc:
            warnings.append(f"{path}: not valid JSON ({exc})")
    sources = dict(module_sources or {})
    if not sources:
        sources = _module_sources_from_hcl(root_dir)
    for name, source in sorted(sources.items()):
        if not (source.startswith("./") or source.startswith("../") or source.startswith("/")):
            continue
        child_dir = os.path.normpath(os.path.join(root_dir, source))
        child_moves, w = load_moves_from_dir(child_dir, None, f"{_prefix}module.{name}.", seen)
        moves.extend(child_moves)
        warnings.extend(w)
    return moves, warnings


def resolve_chains(moves: Sequence[Move]) -> Tuple[List[Move], List[str]]:
    """Compose A->B, B->C into A->C (by prefix), drop cycles with a warning."""
    warnings: List[str] = []
    uniq: List[Move] = []
    for m in moves:
        if m not in uniq and m[0] != m[1]:
            uniq.append(m)
    out: List[Move] = []
    for frm, to in uniq:
        final = to
        trail = [frm, to]
        for _ in range(len(uniq) + 1):
            nxt = _apply_once(final, [m for m in uniq if m != (frm, to)])
            if nxt == final:
                break
            if nxt in trail:
                warnings.append(f"moved-block cycle detected: {' -> '.join(trail + [nxt])}; move dropped")
                final = None
                break
            trail.append(nxt)
            final = nxt
        if final is None:
            continue
        if final == frm:
            warnings.append(f"moved-block cycle detected: {' -> '.join(trail)}; move dropped")
            continue
        if (frm, final) not in out:
            out.append((frm, final))
    return out, warnings


def prefix_matches(prefix: str, address: str) -> bool:
    return address == prefix or address.startswith(prefix + ".") or address.startswith(prefix + "[")


def rewrite(address: str, moves: Sequence[Move]) -> str:
    """Apply the longest matching ``from`` prefix once."""
    best = None
    for frm, to in moves:
        if prefix_matches(frm, address) and (best is None or len(frm) > len(best[0])):
            best = (frm, to)
    if best is None:
        return address
    return best[1] + address[len(best[0]):]


# -- internals -------------------------------------------------------------------

def _apply_once(address: str, moves: Sequence[Move]) -> str:
    return rewrite(address, moves)


def _strip_comment(line: str) -> str:
    out = []
    in_str = False
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == '"' and (i == 0 or line[i - 1] != "\\"):
            in_str = not in_str
        if not in_str and (ch == "#" or line.startswith("//", i)):
            break
        out.append(ch)
        i += 1
    return "".join(out)


def _blocks(text: str, block_type: str) -> List[str]:
    """Bodies of top-level ``<block_type> { ... }`` blocks, brace-matched and
    string/comment aware."""
    pattern = re.compile(r'(?m)^\s*' + re.escape(block_type) + r'\s*\{')
    return [_body_after(text, m.end()) for m in pattern.finditer(text)]


def _body_after(text: str, i: int) -> str:
    """Text from ``i`` (just after an opening brace) to its matching brace."""
    depth = 1
    in_str = False
    in_line_comment = False
    in_block_comment = False
    start = i
    while i < len(text) and depth > 0:
        ch = text[i]
        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
        elif in_block_comment:
            if text.startswith("*/", i):
                in_block_comment = False
                i += 1
        elif in_str:
            if ch == "\\":
                i += 1
            elif ch == '"':
                in_str = False
        else:
            if ch == '"':
                in_str = True
            elif ch == "#" or text.startswith("//", i):
                in_line_comment = True
            elif text.startswith("/*", i):
                in_block_comment = True
                i += 1
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
        i += 1
    return text[start:i - 1]


_MODULE_RE = re.compile(r'(?m)^\s*module\s+"([^"]+)"\s*\{')
_SOURCE_RE = re.compile(r'^\s*source\s*=\s*"([^"]+)"\s*$')


def _module_sources_from_hcl(root_dir: str) -> Dict[str, str]:
    sources: Dict[str, str] = {}
    for path in sorted(glob.glob(os.path.join(root_dir, "*.tf"))):
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
        for m in _MODULE_RE.finditer(text):
            name = m.group(1)
            body = _body_after(text, m.end())
            for line in body.splitlines():
                sm = _SOURCE_RE.match(_strip_comment(line))
                if sm:
                    sources[name] = sm.group(1)
                    break
    return sources
