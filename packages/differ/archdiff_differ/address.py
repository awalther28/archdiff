"""Terraform address parsing: which module does a node or edge live in?

SCHEMA.md section 5 defines module digests over "child node digests, child edge
digests, child module digests" but neither nodes nor edges carry a module
field.  The only link is the ``module.<name>.`` prefix of a node's
``logical_address`` (section 2) and the module tree's ``path`` strings
(section 6).  This module derives a *ModuleKey* -- a tuple of module names --
from both so they can be matched.

The derivation is a heuristic, so ``archdiff_differ.structural`` never trusts it
blindly: every module it actually compares is re-hashed and checked against the
document's digest (see ``structural.verify_compared_modules``).
"""
import re
from typing import List, Tuple

ModuleKey = Tuple[str, ...]
ROOT_KEY: ModuleKey = ()
# Sentinel bucket for nodes/edges that could not be mapped onto the module
# tree.  It is always compared and never pruned, so an unmappable element can
# make the diff slower but never wrong.
UNASSIGNED_KEY: ModuleKey = ("<unassigned>",)

_ROOT_TOKENS = ("", "root", ".")


def split_address(address: str) -> List[str]:
    """Split a Terraform address on ``.`` outside brackets and quotes.

    ``module.a["x.y"].aws_iam_role.r`` -> ``["module", 'a["x.y"]', "aws_iam_role", "r"]``
    """
    segs: List[str] = []
    buf: List[str] = []
    depth = 0
    quote = None
    for ch in address:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in ('"', "'"):
            quote = ch
            buf.append(ch)
            continue
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth = max(0, depth - 1)
        if ch == "." and depth == 0:
            segs.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    segs.append("".join(buf))
    return segs


def module_key_of_address(logical_address: str) -> ModuleKey:
    """``module.a.module.b.aws_iam_role.r`` -> ``("a", "b")``; top level -> ``()``."""
    if not logical_address.startswith("module."):
        return ROOT_KEY
    if "[" in logical_address or '"' in logical_address or "'" in logical_address:
        segs = split_address(logical_address)
    else:
        segs = logical_address.split(".")   # fast path: no index/quote syntax
    names: List[str] = []
    i = 0
    while i + 1 < len(segs) and segs[i] == "module":
        names.append(segs[i + 1])
        i += 2
    return tuple(names)


def module_key_of_path(path: str) -> ModuleKey:
    """Normalise a module-tree ``path`` (SCHEMA.md section 6) to a ModuleKey.

    Accepted spellings (all map to the same key):
      ``root`` / ``""``                    -> ()
      ``module.a.module.b``                -> ("a", "b")
      ``root/module.a/module.b``           -> ("a", "b")
      ``a/b``                              -> ("a", "b")
    Anything else parses to *some* key; if no node maps onto it the module is
    simply empty from the differ's point of view.
    """
    names: List[str] = []
    for part in re.split(r"/", path.strip()):
        if part in _ROOT_TOKENS:
            continue
        segs = split_address(part)
        i = 0
        while i < len(segs):
            if segs[i] == "module" and i + 1 < len(segs):
                names.append(segs[i + 1])
                i += 2
            else:
                names.append(segs[i])
                i += 1
    return tuple(names)


def scope_key_of_id(node_id: str) -> str:
    """``{scope.key}/{logical_address}`` -> ``scope.key`` (section 2)."""
    return node_id.split("/", 1)[0]


def address_of_id(node_id: str) -> str:
    return node_id.split("/", 1)[1] if "/" in node_id else node_id
