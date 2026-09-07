"""Orchestration: two Graphs -> the section-7 diff document."""
import json
import time
from typing import Dict, Optional

from .findings import build_findings, build_unevaluated
from .graph import Graph, GraphError, check_compatible
from .catalog import CATALOG_VERSION, SERVICES
from .semantic import CATALOG_NOTE, MAX_HOPS, semantic_diff
from .moves import apply_moves
from .structural import structural_diff

__version__ = "0.1.0"
DIFF_SCHEMA_VERSION = "1.0"


class DiffResult:
    def __init__(self, doc: dict, timings: Dict[str, float]) -> None:
        self.doc = doc
        self.timings = timings  # seconds, never written into the document

    @property
    def is_empty(self) -> bool:
        return bool(self.doc["empty"])


def diff_graphs(base: Graph, head: Graph, base_ref: str = "base", head_ref: str = "head",
                use_merkle: bool = True, full_semantic: bool = False,
                max_hops: int = MAX_HOPS, allow_version_mismatch: bool = False) -> DiffResult:
    ok, why = check_compatible(base, head)
    if not ok and not allow_version_mismatch:
        raise GraphError(why + " (pass allow_version_mismatch to diff anyway)")
    timings: Dict[str, float] = {}

    # SCHEMA.md 6.1: the head graph's `moved {}` blocks describe base->head
    # renames.  Apply them to the base graph BEFORE any comparison, or a
    # refactor that relocates resources reads as added/removed churn.
    moves_applied: list = []
    move_warnings: list = []
    head_moves = head.doc.get("moves") or []
    if head_moves:
        t0 = time.perf_counter()
        rewritten, moves_applied, move_warnings = apply_moves(base.doc, head_moves)
        if moves_applied:
            base = Graph(rewritten, name=base.name)
        timings["moves"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    struct = structural_diff(base, head, use_merkle=use_merkle)
    timings["structural"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    sem = semantic_diff(base, head, struct.dirty_node_ids, struct.dirty_edge_ids,
                        full=full_semantic, max_hops=max_hops)
    timings["semantic"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    findings = build_findings(base, head, struct, sem)
    unevaluated = build_unevaluated(base, head, struct, sem)
    timings["findings"] = time.perf_counter() - t0

    empty = struct.is_empty and sem.is_empty and not findings and not unevaluated
    stats = dict(struct.stats)
    stats["semantic"] = {
        "mode": sem.mode,
        "principals_evaluated": len(sem.principals_evaluated),
        "paths_enumerated": sem.paths_enumerated,
        "max_hops": max_hops,
    }
    stats["unevaluated_edges_in_head"] = head.unevaluated_edge_count
    warnings = list(move_warnings)
    if not ok:
        warnings.append(why)
    if use_merkle and not stats["merkle"]["enabled"]:
        # requested but could not be trusted -- worth telling the reader
        warnings.append("merkle prune not used: " + str(stats["merkle"]["fallback_reason"]))
    doc = {
        "schema_version": DIFF_SCHEMA_VERSION,
        "base": {"ref": base_ref, "graph_digest": base.graph_digest},
        "head": {"ref": head_ref, "graph_digest": head.graph_digest},
        "empty": empty,
        "moves_applied": moves_applied,
        "structural": struct.as_doc(),
        "semantic": sem.as_doc(),
        "findings": findings,
        "unevaluated": unevaluated,
        "stats": stats,
        "tool": {"name": "archdiff-differ", "version": __version__,
                 "catalog": CATALOG_VERSION,
                 "catalog_services": ", ".join(sorted(SERVICES)),
                 "limits": CATALOG_NOTE + f"; privilege paths bounded to {max_hops} hops"},
        "warnings": warnings,
    }
    return DiffResult(doc, timings)


def dumps(doc: dict) -> str:
    """Byte-reproducible serialisation: sorted keys, 2-space indent, UTF-8,
    trailing newline."""
    return json.dumps(doc, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


def is_empty_doc(doc: dict) -> bool:
    """Affirmative emptiness check straight from the document (section 8)."""
    s = doc["structural"]
    m = doc["semantic"]
    return (not any(s["nodes"].values()) and not any(s["edges"].values())
            and not any(m["capabilities"].values()) and not any(m["paths"].values())
            and not doc["findings"] and not doc["unevaluated"])
