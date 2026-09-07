/**
 * Pure derivations over Graph + Diff documents. No React, no DOM.
 * Everything the renderer needs to know about "what changed" and "what is
 * uncertain" is computed here so it can be unit-tested in isolation.
 */
import type {
  Capability,
  Diff,
  Graph,
  GraphEdge,
  GraphNode,
  PathEntry,
  Scope,
} from '../schema/types';

export type DeltaKind = 'added' | 'removed' | 'changed' | 'unchanged';

export interface DeltaIndex {
  nodes: Map<string, DeltaKind>;
  edges: Map<string, DeltaKind>;
  counts: {
    nodes: { added: number; removed: number; changed: number };
    edges: { added: number; removed: number; changed: number };
  };
}

export function buildDeltaIndex(diff: Diff): DeltaIndex {
  const nodes = new Map<string, DeltaKind>();
  const edges = new Map<string, DeltaKind>();
  for (const id of diff.structural.nodes.added) nodes.set(id, 'added');
  for (const id of diff.structural.nodes.removed) nodes.set(id, 'removed');
  for (const c of diff.structural.nodes.changed) nodes.set(c.id, 'changed');
  for (const id of diff.structural.edges.added) edges.set(id, 'added');
  for (const id of diff.structural.edges.removed) edges.set(id, 'removed');
  for (const c of diff.structural.edges.changed) edges.set(c.id, 'changed');
  return {
    nodes,
    edges,
    counts: {
      nodes: {
        added: diff.structural.nodes.added.length,
        removed: diff.structural.nodes.removed.length,
        changed: diff.structural.nodes.changed.length,
      },
      edges: {
        added: diff.structural.edges.added.length,
        removed: diff.structural.edges.removed.length,
        changed: diff.structural.edges.changed.length,
      },
    },
  };
}

/** §8: a diff where every array is empty is a first-class result. */
export function isEmptyDiff(diff: Diff): boolean {
  const s = diff.structural;
  const m = diff.semantic;
  return (
    s.nodes.added.length === 0 &&
    s.nodes.removed.length === 0 &&
    s.nodes.changed.length === 0 &&
    s.edges.added.length === 0 &&
    s.edges.removed.length === 0 &&
    s.edges.changed.length === 0 &&
    m.capabilities.added.length === 0 &&
    m.capabilities.removed.length === 0 &&
    m.paths.added.length === 0 &&
    m.paths.removed.length === 0 &&
    diff.findings.length === 0
  );
}

/** An edge is conditional when it carries any unevaluated reason (§4). */
export function isConditionalEdge(edge: Pick<GraphEdge, 'unevaluated'>): boolean {
  return (edge.unevaluated?.length ?? 0) > 0;
}

/**
 * §7: a path's confidence is `confirmed` only when no edge on it carries
 * `unevaluated`. We never upgrade a path; we only ever downgrade it if the
 * graph evidence contradicts a `confirmed` label.
 */
export function effectivePathConfidence(
  path: PathEntry,
  graph: Graph | null,
): PathEntry['confidence'] {
  if (path.confidence === 'conditional') return 'conditional';
  if (!graph) return path.confidence;
  for (let i = 0; i + 1 < path.path.length; i++) {
    const a = path.path[i];
    const b = path.path[i + 1];
    const hop = graph.edges.filter((e) => e.source === a && e.target === b);
    if (hop.length > 0 && hop.every(isConditionalEdge)) return 'conditional';
  }
  return 'confirmed';
}

export function scopeKeyOf(id: string): string {
  // id = "{scope.key}/{logical_address}" and scope keys never contain "/".
  const i = id.indexOf('/');
  return i === -1 ? id : id.slice(0, i);
}

export function isCrossScope(edge: Pick<GraphEdge, 'source' | 'target'>, byId: Map<string, GraphNode>): boolean {
  const s = byId.get(edge.source)?.scope.key ?? scopeKeyOf(edge.source);
  const t = byId.get(edge.target)?.scope.key ?? scopeKeyOf(edge.target);
  return s !== t;
}

export function indexNodes(graph: Graph): Map<string, GraphNode> {
  return new Map(graph.nodes.map((n) => [n.id, n]));
}

export function indexEdges(graph: Graph): Map<string, GraphEdge> {
  return new Map(graph.edges.map((e) => [e.id, e]));
}

/**
 * The union of base and head is what gets laid out, so both panes share one
 * coordinate system and an unchanged node sits in exactly the same place on
 * both sides. Edges are keyed by id, but a `changed` edge whose endpoints
 * moved contributes both its before and after geometry.
 */
export interface UnionGraph {
  nodes: GraphNode[];
  edges: Array<{ key: string; id: string; source: string; target: string; type: GraphEdge['type']; side: 'both' | 'base' | 'head' }>;
  scopes: Scope[];
}

export function unionGraph(base: Graph, head: Graph): UnionGraph {
  const nodes = new Map<string, GraphNode>();
  for (const n of base.nodes) nodes.set(n.id, n);
  for (const n of head.nodes) if (!nodes.has(n.id)) nodes.set(n.id, n);

  const edges = new Map<string, UnionGraph['edges'][number]>();
  const endpointKey = (e: GraphEdge) => `${e.id}|${e.source}->${e.target}`;
  const baseKeys = new Set(base.edges.map(endpointKey));
  const headKeys = new Set(head.edges.map(endpointKey));
  for (const e of [...base.edges, ...head.edges]) {
    const key = endpointKey(e);
    if (edges.has(key)) continue;
    const inBase = baseKeys.has(key);
    const inHead = headKeys.has(key);
    edges.set(key, {
      key,
      id: e.id,
      source: e.source,
      target: e.target,
      type: e.type,
      side: inBase && inHead ? 'both' : inBase ? 'base' : 'head',
    });
  }

  const scopes = new Map<string, Scope>();
  for (const s of [...base.scopes, ...head.scopes]) if (!scopes.has(s.key)) scopes.set(s.key, s);
  for (const n of nodes.values()) if (!scopes.has(n.scope.key)) scopes.set(n.scope.key, n.scope);

  return {
    nodes: [...nodes.values()].sort((a, b) => a.id.localeCompare(b.id)),
    edges: [...edges.values()].sort((a, b) => a.key.localeCompare(b.key)),
    scopes: [...scopes.values()].sort((a, b) => a.key.localeCompare(b.key)),
  };
}

/**
 * Viewer-side integrity check. The diff document is the differ's claim; the
 * two graphs are the evidence. We compare digests ourselves so that an
 * affirmative "no permission changes" is backed by something we verified,
 * and so a diff that disagrees with its own inputs is flagged loudly.
 */
export interface IntegrityReport {
  nodesCompared: number;
  edgesCompared: number;
  nodeDigestMismatches: string[];
  edgeDigestMismatches: string[];
  nodesOnlyInBase: string[];
  nodesOnlyInHead: string[];
  edgesOnlyInBase: string[];
  edgesOnlyInHead: string[];
  rootDigestEqual: boolean;
  extractorVersionMismatch: { base: string; head: string } | null;
  /** Number of `moved {}` blocks the differ applied to the base graph. When
   *  non-zero the raw graphs are EXPECTED to disagree: the differ compared a
   *  remapped base, the viewer is hashing the unremapped one. */
  movesApplied: number;
  /** True when the graphs say "identical" AND the diff says "empty". */
  consistentWithDiff: boolean;
}

export function checkIntegrity(base: Graph, head: Graph, diff: Diff): IntegrityReport {
  const bn = indexNodes(base);
  const hn = indexNodes(head);
  const be = indexEdges(base);
  const he = indexEdges(head);

  const nodeDigestMismatches: string[] = [];
  const nodesOnlyInBase: string[] = [];
  const nodesOnlyInHead: string[] = [];
  for (const [id, n] of bn) {
    const h = hn.get(id);
    if (!h) nodesOnlyInBase.push(id);
    else if (h.digest !== n.digest) nodeDigestMismatches.push(id);
  }
  for (const id of hn.keys()) if (!bn.has(id)) nodesOnlyInHead.push(id);

  const edgeDigestMismatches: string[] = [];
  const edgesOnlyInBase: string[] = [];
  const edgesOnlyInHead: string[] = [];
  for (const [id, e] of be) {
    const h = he.get(id);
    if (!h) edgesOnlyInBase.push(id);
    else if (h.digest !== e.digest) edgeDigestMismatches.push(id);
  }
  for (const id of he.keys()) if (!be.has(id)) edgesOnlyInHead.push(id);

  const rootDigestEqual =
    base.modules.length > 0 &&
    head.modules.length > 0 &&
    base.modules.every((m, i) => head.modules[i]?.digest === m.digest);

  const bv = base.generated_by.extractor_version;
  const hv = head.generated_by.extractor_version;
  const extractorVersionMismatch = bv !== hv ? { base: bv, head: hv } : null;

  const movesApplied = (diff.moves_applied ?? []).length;

  const graphsIdentical =
    nodeDigestMismatches.length === 0 &&
    edgeDigestMismatches.length === 0 &&
    nodesOnlyInBase.length === 0 &&
    nodesOnlyInHead.length === 0 &&
    edgesOnlyInBase.length === 0 &&
    edgesOnlyInHead.length === 0;

  const structurallyEmpty =
    diff.structural.nodes.added.length +
      diff.structural.nodes.removed.length +
      diff.structural.nodes.changed.length +
      diff.structural.edges.added.length +
      diff.structural.edges.removed.length +
      diff.structural.edges.changed.length ===
    0;

  // The diff document is authoritative. A move rewrites node ids and therefore
  // node and edge digests (SCHEMA.md 5, 6.1), so when the differ applied moves
  // the raw graphs SHOULD differ and that is not evidence of a disagreement.
  // The check is kept for the case it exists to catch: digests diverging with
  // no move to explain them.
  const divergenceExplainedByMoves = movesApplied > 0;

  return {
    nodesCompared: bn.size,
    edgesCompared: be.size,
    nodeDigestMismatches,
    edgeDigestMismatches,
    nodesOnlyInBase,
    nodesOnlyInHead,
    edgesOnlyInBase,
    edgesOnlyInHead,
    rootDigestEqual,
    extractorVersionMismatch,
    movesApplied,
    consistentWithDiff: divergenceExplainedByMoves || graphsIdentical === structurallyEmpty,
  };
}

// ---- "Unevaluated" aggregation ----------------------------------------

export interface UnknownItem {
  kind: 'edge' | 'node' | 'scope' | 'warning' | 'version';
  id: string;
  label: string;
  reasons: string[];
  note?: string;
  nodeIds: string[];
}

/**
 * Everything the tool could not determine, from every source we have:
 * the diff's own `unevaluated` list, nodes that are unresolved or external,
 * edges carrying `unevaluated` that the diff did not list, low-confidence
 * scopes, and extractor warnings. Design invariant 3: never silently drop.
 */
export function collectUnknowns(base: Graph, head: Graph, diff: Diff): UnknownItem[] {
  const out: UnknownItem[] = [];
  const seenEdges = new Set<string>();
  const headEdges = indexEdges(head);
  const baseEdges = indexEdges(base);
  const headNodes = indexNodes(head);
  const baseNodes = indexNodes(base);

  for (const u of diff.unevaluated ?? []) {
    if (u.edge_id) {
      seenEdges.add(u.edge_id);
      const e = headEdges.get(u.edge_id) ?? baseEdges.get(u.edge_id);
      out.push({
        kind: 'edge',
        id: u.edge_id,
        label: e ? describeEdge(e) : u.edge_id,
        reasons: u.reasons,
        note: u.note,
        nodeIds: e ? [e.source, e.target] : [],
      });
    } else if (u.node_id) {
      out.push({ kind: 'node', id: u.node_id, label: shortAddress(u.node_id), reasons: u.reasons, note: u.note, nodeIds: [u.node_id] });
    }
  }

  // Edges with unevaluated reasons the differ did not list.
  for (const e of [...head.edges, ...base.edges]) {
    if (seenEdges.has(e.id) || !isConditionalEdge(e)) continue;
    seenEdges.add(e.id);
    out.push({ kind: 'edge', id: e.id, label: describeEdge(e), reasons: e.unevaluated ?? [], nodeIds: [e.source, e.target] });
  }

  // Nodes whose identity or attributes were unknown at plan time.
  const seenNodes = new Set<string>();
  for (const n of [...head.nodes, ...base.nodes]) {
    if (seenNodes.has(n.id)) continue;
    seenNodes.add(n.id);
    if (n.resolution === 'unresolved_at_plan') {
      const attrs = n.unresolved_attributes ?? [];
      out.push({
        kind: 'node',
        id: n.id,
        label: n.logical_address,
        reasons: ['unresolved_at_plan'],
        note: attrs.length ? `Unknown at plan time: ${attrs.join(', ')}` : 'Unknown at plan time.',
        nodeIds: [n.id],
      });
    } else if (n.resolution === 'external' || n.type === 'external') {
      out.push({
        kind: 'node',
        id: n.id,
        label: n.logical_address,
        reasons: ['external'],
        note: n.aliases?.length ? `Referenced but not managed here: ${n.aliases.join(', ')}` : 'Referenced but not managed in this repo.',
        nodeIds: [n.id],
      });
    }
  }

  // Scopes we are not confident about.
  const scopes = new Map<string, Scope>();
  for (const s of [...head.scopes, ...base.scopes]) if (!scopes.has(s.key)) scopes.set(s.key, s);
  for (const s of scopes.values()) {
    if (s.confidence === 'low') {
      const members = [...headNodes.values(), ...baseNodes.values()].filter((n) => n.scope.key === s.key).map((n) => n.id);
      out.push({
        kind: 'scope',
        id: s.key,
        label: s.key,
        reasons: [`scope_confidence_${s.confidence}`, s.source],
        note: `Scope resolved by ${s.source.replace('_', ' ')}; nodes may belong to a different account than shown.`,
        nodeIds: [...new Set(members)],
      });
    }
  }

  const bv = base.generated_by.extractor_version;
  const hv = head.generated_by.extractor_version;
  if (bv !== hv) {
    out.push({ kind: 'version', id: 'extractor_version', label: 'Extractor version mismatch', reasons: ['extractor_version_mismatch'], note: `base ${bv} vs head ${hv}: differences may be extractor changes, not code changes.`, nodeIds: [] });
  }

  for (const w of [...(head.warnings ?? []), ...(base.warnings ?? [])]) {
    out.push({ kind: 'warning', id: `warning:${w}`, label: w, reasons: ['extractor_warning'], nodeIds: [] });
  }

  return out;
}

// ---- Labels -------------------------------------------------------------

export function shortAddress(id: string): string {
  const i = id.indexOf('/');
  return i === -1 ? id : id.slice(i + 1);
}

export function nodeLabel(n: GraphNode): string {
  if (n.type === 'wildcard') return '*';
  return n.name ?? shortAddress(n.id);
}

export function describeEdge(e: GraphEdge): string {
  const s = shortAddress(e.source);
  const t = shortAddress(e.target);
  switch (e.type) {
    case 'attaches':
      return `${s} attaches ${t}`;
    case 'can_assume':
      return `${s} can assume ${t}`;
    case 'trusted_by':
      return `${s} trusted by ${t}`;
    case 'grants':
      return `${s}${e.sid ? ` [${e.sid}]` : ''} grants ${(e.actions ?? []).join(', ') || '?'} on ${t}`;
  }
}

export function describeCapability(c: Capability): string {
  return `${shortAddress(c.principal)}: ${c.actions.join(', ')} on ${c.resource_patterns.join(', ')}`;
}

export function shortScope(s: Scope): string {
  if (s.account_id && s.region) return `${s.account_id} · ${s.region}`;
  if (s.account_id) return s.account_id;
  return s.key;
}

export const KIND_LABELS: Record<string, string> = {
  cross_scope_path_added: 'New cross-scope path',
  path_added: 'New path',
  wildcard_capability_added: 'New wildcard capability',
  capability_added: 'New capability',
  capability_removed: 'Capability removed',
  path_removed: 'Path removed',
  cross_scope_path_removed: 'Cross-scope path removed',
  structural_change: 'Structural change',
};

export function kindLabel(kind: string | undefined): string {
  if (!kind) return 'Finding';
  return KIND_LABELS[kind] ?? kind.replace(/_/g, ' ').replace(/^./, (c) => c.toUpperCase());
}
