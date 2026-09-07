/**
 * Deterministic layered layout via dagre.
 *
 * Correctness requirement, not style: the same graph MUST produce the same
 * geometry every time, and both panes of the split view share one layout
 * over the union of base and head. A jittering layout would make "these
 * nodes are unchanged" unreadable, which is the whole point of the tool.
 *
 * Determinism sources:
 *  - nodes and edges are sorted by id/key before insertion (dagre's ordering
 *    heuristics are sensitive to insertion order);
 *  - dagre itself is deterministic given identical input;
 *  - no randomness, no time, no DOM measurement.
 */
import dagre from '@dagrejs/dagre';
import type { UnionGraph } from '../lib/derive';
import type { GraphNode } from '../schema/types';

export interface Point {
  x: number;
  y: number;
}

export interface NodeBox {
  id: string;
  x: number; // centre
  y: number; // centre
  width: number;
  height: number;
}

export interface EdgePath {
  key: string;
  id: string;
  points: Point[]; // from source to target, in schema direction
}

export interface ClusterBox {
  key: string;
  x: number; // top-left
  y: number;
  width: number;
  height: number;
}

export interface Layout {
  nodes: Map<string, NodeBox>;
  edges: Map<string, EdgePath>;
  clusters: Map<string, ClusterBox>;
  width: number;
  height: number;
}

export const NODE_W = 172;
export const NODE_H = 46;
const CLUSTER_PAD = 28;
const CLUSTER_HEADER = 34;

export function nodeSize(n: Pick<GraphNode, 'type'>): { width: number; height: number } {
  if (n.type === 'wildcard') return { width: 96, height: NODE_H };
  return { width: NODE_W, height: NODE_H };
}

/**
 * Edge types whose schema direction runs against the reading direction.
 * `trusted_by` is principal -> identity_provider, but the identity provider
 * is the *entry point*, so for ranking purposes we treat it as flowing
 * idp -> principal and flip the resulting points back to schema direction.
 */
const RANK_REVERSED = new Set(['trusted_by']);

export function layoutGraph(g: UnionGraph): Layout {
  const dg = new dagre.graphlib.Graph({ compound: true, multigraph: true });
  dg.setGraph({
    // Top-to-bottom: identity providers at the top, principals below them,
    // policies, then the resources they reach. Permission graphs are shallow
    // and wide in rank terms, and the split view's panes are portrait, so a
    // vertical rank axis uses the space far better than left-to-right.
    rankdir: 'TB',
    // dagre doubles rank slots for compound graphs (cluster border ranks), so
    // the visible gap between node rows is roughly NODE_H + 3 * ranksep.
    ranksep: 22,
    nodesep: 20,
    edgesep: 14,
    marginx: 16,
    marginy: 16,
    // The default ("network-simplex") is deterministic too, but tight-tree is
    // cheaper and visually calmer for wide, shallow permission graphs.
    ranker: 'tight-tree',
  });
  dg.setDefaultEdgeLabel(() => ({}));

  const scopes = [...g.scopes].sort((a, b) => a.key.localeCompare(b.key));
  for (const s of scopes) {
    dg.setNode(clusterId(s.key), { clusterLabelPos: 'top', paddingTop: CLUSTER_HEADER + CLUSTER_PAD, paddingBottom: CLUSTER_PAD, paddingLeft: CLUSTER_PAD, paddingRight: CLUSTER_PAD });
  }

  const nodes = [...g.nodes].sort((a, b) => a.id.localeCompare(b.id));
  for (const n of nodes) {
    dg.setNode(n.id, { ...nodeSize(n), label: n.id });
    dg.setParent(n.id, clusterId(n.scope.key));
  }

  const edges = [...g.edges].sort((a, b) => a.key.localeCompare(b.key));
  const nodeIds = new Set(nodes.map((n) => n.id));
  for (const e of edges) {
    if (!nodeIds.has(e.source) || !nodeIds.has(e.target)) continue;
    if (e.source === e.target) continue;
    const reversed = RANK_REVERSED.has(e.type);
    const [from, to] = reversed ? [e.target, e.source] : [e.source, e.target];
    dg.setEdge(from, to, { key: e.key, reversed, width: 0, height: 0, labelpos: 'c' }, e.key);
  }

  dagre.layout(dg);

  const outNodes = new Map<string, NodeBox>();
  for (const n of nodes) {
    const p = dg.node(n.id);
    outNodes.set(n.id, { id: n.id, x: round(p.x), y: round(p.y), width: p.width, height: p.height });
  }

  const outEdges = new Map<string, EdgePath>();
  for (const e of edges) {
    if (!nodeIds.has(e.source) || !nodeIds.has(e.target) || e.source === e.target) continue;
    const reversed = RANK_REVERSED.has(e.type);
    const [from, to] = reversed ? [e.target, e.source] : [e.source, e.target];
    const lbl = dg.edge(from, to, e.key) as { points?: Point[] } | undefined;
    let pts = (lbl?.points ?? []).map((p) => ({ x: round(p.x), y: round(p.y) }));
    if (reversed) pts = [...pts].reverse();
    outEdges.set(e.key, { key: e.key, id: e.id, points: pts });
  }

  const outClusters = new Map<string, ClusterBox>();
  for (const s of scopes) {
    const c = dg.node(clusterId(s.key)) as { x: number; y: number; width: number; height: number } | undefined;
    if (!c || !Number.isFinite(c.x)) continue;
    outClusters.set(s.key, { key: s.key, x: round(c.x - c.width / 2), y: round(c.y - c.height / 2), width: round(c.width), height: round(c.height) });
  }

  const gi = dg.graph() as { width?: number; height?: number };
  return { nodes: outNodes, edges: outEdges, clusters: outClusters, width: round(gi.width ?? 0), height: round(gi.height ?? 0) };
}

function clusterId(scopeKey: string): string {
  return `cluster::${scopeKey}`;
}

/** Round to 0.01px so floating-point noise cannot masquerade as a change. */
function round(v: number): number {
  return Math.round(v * 100) / 100;
}

/** Stable, comparable snapshot of a layout (for tests and debugging). */
export function layoutSnapshot(l: Layout): string {
  const nodes = [...l.nodes.values()].sort((a, b) => a.id.localeCompare(b.id)).map((n) => `${n.id}@${n.x},${n.y},${n.width}x${n.height}`);
  const edges = [...l.edges.values()].sort((a, b) => a.key.localeCompare(b.key)).map((e) => `${e.key}:${e.points.map((p) => `${p.x},${p.y}`).join(';')}`);
  const clusters = [...l.clusters.values()].sort((a, b) => a.key.localeCompare(b.key)).map((c) => `${c.key}@${c.x},${c.y},${c.width}x${c.height}`);
  return [...nodes, ...edges, ...clusters].join('\n');
}
