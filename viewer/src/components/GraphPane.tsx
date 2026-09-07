import { memo, useMemo, type PointerEvent as ReactPointerEvent, type WheelEvent as ReactWheelEvent } from 'react';
import type { Graph, GraphEdge, GraphNode, Scope } from '../schema/types';
import { indexEdges, indexNodes, isConditionalEdge, isCrossScope, nodeLabel, type DeltaIndex, type UnionGraph } from '../lib/derive';
import type { Layout, Point } from '../layout/layout';
import type { FocusSets, Selection } from '../lib/focus';

export interface ViewTransform {
  k: number;
  tx: number;
  ty: number;
}

interface Props {
  side: 'base' | 'head';
  ref_: string;
  graph: Graph;
  union: UnionGraph;
  layout: Layout;
  delta: DeltaIndex;
  focus: FocusSets | null;
  selected: Selection | null;
  view: ViewTransform;
  identical?: boolean;
  onSelect: (s: Selection | null) => void;
  onWheel: (e: ReactWheelEvent<SVGSVGElement>) => void;
  onPointerDown: (e: ReactPointerEvent<SVGSVGElement>) => void;
  onPointerMove: (e: ReactPointerEvent<SVGSVGElement>) => void;
  onPointerUp: (e: ReactPointerEvent<SVGSVGElement>) => void;
  dragging: boolean;
  svgRef?: (el: SVGSVGElement | null) => void;
}

export const GraphPane = memo(function GraphPane(p: Props) {
  const nodesById = useMemo(() => indexNodes(p.graph), [p.graph]);
  const edgesById = useMemo(() => indexEdges(p.graph), [p.graph]);
  const scopesByKey = useMemo(() => new Map(p.graph.scopes.map((s) => [s.key, s])), [p.graph]);
  const sideLabel = p.side === 'base' ? 'Before' : 'After';

  return (
    <div className="pane" data-testid={`pane-${p.side}`}>
      <div className="pane-head">
        <span className="side">{sideLabel}</span>
        <span className="ref">{p.ref_}</span>
        {p.identical && <span className="identical">identical</span>}
      </div>
      <svg
        ref={p.svgRef}
        role="img"
        aria-label={`${sideLabel} graph, ${p.ref_}`}
        className={p.dragging ? 'dragging' : undefined}
        onWheel={p.onWheel}
        onPointerDown={p.onPointerDown}
        onPointerMove={p.onPointerMove}
        onPointerUp={p.onPointerUp}
        onPointerCancel={p.onPointerUp}
        onClick={(e) => { if (e.target === e.currentTarget) p.onSelect(null); }}
      >
        <defs>
          <pattern id="hatch" width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
            <rect width="6" height="6" fill="var(--surface)" />
            <line x1="0" y1="0" x2="0" y2="6" stroke="var(--uncertain-soft)" strokeWidth="3" />
          </pattern>
        </defs>
        <g transform={`translate(${p.view.tx} ${p.view.ty}) scale(${p.view.k})`}>
          <g className="layer clusters">
            {[...p.layout.clusters.values()].map((c) => {
              const scope = scopesByKey.get(c.key) ?? p.union.scopes.find((s) => s.key === c.key);
              return <Cluster key={c.key} box={c} scope={scope} />;
            })}
          </g>
          <g className="layer edges">
            {p.union.edges.map((ue) => {
              if (ue.side !== 'both' && ue.side !== p.side) return null;
              const edge = edgesById.get(ue.id);
              const path = p.layout.edges.get(ue.key);
              if (!edge || !path || edge.source !== ue.source || edge.target !== ue.target) return null;
              const dk = p.delta.edges.get(ue.id);
              const dimmed = p.focus ? !p.focus.edges.has(ue.key) : false;
              return (
                <Edge
                  key={ue.key}
                  edge={edge}
                  points={path.points}
                  delta={dk}
                  cross={isCrossScope(edge, nodesById)}
                  dimmed={dimmed}
                  selected={p.selected?.kind === 'edge' && p.selected.id === edge.id}
                  onSelect={() => p.onSelect({ kind: 'edge', id: edge.id })}
                />
              );
            })}
          </g>
          <g className="layer nodes">
            {p.union.nodes.map((un) => {
              const box = p.layout.nodes.get(un.id);
              if (!box) return null;
              const node = nodesById.get(un.id);
              const ghost = !node;
              const dk = p.delta.nodes.get(un.id);
              const dimmed = p.focus ? !(p.focus.primary.has(un.id) || p.focus.secondary.has(un.id)) : false;
              return (
                <Node
                  key={un.id}
                  node={node ?? un}
                  box={box}
                  ghost={ghost}
                  delta={ghost ? undefined : dk}
                  dimmed={dimmed}
                  primary={p.focus?.primary.has(un.id) ?? false}
                  selected={p.selected?.kind === 'node' && p.selected.id === un.id}
                  onSelect={() => p.onSelect({ kind: 'node', id: un.id })}
                />
              );
            })}
          </g>
        </g>
      </svg>
    </div>
  );
});

// ---- Cluster ------------------------------------------------------------

function Cluster({ box, scope }: { box: { x: number; y: number; width: number; height: number; key: string }; scope?: Scope }) {
  const low = scope?.confidence === 'low';
  const sub = scope ? [scope.source.replace('_', ' '), `${scope.confidence} confidence`, scope.root_module ?? null].filter(Boolean).join(' · ') : '';
  return (
    <g data-testid="scope-cluster" data-scope={box.key} data-confidence={scope?.confidence}>
      <rect className={`cluster-box${low ? ' low' : ''}`} x={box.x} y={box.y} width={box.width} height={box.height} rx={10} />
      <text className="cluster-title" x={box.x + 14} y={box.y + 20}>{box.key}</text>
      <text className="cluster-sub" x={box.x + 14} y={box.y + 34}>{sub}</text>
      {low && (
        <g transform={`translate(${box.x + box.width - 14} ${box.y + 12})`} data-testid="scope-low-confidence">
          <rect className="cluster-warn-bg" x={-150} y={-2} width={150} height={16} rx={3} />
          <text className="cluster-warn" x={-75} y={10} textAnchor="middle">LOW-CONFIDENCE SCOPE</text>
        </g>
      )}
    </g>
  );
}

// ---- Edge -------------------------------------------------------------------

function smoothPath(pts: Point[]): string {
  if (pts.length === 0) return '';
  if (pts.length === 1) return `M${pts[0].x} ${pts[0].y}`;
  if (pts.length === 2) return `M${pts[0].x} ${pts[0].y} L${pts[1].x} ${pts[1].y}`;
  let d = `M${pts[0].x} ${pts[0].y}`;
  for (let i = 1; i < pts.length - 1; i++) {
    const c = pts[i];
    const n = pts[i + 1];
    const mx = (c.x + n.x) / 2;
    const my = (c.y + n.y) / 2;
    d += ` Q${c.x} ${c.y} ${mx} ${my}`;
  }
  const last = pts[pts.length - 1];
  d += ` L${last.x} ${last.y}`;
  return d;
}

function midpoint(pts: Point[]): { p: Point; angle: number } {
  let total = 0;
  const seg: number[] = [];
  for (let i = 1; i < pts.length; i++) {
    const l = Math.hypot(pts[i].x - pts[i - 1].x, pts[i].y - pts[i - 1].y);
    seg.push(l);
    total += l;
  }
  let acc = 0;
  for (let i = 0; i < seg.length; i++) {
    if (acc + seg[i] >= total / 2) {
      const t = seg[i] === 0 ? 0 : (total / 2 - acc) / seg[i];
      const a = pts[i];
      const b = pts[i + 1];
      return { p: { x: a.x + (b.x - a.x) * t, y: a.y + (b.y - a.y) * t }, angle: Math.atan2(b.y - a.y, b.x - a.x) };
    }
    acc += seg[i];
  }
  const l = pts[pts.length - 1];
  return { p: l, angle: 0 };
}

function arrowHead(pts: Point[], size = 7): string {
  const b = pts[pts.length - 1];
  const a = pts[pts.length - 2] ?? b;
  const ang = Math.atan2(b.y - a.y, b.x - a.x);
  const p1 = { x: b.x - size * Math.cos(ang - Math.PI / 7), y: b.y - size * Math.sin(ang - Math.PI / 7) };
  const p2 = { x: b.x - size * Math.cos(ang + Math.PI / 7), y: b.y - size * Math.sin(ang + Math.PI / 7) };
  return `${b.x},${b.y} ${p1.x},${p1.y} ${p2.x},${p2.y}`;
}

const REASON_SHORT: Record<string, string> = {
  condition: 'condition',
  unresolved_policy_body: 'unresolved body',
  not_action: 'NotAction',
  resource_policy: 'resource policy',
};

function edgeLabelText(e: GraphEdge): string | null {
  if (e.type === 'grants') {
    const acts = e.actions ?? [];
    if (acts.length === 0) return e.resolution === 'unresolved_at_plan' ? 'actions unknown' : null;
    const shown = acts.slice(0, 2).join(', ');
    const more = acts.length > 2 ? ` +${acts.length - 2}` : '';
    const deny = e.effect === 'Deny' ? 'DENY ' : '';
    const star = (e.resource_patterns ?? []).includes('*') ? ' on *' : '';
    return `${deny}${shown}${more}${star}`;
  }
  return null;
}

function Edge({ edge, points, delta, cross, dimmed, selected, onSelect }: { edge: GraphEdge; points: Point[]; delta?: string; cross: boolean; dimmed: boolean; selected: boolean; onSelect: () => void }) {
  const conditional = isConditionalEdge(edge);
  const cls = [edge.type, conditional ? 'conditional' : '', cross ? 'cross' : '', delta ? `delta-${delta}` : ''].filter(Boolean).join(' ');
  const d = smoothPath(points);
  const mid = midpoint(points);
  const label = edgeLabelText(edge);
  const charW = 5.7;
  const labelW = label ? label.length * charW + 12 : 0;
  const crossW = 84;
  const reasons = (edge.unevaluated ?? []).map((r) => REASON_SHORT[r] ?? r).join(', ');
  const qW = reasons.length * charW + 24;
  // Stack badges above the label so they never overlap.
  let stackY = mid.p.y - 9;
  const items: JSX.Element[] = [];
  if (label) {
    items.push(
      <g key="l" className={`edge-label ${cls}`} transform={`translate(${mid.p.x - labelW / 2} ${stackY})`}>
        <rect width={labelW} height={16} />
        <text x={labelW / 2} y={11} textAnchor="middle">{label}</text>
      </g>,
    );
    stackY -= 20;
  }
  if (cross) {
    items.push(
      <g key="c" className="edge-label cross" transform={`translate(${mid.p.x - crossW / 2} ${stackY})`} data-testid="cross-scope-marker">
        <rect width={crossW} height={16} />
        <text x={crossW / 2} y={11} textAnchor="middle">⇄ crosses scope</text>
      </g>,
    );
    stackY -= 20;
  }
  if (conditional) {
    items.push(
      <g key="q" className="qbadge" transform={`translate(${mid.p.x - qW / 2} ${stackY})`} data-testid="unevaluated-marker">
        <rect width={qW} height={16} />
        <text x={qW / 2} y={11} textAnchor="middle">? {reasons}</text>
      </g>,
    );
  }
  return (
    <g
      className={dimmed ? 'dimmed' : undefined}
      data-testid="edge"
      data-edge-id={edge.id}
      data-edge-type={edge.type}
      data-unevaluated={conditional ? 'true' : 'false'}
      data-cross-scope={cross ? 'true' : 'false'}
      data-delta={delta ?? 'unchanged'}
      onClick={(ev) => { ev.stopPropagation(); onSelect(); }}
    >
      <path className="edge-hit" d={d} />
      <path className={`edge ${cls}`} d={d} style={selected ? { filter: 'drop-shadow(0 0 3px var(--accent))' } : undefined} />
      <polygon className={`arrow ${cls}`} points={arrowHead(points)} />
      {items}
    </g>
  );
}

// ---- Node -------------------------------------------------------------------

function Glyph({ type }: { type: GraphNode['type'] }) {
  switch (type) {
    case 'principal':
      return (
        <g className="glyph">
          <circle cx="8" cy="5.5" r="3" />
          <path d="M2.5 14.5c0-3 2.5-5 5.5-5s5.5 2 5.5 5" />
        </g>
      );
    case 'policy':
      return (
        <g className="glyph">
          <path d="M3.5 1.5h6l3.5 3.5v9.5h-9.5z" />
          <path d="M9.5 1.5v3.5h3.5M5.5 8h5M5.5 11h5" />
        </g>
      );
    case 'resource':
      return (
        <g className="glyph">
          <path d="M2.5 4.5l5.5-2.5 5.5 2.5v7l-5.5 2.5-5.5-2.5z" />
          <path d="M2.5 4.5l5.5 2.5 5.5-2.5M8 7v7" />
        </g>
      );
    case 'identity_provider':
      return (
        <g className="glyph">
          <circle cx="5.5" cy="10.5" r="3" />
          <path d="M7.7 8.3l5.8-5.8M11 5l2 2M9 7l2 2" />
        </g>
      );
    case 'external':
      return (
        <g className="glyph">
          <circle cx="8" cy="8" r="6" strokeDasharray="2 2" />
          <path d="M6 10l4-4M7 6h3v3" />
        </g>
      );
    default:
      return null;
  }
}

function Node({ node, box, ghost, delta, dimmed, primary, selected, onSelect }: { node: GraphNode; box: { x: number; y: number; width: number; height: number }; ghost: boolean; delta?: string; dimmed: boolean; primary: boolean; selected: boolean; onSelect: () => void }) {
  const x = box.x - box.width / 2;
  const y = box.y - box.height / 2;
  const unresolved = node.resolution === 'unresolved_at_plan';
  const external = node.resolution === 'external' || node.type === 'external';
  const wildcard = node.type === 'wildcard';
  const cls = ['node', node.type, unresolved ? 'unresolved' : '', external ? 'external' : '', ghost ? 'ghost' : '', delta ? `delta-${delta}` : '', selected ? 'selected' : '', dimmed ? 'dimmed' : ''].filter(Boolean).join(' ');
  const label = nodeLabel(node);
  const maxChars = wildcard ? 12 : 20;
  const name = label.length > maxChars ? `${label.slice(0, maxChars - 1)}…` : label;
  const addr = node.logical_address.length > 28 ? `…${node.logical_address.slice(-27)}` : node.logical_address;

  const badges: Array<{ cls: string; text: string; w: number }> = [];
  if (delta === 'added') badges.push({ cls: 'added', text: '+', w: 14 });
  if (delta === 'removed') badges.push({ cls: 'removed', text: '−', w: 14 });
  if (delta === 'changed') badges.push({ cls: 'changed', text: '~', w: 14 });
  if (unresolved) badges.push({ cls: 'q', text: '?', w: 14 });
  if (external) badges.push({ cls: 'ext', text: 'ext', w: 24 });

  return (
    <g
      className={cls}
      transform={`translate(${x} ${y})`}
      onClick={(ev) => { ev.stopPropagation(); if (!ghost) onSelect(); }}
      data-testid="node"
      data-node-id={node.id}
      data-node-type={node.type}
      data-resolution={node.resolution}
      data-delta={ghost ? 'absent' : (delta ?? 'unchanged')}
      data-ghost={ghost ? 'true' : 'false'}
      data-wildcard={wildcard ? 'true' : 'false'}
      role={ghost ? undefined : 'button'}
      tabIndex={ghost ? -1 : 0}
      onKeyDown={(ev) => { if (!ghost && (ev.key === 'Enter' || ev.key === ' ')) { ev.preventDefault(); onSelect(); } }}
      aria-label={`${node.type} ${label}${delta ? `, ${delta}` : ''}${unresolved ? ', unresolved at plan time' : ''}${external ? ', external' : ''}`}
    >
      {primary && <rect className="node-halo" x={-4} y={-4} width={box.width + 8} height={box.height + 8} />}
      <rect className="node-box" width={box.width} height={box.height} />
      {wildcard ? (
        <>
          <text className="node-name" x={box.width / 2} y={box.height / 2 + 1} textAnchor="middle" dominantBaseline="middle">*</text>
          <text className="node-addr" x={box.width / 2} y={box.height - 7} textAnchor="middle">any resource</text>
        </>
      ) : (
        <>
          <g transform="translate(10 15)"><Glyph type={node.type} /></g>
          <text className="node-name" x={32} y={20}>{name}</text>
          <text className="node-addr" x={32} y={35}>{addr}</text>
        </>
      )}
      {badges.map((b, i) => {
        const bx = box.width - 6 - badges.slice(0, i + 1).reduce((s, q) => s + q.w + 4, 0) + 4;
        return (
          <g key={b.cls} className={`badge ${b.cls}`} transform={`translate(${bx} -7)`}>
            <rect width={b.w} height={14} />
            <text x={b.w / 2} y={10.5} textAnchor="middle">{b.text}</text>
          </g>
        );
      })}
    </g>
  );
}
