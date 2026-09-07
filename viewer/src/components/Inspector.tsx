import type { Diff, Graph, GraphEdge, GraphNode } from '../schema/types';
import { describeEdge, indexEdges, indexNodes, isConditionalEdge, isCrossScope, shortAddress, shortScope } from '../lib/derive';
import type { Selection } from '../lib/focus';

interface Props {
  selection: Selection;
  base: Graph;
  head: Graph;
  diff: Diff;
  onClose: () => void;
}

export function Inspector({ selection, base, head, diff, onClose }: Props) {
  if (selection.kind === 'node') {
    const b = indexNodes(base).get(selection.id) ?? null;
    const h = indexNodes(head).get(selection.id) ?? null;
    const changed = diff.structural.nodes.changed.find((c) => c.id === selection.id);
    return (
      <div className="inspector" data-testid="inspector" role="region" aria-label="Selected node">
        <div className="inspector-head">
          <span className="title">{(h ?? b)!.type} · {shortAddress(selection.id)}</span>
          {!b && <span className="chip added">added</span>}
          {!h && <span className="chip removed">removed</span>}
          {changed && <span className="chip changed">changed</span>}
          <button type="button" className="iconbtn close" onClick={onClose} aria-label="Close">×</button>
        </div>
        {b && h && b.digest === h.digest ? <NodeFacts n={h} /> : (
          <div className="compare">
            <div className="col removed"><h4>before · {diff.base.ref}</h4>{b ? <NodeFacts n={b} other={h} /> : <span className="muted small">absent</span>}</div>
            <div className="col added"><h4>after · {diff.head.ref}</h4>{h ? <NodeFacts n={h} other={b} /> : <span className="muted small">absent</span>}</div>
          </div>
        )}
        {changed?.property_deltas != null && (
          <pre className="mono small muted" style={{ marginTop: 8, whiteSpace: 'pre-wrap' }}>{JSON.stringify(changed.property_deltas, null, 2)}</pre>
        )}
      </div>
    );
  }

  const bE = indexEdges(base).get(selection.id) ?? null;
  const hE = indexEdges(head).get(selection.id) ?? null;
  const e = hE ?? bE;
  if (!e) return null;
  const nodesById = indexNodes(hE ? head : base);
  const cross = isCrossScope(e, nodesById);
  const conditional = isConditionalEdge(e);
  const changed = diff.structural.edges.changed.find((c) => c.id === selection.id);
  const note = diff.unevaluated.find((u) => u.edge_id === selection.id)?.note;
  return (
    <div className="inspector" data-testid="inspector" role="region" aria-label="Selected edge">
      <div className="inspector-head">
        <span className="title">{describeEdge(e)}</span>
        {!bE && <span className="chip added">added</span>}
        {!hE && <span className="chip removed">removed</span>}
        {changed && <span className="chip changed">changed</span>}
        {cross && <span className="chip cross">crosses scope</span>}
        {conditional && <span className="chip conditional">? conditional</span>}
        <button type="button" className="iconbtn close" onClick={onClose} aria-label="Close">×</button>
      </div>
      {note && <p className="small" style={{ color: 'var(--uncertain)', margin: '0 0 8px' }}>{note}</p>}
      {bE && hE && bE.digest === hE.digest ? <EdgeFacts e={hE} /> : (
        <div className="compare">
          <div className="col removed"><h4>before · {diff.base.ref}</h4>{bE ? <EdgeFacts e={bE} other={hE} /> : <span className="muted small">absent</span>}</div>
          <div className="col added"><h4>after · {diff.head.ref}</h4>{hE ? <EdgeFacts e={hE} other={bE} /> : <span className="muted small">absent</span>}</div>
        </div>
      )}
    </div>
  );
}

function same(a: unknown, b: unknown) {
  return JSON.stringify(a) === JSON.stringify(b);
}

function NodeFacts({ n, other }: { n: GraphNode; other?: GraphNode | null }) {
  const d = (k: keyof GraphNode) => (other && !same(n[k], other[k]) ? 'diff' : '');
  return (
    <dl className="kv">
      <dt>id</dt><dd>{n.id}</dd>
      <dt>scope</dt><dd className={d('scope')}>{shortScope(n.scope)} <span className="muted">· {n.scope.source} · {n.scope.confidence}{n.scope.root_module ? ` · ${n.scope.root_module}` : ''}</span></dd>
      <dt>name</dt><dd className={d('name')}>{n.name ?? <span className="muted">null</span>}</dd>
      <dt>resolution</dt><dd className={d('resolution')}>{n.resolution}{(n.unresolved_attributes?.length ?? 0) > 0 ? ` (${n.unresolved_attributes!.join(', ')})` : ''}</dd>
      {(n.aliases?.length ?? 0) > 0 && (<><dt>aliases</dt><dd className={d('aliases')}>{n.aliases!.join('\n')}</dd></>)}
      {n.properties && Object.keys(n.properties).length > 0 && (<><dt>properties</dt><dd className={d('properties')}>{JSON.stringify(n.properties)}</dd></>)}
      <dt>digest</dt><dd className={d('digest')}>{n.digest}</dd>
    </dl>
  );
}

function EdgeFacts({ e, other }: { e: GraphEdge; other?: GraphEdge | null }) {
  const d = (k: keyof GraphEdge) => (other && !same(e[k], other[k]) ? 'diff' : '');
  return (
    <dl className="kv">
      <dt>type</dt><dd className={d('type')}>{e.type}</dd>
      <dt>source</dt><dd className={d('source')}>{e.source}</dd>
      <dt>target</dt><dd className={d('target')}>{e.target}</dd>
      {e.effect != null && (<><dt>effect</dt><dd className={d('effect')}>{e.effect}</dd></>)}
      {(e.actions?.length ?? 0) > 0 && (<><dt>actions</dt><dd className={d('actions')}>{e.actions!.join(', ')}</dd></>)}
      {(e.resource_patterns?.length ?? 0) > 0 && (<><dt>resources</dt><dd className={d('resource_patterns')}>{e.resource_patterns!.join(', ')}</dd></>)}
      {e.sid && (<><dt>sid</dt><dd className={d('sid')}>{e.sid}</dd></>)}
      <dt>resolution</dt><dd className={d('resolution')}>{e.resolution}</dd>
      <dt>unevaluated</dt><dd className={d('unevaluated')}>{(e.unevaluated?.length ?? 0) > 0 ? e.unevaluated!.join(', ') : <span className="muted">none</span>}</dd>
      <dt>digest</dt><dd className={d('digest')}>{e.digest}</dd>
    </dl>
  );
}
