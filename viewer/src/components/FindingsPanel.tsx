import { useState } from 'react';
import type { Capability, Diff, Finding, Graph, PathEntry } from '../schema/types';
import { effectivePathConfidence, isConditionalEdge, kindLabel, shortAddress, type DeltaIndex } from '../lib/derive';
import type { Focus } from '../lib/focus';
import { AddrChip, ConfidenceChip, SeverityChip } from './Chips';

interface Props {
  diff: Diff;
  head: Graph;
  base: Graph;
  delta: DeltaIndex;
  focus: Focus | null;
  onFocus: (f: Focus | null) => void;
}

export function FindingsPanel({ diff, head, base, delta, focus, onFocus }: Props) {
  const findings = [...diff.findings].sort((a, b) => (a.rank ?? 1e9) - (b.rank ?? 1e9));
  const toggle = (f: Focus) => onFocus(focus?.key === f.key ? null : f);

  return (
    <section aria-labelledby="findings-h">
      <div className="section-head">
        <h2 id="findings-h">Findings</h2>
        <span className="count">{findings.length}</span>
        <span className="hint">ranked · click to locate</span>
      </div>

      {findings.length === 0 ? (
        <p className="empty-note">No ranked findings. The structural and semantic deltas below are the full change.</p>
      ) : (
        <ol style={{ listStyle: 'none', margin: 0, padding: 0 }}>
          {findings.map((f, i) => (
            <li key={`${f.rank ?? i}-${f.title}`}>
              <FindingCard finding={f} index={i} active={focus?.key === findingKey(f, i)} onClick={() => toggle({ key: findingKey(f, i), nodeIds: f.node_ids ?? [], edgeIds: f.edge_ids })} onAddr={(id) => onFocus({ key: `node:${id}`, nodeIds: [id] })} focus={focus} />
            </li>
          ))}
        </ol>
      )}

      <CapabilitySection title="Capabilities" diff={diff} focus={focus} onFocus={toggle} />
      <PathSection diff={diff} head={head} focus={focus} onFocus={toggle} />
      <StructuralSection diff={diff} delta={delta} base={base} head={head} focus={focus} onFocus={toggle} />
    </section>
  );
}

function findingKey(f: Finding, i: number) {
  return `finding:${f.rank ?? i}:${f.title}`;
}

function FindingCard({ finding: f, index, active, onClick, onAddr, focus }: { finding: Finding; index: number; active: boolean; onClick: () => void; onAddr: (id: string) => void; focus: Focus | null }) {
  return (
    <div
      role="button"
      tabIndex={0}
      className={`finding${active ? ' active' : ''}`}
      onClick={onClick}
      onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onClick(); } }}
      aria-pressed={active}
      data-testid="finding"
    >
      <span className="rank">{String(f.rank ?? index + 1).padStart(2, '0')}</span>
      <span>
        <span className="meta">
          <SeverityChip severity={f.severity} />
          <span className="kind">{kindLabel(f.kind)}</span>
        </span>
        <span className="title" style={{ display: 'block' }}>{f.title}</span>
        {f.detail && <span className="detail" style={{ display: 'block' }}>{f.detail}</span>}
        {(f.node_ids?.length ?? 0) > 0 && (
          <span className="nodes">
            {f.node_ids!.map((id) => (
              <AddrChip key={id} id={id} active={focus?.key === `node:${id}`} onClick={(nid) => { onAddr(nid); }} />
            ))}
          </span>
        )}
      </span>
    </div>
  );
}

function CapabilitySection({ title, diff, focus, onFocus }: { title: string; diff: Diff; focus: Focus | null; onFocus: (f: Focus) => void }) {
  const added = diff.semantic.capabilities.added;
  const removed = diff.semantic.capabilities.removed;
  if (added.length + removed.length === 0) return null;
  return (
    <div className="subsection">
      <h3>{title} <span className="count">+{added.length} −{removed.length}</span></h3>
      {added.map((c, i) => <CapabilityRow key={`a${i}`} c={c} sign="added" focus={focus} onFocus={onFocus} />)}
      {removed.map((c, i) => <CapabilityRow key={`r${i}`} c={c} sign="removed" focus={focus} onFocus={onFocus} />)}
    </div>
  );
}

function CapabilityRow({ c, sign, focus, onFocus }: { c: Capability; sign: 'added' | 'removed'; focus: Focus | null; onFocus: (f: Focus) => void }) {
  const key = `cap:${sign}:${c.principal}:${c.actions.join(',')}:${c.resource_patterns.join(',')}`;
  const wildcard = c.resource_patterns.includes('*') || c.actions.some((a) => a === '*' || a.endsWith(':*'));
  return (
    <button type="button" className={`row ${c.confidence}${focus?.key === key ? ' active' : ''}`} onClick={() => onFocus({ key, nodeIds: [c.principal] })} data-testid={`capability-${sign}`} data-confidence={c.confidence}>
      <span className={`sign ${sign}`}>{sign === 'added' ? '+' : '−'}</span>
      <span className="body">
        <span className="principal">{shortAddress(c.principal)}</span>
        <div className="cap">
          {c.actions.join(', ')} <span className="muted">on</span> {c.resource_patterns.join(', ')}
        </div>
      </span>
      <span style={{ display: 'flex', gap: 4 }}>
        {wildcard && <span className="chip wild">*</span>}
        <ConfidenceChip confidence={c.confidence} />
      </span>
    </button>
  );
}

function PathSection({ diff, head, focus, onFocus }: { diff: Diff; head: Graph; focus: Focus | null; onFocus: (f: Focus) => void }) {
  const added = diff.semantic.paths.added;
  const removed = diff.semantic.paths.removed;
  if (added.length + removed.length === 0) return null;
  return (
    <div className="subsection">
      <h3>Privilege paths <span className="count">+{added.length} −{removed.length}</span></h3>
      {added.map((p, i) => <PathRow key={`a${i}`} p={p} sign="added" graph={head} focus={focus} onFocus={onFocus} />)}
      {removed.map((p, i) => <PathRow key={`r${i}`} p={p} sign="removed" graph={null} focus={focus} onFocus={onFocus} />)}
    </div>
  );
}

export function PathRow({ p, sign, graph, focus, onFocus }: { p: PathEntry; sign: 'added' | 'removed'; graph: Graph | null; focus: Focus | null; onFocus: (f: Focus) => void }) {
  const confidence = effectivePathConfidence(p, graph);
  const key = `path:${sign}:${p.path.join('>')}`;
  // Which hops are conditional, so the chain itself can show where the doubt is.
  const hopConditional = p.path.slice(0, -1).map((a, i) => {
    const b = p.path[i + 1];
    if (!graph) return confidence === 'conditional';
    const es = graph.edges.filter((e) => e.source === a && e.target === b);
    return es.length > 0 && es.every(isConditionalEdge);
  });
  const conditionalHops = hopConditional.filter(Boolean).length;
  return (
    <button type="button" className={`row ${confidence}${focus?.key === key ? ' active' : ''}`} onClick={() => onFocus({ key, nodeIds: p.path })} data-testid={`path-${sign}`} data-confidence={confidence}>
      <span className={`sign ${sign}`}>{sign === 'added' ? '+' : '−'}</span>
      <span className="body">
        <span className="pathchain">
          {p.path.map((id, i) => (
            <span key={id + i} style={{ display: 'contents' }}>
              {i > 0 && <span className={`hop${hopConditional[i - 1] ? ' conditional' : ''}`} title={hopConditional[i - 1] ? 'this hop was not fully evaluated' : undefined}>{hopConditional[i - 1] ? '⇢' : '→'}</span>}
              <span title={id}>{shortAddress(id)}</span>
            </span>
          ))}
        </span>
        <span className="pathmeta">
          {p.crosses_scopes && <span className="chip cross">crosses scope</span>}
          <span className="muted small">{p.hops} hop{p.hops === 1 ? '' : 's'}</span>
          {p.terminal_capabilities.length > 0 && <span className="caps">→ {p.terminal_capabilities.join(', ')}</span>}
        </span>
        {confidence === 'conditional' && (
          <span className="pathnote" style={{ display: 'block' }}>
            Conditional: {conditionalHops > 0 ? `${conditionalHops} hop${conditionalHops === 1 ? '' : 's'} could not be evaluated` : 'one or more hops could not be evaluated'}. Not counted as a confirmed capability.
          </span>
        )}
      </span>
      <ConfidenceChip confidence={confidence} />
    </button>
  );
}

function StructuralSection({ diff, delta, base, head, focus, onFocus }: { diff: Diff; delta: DeltaIndex; base: Graph; head: Graph; focus: Focus | null; onFocus: (f: Focus) => void }) {
  const [open, setOpen] = useState(true);
  const n = delta.counts.nodes;
  const e = delta.counts.edges;
  const total = n.added + n.removed + n.changed + e.added + e.removed + e.changed;
  if (total === 0) return null;
  const edgeById = new Map([...base.edges, ...head.edges].map((x) => [x.id, x]));
  const rows: Array<{ id: string; kind: 'added' | 'removed' | 'changed'; what: 'node' | 'edge'; nodeIds: string[]; edgeIds: string[] }> = [];
  for (const id of diff.structural.nodes.added) rows.push({ id, kind: 'added', what: 'node', nodeIds: [id], edgeIds: [] });
  for (const id of diff.structural.nodes.removed) rows.push({ id, kind: 'removed', what: 'node', nodeIds: [id], edgeIds: [] });
  for (const c of diff.structural.nodes.changed) rows.push({ id: c.id, kind: 'changed', what: 'node', nodeIds: [c.id], edgeIds: [] });
  const edgeRow = (id: string, kind: 'added' | 'removed' | 'changed') => {
    const ed = edgeById.get(id);
    rows.push({ id, kind, what: 'edge', nodeIds: ed ? [ed.source, ed.target] : [], edgeIds: [id] });
  };
  for (const id of diff.structural.edges.added) edgeRow(id, 'added');
  for (const id of diff.structural.edges.removed) edgeRow(id, 'removed');
  for (const c of diff.structural.edges.changed) edgeRow(c.id, 'changed');

  return (
    <div className="subsection">
      <h3>
        <button type="button" onClick={() => setOpen(!open)} style={{ display: 'inline-flex', gap: 6, alignItems: 'baseline' }} aria-expanded={open}>
          <span className="muted" style={{ fontSize: 10 }}>{open ? '▾' : '▸'}</span> Structural
          <span className="count">
            {n.added + n.removed + n.changed} node{n.added + n.removed + n.changed === 1 ? '' : 's'} · {e.added + e.removed + e.changed} edge{e.added + e.removed + e.changed === 1 ? '' : 's'}
          </span>
        </button>
      </h3>
      {open &&
        rows.map((r) => {
          const key = `struct:${r.kind}:${r.id}`;
          return (
            <button type="button" key={key} className={`row${focus?.key === key ? ' active' : ''}`} onClick={() => onFocus({ key, nodeIds: r.nodeIds, edgeIds: r.edgeIds })}>
              <span className={`sign ${r.kind}`}>{r.kind === 'added' ? '+' : r.kind === 'removed' ? '−' : '~'}</span>
              <span className="body">
                <div className="cap" title={r.id}>{shortAddress(r.id)}</div>
              </span>
              <span className="chip neutral">{r.what}</span>
            </button>
          );
        })}
    </div>
  );
}
