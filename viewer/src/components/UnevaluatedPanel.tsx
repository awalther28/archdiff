import type { UnknownItem } from '../lib/derive';
import type { Focus } from '../lib/focus';

interface Props {
  items: UnknownItem[];
  focus: Focus | null;
  onFocus: (f: Focus | null) => void;
  unchanged?: boolean;
}

const GROUPS: Array<{ kind: UnknownItem['kind']; title: string }> = [
  { kind: 'version', title: 'Extractor' },
  { kind: 'scope', title: 'Scopes with low confidence' },
  { kind: 'edge', title: 'Statements and trusts not evaluated' },
  { kind: 'node', title: 'Nodes unresolved at plan time or external' },
  { kind: 'warning', title: 'Extractor warnings' },
];

/**
 * Design invariant 3: never silently drop what we could not evaluate.
 * This section is always present, even when empty, so its absence can never
 * be mistaken for "nothing was uncertain".
 */
export function UnevaluatedPanel({ items, focus, onFocus, unchanged }: Props) {
  return (
    <section aria-labelledby="unevaluated-h" data-testid="unevaluated">
      <div className="section-head">
        <h2 id="unevaluated-h">Not evaluated</h2>
        <span className="count">{items.length}</span>
      </div>
      <p className="section-intro">
        {items.length === 0
          ? 'Every node and edge was fully resolved. Nothing was left unevaluated.'
          : unchanged
            ? 'These unknowns exist on both sides and did not change. Nothing here is counted as a confirmed capability.'
            : 'The tool could not determine these. Nothing here is counted as a confirmed capability.'}
      </p>
      {GROUPS.map((g) => {
        const rows = items.filter((i) => i.kind === g.kind);
        if (rows.length === 0) return null;
        return (
          <div className="subsection" key={g.kind} style={{ marginTop: 10 }}>
            <h3>{g.title} <span className="count">{rows.length}</span></h3>
            {rows.map((it) => {
              const key = `unknown:${it.id}`;
              const active = focus?.key === key;
              return (
                <button type="button" key={it.id} className={`unknown${active ? ' active' : ''}`} onClick={() => onFocus(active ? null : { key, nodeIds: it.nodeIds, edgeIds: it.kind === 'edge' ? [it.id] : undefined })} disabled={it.nodeIds.length === 0 && it.kind !== 'edge'} data-testid={`unknown-${it.kind}`}>
                  <span className="q" aria-hidden="true">?</span>
                  <span>
                    <span className="label" title={it.id}>{it.label}</span>
                    <span className="reasons">{it.reasons.map((r) => <span className="reason" key={r}>{r}</span>)}</span>
                    {it.note && <span className="note" style={{ display: 'block' }}>{it.note}</span>}
                  </span>
                </button>
              );
            })}
          </div>
        );
      })}
    </section>
  );
}
