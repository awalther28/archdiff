import { useEffect, useMemo, useState } from 'react';
import { createPortal } from 'react-dom';
import type { Diff, Graph, Scenario } from '../schema/types';
import { buildDeltaIndex, checkIntegrity, collectUnknowns, isEmptyDiff, unionGraph } from '../lib/derive';
import { layoutGraph } from '../layout/layout';
import { resolveFocus, type Focus, type Selection } from '../lib/focus';
import { FindingsPanel, findingKey } from './FindingsPanel';
import { UnevaluatedPanel } from './UnevaluatedPanel';
import { EmptyDiff } from './EmptyDiff';
import { SplitView } from './SplitView';
import { Inspector } from './Inspector';
import { Legend } from './Legend';

interface Props {
  scenario: Scenario;
  base: Graph;
  head: Graph;
  diff: Diff;
}

export function DiffView({ scenario, base, head, diff }: Props) {
  const union = useMemo(() => unionGraph(base, head), [base, head]);
  const layout = useMemo(() => layoutGraph(union), [union]);
  const delta = useMemo(() => buildDeltaIndex(diff), [diff]);
  const integrity = useMemo(() => checkIntegrity(base, head, diff), [base, head, diff]);
  const unknowns = useMemo(() => collectUnknowns(base, head, diff), [base, head, diff]);
  const empty = isEmptyDiff(diff);

  // Focus the top-ranked finding on load. Without it every PR opens on the same
  // zoomed-out estate -- the delta is one edge among dozens, so three different
  // pull requests are visually indistinguishable until you click something. The
  // empty diff has no findings and correctly stays unfocused.
  const [focus, setFocus] = useState<Focus | null>(() => {
    const top = (diff.findings ?? [])[0];
    if (!top) return null;
    const ids = [...(top.node_ids ?? [])];
    if (!ids.length && !top.edge_ids?.length) return null;
    return { key: findingKey(top, 0), nodeIds: ids, edgeIds: top.edge_ids };
  });
  const [selected, setSelected] = useState<Selection | null>(null);
  const focusSets = useMemo(() => resolveFocus(focus, union), [focus, union]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { setFocus(null); setSelected(null); }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const slot = typeof document !== 'undefined' ? document.getElementById('topbar-slot') : null;

  return (
    <div className="main" data-testid="diff-view" data-empty={empty ? 'true' : 'false'}>
      {slot && createPortal(
        <>
          <div className="refs" aria-label="Compared refs">
            <span>{diff.base.ref}</span>
            <span className="arrow">→</span>
            <span>{diff.head.ref}</span>
          </div>
          <div className="stats" aria-label="Diff statistics">
            <span><b>{diff.stats.nodes_compared}</b> nodes compared</span>
            <span><b>{diff.stats.modules_skipped}</b> modules skipped</span>
          </div>
        </>,
        slot,
      )}
      <aside className="sidebar">
        {integrity.extractorVersionMismatch && (
          <section>
            <div className="banner warn" role="alert">
              <b>Extractor version mismatch.</b> base was extracted by v{integrity.extractorVersionMismatch.base}, head by v{integrity.extractorVersionMismatch.head}. Differences below may be extractor changes rather than code changes.
            </div>
          </section>
        )}
        {!empty && !integrity.consistentWithDiff && (
          <section>
            <div className="banner danger" role="alert">
              <b>Diff disagrees with its inputs.</b> The structural section is non-empty but the viewer found no digest differences between the two graphs (or vice versa).
            </div>
          </section>
        )}
        {empty ? <EmptyDiff diff={diff} integrity={integrity} scenario={scenario} /> : (
          <FindingsPanel diff={diff} base={base} head={head} delta={delta} focus={focus} onFocus={setFocus} />
        )}
        <UnevaluatedPanel items={unknowns} focus={focus} onFocus={setFocus} unchanged={empty} />
      </aside>
      <div className="graph-area">
        <SplitView base={base} head={head} diff={diff} union={union} layout={layout} delta={delta} focus={focusSets} selected={selected} identical={empty && integrity.consistentWithDiff} onSelect={setSelected} />
        {selected && <Inspector selection={selected} base={base} head={head} diff={diff} onClose={() => setSelected(null)} />}
        <div className="graph-footer">
          <Legend />
          <span className="spacer" />
          <span className="muted small">{focus ? 'Esc to clear focus · ' : ''}scroll to zoom · drag to pan</span>
        </div>
      </div>
    </div>
  );
}
