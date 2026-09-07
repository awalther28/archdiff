import type { Diff, Scenario } from '../schema/types';
import type { IntegrityReport } from '../lib/derive';

interface Props {
  diff: Diff;
  integrity: IntegrityReport;
  scenario: Scenario;
}

/**
 * §8: the empty diff is a first-class result. It is rendered as an
 * affirmative claim backed by evidence the viewer itself computed from the
 * two graphs, not as an absence of output.
 */
export function EmptyDiff({ diff, integrity, scenario }: Props) {
  const ok = integrity.consistentWithDiff;
  const rootDigest = diff.head.graph_digest;
  return (
    <section className="empty-diff" data-testid="empty-diff" aria-labelledby="empty-h">
      <div className="glyph" aria-hidden="true">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round">
          <path d="M5 12.5l4.5 4.5L19 7" />
        </svg>
      </div>
      <h2 id="empty-h">No permission changes</h2>
      <p className="lede">
        <code>{diff.head.ref}</code> grants exactly what <code>{diff.base.ref}</code> grants. {scenario.summary ? scenario.summary : ''}
      </p>
      {!ok && (
        <div className="banner danger" role="alert">
          <b>Inconsistent.</b> The diff document says nothing changed, but the viewer found differing digests between the two graphs. Do not trust this result until the differ and the graphs agree.
        </div>
      )}
      <dl className="evidence">
        <dt>Nodes compared</dt>
        <dd><b>{integrity.nodesCompared}</b> <span className="muted">of {integrity.nodesCompared + integrity.nodesOnlyInHead.length}</span> · digests identical <span className={integrity.nodeDigestMismatches.length === 0 && integrity.nodesOnlyInBase.length + integrity.nodesOnlyInHead.length === 0 ? 'ok' : 'warn'}>{integrity.nodeDigestMismatches.length === 0 ? '✓' : `✗ ${integrity.nodeDigestMismatches.length}`}</span></dd>
        <dt>Edges compared</dt>
        <dd><b>{integrity.edgesCompared}</b> · digests identical <span className={integrity.edgeDigestMismatches.length === 0 ? 'ok' : 'warn'}>{integrity.edgeDigestMismatches.length === 0 ? '✓' : `✗ ${integrity.edgeDigestMismatches.length}`}</span></dd>
        <dt>Root digest</dt>
        <dd><code>{rootDigest}</code> {integrity.rootDigestEqual ? <span className="ok">unchanged</span> : <span className="warn">differs</span>}</dd>
        <dt>Merkle rollup</dt>
        <dd>
          {diff.stats.modules_skipped > 0
            ? <><b>{diff.stats.modules_skipped}</b> module{diff.stats.modules_skipped === 1 ? '' : 's'} skipped by digest; <b>{diff.stats.nodes_compared}</b> node{diff.stats.nodes_compared === 1 ? '' : 's'} needed comparison</>
            : <><b>{diff.stats.nodes_compared}</b> nodes compared; no modules skipped</>}
        </dd>
        <dt>Capabilities</dt>
        <dd>none added, none removed</dd>
        <dt>Privilege paths</dt>
        <dd>none added, none removed</dd>
      </dl>
      <p className="small muted" style={{ marginTop: 14 }}>
        Both panes on the right are drawn from the same layout; a refactor that only moves resources between modules or renames files leaves every node in place.
      </p>
    </section>
  );
}
