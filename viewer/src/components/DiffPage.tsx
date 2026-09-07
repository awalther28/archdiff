import { useEffect, useState } from 'react';
import type { Scenario } from '../schema/types';
import { loadScenario, type LoadedScenario } from '../lib/load';
import { DiffView } from './DiffView';

export function DiffPage({ scenario }: { scenario: Scenario }) {
  const [data, setData] = useState<LoadedScenario | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    setData(null);
    setError(null);
    loadScenario(scenario)
      .then((d) => { if (alive) setData(d); })
      .catch((e: Error) => { if (alive) setError(e.message); });
    return () => { alive = false; };
  }, [scenario]);

  if (error) {
    return (
      <div className="state error" role="alert">
        <div>Could not load scenario “{scenario.label}”</div>
        <code>{error}</code>
      </div>
    );
  }
  if (!data) return <div className="state" aria-busy="true">Loading {scenario.label}…</div>;
  return <DiffView scenario={data.scenario} base={data.base} head={data.head} diff={data.diff} />;
}
