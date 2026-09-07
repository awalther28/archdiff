import type { Diff, Graph, Manifest, Scenario } from '../schema/types';

/**
 * Data is fetched at runtime from public/data/. A newly generated graph is a
 * file drop, not a rebuild. All URLs are resolved against Vite's BASE_URL so
 * the same code works at "/" locally and at "/<repo>/" on GitHub Pages.
 */
export function dataUrl(name: string): string {
  const base = import.meta.env.BASE_URL.endsWith('/') ? import.meta.env.BASE_URL : `${import.meta.env.BASE_URL}/`;
  return `${base}data/${name}`;
}

async function fetchJson<T>(url: string): Promise<T> {
  const res = await fetch(url, { cache: 'no-cache' });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText} fetching ${url}`);
  return (await res.json()) as T;
}

export function loadManifest(): Promise<Manifest> {
  return fetchJson<Manifest>(dataUrl('scenarios.json'));
}

export interface LoadedScenario {
  scenario: Scenario;
  base: Graph;
  head: Graph;
  diff: Diff;
}

export async function loadScenario(scenario: Scenario): Promise<LoadedScenario> {
  const [base, head, diff] = await Promise.all([
    fetchJson<Graph>(dataUrl(scenario.base)),
    fetchJson<Graph>(dataUrl(scenario.head)),
    fetchJson<Diff>(dataUrl(scenario.diff)),
  ]);
  for (const [label, g] of [['base', base], ['head', head]] as const) {
    if (g.schema_version !== '1.0') throw new Error(`${label} graph has schema_version ${String(g.schema_version)}; viewer supports 1.0`);
  }
  if (diff.schema_version !== '1.0') throw new Error(`diff has schema_version ${String(diff.schema_version)}; viewer supports 1.0`);
  return { scenario, base, head, diff };
}
