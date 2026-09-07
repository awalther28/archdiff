import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Diff, Graph } from '../schema/types';

const dataDir = join(process.cwd(), 'public', 'data');
function load<T>(name: string): T {
  return JSON.parse(readFileSync(join(dataDir, name), 'utf8')) as T;
}

export const baseGraph = (): Graph => load<Graph>('base.graph.json');
export const headGraph = (): Graph => load<Graph>('head.graph.json');
export const noopGraph = (): Graph => load<Graph>('refactor-noop.graph.json');
export const starDiff = (): Diff => load<Diff>('expected.diff.json');
export const noopDiff = (): Diff => load<Diff>('refactor-noop.diff.json');
