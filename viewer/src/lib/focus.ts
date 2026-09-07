import type { UnionGraph } from './derive';

/** What the user asked us to draw attention to. `key` identifies the source
 *  (a finding, a path, an unknown) so the originating row can show as active. */
export interface Focus {
  key: string;
  nodeIds: string[];
  edgeIds?: string[];
}

export interface Selection {
  kind: 'node' | 'edge';
  id: string;
}

export interface FocusSets {
  primary: Set<string>;
  secondary: Set<string>;
  edges: Set<string>; // union edge keys
}

export function resolveFocus(focus: Focus | null, union: UnionGraph): FocusSets | null {
  if (!focus) return null;
  const primary = new Set(focus.nodeIds);
  const edgeIds = new Set(focus.edgeIds ?? []);
  const edges = new Set<string>();
  const secondary = new Set<string>();
  for (const e of union.edges) {
    const byId = edgeIds.has(e.id);
    const byNode = primary.has(e.source) || primary.has(e.target);
    const both = primary.has(e.source) && primary.has(e.target);
    // Only walk one hop out from explicitly focused nodes when there is no
    // explicit edge list; a path focus already names every node on it.
    if (byId || both || (byNode && edgeIds.size === 0 && primary.size === 1)) {
      edges.add(e.key);
      if (!primary.has(e.source)) secondary.add(e.source);
      if (!primary.has(e.target)) secondary.add(e.target);
    }
  }
  return { primary, secondary, edges };
}
