import { describe, expect, it } from 'vitest';
import { layoutGraph, layoutSnapshot } from './layout';
import { unionGraph } from '../lib/derive';
import { baseGraph, headGraph, noopGraph } from '../test/fixtures';

function shuffled<T>(arr: T[], seed: number): T[] {
  // Deterministic LCG shuffle so the test itself is reproducible.
  const out = [...arr];
  let s = seed;
  for (let i = out.length - 1; i > 0; i--) {
    s = (s * 1103515245 + 12345) & 0x7fffffff;
    const j = s % (i + 1);
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

describe('layout determinism', () => {
  it('lays out the same graph twice with identical coordinates', () => {
    const u = unionGraph(baseGraph(), headGraph());
    const a = layoutGraph(u);
    const b = layoutGraph(u);
    expect(layoutSnapshot(a)).toEqual(layoutSnapshot(b));
    // and structurally, not just as a string
    expect([...a.nodes.entries()]).toEqual([...b.nodes.entries()]);
    expect([...a.edges.entries()]).toEqual([...b.edges.entries()]);
    expect([...a.clusters.entries()]).toEqual([...b.clusters.entries()]);
  });

  it('is independent of input order (nodes and edges are sorted before layout)', () => {
    const u = unionGraph(baseGraph(), headGraph());
    const reference = layoutSnapshot(layoutGraph(u));
    for (const seed of [1, 7, 42]) {
      const permuted = { ...u, nodes: shuffled(u.nodes, seed), edges: shuffled(u.edges, seed + 1), scopes: shuffled(u.scopes, seed + 2) };
      expect(layoutSnapshot(layoutGraph(permuted))).toEqual(reference);
    }
  });

  it('a refactor that changes only root_module produces identical geometry', () => {
    const a = layoutSnapshot(layoutGraph(unionGraph(baseGraph(), baseGraph())));
    const b = layoutSnapshot(layoutGraph(unionGraph(baseGraph(), noopGraph())));
    expect(a).toEqual(b);
  });

  it('places every node, routes every edge and boxes every scope', () => {
    const base = baseGraph();
    const u = unionGraph(base, headGraph());
    const l = layoutGraph(u);
    expect(l.nodes.size).toBe(u.nodes.length);
    for (const n of u.nodes) {
      const box = l.nodes.get(n.id)!;
      expect(Number.isFinite(box.x)).toBe(true);
      expect(Number.isFinite(box.y)).toBe(true);
    }
    expect(l.edges.size).toBe(u.edges.length);
    for (const e of l.edges.values()) expect(e.points.length).toBeGreaterThanOrEqual(2);
    expect(l.clusters.size).toBe(2);
    // nodes sit inside their scope cluster
    for (const n of u.nodes) {
      const box = l.nodes.get(n.id)!;
      const c = l.clusters.get(n.scope.key)!;
      expect(box.x - box.width / 2).toBeGreaterThanOrEqual(c.x - 0.01);
      expect(box.x + box.width / 2).toBeLessThanOrEqual(c.x + c.width + 0.01);
      expect(box.y - box.height / 2).toBeGreaterThanOrEqual(c.y - 0.01);
      expect(box.y + box.height / 2).toBeLessThanOrEqual(c.y + c.height + 0.01);
    }
  });

  it('draws trusted_by edges in schema direction (principal -> identity provider)', () => {
    const u = unionGraph(baseGraph(), headGraph());
    const l = layoutGraph(u);
    const e = u.edges.find((x) => x.type === 'trusted_by')!;
    const path = l.edges.get(e.key)!;
    const src = l.nodes.get(e.source)!;
    const tgt = l.nodes.get(e.target)!;
    const first = path.points[0];
    const last = path.points[path.points.length - 1];
    const d = (p: { x: number; y: number }, n: { x: number; y: number }) => Math.hypot(p.x - n.x, p.y - n.y);
    expect(d(first, src)).toBeLessThan(d(first, tgt));
    expect(d(last, tgt)).toBeLessThan(d(last, src));
  });
});
