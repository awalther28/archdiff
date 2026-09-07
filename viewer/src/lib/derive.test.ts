import { describe, expect, it } from 'vitest';
import { buildDeltaIndex, checkIntegrity, collectUnknowns, effectivePathConfidence, indexNodes, isConditionalEdge, isCrossScope, isEmptyDiff, unionGraph } from './derive';
import { baseGraph, headGraph, noopDiff, noopGraph, starDiff } from '../test/fixtures';
import type { PathEntry } from '../schema/types';

describe('isEmptyDiff', () => {
  it('is true for the refactor no-op diff and false for the star policy diff', () => {
    expect(isEmptyDiff(noopDiff())).toBe(true);
    expect(isEmptyDiff(starDiff())).toBe(false);
  });
  it('is false when only semantic arrays are non-empty', () => {
    const d = noopDiff();
    d.semantic.paths.added.push({ path: ['a', 'b'], hops: 1, crosses_scopes: false, terminal_capabilities: [], confidence: 'confirmed' });
    expect(isEmptyDiff(d)).toBe(false);
  });
});

describe('delta index', () => {
  it('marks the widened statement as changed and nothing else', () => {
    const idx = buildDeltaIndex(starDiff());
    expect(idx.edges.get('aws:111122223333:us-east-1/aws_iam_policy.app_data#stmt:ReadData')).toBe('changed');
    expect(idx.edges.size).toBe(1);
    expect(idx.nodes.size).toBe(0);
  });
});

describe('cross-scope and conditional detection', () => {
  it('flags mgmt_deploy -> app_admin as cross-scope', () => {
    const base = baseGraph();
    const byId = indexNodes(base);
    const e = base.edges.find((x) => x.id.endsWith('#trust:mgmt'))!;
    expect(isCrossScope(e, byId)).toBe(true);
    const attach = base.edges.find((x) => x.type === 'attaches')!;
    expect(isCrossScope(attach, byId)).toBe(false);
  });
  it('treats any non-empty unevaluated list as conditional', () => {
    expect(isConditionalEdge({ unevaluated: [] })).toBe(false);
    expect(isConditionalEdge({ unevaluated: ['condition'] })).toBe(true);
    expect(isConditionalEdge({})).toBe(false);
  });
  it('never upgrades a conditional path, and downgrades a mislabeled confirmed one', () => {
    const base = baseGraph();
    const conditional: PathEntry = { path: ['aws:111122223333:us-east-1/external.audit_role', 'aws:111122223333:us-east-1/aws_iam_role.app_admin'], hops: 1, crosses_scopes: false, terminal_capabilities: [], confidence: 'conditional' };
    expect(effectivePathConfidence(conditional, base)).toBe('conditional');
    const mislabeled: PathEntry = { ...conditional, confidence: 'confirmed' };
    expect(effectivePathConfidence(mislabeled, base)).toBe('conditional');
    const confirmed: PathEntry = { path: ['aws:999988887777:us-east-1/aws_iam_role.gha', 'aws:999988887777:us-east-1/aws_iam_role.mgmt_deploy', 'aws:111122223333:us-east-1/aws_iam_role.app_admin'], hops: 2, crosses_scopes: true, terminal_capabilities: [], confidence: 'confirmed' };
    expect(effectivePathConfidence(confirmed, base)).toBe('confirmed');
  });
});

describe('union graph', () => {
  it('keeps both endpoints for a changed edge whose target moved', () => {
    const u = unionGraph(baseGraph(), headGraph());
    const readData = u.edges.filter((e) => e.id.endsWith('#stmt:ReadData'));
    expect(readData).toHaveLength(2);
    expect(readData.map((e) => e.side).sort()).toEqual(['base', 'head']);
    expect(u.nodes).toHaveLength(10);
  });
});

describe('integrity check', () => {
  it('agrees with the differ on both fixtures', () => {
    const star = checkIntegrity(baseGraph(), headGraph(), starDiff());
    expect(star.consistentWithDiff).toBe(true);
    expect(star.edgeDigestMismatches).toEqual(['aws:111122223333:us-east-1/aws_iam_policy.app_data#stmt:ReadData']);
    expect(star.rootDigestEqual).toBe(false);
    const noop = checkIntegrity(baseGraph(), noopGraph(), noopDiff());
    expect(noop.consistentWithDiff).toBe(true);
    expect(noop.rootDigestEqual).toBe(true);
    expect(noop.nodeDigestMismatches).toEqual([]);
    expect(noop.nodesCompared).toBe(10);
    expect(noop.edgesCompared).toBe(8);
  });
  it('flags a diff that claims empty when the graphs differ', () => {
    const r = checkIntegrity(baseGraph(), headGraph(), noopDiff());
    expect(r.consistentWithDiff).toBe(false);
  });
  it('reports an extractor version mismatch', () => {
    const h = headGraph();
    h.generated_by.extractor_version = '2';
    expect(checkIntegrity(baseGraph(), h, starDiff()).extractorVersionMismatch).toEqual({ base: '1', head: '2' });
  });
});

describe('collectUnknowns', () => {
  it('surfaces diff.unevaluated, unresolved nodes and externals', () => {
    const items = collectUnknowns(baseGraph(), headGraph(), starDiff());
    const ids = items.map((i) => i.id);
    expect(ids).toContain('aws:111122223333:us-east-1/aws_iam_role.app_admin#trust:audit');
    expect(ids).toContain('aws:111122223333:us-east-1/aws_iam_policy.kms_use#stmt:unresolved');
    expect(ids).toContain('aws:111122223333:us-east-1/aws_kms_key.main');
    expect(ids).toContain('aws:111122223333:us-east-1/aws_iam_policy.kms_use');
    expect(ids).toContain('aws:111122223333:us-east-1/external.audit_role');
    // no duplicates
    expect(new Set(ids).size).toBe(ids.length);
  });
  it('surfaces low-confidence scopes', () => {
    const h = headGraph();
    for (const n of h.nodes) if (n.scope.key.startsWith('aws:9999')) n.scope = { ...n.scope, confidence: 'low', source: 'variable_heuristic' };
    h.scopes = h.scopes.map((s) => (s.key.startsWith('aws:9999') ? { ...s, confidence: 'low', source: 'variable_heuristic' } : s));
    const items = collectUnknowns(baseGraph(), h, starDiff());
    const scope = items.find((i) => i.kind === 'scope');
    expect(scope?.id).toBe('aws:999988887777:us-east-1');
    expect(scope?.nodeIds.length).toBe(3);
  });
});
