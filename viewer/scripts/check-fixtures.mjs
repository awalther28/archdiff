// Validates every graph in public/data against the digest rules in SCHEMA.md §5
// and the sorting rule in §6. Run after dropping in a newly generated graph.
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { edgeDigest, moduleDigest, nodeDigest } from './canonical.mjs';

const dir = join(process.cwd(), 'public', 'data');
let failures = 0;
for (const f of readdirSync(dir).filter((x) => x.endsWith('.graph.json')).sort()) {
  const g = JSON.parse(readFileSync(join(dir, f), 'utf8'));
  const problems = [];
  if (g.schema_version !== '1.0') problems.push(`schema_version ${g.schema_version}`);
  for (const n of g.nodes) {
    if (n.id !== `${n.scope.key}/${n.logical_address}`) problems.push(`node id mismatch: ${n.id}`);
    const d = nodeDigest(n);
    if (d !== n.digest) problems.push(`node digest ${n.id}: have ${n.digest}, want ${d}`);
  }
  for (const e of g.edges) {
    const d = edgeDigest(e);
    if (d !== e.digest) problems.push(`edge digest ${e.id}: have ${e.digest}, want ${d}`);
  }
  const ids = g.nodes.map((n) => n.id);
  if (JSON.stringify(ids) !== JSON.stringify([...ids].sort())) problems.push('nodes not sorted by id');
  const eids = g.edges.map((e) => e.id);
  if (JSON.stringify(eids) !== JSON.stringify([...eids].sort())) problems.push('edges not sorted by id');
  // Single-root fixture convention: root module digest covers all nodes/edges.
  if (g.modules.length === 1 && (g.modules[0].children ?? []).length === 0) {
    const want = moduleDigest(g.nodes.map((n) => n.digest), g.edges.map((e) => e.digest), []);
    if (want !== g.modules[0].digest) problems.push(`root module digest: have ${g.modules[0].digest}, want ${want}`);
  }
  if (problems.length) { failures++; console.log(`FAIL ${f}\n  ${problems.join('\n  ')}`); }
  else console.log(`ok   ${f}  root=${g.modules[0]?.digest}  nodes=${g.nodes.length} edges=${g.edges.length}`);
}
for (const f of readdirSync(dir).filter((x) => x.endsWith('.diff.json')).sort()) {
  const d = JSON.parse(readFileSync(join(dir, f), 'utf8'));
  const problems = [];
  for (const k of ['structural', 'semantic', 'findings', 'unevaluated', 'stats', 'base', 'head']) if (!(k in d)) problems.push(`missing ${k}`);
  if (problems.length) { failures++; console.log(`FAIL ${f}\n  ${problems.join('\n  ')}`); }
  else console.log(`ok   ${f}  ${d.base.ref} -> ${d.head.ref}  findings=${d.findings.length}`);
}
process.exit(failures ? 1 : 0);
