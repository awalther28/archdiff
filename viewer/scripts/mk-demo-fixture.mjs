// Authors the third demo scenario, "PR-3 · contractor trust", from base.graph.json.
// This is VIEWER demo data written against SCHEMA.md, not differ output. It
// exists to exercise: an added node, added edges, a confirmed cross-scope
// path, a conditional cross-scope path, a wildcard grant, a removed edge and a
// low-confidence scope. Digests follow SCHEMA.md §5 via canonical.mjs.
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { edgeDigest, moduleDigest, nodeDigest, nodeId } from './canonical.mjs';

const dir = join(process.cwd(), 'public', 'data');
const base = JSON.parse(readFileSync(join(dir, 'base.graph.json'), 'utf8'));
const head = JSON.parse(JSON.stringify(base));

const MGMT = base.scopes.find((s) => s.key.startsWith('aws:9999'));
const SUB = base.scopes.find((s) => s.key.startsWith('aws:1111'));
const VENDOR = { key: 'aws:444455556666:us-east-1', partition: 'aws', account_id: '444455556666', region: 'us-east-1', source: 'variable_heuristic', confidence: 'low', root_module: 'live/vendor/iam' };

function node(scope, addr, type, name, aliases = [], resolution = 'resolved', unresolved = [], properties = {}) {
  const n = { id: nodeId(scope.key, addr), type, scope, logical_address: addr, name, aliases, resolution, unresolved_attributes: unresolved, properties };
  n.digest = nodeDigest(n);
  return n;
}
function edge(id, type, source, target, extra = {}) {
  const e = { id, type, source, target, effect: extra.effect ?? null, actions: extra.actions ?? [], resource_patterns: extra.resource_patterns ?? [], sid: extra.sid ?? null, resolution: extra.resolution ?? 'resolved', unevaluated: extra.unevaluated ?? [] };
  e.digest = edgeDigest(e);
  return e;
}

const contractor = node(VENDOR, 'aws_iam_role.contractor', 'principal', 'contractor-deploy', ['arn:aws:iam::444455556666:role/contractor-deploy']);
const vendorPolicy = node(VENDOR, 'aws_iam_policy.contractor_admin', 'policy', 'contractor-admin', ['arn:aws:iam::444455556666:policy/contractor-admin']);
const vendorWildcard = node(VENDOR, 'wildcard.all', 'wildcard', null);
head.scopes.push(VENDOR);
head.nodes.push(contractor, vendorPolicy, vendorWildcard);

const appAdmin = nodeId(SUB.key, 'aws_iam_role.app_admin');
const mgmtDeploy = nodeId(MGMT.key, 'aws_iam_role.mgmt_deploy');
const gha = nodeId(MGMT.key, 'aws_iam_role.gha');

// gha -> contractor (confirmed), contractor -> app_admin (guarded by a Condition => conditional)
const eGhaContractor = edge(`${VENDOR.key}/aws_iam_role.contractor#trust:gha`, 'can_assume', gha, contractor.id, { effect: 'Allow', actions: ['sts:AssumeRole'] });
const eContractorApp = edge(`${SUB.key}/aws_iam_role.app_admin#trust:contractor`, 'can_assume', contractor.id, appAdmin, { effect: 'Allow', actions: ['sts:AssumeRole'], unevaluated: ['condition'] });
const eAttach = edge(`${VENDOR.key}/aws_iam_role.contractor#attach:contractor_admin`, 'attaches', contractor.id, vendorPolicy.id);
const eGrant = edge(`${VENDOR.key}/aws_iam_policy.contractor_admin#stmt:Admin`, 'grants', vendorPolicy.id, vendorWildcard.id, { effect: 'Allow', actions: ['iam:PassRole', 'sts:AssumeRole'], resource_patterns: ['*'], sid: 'Admin' });
head.edges.push(eGhaContractor, eContractorApp, eAttach, eGrant);

// The old mgmt -> app_admin trust is removed in this PR.
const removedId = `${SUB.key}/aws_iam_role.app_admin#trust:mgmt`;
head.edges = head.edges.filter((e) => e.id !== removedId);

head.nodes.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
head.edges.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
head.modules = [{ path: 'root', digest: moduleDigest(head.nodes.map((n) => n.digest), head.edges.map((e) => e.digest), []), children: [] }];
head.warnings = ['scope for live/vendor/iam resolved from var.account_id; confirm the target account'];

const diff = {
  schema_version: '1.0',
  base: { ref: 'main', graph_digest: base.modules[0].digest },
  head: { ref: 'pr-3-contractor-trust', graph_digest: head.modules[0].digest },
  structural: {
    nodes: { added: [contractor.id, vendorPolicy.id, vendorWildcard.id].sort(), removed: [], changed: [] },
    edges: { added: [eGhaContractor.id, eContractorApp.id, eAttach.id, eGrant.id].sort(), removed: [removedId], changed: [] },
  },
  semantic: {
    capabilities: {
      added: [{ principal: contractor.id, actions: ['iam:PassRole', 'sts:AssumeRole'], resource_patterns: ['*'], confidence: 'confirmed' }],
      removed: [],
    },
    paths: {
      added: [
        { path: [gha, contractor.id], hops: 1, crosses_scopes: true, terminal_capabilities: ['iam:PassRole', 'sts:AssumeRole'], confidence: 'confirmed' },
        { path: [gha, contractor.id, appAdmin], hops: 2, crosses_scopes: true, terminal_capabilities: ['s3:GetObject', 's3:ListBucket'], confidence: 'conditional' },
      ],
      removed: [
        { path: [gha, mgmtDeploy, appAdmin], hops: 2, crosses_scopes: true, terminal_capabilities: ['s3:GetObject', 's3:ListBucket'], confidence: 'confirmed' },
      ],
    },
  },
  findings: [
    { rank: 1, severity: 'high', kind: 'cross_scope_path_added', title: 'gha-role can now assume a role in account 444455556666', detail: 'A new trust lets aws_iam_role.gha (mgmt) assume aws_iam_role.contractor in a scope resolved only by variable heuristic (low confidence). The target account may not be the one shown.', node_ids: [gha, contractor.id], edge_ids: [eGhaContractor.id] },
    { rank: 2, severity: 'high', kind: 'wildcard_capability_added', title: 'contractor-deploy gained iam:PassRole and sts:AssumeRole on *', detail: 'aws_iam_policy.contractor_admin statement Admin grants iam:PassRole, sts:AssumeRole on Resource "*". Reachable from gha-role via the new trust.', node_ids: [vendorPolicy.id, vendorWildcard.id], edge_ids: [eGrant.id] },
    { rank: 3, severity: 'medium', kind: 'path_added', title: 'Conditional path from gha-role into prod app-admin via contractor', detail: 'aws_iam_role.contractor may assume aws_iam_role.app_admin, but the trust carries a Condition that was not evaluated. Treat as unconfirmed until reviewed.', node_ids: [gha, contractor.id, appAdmin], edge_ids: [eContractorApp.id] },
    { rank: 4, severity: 'low', kind: 'cross_scope_path_removed', title: 'mgmt-deploy can no longer assume app-admin', detail: 'The trust from aws_iam_role.mgmt_deploy (mgmt) to aws_iam_role.app_admin (prod) was removed.', node_ids: [mgmtDeploy, appAdmin], edge_ids: [removedId] },
  ],
  unevaluated: [
    { edge_id: eContractorApp.id, reasons: ['condition'], note: 'Trust from contractor-deploy guarded by a Condition (likely sts:ExternalId); not evaluated.' },
    { edge_id: `${SUB.key}/aws_iam_role.app_admin#trust:audit`, reasons: ['condition'], note: 'Third-party trust guarded by a Condition; not evaluated.' },
    { edge_id: `${SUB.key}/aws_iam_policy.kms_use#stmt:unresolved`, reasons: ['unresolved_policy_body'], note: 'Policy body references aws_kms_key.main.arn, unknown at plan time.' },
  ],
  stats: { nodes_compared: head.nodes.length, modules_skipped: 0 },
};

const dump = (o) => JSON.stringify(o, null, 2);
const sortKeys = (v) => (Array.isArray(v) ? v.map(sortKeys) : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortKeys(v[k])])) : v);
writeFileSync(join(dir, 'head-contractor.graph.json'), `${dump(sortKeys(head))}\n`);
writeFileSync(join(dir, 'contractor.diff.json'), `${dump(sortKeys(diff))}\n`);
console.log('wrote head-contractor.graph.json and contractor.diff.json; head root digest', head.modules[0].digest);
