// JS port of ../schema/canonical.py. Normative digest rules live in SCHEMA.md §5.
import { createHash } from 'node:crypto';

export function canonicalJson(obj) {
  // Python: json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return `[${obj.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(obj).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(',')}}`;
}

export function digest(obj) {
  return createHash('sha256').update(canonicalJson(obj), 'utf8').digest('hex').slice(0, 16);
}

export function nodeDigest(n) {
  return digest({
    type: n.type,
    scope_key: n.scope.key,
    logical_address: n.logical_address,
    name: n.name ?? null,
    aliases: [...(n.aliases ?? [])].sort(),
    resolution: n.resolution ?? 'resolved',
    unresolved_attributes: [...(n.unresolved_attributes ?? [])].sort(),
    properties: n.properties ?? {},
  });
}

export function edgeDigest(e) {
  return digest({
    type: e.type,
    source: e.source,
    target: e.target,
    effect: e.effect ?? null,
    actions: [...(e.actions ?? [])].sort(),
    resource_patterns: [...(e.resource_patterns ?? [])].sort(),
    sid: e.sid ?? null,
    resolution: e.resolution ?? 'resolved',
    unevaluated: [...(e.unevaluated ?? [])].sort(),
  });
}

export function moduleDigest(nodeDigests, edgeDigests, moduleDigests) {
  return digest({ nodes: [...nodeDigests].sort(), edges: [...edgeDigests].sort(), modules: [...moduleDigests].sort() });
}

export function nodeId(scopeKey, addr) {
  return `${scopeKey}/${addr}`;
}
