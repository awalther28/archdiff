/**
 * TypeScript mirror of Permission Graph Schema v1 (../schema/SCHEMA.md).
 * SCHEMA.md is normative; if this file disagrees with it, SCHEMA.md wins.
 */

export type ScopeSource =
  | 'explicit'
  | 'provider_config'
  | 'terragrunt_unit'
  | 'variable_heuristic'
  | 'fallback';

export type Confidence = 'high' | 'medium' | 'low';

export interface Scope {
  key: string;
  partition: string;
  account_id: string | null;
  region: string | null;
  source: ScopeSource;
  confidence: Confidence;
  /** Informational only. MUST NOT affect any digest. */
  root_module?: string | null;
}

export type NodeType =
  | 'principal'
  | 'policy'
  | 'resource'
  | 'identity_provider'
  | 'external'
  | 'wildcard';

export type Resolution = 'resolved' | 'unresolved_at_plan' | 'external';

export interface GraphNode {
  id: string;
  type: NodeType;
  scope: Scope;
  logical_address: string;
  name?: string | null;
  aliases?: string[];
  resolution: Resolution;
  unresolved_attributes?: string[];
  properties?: Record<string, unknown>;
  digest: string;
}

export type EdgeType = 'attaches' | 'can_assume' | 'trusted_by' | 'grants';

export type UnevaluatedReason =
  | 'condition'
  | 'unresolved_policy_body'
  | 'not_action'
  | 'resource_policy';

export interface GraphEdge {
  id: string;
  type: EdgeType;
  /** For can_assume: the principal that CAN ASSUME the target. */
  source: string;
  target: string;
  effect?: 'Allow' | 'Deny' | null;
  actions?: string[];
  resource_patterns?: string[];
  sid?: string | null;
  resolution: Resolution;
  /** Non-empty => this edge MUST render with an explicit marker (§4). */
  unevaluated?: UnevaluatedReason[];
  digest: string;
}

export interface ModuleEntry {
  path: string;
  digest: string;
  children?: ModuleEntry[];
}

export interface Graph {
  schema_version: '1.0';
  generated_by: { tool_version: string; extractor_version: string };
  scopes: Scope[];
  modules: ModuleEntry[];
  nodes: GraphNode[];
  edges: GraphEdge[];
  warnings?: string[];
}

// ---- Diff document (§7) ------------------------------------------------

export interface ChangedEntry {
  id: string;
  before_digest: string;
  after_digest: string;
  property_deltas?: unknown;
}

export interface StructuralSet {
  added: string[];
  removed: string[];
  changed: ChangedEntry[];
}

export type PathConfidence = 'confirmed' | 'conditional';

export interface Capability {
  principal: string;
  actions: string[];
  resource_patterns: string[];
  confidence: PathConfidence;
}

export interface PathEntry {
  path: string[];
  hops: number;
  crosses_scopes: boolean;
  terminal_capabilities: string[];
  confidence: PathConfidence;
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/**
 * SCHEMA.md §7 describes `findings` only as "the ranked, human-readable
 * layer". The field shape below is taken from fixtures/expected.diff.json;
 * everything except `title` is treated as optional so a differ that emits
 * a leaner finding still renders.
 */
export interface Finding {
  rank?: number;
  severity?: Severity | string;
  kind?: string;
  title: string;
  detail?: string;
  node_ids?: string[];
  edge_ids?: string[];
}

export interface UnevaluatedEntry {
  edge_id?: string;
  node_id?: string;
  reasons: string[];
  note?: string;
}

export interface Diff {
  /** `moved {}` blocks the differ applied to the base graph before comparing
   *  (SCHEMA.md 6.1). Non-empty means base node ids were rewritten, so the raw
   *  graphs are expected to differ. */
  moves_applied?: { scope_key: string; from: string; to: string }[];
  schema_version: '1.0';
  base: { ref: string; graph_digest: string };
  head: { ref: string; graph_digest: string };
  structural: { nodes: StructuralSet; edges: StructuralSet };
  semantic: {
    capabilities: { added: Capability[]; removed: Capability[] };
    paths: { added: PathEntry[]; removed: PathEntry[] };
  };
  findings: Finding[];
  unevaluated: UnevaluatedEntry[];
  stats: { nodes_compared: number; modules_skipped: number };
}

// ---- Viewer-only manifest ---------------------------------------------

export interface Scenario {
  id: string;
  label: string;
  summary?: string;
  base: string;
  head: string;
  diff: string;
}

export interface Manifest {
  scenarios: Scenario[];
}
