# Permission Graph Schema v1

The contract between the extractor, the differ, and the renderer.
Everything in this document is normative. If an implementation and this
document disagree, this document wins.

## 0. Design invariants

1. **The graph is a pure function of the IaC configuration.** No state, no
   account access, no clock. Same config in, byte-identical graph out.
2. **Identity is readable; change detection is hashed.** Node `id` is a stable
   human-readable composite. Node `digest` is a content hash. They are
   different things and both are required.
3. **Never silently drop what we could not evaluate.** Every unknown is
   represented explicitly and surfaces in the UI. A `null` that means
   "unknown" must never be indistinguishable from a `null` that means "absent".
4. **Structural graph is stored; semantic layer is computed.** The committed
   artifact holds nodes and edges. Effective capabilities and privilege paths
   are derived by the differ, never persisted.

## 1. Scope

A scope identifies *which real-world deployment target* a node belongs to.
It is resolved **per resource**, from the resource's `provider_config_key`,
not per plan — so one root module with aliased providers spans multiple scopes,
and many Terragrunt roots targeting one account share a scope.

```json
{
  "key": "aws:111122223333:us-east-1",
  "partition": "aws",
  "account_id": "111122223333",
  "region": "us-east-1",
  "source": "provider_config",
  "confidence": "high",
  "root_module": "live/prod/iam"
}
```

`source` is one of, in precedence order:

| source | derivation | confidence |
|---|---|---|
| `explicit` | `.archdiff.yml` scope template | high |
| `provider_config` | `allowed_account_ids` / `assume_role.role_arn` / `profile`, resolved against top-level `variables` | high |
| `terragrunt_unit` | `TERRAGRUNT_WORKING_DIR` (never `cwd` — Terragrunt runs in `.terragrunt-cache/<hash>/`) | medium |
| `variable_declared` | a `variable` whose `validation {}` block constrains it to an account ID (see §1.1) | high |
| `variable_heuristic` | `var.account_id`, `var.environment`, `var.env` by name alone | low-medium |
| `fallback` | single unnamed scope | low |

Semantic scope (account+region) is preferred over path scope because path scope
churns on directory refactors. `confidence: low` MUST be surfaced in the UI.

`root_module` is informational only. It MUST NOT contribute to `key` or to any
digest, or a directory move would churn every node.

### 1.1 Confidence is evidence-based, not source-based

A scope carries the evidence that produced it:

```json
"evidence": [
  "variable_validation:^[0-9]{12}$",
  "arn_corroboration:12 literal ARNs use this account",
  "variable_name:account_id",
  "variable_description"
]
```

| confidence | requires |
|---|---|
| `high` | a `validation {}` block constraining the variable to an account ID, **or** ARN corroboration |
| `medium` | known variable name **and** a 12-digit value |
| `low` | variable name alone |

**`validation {}` blocks DO NOT appear in `tofu show -json`** — verified: `condition`,
`regex` and `error_message` all have zero occurrences in the plan JSON, though the
constraint IS enforced at plan time. Like `moved {}` (§6.1), they must be read from
HCL. Both live in the same HCL pass, so the marginal cost is nil.

Why this is not a heuristic: a `validation` block is the repository *declaring* what
the variable means, not the tool guessing from its name. `description` (which does
survive into the plan JSON) is free text and counts only as weak corroboration.

**ARN corroboration**: if the variable's value also appears as the account field of
literal ARNs the configuration emits, that is independent confirmation the value is
used as an account ID. Name matching alone never reaches `high`.

The UI MUST surface `evidence` wherever it warns about `confidence`. Saying *why* a
scope was inferred is the difference between a warning a reviewer can act on and one
they learn to ignore.

## 2. Node identity

```
id = "{scope.key}/{logical_address}"
```

`logical_address` is the full Terraform address including module path, e.g.
`module.iam.aws_iam_role.ci`. Example id:

```
aws:111122223333:us-east-1/module.iam.aws_iam_role.ci
```

Readable, stable, sortable, greppable, and diffable in git — which matters
because the graph is a committed artifact a human may read in a PR.

**Terraform addresses, not ARNs.** ARNs are unknown at plan time, and are
account-dependent. Addresses are neither.

Honor Terraform `moved {}` blocks: a declared rename is a move, not
remove+add. See §6.1 — this is required, not optional.

## 3. Node types

| type | represents |
|---|---|
| `principal` | IAM role or user |
| `policy` | managed policy or inline policy document |
| `resource` | permission target managed in the repo (KMS key, S3 bucket) |
| `identity_provider` | OIDC / SAML provider |
| `external` | an ARN referenced but not managed in this repo |
| `wildcard` | synthetic target for `Resource: "*"` |

```json
{
  "id": "aws:111122223333:us-east-1/aws_iam_role.ci",
  "type": "principal",
  "scope": { "...": "see §1" },
  "logical_address": "aws_iam_role.ci",
  "name": "ci-role",
  "aliases": ["arn:aws:iam::111122223333:role/ci-role"],
  "resolution": "resolved",
  "unresolved_attributes": [],
  "properties": {},
  "digest": "a3f9c1d2e8b40571"
}
```

`aliases` are **predicted ARNs**, built from `scope.account_id` plus the
resolved resource name. They are the join key for cross-scope reference
resolution (§4). They are NOT identity — two nodes may never be merged on
alias match alone; aliases only resolve *references*.

`resolution` is one of `resolved` | `unresolved_at_plan` | `external`.

## 4. Edge types

| type | direction | meaning |
|---|---|---|
| `attaches` | principal → policy | policy is attached to principal |
| `can_assume` | principal → principal \| external | **source can assume target** |
| `trusted_by` | principal → identity_provider \| external | federated entry point |
| `grants` | policy → resource \| external \| wildcard | a policy statement |

Direction of `can_assume` is stated explicitly because trust policies are
written from the target's perspective and inverting them is the single easiest
bug to introduce. The trust policy on role B naming principal A produces the
edge **A → B**.

```json
{
  "id": "aws:111122223333:us-east-1/aws_iam_policy.ci#stmt:ReadBuckets",
  "type": "grants",
  "source": "aws:111122223333:us-east-1/aws_iam_policy.ci",
  "target": "aws:111122223333:us-east-1/aws_s3_bucket.data",
  "effect": "Allow",
  "actions": ["s3:GetObject", "s3:ListBucket"],
  "resource_patterns": ["arn:aws:s3:::my-bucket/*"],
  "sid": "ReadBuckets",
  "resolution": "resolved",
  "unevaluated": [],
  "digest": "77c2b0aa19de3f84"
}
```

`unevaluated` is a list of reasons this edge's effect could not be fully
determined. Defined values:

- `condition` — statement carries a `Condition` block
- `unresolved_policy_body` — the policy document was deferred at plan time
- `not_action` — statement uses `NotAction` / `NotResource`
- `resource_policy` — resource-based policy, not evaluated in v1

An edge with a non-empty `unevaluated` MUST render with an explicit marker and
MUST NOT be counted as a confirmed capability in the semantic layer.

## 5. Digests and the Merkle rollup

Canonical form: JSON, keys sorted, no insignificant whitespace, UTF-8,
separators `(",", ":")`. Digest = `sha256(canonical)` truncated to 16 hex chars.

- **Node digest** covers `type`, `scope.key`, `logical_address`, `name`,
  sorted `aliases`, `resolution`, sorted `unresolved_attributes`, `properties`.
  It excludes `id` (derivable) and `scope.root_module` (churns on refactor).
- **Edge digest** covers `type`, `source`, `target`, `effect`, sorted `actions`,
  sorted `resource_patterns`, `sid`, `resolution`, sorted `unevaluated`.
- **Module digest** = digest over the sorted list of child node digests, child
  edge digests, and child module digests.

The module rollup is over the **module tree**, not the graph, so it is acyclic
by construction. An unchanged module compares in O(1) regardless of how many
nodes it contains — which is what makes cost scale with the size of the change
rather than the size of the repo.

## 6. Graph document

```json
{
  "schema_version": "1.0",
  "generated_by": { "tool_version": "0.1.0", "extractor_version": "1" },
  "scopes": [ { "...": "see §1" } ],
  "modules": [ { "path": "root", "digest": "...", "children": [] } ],
  "moves": [ { "...": "see §6.1" } ],
  "nodes": [],
  "edges": [],
  "warnings": []
}
```

`nodes` and `edges` MUST be sorted by `id`. The document MUST be
byte-reproducible for identical input — it is committed to git, and a
non-deterministic artifact would produce phantom diffs.

`generated_by.extractor_version` exists so a version mismatch between the two
sides of a diff can be detected and reported rather than rendered as code
change. (In the PR workflow both sides are extracted in the same run by the
same version, so this should never fire — it is a guard, not a mechanism.)

### 6.1 `moves` — Terraform `moved {}` blocks

```json
"moves": [
  { "scope_key": "aws:111122223333:us-east-1",
    "from": "module.app", "to": "module.workload" },
  { "scope_key": "aws:111122223333:us-east-1",
    "from": "aws_iam_role.deployer", "to": "module.deployer.aws_iam_role.this" }
]
```

**`moved {}` blocks DO NOT appear anywhere in `tofu show -json`** when there is no
prior state — verified against the demo repo: zero occurrences of `moved`,
`move_`, or the old address in the plan JSON. The extractor MUST parse them from
the HCL source. There is no way to recover them from the plan.

Semantics:

- **Prefix match, not exact match.** `from = module.app` matches the address
  `module.app` *and* every address beneath it (`module.app.aws_iam_role.this`
  -> `module.workload.aws_iam_role.this`). Exact-match-only will silently miss
  every resource inside a moved module, which is the common case.
- Moves are scoped to the root module they are declared in; carry `scope_key`.
- Resolve chains transitively (A->B, B->C means A->C) and detect cycles.
- The **head** graph's `moves` describe the base->head renames. The differ
  applies them to rewrite **base** node and edge ids before comparison (§7).

Without this, a refactor that moves resources between modules produces a large
added/removed churn — the exact false positive §8 exists to prevent.

## 7. Diff document

```json
{
  "schema_version": "1.0",
  "base": { "ref": "main", "graph_digest": "..." },
  "head": { "ref": "pr-42", "graph_digest": "..." },
  "moves_applied": [ { "from": "...", "to": "...", "scope_key": "..." } ],
  "structural": {
    "nodes": { "added": [], "removed": [], "changed": [] },
    "edges": { "added": [], "removed": [], "changed": [] }
  },
  "semantic": {
    "capabilities": { "added": [], "removed": [] },
    "paths": { "added": [], "removed": [] }
  },
  "findings": [],
  "unevaluated": [],
  "stats": { "nodes_compared": 0, "modules_skipped": 0 }
}
```

A `changed` entry carries `{ id, before_digest, after_digest, property_deltas }`.

**Before any comparison**, the differ MUST apply the head graph's `moves` (§6.1)
to the base graph, rewriting node ids, edge ids, and edge `source`/`target`
endpoints by prefix. Report what was applied in `moves_applied`. Digests are
Digests ARE affected and MUST be recomputed. `node_digest` covers
`logical_address` and `edge_digest` covers `source`/`target` (§5), so a move
invalidates both, and any module containing either needs its rollup recomputed.
Rewriting ids alone is NOT sufficient: the stale digests would then read as
`changed` on every moved element — the same false positive in a new place.



A path entry:

```json
{
  "path": ["aws:999.../aws_iam_role.gha", "aws:999.../aws_iam_role.mgmt_deploy",
           "aws:111.../aws_iam_role.app_admin"],
  "hops": 2,
  "crosses_scopes": true,
  "terminal_capabilities": ["s3:*", "iam:PassRole"],
  "confidence": "confirmed"
}
```

`confidence` is `confirmed` when no edge on the path carries `unevaluated`,
otherwise `conditional`. A `conditional` path MUST be visually distinct from a
`confirmed` one.

`findings` is the ranked, human-readable layer that the PR comment renders.
Ranking: new cross-scope confirmed paths > new confirmed paths > new wildcard
capabilities > new capabilities > removals > structural churn.

**`stats.modules_skipped` is load-bearing for the story** — it is the evidence
that the Merkle rollup did work.

## 8. The empty diff

A diff where every array is empty is a first-class, expected result and MUST
render as an affirmative statement ("no permission changes") rather than an
absence of output. A refactor that moves resources between modules, renames
files, or reorders statements MUST produce an empty diff.

This is the correctness property the whole design serves: if it does not hold,
nothing else in the tool is trustworthy.
