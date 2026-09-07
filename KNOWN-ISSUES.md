# Known issues

Ordered by how much they matter.

## 1. Module membership is unspecified, so Merkle pruning falls back

`SCHEMA.md` §5 defines module digests over "child node digests, child edge
digests, child module digests" but never says **which module a node or edge
belongs to**. The extractor and the differ chose differently: the extractor
emits a module tree whose second level is a per-plan label (`mgmt`, `prod`),
while the differ derives membership from the `module.<name>.` prefix of a
Terraform address, and a plan label is not an address.

Consequence: `permdiff` cannot verify the rollups, so it refuses to prune and
falls back to full O(V+E) comparison, emitting a warning. **Results are
correct** — the fallback is the safe direction, and it is loud rather than
silent — but the Merkle optimisation is inactive on real graphs and the warning
is noise a reviewer should not see.

Fix: specify module membership in the schema and make both sides derive it the
same way.

## 2. Scope confidence is `low` on the demo repo

The extractor derives account identity from `var.account_id` by name, which
`SCHEMA.md` §1 classes as `variable_heuristic`/low confidence. §1.1 defines a
better rule the extractor does not yet implement: read the `validation {}` block
from HCL (the demo repo already has one constraining the value to 12 digits) and
corroborate against literal ARNs the config emits, which earns `high` honestly
rather than by name-matching.

The HCL reader already exists for `moved {}` blocks, so the marginal cost is
small. Until then the viewer shows a low-confidence warning on every scope.

## 3. The viewer's third scenario is synthetic

`viewer/public/data/head-contractor.graph.json` and `contractor.diff.json` were
authored by hand to exercise cross-scope paths before real extractor output
existed. They are labelled as demo data in the manifest, but they should be
replaced with the real `invisible-escalation` output now that it exists.

## 4. No JSON Schema for the diff document

`graph.schema.json` covers graphs only. The diff document is specified in prose
in §7, so `findings` severity/kind vocabularies are undefined and consumers
guess. The viewer had to infer the finding shape from a fixture.

Related: findings can reference `node_ids` but not edge ids, so the
star-policy finding — which *is* an edge change — cannot point at the thing that
changed.

## 5. Node ids still collide for multiple deployments in one account

`id = {scope.key}/{logical_address}` distinguishes deployments across accounts,
but two Terragrunt units in the **same** account instantiating the same module
produce the same id. The extractor currently qualifies collisions with a root
label and warns, but that makes an id depend on collision detection: adding a
third unit could change an existing node's id, which is exactly the churn the
design exists to prevent.

Likely fix: an explicit deployment discriminator in `scope`, declared rather
than inferred, absent for the common single-deployment-per-account case.

## 6. Package naming is inconsistent

The extractor is `archdiff_extractor`; the differ is `permdiff`.
