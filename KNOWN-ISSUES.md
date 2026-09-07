# Known issues

Ordered by how much they matter. Everything here is reproducible against the
live demo: https://awalther28.github.io/archdiff-demo/

## 1. Viewer flags a false "Inconsistent" on the no-op PR

Open https://awalther28.github.io/archdiff-demo/#/pr/3 and the page says
**No permission changes** — then contradicts itself with a red banner:

> The diff document says nothing changed, but the viewer found differing
> digests between the two graphs.

The diff is right and the viewer's check is wrong. The differ applies the head
graph's `moves` to the base graph *before* comparing (§6.1) — that is how a
module refactor comes out empty. The viewer fetches the raw base and head
graphs and recomputes root digests directly, knows nothing about `moves`, and
so correctly observes that they differ and concludes the differ is lying. It
reports `20 of 24 · digests identical` — the four moved nodes.

The self-check itself is good and worth keeping: it is the viewer refusing to
take the differ's word for its most important claim. It just needs teaching
about `moves_applied` — either apply the same remapping before hashing, or
treat the check as satisfied when moves were applied and say so.

This lands on the single most important scenario, so it is first.

## 2. Scope confidence is `low` on the demo

The same page shows two `LOW-CONFIDENCE SCOPE` warnings: "Scope resolved by
variable heuristic; nodes may belong to a different account than shown."

`.archdiff.json` declares both scopes explicitly, and `SCHEMA.md` §1 ranks
`explicit` highest — but the extractor only accepts explicit scopes via
`--scope-overrides`, and the CI action does not pass it. So the config file is
doing half its job: declaring roots and plan variables, but not scope.

§1.1 also defines a better automatic rule the extractor does not yet implement:
read the `validation {}` block from HCL (the demo repo already constrains
`account_id` to 12 digits) and corroborate against literal ARNs the config
emits. The HCL reader already exists for `moved {}` blocks, so the marginal
cost is small.

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

---

Resolved earlier in development (see git history): module membership was
unspecified so Merkle pruning always fell back (fixed by SCHEMA.md 6.2), and
the two packages disagreed on naming (both are now `archdiff_*`).
