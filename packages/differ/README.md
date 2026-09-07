# archdiff_differ -- Permission Graph v1 differ

Two Permission Graph v1 documents in, one section-7 diff document (plus a
PR-comment markdown rendering) out.  Python 3.9+, standard library only, no
network.  `../../schema/SCHEMA.md` is normative; where this README and the
schema disagree, the schema wins and this README is wrong.

```
archdiff_differ diff   --base base.graph.json --head head.graph.json --out diff.json \
                [--base-ref main --head-ref pr-42] [--markdown comment.md] \
                [--no-merkle] [--full-semantic] [--max-hops 4] [--stats] [--fail-on high]
archdiff_differ render --diff diff.json [--out comment.md]
archdiff_differ verify graph.json ...        # audit every digest and rollup against canonical.py
python -m pytest                      # ~135 tests, ~20 s (the 100k-node perf test is ~10 s of that)
python bench/run.py                   # reproduce the performance table below
```

`archdiff_differ/canonical.py` is a byte-for-byte copy of `schema/canonical.py`
(asserted by `tests/test_canonical_copy.py`, which also asserts that no other
module in the package touches `hashlib`).  Digests are never reimplemented.

## Architecture

```
graph.py       load + index (id -> node/edge, per-node incidence lists, module tree)   O(repo), once
address.py     Terraform address -> module key; module path -> module key
structural.py  STAGE 1  hash-set diff with the Merkle prune + self-verification         O(change)
catalog.py     bundled action catalog (s3, sts, iam, kms, secretsmanager)
semantic.py    STAGE 2  effective capabilities, privilege paths, confidence             O(change)
findings.py    ranked findings + the `unevaluated` section
differ.py      orchestration -> diff document; byte-stable serialisation
render.py      diff document -> markdown
cli.py         diff / render / verify
builder.py     schema-honest graph builder used by tests and bench (not an extractor)
bench/         synthetic generator + reproducible benchmark
```

The two stages are separate modules with separate result objects, separate
tests (`test_structural.py` vs `test_semantic.py`) and separate sections in
the output; Stage 2 consumes only Stage 1's dirty id sets, never its internals.

### Stage 1 -- structural

Ids are stable and digests are content hashes, so the diff is three set
operations per kind (`added = head - base`, `removed = base - head`,
`changed = shared with differing digest`).  No graph matching.

**Merkle prune.**  The module tree is walked top-down on both sides together.
A module whose digest matches on both sides is cut off in O(1) with its whole
subtree; `stats.modules_skipped` counts every module not descended into and
`stats.merkle.prune_points` counts the cut-offs.  Only the buckets of
modules that *did* differ are compared, so `stats.nodes_compared` is the size
of the changed modules, not the repo.

**Membership is derived, then verified.**  SCHEMA.md never says which module a
node or edge belongs to.  `address.py` derives it from the `module.<name>.`
prefix of `logical_address` (and for edges, from the node named before `#` in
the edge id, else the source node).  That is a heuristic, so it is not
trusted: every module that was compared is re-hashed from its buckets with
`canonical.module_digest` and checked against the document's digest, on both
sides.  Any mis-assignment that could hide a change necessarily involves a
compared module (proof: a node wrongly placed *into* or *out of* a changed
module changes that module's recomputed digest), so a mismatch means the
prune cannot be trusted and the differ silently falls back to the full O(V+E)
comparison, recording why in `stats.merkle.fallback_reason` and `warnings`.
Nodes whose address maps to no module in the tree go to an "unassigned"
bucket that is always compared, never skipped.  Cost of verification: hashing
the changed modules only.

When every root digest matches, nothing is bucketed at all -- the empty diff
on a 100k-node graph is O(1) after parsing (`test_unchanged_big_graph_is_o1`).

**Trust boundary.**  The prune trusts unchanged rollups exactly as section 5
intends.  An extractor that emits a *stale* rollup (module digest unchanged,
contents changed) defeats it silently -- this happened once during
development, in the bench generator's mutation step, and `archdiff_differ verify`
caught it.  Run `archdiff_differ verify` in the extractor's own tests.

### Stage 2 -- semantic

**Capabilities.**  For each principal: `attaches` -> policy -> `grants`.
Each Allow statement yields one capability entry `{principal, actions,
resource_patterns, confidence, ...}`; identity deliberately excludes
provenance (which policy, which target node), so moving a statement between
policies is structural churn, not a semantic change.  Explicit deny wins: a
Deny whose resource patterns cover the Allow's carves its matching actions
out (`denied_actions`); an Allow so carved is reported with its concrete
remaining actions.  A Deny that carries `unevaluated` is *not* applied (it
might not apply, and hiding an Allow behind a maybe-Deny is the unsafe
direction); it is surfaced in `unevaluated` instead.  A Deny that only
partially covers the Allow's resources also does not carve (over-report,
never under-report).

Wildcards are expanded against `catalog.py`.  **Limit:** the catalog covers
only `s3`, `sts`, `iam`, `kms`, `secretsmanager` (a bundled snapshot, no
network).  Wildcards in other services (`ec2:*`) stay as opaque tokens, are
matched by exact string or glob only, and are listed under `unexpandable` on
the capability and in the finding text.  Bare `*` expands to the whole
catalog *and* keeps the literal `*` so it still covers unknown services.
The diff document states the limit in `tool.limits`.

**Paths.**  Simple paths over `can_assume` hops, at most `--max-hops` (4)
long, starting at *entry* nodes: principals with outgoing trust and no
incoming trust.  A trust cycle no real entry reaches gets the smallest id of
its backward closure as its entry so it is still reported.  Every prefix of a
path is a path, so adding one edge reports every reach it opens.
`crosses_scopes` is true when the path's node ids span more than one
`scope.key`.  Parallel edges collapse into one hop that is confirmed if any
of them is; a confirmed Deny trust edge removes the hop.

**Confidence.**  `confirmed` only when *no* edge involved (attach + grant for
a capability, every hop for a path) has a non-empty `unevaluated`.  An
unevaluated edge cannot become a confirmed capability by any route: it is
excluded from Deny application, it makes its capability conditional, it
makes any path through it conditional, and conditional capabilities are kept
out of `terminal_capabilities` (they go to `terminal_conditional_capabilities`).
Confidence is part of both identities, so a condition being removed shows as
"became confirmed" (`path_confirmed`, or a capability finding titled
"now confirmed ... (was conditional)").

**Incremental evaluation.**  Stage 2 evaluates only what Stage 1 dirtied:
principals whose attach/grant neighbourhood contains a dirty node or edge
(an untouched principal has byte-identical policies and edges on both sides,
so its capabilities cannot differ), and paths that either traverse a dirty
`can_assume` pair (found by backward+forward search from the pair, not by
enumerating the graph) or start at a node whose entry status flipped.  The
trust graph is materialised lazily.  `--full-semantic` evaluates everything;
`test_incremental_semantic_equals_full` proves the two agree on 40 random
mutated graphs plus targeted entry-flip cases.

**Findings** are ranked in the schema's order, with conditional items
directly after the confirmed items they would otherwise sit with:

| tier | kind | severity |
|---|---|---|
| 1 | new cross-scope confirmed path | critical |
| 2 | new confirmed path | high |
| 3 | new conditional path (cross-scope first) | high / medium |
| 4 | new wildcard capability (`*`/`*` is critical) | high (medium if conditional) |
| 5 | new capability | medium (low if conditional) |
| 6 | removals (paths, lost actions) | info |
| 7 | structural churn nothing above explains | info |

Capability findings are driven by the **action-level** delta, not by grant
identities: an added grant that gives a principal nothing new (an explicit
Deny narrowing `s3:*`) is not a "new capability"; a removed grant whose
actions are still covered by another grant is a *widening* (title "widened
to ..."), not a loss; and a loss names the actions actually lost.  A policy
attached to N principals produces one finding naming N principals.

**`unevaluated`** lists the unevaluated edges that bear on this diff: dirty
ones, those in the trust/capability neighbourhood of any principal the diff
touched, and those incident to a node whose content changed.  It is empty
for an empty diff (section 8 asks for *every* array empty).
`stats.unevaluated_edges_in_head` gives the graph-wide count for context.

### Output conventions

* Byte-stable: sorted keys, 2-space indent, UTF-8, trailing newline; every
  list in the document is sorted.  Tested across processes with different
  `PYTHONHASHSEED`s and with shuffled input order.
* `empty: true/false` at the top level states the section-8 verdict
  affirmatively; the markdown opens with "**No permission changes**".
* Timings are returned by the API (`DiffResult.timings`) and printed with
  `--stats`, never written into the document.
* Extractor version mismatch (section 6) is refused with exit code 2 unless
  `--allow-version-mismatch`, in which case it is recorded in `warnings`.

## Performance (`python bench/run.py`)

Shape: `root -> 20 groups -> 25 leaves` (521 modules), one grants statement in
leaf `g7/l3` widened to `s3:*`.  Best of 3, `time.perf_counter`, Python
3.9.6, Apple Silicon laptop, 2026-09-07.  Rerun rather than quote; the
generator and the mutation are deterministic so the *shape* of the numbers
reproduces anywhere.

| nodes | edges | json load (s) | index (s) | bucket (s) | structural, Merkle (s) | structural, full (s) | whole diff (s) | modules skipped | nodes compared | principals evaluated |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 13,002 | 15,000 | 0.189 | 0.016 | 0.046 | 0.0001 | 0.0183 | 0.0005 | 518/521 | 28 | 1 |
| 25,502 | 29,500 | 0.374 | 0.030 | 0.094 | 0.0001 | 0.0468 | 0.0005 | 518/521 | 53 | 1 |
| 50,502 | 59,000 | 0.931 | 0.060 | 0.183 | 0.0002 | 0.0930 | 0.0005 | 518/521 | 103 | 1 |
| 100,502 | 118,000 | 1.837 | 0.128 | 0.384 | 0.0003 | 0.2121 | 0.0007 | 518/521 | 203 | 1 |
| 200,502 | 235,500 | 3.682 | 0.267 | 0.807 | 0.0006 | 0.4589 | 0.0015 | 518/521 | 403 | 1 |

Reading it honestly:

* **JSON parse, indexing and bucketing are O(repo)** and dominate wall-clock.
  Parsing cannot be avoided without a streaming format; indexing is one dict
  pass; bucketing (address -> module) is lazy and only runs when root digests
  differ.  Together they are ~2.3 s at 100k nodes.
* **Comparison and semantics are O(change).**  With the prune, the structural
  stage is 0.1-0.6 ms across a 15x size range, growing only with the changed
  leaf (`nodes compared` 28 -> 403, the leaf's size); without it, 18 -> 459 ms,
  linear in the repo.  The whole diff (structural + semantic + findings) is
  0.5-1.5 ms.
* **`modules_skipped` = 518/521** in every row: root, `g7` and `l3` are
  compared and verified; 19 groups and 24 sibling leaves are prune points.
* Unchanged graph: `modules_skipped = 521`, `nodes_compared = 0`, no bucket
  built, < 1 ms (`test_unchanged_big_graph_is_o1`).

## Golden fixture: where this implementation differs from `expected.diff.json`

The structural section matches exactly (`test_structural_section_matches_exactly`).
The semantic and findings sections match on every field the hand-authored
fixture defines (`test_golden.py` compares projections), with these deliberate
differences:

1. **Extra provenance fields.**  Capabilities carry `targets`, `via_policies`,
   `edge_ids`, `wildcard`, `expanded_action_count`, `gained_action_count` /
   `lost_actions`; findings carry `edge_ids`, `confidence`, `principals`,
   `new_actions_count`; unevaluated entries carry `edge_type`, `source`,
   `target`, `relevance`.  The renderer needs them; the fixture's fields are
   a subset.
2. **The "removed" capability is annotated as superseded.**  The fixture lists
   `[s3:GetObject, s3:ListBucket] on app-data/*` as removed.  Literally true at
   grant level and reproduced; but the principal lost nothing, so the entry
   also carries `superseded_by: {s3:* on *}` and `lost_actions: []`, and no
   "removal" finding is emitted -- exactly as the fixture's single finding
   intends.
3. **Finding title.**  The fixture says "ci role gained s3:* on all resources".
   The principal is `app-admin`, not a CI role, and the change is a widening;
   the generated title is "app-admin widened to [s3:*] on all resources (*)".
   Kind, severity, rank and node ids match; the detail carries the same
   substance (statement `ReadData`, before/after actions and resources).
4. **Finding `node_ids`** includes the principal and the target as well as the
   policy the fixture names (superset asserted).
5. **`unevaluated[].note`** is generated from the reason (plus the target's
   `unresolved_attributes` when relevant) rather than the fixture's
   hand-written prose; `edge_id` and `reasons` match exactly.

## Where SCHEMA.md is ambiguous or (I think) wrong

1. **Module membership is unspecified** (sections 5, 6).  Module digests are
   defined over "child node digests" but nothing says which module a node or
   edge is a child of, and the only module `path` shown is `"root"`.  Handled
   by derivation from Terraform addresses plus verification of every compared
   module (above).  The schema should state the rule -- proposed: a node
   belongs to the module of its `logical_address` prefix; an edge belongs to
   the module of the resource whose configuration produced it, which is the
   node named before `#` in its id -- and should fix the `path` spelling
   (`module.a.module.b` is what the builder emits; `address.py` also accepts
   `root/module.a/module.b` and `a/b`).
2. **`property_deltas`** (section 7): "A `changed` entry carries `{ id,
   before_digest, after_digest, property_deltas }`", but the machine-generated
   `expected.diff.json`, which the structural section must match exactly, has
   no `property_deltas`.  The fixture is followed; field deltas are still
   computed (`StructuralResult.field_deltas`) and used in the churn finding's
   text.  One of the two documents should change.
3. **`unevaluated` vs the empty diff** (sections 7, 8).  The fixture lists
   *unchanged* unevaluated edges for the golden diff, yet section 8 requires
   every array empty for a no-op diff -- and the same two unevaluated edges
   exist in the no-op head.  Resolved with a relevance rule (edges that bear on
   the change); the schema should say what `unevaluated` enumerates.
4. **Ranking of conditional items** (section 7) is unspecified; placed after
   the confirmed items of their tier, severity one notch lower.
5. **`crosses_scopes`** and the `graph_digest` for a multi-root module tree
   are unspecified; `crosses_scopes` uses the `scope.key` prefix of node ids
   (works for dangling targets too); `graph_digest` is the single root's digest
   (the fixture's convention) or a rollup over the roots.
6. **`stats.nodes_compared`** is not defined; here it is the number of node
   ids (union of both sides) in the compared modules -- 10 for the golden
   fixture, 0 for the no-op, matching the fixture values.
7. Section 4 says an edge with `unevaluated` "MUST NOT be counted as a
   confirmed capability" but is silent on Deny statements with `unevaluated`.
   Not applying them is the only reading under which an unevaluated edge can
   never make the result *more* permissive-looking than reality in the
   dangerous direction (hiding an Allow); documented above.

## Known limits

* Action catalog: five services (see above).  `iam:PassRole` and `sts:*` are
  in it, so the classic escalation primitives are covered.
* Resource pattern reasoning is glob subsumption (`*`, exact, `fnmatch` of the
  literal); no ARN parsing, no policy variables, no `NotResource` (which the
  extractor flags as `not_action`, making the edge conditional).
* Group membership, permission boundaries, SCPs, session policies and
  resource-based policies are outside the v1 graph and therefore outside the
  differ.
* Paths are simple paths of at most 4 hops from entry nodes; a densely
  connected trust graph can have many, and every prefix is reported.
* The prune's safety argument assumes the extractor's *unchanged* rollups are
  honest (section 5).  `archdiff_differ verify` audits a document in O(V+E).
