# archdiff

Terraform tells you which **resources** change. It cannot tell you what that
change **means**. `archdiff` lifts an OpenTofu plan from an *attribute diff* to a
*capability diff*: it builds a permission graph from the plan, diffs two graphs,
and reports the privilege paths and capabilities a pull request actually creates.

The motivating case is the pull request whose text diff tells you nothing:

```
-      identifiers = [local.sso_operator_role_arn]
+      identifiers = [local.sso_operator_role_arn, local.gha_role_arn]
```

One line. It mentions no privileged action, no admin role, and no account
number. It creates a two-hop, cross-account path from a role any contributor can
reach to a role that administers production.

## Layout

| path | what it is |
|---|---|
| `schema/` | **The contract.** `SCHEMA.md` is normative; `graph.schema.json` validates output; `canonical.py` is the one true digest implementation. |
| `packages/extractor/` | OpenTofu plan JSON -> permission graph. |
| `packages/differ/` | Two graphs -> a structural + semantic diff, with findings and a markdown renderer for PR comments. |
| `viewer/` | React + Vite viewer, deployable to GitHub Pages. |
| `examples/` | Graphs and diffs generated from the demo repo, for the three scenarios. |

The demo repository — an OpenTofu estate with two AWS accounts and three PR
branches — lives separately, so its branches can be opened as real pull requests.

## Design invariants

1. **The graph is a pure function of the IaC configuration.** No state, no
   account access, no clock. Same config in, byte-identical graph out.
2. **Identity is readable; change detection is hashed.** A node's `id` is a
   stable human-readable composite; its `digest` is a content hash. Different
   things, both required.
3. **Never silently drop what could not be evaluated.** Conditions, deferred
   policy bodies and unresolved references are represented explicitly and can
   never count as a confirmed capability.
4. **The empty diff is a first-class result.** A refactor that moves resources
   between modules must produce *nothing*. If that does not hold, no other
   output is trustworthy.

## Running it

```bash
python -m archdiff_extractor \
    --plan plans/mgmt.plan.json --root mgmt --src live/mgmt \
    --plan plans/prod.plan.json --root prod --src live/prod \
    --out head.graph.json

python -m archdiff_differ diff --base base.graph.json --head head.graph.json --out diff.json
python -m archdiff_differ render --diff diff.json     # markdown for a PR comment
python -m archdiff_differ verify --graph head.graph.json  # re-hash every module rollup
```

Merging several plans into one graph is what makes cross-root privilege paths
visible: a path that crosses account boundaries is invisible to each individual
`tofu plan`.

## Status

Working end to end against the demo repository. Known gaps are tracked in
`KNOWN-ISSUES.md`.
