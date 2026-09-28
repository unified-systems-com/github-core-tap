# PRODUCES_CHECK

## Blurb

A workflow declares a job whose check run carries a context some ruleset requires — the machinery that satisfies the gate, derived from names and honest about it.

## Purpose

The other half of the convergence. [`REQUIRES_CHECK`](REQUIRES_CHECK.md) says what a gate waits for; this edge says what, in the declared machinery, produces it. Together they answer the two questions a gate view exists for: which workflow satisfies this required check, and — by the absence of an inbound edge from a repository's workflows on a check node that repository's ruleset requires — which required check has no producer there, so the ref can never move or the rule is silently unsatisfiable.

## Goals

- Join the declared machinery to the gate, with fan-in on the context.
- State the confidence of the derivation on every edge, because it *is* a derivation.
- Emit only where an Actions job can be the producer.

## Identity

Edge id is `uuid5(ns, "edge:PRODUCES_CHECK__github_core:<workflow id>:<check id>")`. One workflow produces a given context once; if two jobs in one workflow share a display name — which GitHub allows and which makes the check ambiguous on GitHub's side too — the first in file order is recorded.

## Boundaries

`confidence` is the honest part and the corpus asked for it. A GitHub Actions check run is named after the job's display name (`name:`, or the key), so **`exact`** means the declared name equals the required context. A matrix job's runs are named `name (value, …)`; when a context has that shape and the declared name is its prefix, the edge says **`matrix_template`** — the producer is inferred from the template, not observed as the context — and a view scoring the gate should weigh it accordingly.

Not covered:

- **Checks from Apps.** A requirement whose `integration_id` is neither null nor GitHub Actions (15368) is satisfied by an App's check run. No edge is derived for it; the corpus's `app → status_check` producer waits on the App's numeric id being on the grid. **Compatibility is per requirement, not per node**: when two rulesets name one context — one App-only, one admitting Actions — the shared node carries the workflow producers the second admits, and a traversal from the App-only ruleset must read *its own* `REQUIRES_CHECK.integration_id` before treating a producer as satisfying it. This edge asserts "produces a check run with this name via GitHub Actions", never "satisfies every inbound requirement" (PR #62 review).
- **Reusable-workflow checks** (`<caller job> / <callee job>`). Not composed; named as a gap.
- **Whether the job actually ran and passed.** Execution-side; `github_actions_job` is where that lives.
- **Sourcing from the job.** The corpus and the bake list name the workflow as the source — the check is what the *workflow* contributes to the gate — and `job_key` / `job_name` on the edge say which job. A job-sourced edge would be the same fact one hop lower.

## Neutrality

**Vendor-specific**, with its endpoints: the naming rule the derivation rests on is GitHub Actions'.

## Observability

Derived from the workflow YAML at **`repository:contents:read`** — the job display names already parsed onto `workflow_job` — matched against the required contexts collected under **`repository:administration:read`** (the ruleset detail). No call is specific to this edge. Resolution runs in the post-pass over the whole scope: contexts are per owner, workflows per repository, so a producer in repository B for an organization requirement is found regardless of walk order.

Emitted only toward a [`status_check`](status_check.md) node (a context some rule requires) and only when at least one requirement on that node admits an Actions-produced check (`integration_id` null or 15368). The `STATUS_CHECKS` summary lists the Actions-producible contexts with **no** declared producer anywhere in scope.

**Absence shape** (github-core#14): **Shape A, git-provable** — a commit that renames or removes the job is positive proof — conditional on the target node, which is credential-shaped through its requirements.

## Authoritative Source

- **Source:** GitHub Actions documentation — check-run naming (a job's `name:` or key; matrix expansion `name (value)`), `jobs.<job_id>.name`; Repository Rulesets `required_status_checks` parameters for the contexts matched against
- **Version:** workflow syntax and rulesets docs as published 2026-09; REST API version `2022-11-28`
- **Retrieved:** 2026-09-02

## Prior Art

- `specs/spec-github-core-vocabulary.md` (2026-08-27) — `PRODUCES_CHECK` `{confidence}` — "honest about inference".
- unified-systems-com/github-core-tap#61 (2026-09-02) — the bake issue and the matrix-name trap.
- [`DEFINES_JOB`](../edges/DEFINES_JOB.edge.json) — the workflow → job edge whose target's `name` this derivation reads.

## Endpoints

- **Source:** `github_core__github_workflow` — the workflow declaring the producing job.
- **Target:** `github_core__status_check` — the required context.
- **Dimensions:** `git.host`, `github.surface: actions`, `github.observation: declaration`, plus the workflow's own `github.owner` / `github.repo` — the production is that repository's fact, which is what lets a query find the repositories where a shared requirement has no producer.
