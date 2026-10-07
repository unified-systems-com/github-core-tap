# UPLOADS_ARTIFACT

## Blurb

A workflow run produced an artifact — the exact, execution-side join from a run to its output.

## Purpose

The outputs column of a pipeline view needs one thing: which run made which artifact. GitHub's artifact listing names the producing run on every item, so this edge is derived rather than matched, in the same way [`EXECUTES_WORKFLOW`](EXECUTES_WORKFLOW.md) is — no name comparison, no guess. It is the run-side half of the supply-chain question the corpus keeps asking: a version with no build behind it is a registry object with no path back along edges like this one.

## Goals

- Join each artifact to the run that uploaded it, exactly.
- Keep the join batch-honest: an artifact whose run lies outside the collected window is counted, not silently dropped by the dangling-edge guard.

## Identity

Edge id is `uuid5(ns, "edge:UPLOADS_ARTIFACT__github_core:<run id>:<artifact id>")`. One run uploads an artifact once; a re-run that uploads again produces a different artifact id and therefore a different edge.

## Boundaries

Carries **no properties**, justified: everything a property could say — the digest, the size, the timestamps, whether it has expired — is a field on the artifact node, which *is* the event. A property here would derive a fact twice.

Not covered:

- **The job.** The listing names the run, not the job whose step ran `actions/upload-artifact`. The corpus wrote workflow_job → artifact; the API cannot support that exactly, so the edge sources from the run and the declared step stays on the job's `configuration.artifact_steps`.
- **Downloads.** There is no `DOWNLOADS_ARTIFACT`: GitHub keeps no record of who downloaded, and a declared download names a pattern, not an artifact. See [`actions_artifact`](actions_artifact.md) § Boundaries.

## Neutrality

**Neutral-capable**, with its endpoints: run-produces-output is the shape every CI system has.

## Observability

Derived from `workflow_run.id` on each item of `GET /repos/{o}/{r}/actions/artifacts` at **`repository:actions:read`** — the same call that mints the artifact, so the edge costs nothing extra. Emitted only when that run is in the same collection batch: GRIFT rejects an edge to a node not in the batch, and the collector's dangling-edge guard would otherwise drop it with a generic count. Artifacts of runs outside the window are reported in the `ARTIFACTS_COLLECTED` summary (`linked` / `unlinked`) and carry `run_id` and `configuration.run_in_batch: false`, so the join can still be made on the grid by id.

Observed 2026-09-02 with a classic `repo`-scoped token; not yet observed with the App installation token (the artifact article records the caveat).

**Absence shape** (github-core#14): **Shape C**, inherited from its target — an immutable event. Never reconciled on absence.

## Authoritative Source

- **Source:** GitHub REST API — Actions Artifacts, "List artifacts for a repository" (`GET /repos/{owner}/{repo}/actions/artifacts`), the `workflow_run` object on each artifact
- **Version:** REST API version `2022-11-28`; OpenAPI description commit `875b39fae632318533e61d3e5217b340f5ec3ebd`
- **Retrieved:** 2026-09-02

## Prior Art

- `specs/spec-github-core-vocabulary.md` (2026-08-27) — `UPLOADS_ARTIFACT` `{cross_workflow}`; the property moved to the declared download step, where it is derivable, and the source moved to the run, where it is exact.
- unified-systems-com/github-core-tap#55 (2026-09-02) — the bake issue.
- [`EXECUTES_WORKFLOW`](EXECUTES_WORKFLOW.md) — the precedent for an exact, property-free execution-side join.

## Endpoints

- **Source:** `github_core__github_actions_run` — the run named by the artifact's `workflow_run.id`.
- **Target:** `github_core__actions_artifact`.
- **Dimensions:** `git.host`, `github.surface: actions`, `github.observation: execution`, plus the repository's `github.owner` / `github.repo` — both ends belong to one repository.
