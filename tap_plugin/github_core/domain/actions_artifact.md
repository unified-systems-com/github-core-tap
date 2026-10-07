# Actions Artifact

## Blurb

A file set a workflow run uploaded — the output of a pipeline as GitHub recorded it, with its content digest and the retention state GitHub reports.

## Purpose

Everything upstream of this node is about what CI is allowed to do and what it did; this is the first node about what it *produced*. The machinery view draws an outputs column and, until now, rendered it "not yet collected" (github-core#31). Eleven surveyed sources model an artifact, and the supply-chain incidents in the corpus read as a question about outputs: a version in a registry with no build behind it, a build whose output was swapped between upload and download.

Two fields carry that weight. `digest` is the SHA-256 GitHub computed at upload — the value a consumer can compare against what it downloaded, and the value whose field history would show an artifact re-uploaded under the same name. `expired` is retention as GitHub *reports* it: an expired artifact stays in the listing with the flag set, which is what makes absence from the listing say nothing at all.

## Goals

- Put the output of a run on the grid, joined exactly to the run that made it.
- Carry the content digest, so "is this what was built" is a comparison rather than a guess.
- Keep retention honest: `expired` is observed, never inferred from absence.
- Record what GitHub does not know — who downloaded — rather than inventing it.

## Identity

Natural key: **`<full_name>#<artifact_id>`** — the repository plus GitHub's artifact id. Entity id is `uuid5(ns, "github_core__actions_artifact:<full_name>#<artifact_id>")`.

The id is platform-global (the same id space as runs and caches), so the repository prefix is belt-and-braces in the way `ruleset_id`'s owner prefix is. Recorded rather than re-derived: a natural key cannot change once nodes exist. The name is **not** identity — every run of a workflow uploads an artifact called `sbom`, and they are different objects with different digests.

## Boundaries

Deliberately **not** covered:

- **Who downloaded it.** GitHub records the uploader (`workflow_run` on every listing item) and keeps no record of downloads. The corpus's `DOWNLOADS_ARTIFACT` therefore has **no observable target** and is not built. A declared download — a job step using `actions/download-artifact` with `name:` or `pattern:` — names a pattern, and the node is one concrete id; joining them would be the inference `req-github-core-caches-4` refuses for caches. The declaration lives on `workflow_job.configuration.artifact_steps`, carrying the corpus's `cross_workflow` (a `run-id:` or `repository:` input means the step reaches into another run's outputs) so the security-relevant bit survives without a guessed edge.
- **The declared upload.** Symmetric: `actions/upload-artifact` steps are on `artifact_steps`, not joined to this node, because the declaration exists before the artifact does.
- **The content.** `archive_download_url` is not followed and nothing is fetched; the node is metadata. Attestations over the artifact (`actions/attest`) are a supply-chain concept for `supply_chain_core`, not here.
- **Job-level attribution.** The listing names the run, not the job that ran the upload step. `UPLOADS_ARTIFACT` sources from the run for that reason; the corpus wrote workflow_job → artifact, which the API cannot support exactly.

## Neutrality

**Neutral-capable**, as the corpus marks it: every CI system has run outputs, and the kernel pressure test's non-forge pipeline produces them. What is GitHub's is the retention model (`expires_at`, the `expired` flag on a listed row), the `digest` field's recent arrival, and the `workflow_run` envelope — properties, not structure.

## Observability

Populated from **`GET /repos/{o}/{r}/actions/artifacts`** — the repository listing, newest first, capped per repository with `total_count` reported — at **`repository:actions:read`** per GitHub's documentation. The repository listing rather than the per-run endpoint the corpus implied: one call per page instead of one per run, and each item carries `workflow_run.id`, which is what makes `UPLOADS_ARTIFACT` exact.

Observed 2026-09-02 by executed call on `unified-systems-com/tap`: `total_count: 3831`; item keys `id, node_id, name, size_in_bytes, url, archive_download_url, expired, created_at, updated_at, expires_at, digest, workflow_run{id, repository_id, head_repository_id, head_branch, head_sha}`. The per-run endpoint for the latest in-progress `product-lines` run returned `total_count: 0` — a run that has not finished has no artifacts yet, which is not "produces none".

**Credential caveat, stated because it was not tested:** the observation above was made with a classic `repo`-scoped token (`X-Oauth-Scopes: … repo, workflow`). The App installation token this plugin recommends has not yet been observed against this endpoint; the manifest declares `actions:read` from the documentation and degrades with a warning on 403/404, so a refused read renders as *not observable*, not as an empty repository.

**Three states, on the repository node** (github-core#31). `github_repository.outputs_observability.artifacts` is `observed` on a 200 and `unobservable` on a 403 or 404, with the status in `notes.artifacts`. A refusal lands no nodes and is recorded on the node the absence is about, never rendered as a repository that uploads nothing. Every artifact that does land hangs off its repository through `STORES_ARTIFACT`, so one whose run is outside the collected window stays reachable without the `UPLOADS_ARTIFACT` edge.

**Absence shape** (github-core#14): **Shape C — an immutable event with a retention window.** The upload happened; it does not stop having happened when retention ends. GitHub keeps expired artifacts listed with `expired: true`, so expiry is an observed field on this node and absence from the listing — which also happens under the per-repository cap — is never grounds for a tombstone. A reconciler must refuse this type.

**Not observable at all:** downloads (see Boundaries); which job uploaded (the listing names the run); anything about an artifact that has aged out of the listing entirely.

## Authoritative Source

- **Source:** GitHub REST API — Actions Artifacts, "List artifacts for a repository" (`GET /repos/{owner}/{repo}/actions/artifacts`); `actions/upload-artifact` and `actions/download-artifact` action inputs (`name`, `pattern`, `run-id`, `repository`) for the declared side
- **Version:** REST API version `2022-11-28`; OpenAPI description commit `875b39fae632318533e61d3e5217b340f5ec3ebd` (pinned extract refreshed 2026-09-02)
- **Retrieved:** 2026-09-02

## Prior Art

- `specs/spec-github-core-vocabulary.md` (2026-08-27) — `actions_artifact`, friends tier, 11 sources; `UPLOADS_ARTIFACT` / `DOWNLOADS_ARTIFACT` `{cross_workflow}`. Pulled forward to self by the machinery view's outputs column.
- unified-systems-com/github-core-tap#55 (2026-09-02) — the bake issue: the repository listing, the executed-call shape, the `DOWNLOADS_ARTIFACT` finding, Shape C.
- unified-systems-com/github-core-tap#31 (2026-09-02) — outputs not observable in the machinery view.
- [`actions_cache`](actions_cache.md) — the sibling "observed entry versus declared step" split this node copies, including the refusal to join a declaration to an instance by pattern.

## Fields

- `full_name` — the owning repository's `owner/repo`; half the natural key.
- `artifact_id` — GitHub's artifact id, the other half. Nullable in the schema only so a node can be minted from a reference; the collector always has it.
- `name` — the artifact's declared name (`sbom`, `wheel`). What a download step names; deliberately not identity, since every run re-uses it.
- `size_in_bytes` — as reported. A size that changes between runs of the same artifact name is a cheap anomaly signal beside the digest.
- `digest` — `sha256:<64 hex>` of the archive as GitHub computed it. Empty when GitHub did not report one (older artifacts predate the field), which is *observed-empty*, not unknown.
- `expired` — retention state as GitHub reports it. True on a row that is still listed; the reason absence is never read as expiry.
- `expires_at` — when retention ends or ended.
- `created_at` — the upload time; the event's timestamp.
- `updated_at` — as reported.
- `run_id` — the producing run's id from `workflow_run.id`. A column so the join to `github_actions_run` is exact whether or not that run was in the collected window (`configuration.run_in_batch` says which).
- `head_sha` — the commit the producing run built, from `workflow_run.head_sha`. The value a consumer would want to attest against.
- `head_branch` — the producing run's branch, from `workflow_run.head_branch`; a pull-request artifact carries the PR's head branch here.
- `configuration` — the `workflow_run` envelope as received, and `run_in_batch`.
- `tags` — TAP's tag map.
