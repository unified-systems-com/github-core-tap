# Analyzes Commit

## Blurb

A code scanning analysis was run at this commit — from the scan record to the neutral `git_commit`, drawn only when that commit is on the grid.

## Purpose

"Was this commit scanned before it merged" and "which analyses looked at the commit a release was cut from" are commit-anchored questions, and the commit on the grid is git_core's neutral node. This edge is the hop from a scan record to it. It joins the security axis to everything else that meets at a commit — the pull request that proposed it (`PROPOSES_COMMIT`), the ref that resolves to it, the runs that built it — so a gate view can ask whether the head commit it is about to admit carries a CodeQL analysis at all.

## Goals

- Reach an analysis from the commit it analysed, when both are on the grid.
- Never fabricate the commit: a `git_commit` node is minted by the commit slice on the config-layer refs query, not by this surface.

## Identity

One edge per (source, target) pair, id minted by `identity.edge_id`; property-free. The target id is computed from the analysis's `commit_sha` through git_core's identity (`sha1:<oid>`, lower-cased); a commit not observed in the batch leaves the edge dangling and it is dropped, with `commit_sha` on the analysis as the fact.

## Boundaries

- **Absence is not "not analysed".** The edge is missing whenever the commit was not collected — a pull-request merge commit (`refs/pull/N/merge`) is never on the grid, and the config layer's commit slice reaches only the tips of collected refs — so most analyses on this organisation will carry no commit edge. The truth is `commit_sha` on the node; this edge is the join when both ends were seen.
- **Not the ref.** The analysis's `ref` is a string on the node; no `ANALYZES_REF` edge, because a merge ref is not a grid object and a branch tip moves under the analysis.
- **Not an alert edge.** Alerts also carry a `commit_sha`; no commit edge is drawn from them, because an alert is about a location that persists across commits and its `most_recent_instance` commit is incidental.

## Neutrality

GitHub-owned edge onto a neutral target, the pattern of `PROPOSES_COMMIT` and `OBSERVES_COMMIT`: the relationship holds on any forge and the target already lives in the substrate.

## Observability

Emitted from the analyses read (`repository:security_events:read`) and present only when the analysis landed AND the commit was observed in the same batch (`repository:contents:read`, via the config-layer commit slice). Two permissions, two surfaces: a credential that can read analyses but whose commit slice degraded yields analyses with no commit edges, and the absence then says nothing about scanning. Read it beside `code_scanning_observability` on the repository and the presence of the commit node.

**Absence shape** (github-core#14): the analysis is **Shape C, an immutable event** — the scan happened and is never tombstoned because it aged off the page — and this edge is **conditional on the target node**, the pattern `PRODUCES_CHECK` and `PROPOSES_COMMIT` already follow: the fact is `commit_sha` on the analysis; the edge exists when the commit was collected, and its absence is never evidence about scanning.

## Authoritative Source

- **Source:** the collector's own emission over `GET /repos/{owner}/{repo}/code-scanning/analyses` (`commit_sha`) joined to `git_core`'s commit identity (`tap_plugin/git_core` identity helpers, `sha1:<oid>`)
- **Version:** REST API version `2022-11-28`, as pinned in `github_openapi_extract.json`; git_core v0.1.0 (the neutral commit node as pinned in the boot profile)
- **Retrieved:** 2026-09-09

## Prior Art

- Operator ruling, session double-tap-git-serious (2026-09-09; github-core#89) — the commit edge as conditional, absence ≠ not analysed.
- unified-systems-com/github-core-tap#76 rev 2 (2026-09-08) — the neutral commit and the rule that a forge edge onto it is drawn only when the commit was observed (`PROPOSES_COMMIT`, `OBSERVES_COMMIT` follow the same rule).
- `git_core/domain/git_commit.md` (2026-09-08) — one commit node per `(hash_algorithm, oid)` however many hosts observe it.
- OASIS SARIF 2.1.0 (2020-03-27) — `run.versionControlProvenance[].revisionId`: the standard's own commit pointer on a run.

## Endpoints

- **Source:** `github_core__code_scanning_analysis`
- **Target:** `git_core__git_commit`
- **Dimensions:** `git.host`, `github.surface: security`, `github.observation: execution`.
- **Properties:** none — the ref and the tool are on the analysis node; the commit's identity is the target.
