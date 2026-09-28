# Proposes Commit

## Blurb

The commit at the pull request's head when observed — what the check rollup is a verdict about, and the join to the runs that executed on it.

## Purpose

Build status is a fact about a commit, not about a pull request: runs execute on a SHA, and the check rollup is stored on the commit. This edge is the hop from the proposal to that commit, so "which runs executed on this proposal" is a traversal through the neutral commit rather than a string join on `head_sha`, and a re-push (a new head) is visible as the edge moving.

## Goals

- Join the proposal to the neutral commit without copying it.
- Let a re-pushed head read as a new join, not an edited field alone.

## Identity

One edge per (source, target) pair, id minted by `identity.edge_id`. The target id is the neutral commit identity `(hash_algorithm, oid)` computed from `head_sha`; a head commit not observed in the batch (it is only emitted as the head of an observed ref) leaves the edge dangling and dropped, with `head_sha` on the node as the fact.

## Boundaries

Not the ref — that is `PROPOSES_REF`. Not the merge commit: `merge_commit_sha` stays a field until a consumer needs it as an edge. Property-free: the head SHA is on the node and the commit carries its own dates and authorship.

## Neutrality

GitHub-owned edge onto a neutral target; the relationship exists on every forge.

## Observability

Emitted from the config-layer read; present when the head commit was emitted in the same batch, which is the case when the head branch is in this repository's ref page. A fork's head commit is not in scope, so a fork's pull request carries `head_sha` and no edge.

## Authoritative Source

- **Source:** GitHub GraphQL API — `PullRequest.headRefOid`
- **Version:** GraphQL schema as pinned in `github_openapi_extract.json`
- **Retrieved:** 2026-09-08

## Prior Art

- unified-systems-com/github-core-tap#82 (2026-09-08) — the bake issue.
- git_core's `RESOLVES_COMMIT` (2026-09-08, github-core#76) — the ref-to-commit peel this edge parallels from the proposal's side.

## Endpoints

- **Source:** `github_core__pull_request`
- **Target:** `git_core__git_commit`
- **Dimensions:** `git.host`, `github.surface: pulls`, `github.observation: execution`.
- **Properties:** none — the head SHA lives on the pull request and the commit carries its own facts; an edge property would be a third copy.
