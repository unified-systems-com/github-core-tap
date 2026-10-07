# Observes Commit

## Blurb

GitHub's observation of a commit links to the neutral commit it is an observation of.

## Purpose

Many hosts may observe one commit, each with its own resolved logins and its own verification verdict; the commit stays one node and each observation points at it (ruling 0.2). A required-signatures view walks ref → commit → observation-in-this-repository.

## Goals

- Let a verdict be found from the commit without ever living on it.

## Identity

One edge per (source, target) pair, id minted by `identity.edge_id`; property-free.

## Boundaries

Not the repository scope — that is `OBSERVED_IN_REPOSITORY`; not the peel — that is git_core's `RESOLVES_COMMIT`.

## Neutrality

GitHub-owned; the target is neutral.

## Observability

Emitted by the collector from the same config-layer read that produced its endpoints; absent when either endpoint was not observed.

## Authoritative Source

- **Source:** the collector's own emission (`collectors/github_collector/collector.py`, `_collect_repo` / `_emit_commit`) over the GraphQL config layer
- **Version:** GraphQL schema as pinned in `github_openapi_extract.json`
- **Retrieved:** 2026-09-08 (github-core#78)

## Prior Art

- unified-systems-com/github-core-tap#76 rev 2 (2026-09-08) — the extraction rulings this edge implements.
- `specs/spec-github-core-vocabulary.md` — the concept table rows for the endpoints.

## Endpoints

- **Source:** `github_core__commit_observation`
- **Target:** `git_core__git_commit`
- **Dimensions:** `git.host`, `github.observation: declaration`.
- **Properties:** none.
