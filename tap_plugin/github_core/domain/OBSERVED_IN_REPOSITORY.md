# Observed In Repository

## Blurb

The hosting record GitHub made this commit observation in — the network the verification record is persisted for.

## Purpose

The observation's key already carries the repository's stable id; this edge makes the scope traversable, so a view can ask for the verdicts made in one repository without decoding keys.

## Goals

- Make the per-repository scope of a verdict a walk, not a string.

## Identity

One edge per (source, target) pair, id minted by `identity.edge_id`; property-free.

## Boundaries

Not membership of the commit in the repository — that is git_core's `STORES_COMMIT` from the neutral repository.

## Neutrality

GitHub-owned on both ends.

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
- **Target:** `github_core__github_repository`
- **Dimensions:** `git.host`, `github.observation: declaration`.
- **Properties:** none.
