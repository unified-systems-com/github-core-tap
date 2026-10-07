# Hosts Repository

## Blurb

GitHub's hosting record for a repository links to the neutral git_core repository it hosts.

## Purpose

The hosting record — owner, visibility, API configuration, what a credential could observe — is GitHub's; the repository as a Git object belongs to no host (github-core#76). Generic consumers start from the neutral node and never read a forge's vocabulary; GitHub views reach the hosting facts through this edge. One per hosting record, emitted when the payload carried a stable `id`.

## Goals

- Keep hosting facts and Git facts on different nodes without losing the join between them.

## Identity

One edge per (source, target) pair, id minted by `identity.edge_id`; property-free.

## Boundaries

Not a fork relation, not a mirror relation: two hosting records for the same content are two neutral repositories, each with its own edge.

## Neutrality

GitHub-owned: another forge draws its own hosting edge to the same neutral type.

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

- **Source:** `github_core__github_repository`
- **Target:** `git_core__git_repository`
- **Dimensions:** `git.host`, `github.observation: declaration`.
- **Properties:** none.
