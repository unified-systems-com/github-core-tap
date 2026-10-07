# Proposes Ref

## Blurb

The pull request proposes merging this branch: its head ref, when the head lives in the base repository.

## Purpose

The proposal's branch is where the commits under review accumulate, and it is the ref a `pull_request_target` workflow checks out when it should not. Linking the pull request to the neutral ref makes "which open proposals sit on this branch" and "which branch does this proposal come from" traversals rather than string joins on `head_ref`.

## Goals

- Join the proposal to the neutral branch node without copying the branch.
- Say nothing when the branch is not ours to see.

## Identity

One edge per (source, target) pair, id minted by `identity.edge_id`. The target id is computed from the base repository's neutral identity and `refs/heads/<head_ref>`; when that ref was not observed in the batch the edge dangles and is dropped, so the edge exists only when both ends were seen.

## Boundaries

Not drawn for a fork: the head then lives in another repository whose refs are out of scope, and `head_repository` on the node records that instead. Not the commit — that is `PROPOSES_COMMIT`. Not the base — that is `TARGETS_BASE_REF`.

## Neutrality

GitHub-owned edge onto a neutral target; the relationship (a merge request proposes a branch) exists on every forge.

## Observability

Emitted from the config-layer read; present only when `headRepository.nameWithOwner` equals the base repository and the ref landed in the same batch (the ref page is capped at 100 branches — a branch beyond the cap yields no edge, and the run's `REFS_TRUNCATED` warning says why).

## Authoritative Source

- **Source:** GitHub GraphQL API — `PullRequest.headRefName`, `PullRequest.headRepository`
- **Version:** GraphQL schema as pinned in `github_openapi_extract.json`
- **Retrieved:** 2026-09-08

## Prior Art

- unified-systems-com/github-core-tap#82 (2026-09-08) — the bake issue and the dangling-edge rule.
- git_core's `DECLARES_REF` (2026-09-08, github-core#76) — the neutral ref this edge lands on.

## Endpoints

- **Source:** `github_core__pull_request`
- **Target:** `git_core__git_ref`
- **Dimensions:** `git.host`, `github.surface: pulls`, `github.observation: execution`.
- **Properties:** `ref_name` — the branch name as the pull request names it, without the `refs/heads/` prefix, so the edge reads without dereferencing the ref.
