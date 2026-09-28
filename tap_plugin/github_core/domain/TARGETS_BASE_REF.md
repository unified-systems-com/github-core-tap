# Targets Base Ref

## Blurb

The branch the pull request asks to land on — the ref whose rulesets gate the merge.

## Purpose

*Why isn't this merging* is answered on the base: the rulesets that protect the base ref (`PROTECTS_REF` lands on the same node) name the required checks, and those are what the pull request's head commit must satisfy. This edge is the hop from a proposal to its gate, which turns the chain ruleset → required check → producing workflow into a traversal that starts at the pull request.

## Goals

- Reach a pull request's gate from the pull request in one hop.
- Group open proposals by the branch they target.

## Identity

One edge per (source, target) pair, id minted by `identity.edge_id`. The target id is computed from the base repository's neutral identity and `refs/heads/<base_ref>`; a base ref not observed in the batch leaves the edge dangling and dropped, with `base_ref` on the node as the fact.

## Boundaries

Not the head — that is `PROPOSES_REF`. Not the release-to-tag relationship — that is `TARGETS_REF`, kept separate because its properties and its meaning (a release cut on a tag) are different.

## Neutrality

GitHub-owned edge onto a neutral target; the relationship exists on every forge.

## Observability

Emitted from the config-layer read; present when the base ref landed in the same batch, which for a default branch is always.

## Authoritative Source

- **Source:** GitHub GraphQL API — `PullRequest.baseRefName`, `PullRequest.baseRefOid`
- **Version:** GraphQL schema as pinned in `github_openapi_extract.json`
- **Retrieved:** 2026-09-08

## Prior Art

- unified-systems-com/github-core-tap#82 (2026-09-08) — the bake issue.
- `git-serious-tap/specs/spec-git-serious-why-not-merging.md` (2026-09-02) — the gate-chain requirement this edge starts.

## Endpoints

- **Source:** `github_core__pull_request`
- **Target:** `git_core__git_ref`
- **Dimensions:** `git.host`, `github.surface: pulls`, `github.observation: execution`.
- **Properties:** `ref_name` — the base branch name as the pull request names it, without the `refs/heads/` prefix.
