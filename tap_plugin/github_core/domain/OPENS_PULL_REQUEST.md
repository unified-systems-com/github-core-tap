# Opens Pull Request

## Blurb

The account or App that opened a pull request, carrying what the author was to the repository at the time.

## Purpose

Who proposed a change is half of every admission question — a member's proposal and a first-time contributor's are different admissions to the same gate, and `pull_request_target` incidents turn on exactly that difference. The edge puts the author on the graph so "what did this account propose across the organization" is a fan-out from one node, and carries `author_association` because the relationship is a property of the act, not of the account (the same login is `MEMBER` here and `NONE` elsewhere).

## Goals

- Let a pull request be reached from its author and an author's proposals from the account.
- Keep the author's standing at the time of the proposal on the edge, where it was observed.

## Identity

One edge per (source, target) pair, id minted by `identity.edge_id`; a pull request has exactly one author.

## Boundaries

Not reviewers or assignees — those are data on the node (`review_requests`, `latest_reviews`) until a consumer needs them as edges. Not the merger: who merged is not collected.

## Neutrality

GitHub-owned; both endpoints are GitHub types. The `author_association` vocabulary is GitHub's `CommentAuthorAssociation`.

## Observability

Emitted by the collector from the config-layer read that produced the pull request. The source is a `github_account` minted from the login (GitHub's actor kind stored as `account_type`) or, when GitHub reports the actor as a `Bot`, the `github_app` whose slug is the bot's login — the same node the installation inventory mints. Absent when the pull request carried no author (a deleted account renders as a `Mannequin` or null).

## Authoritative Source

- **Source:** GitHub GraphQL API — `PullRequest.author` (`Actor`: `__typename`, `login`) and `PullRequest.authorAssociation`
- **Version:** GraphQL schema as pinned in `github_openapi_extract.json`
- **Retrieved:** 2026-09-08

## Prior Art

- `specs/spec-github-core-vocabulary.md` (2026-08-27) — `OPENS_PULL_REQUEST`, account|app → pull_request, `{author_association}`, friends tier.
- unified-systems-com/github-core-tap#82 (2026-09-08) — the bake issue.

## Endpoints

- **Source:** `github_core__github_account` or `github_core__github_app`
- **Target:** `github_core__pull_request`
- **Dimensions:** `git.host`, `github.surface: pulls`, `github.observation: execution`.
- **Properties:** `author_association` — GitHub's association of the author with the base repository when the pull request was read; settles inside-versus-outside the trust boundary.
