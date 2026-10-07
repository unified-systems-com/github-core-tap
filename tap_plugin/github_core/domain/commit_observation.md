# Commit Observation

## Blurb

GitHub's view of a commit in one repository — the accounts it resolved the author and committer to, and its signature verification verdict. The object a required-signatures rule checks.

## Purpose

A commit is the same object wherever it lives, so its intrinsic facts live once, on the neutral `git_core__git_commit` (github-core#76). But two things about a commit are not intrinsic: which GitHub account an author email resolved to, and whether GitHub verified the signature — and the second is persisted per repository *network*, so the same commit in two unrelated networks can carry two verdicts. Putting either on the commit would let one host's judgement pose as a property of the object, and let one network's verdict overwrite another's (PR #60 review). This node is the observer's half: one record per host, repository and commit, linked to the commit it is about and to the hosting record it was made in.

## Goals

- Answer a ruleset's `required_signatures` question from what GitHub actually verified, per repository.
- Record identity **as observed** — the login GitHub resolved, or the fact that it resolved none.
- Hold the signature in three states, so "unsigned" and "could not read" and "verified" are never the same row.
- Never write a forge fact onto the neutral commit.

## Identity

Natural key: **`<host>#<repository stable id>#<hash_algorithm>:<oid>`** — `identity.commit_observation_id`. The repository's numeric id rather than `owner/repo`, so a rename does not re-mint; the commit identity is git_core's. A stable record updated in place (ruling 0.2): a re-collection that finds a changed verdict changes the field, and TAP history keeps the old one.

## Boundaries

Deliberately **not** covered:

- **The commit's own facts.** Object id, dates, author/committer name and email are on `git_core__git_commit`; this node repeats only the `sha` and algorithm as its key.
- **The network-root join.** Which repositories share one verification record needs `Repository.parent`, not yet collected; until then a fork's copy is a second observation.
- **The signature payload.** Bulk with no question behind it.
- **Who the signer *is*.** `signer_login` is a GitHub login; whether that account is the committer or a bot is a query over `identity_core`.

## Neutrality

**Vendor-specific by construction.** Every field is GitHub's resolution or GitHub's verdict; another forge would have its own observation node with its own verification vocabulary. That is the point of the split: the neutral commit travels, this stays.

## Observability

Every field is what the CommitSlice fragment on the config-layer refs query returned for the commit at a ref head. A degraded `signature` field is pruned before shaping and lands as `unobservable`; a null one is `unsigned`; a login is `""` when GitHub resolved no account — observed-absent, never unknown.

## Authoritative Source

- **Source:** GitHub GraphQL API — `Commit` (`author`/`committer` as `GitActor` with `user { login }`, `signature` as `GitSignature`), selected by the `CommitSlice` fragment inside the config-layer refs query
- **Version:** GraphQL schema as pinned in `github_openapi_extract.json` (`graphql.commit`)
- **Retrieved:** 2026-09-02 (fragment measured at `rateLimit.cost: 1`); split from the former `git_commit` node 2026-09-08 (github-core#78)

## Prior Art

- `specs/spec-github-core-vocabulary.md` (2026-08-27, #57 2026-09-02) — `git_commit` pulled to the self tier because signature state is a ruleset input; the repository-scoped key argued in PR #60 review.
- unified-systems-com/github-core-tap#76 rev 2 (2026-09-08) — ruling 0.2: observation identity = forge instance + stable repository id + commit identity; a stable record updated in place; network-level dedup later.
- GitHub docs, "About commit signature verification" (retrieved 2026-09-02) — the verification record is persistent across the repository network.

## Fields

- `host` — the forge this observation was read from (`github.com`, or a GHES tenant's host). A constituting property: GitHub's repository ids are unique per HOST, not across hosts, so two tenants sharing one grid could collide on repository id alone. Every row carries `github.com` today; the field earns its keep the day a second host does not (Issue# 164).
- `full_name` — `owner/repo` of the repository the observation was made in, for the reader; the key uses the stable id.
- `repository_github_id` — GitHub's numeric repository id, the identity half that survives a rename. Nullable only because the grid's create contract wants every field declared.
- `hash_algorithm` — `sha1` today; the algorithm half of the commit identity this observation is about.
- `sha` — the full object id, lower-case; with `hash_algorithm` it names the neutral commit (`git_core.identity.git_commit_id`).
- `author_login` / `committer_login` — the GitHub account each email resolved to; `""` when GitHub resolved none, which is observed, not unknown.
- `signature_kind` — `gpg`, `smime`, `ssh` from GitHub's signature type, `""` when unsigned or unobservable.
- `signature_state` — GitHub's verification `state` lower-cased (`valid`, `unknown_key`, `bad_email`, …), `unsigned` for a null signature, `unobservable` when the field was not answered. Three states, never two.
- `signature_valid` — GitHub's `isValid`; `null` when there is no signature to be valid.
- `signer_login` — the login GitHub attributes the signature to; `""` when none.
- `signed_by_github` — GitHub's `wasSignedByGitHub`: the web-flow signature, a claim about the signer being GitHub itself.
- `configuration` — JSONB residue for what the API returns that is not lifted into a column.
- `tags` — TAP's own tag map, uniform across every model.
