# DEFINES_SECRET

## Blurb

A repository, an organisation account, or a deployment environment holds an Actions secret. The edge says which of the three scopes defines it; the node carries the name.

## Purpose

A secret's *scope* is its blast radius. An organisation secret marked `visibility: all` is readable by every workflow in every repository the organisation owns; the same name held by one repository reaches one repository; held by an environment, it reaches only jobs that have passed that environment's protection rules. Those are three very different exposures for three objects that look identical in a workflow file — `${{ secrets.X }}` is written the same way whichever one answers.

This edge is what makes the difference visible. It also does the unglamorous work of making reference resolution *correct*: without the account as a source, the most widely-shared credentials on an estate appear to exist nowhere.

## Goals

1. Attach every secret to the thing that actually holds it, at the right scope.
2. Make organisation-scope sharing legible beside repository-scope and environment-scope holding.
3. Give `REFERENCES_SECRET` something to resolve against in all three places a name can live.

## Identity

Derived: `uuid5(ns, "DEFINES_SECRET__github_core:<holder_uuid>:<secret_uuid>")`.

## Boundaries

- **Not a grant.** That a repository defines a secret does not say who may read, rotate or delete it. Write permissions on secrets are invisible to a read-only credential.
- **Not consumption.** Definition is `REFERENCES_SECRET`'s counterpart, not its equivalent. A defined secret nothing references is exactly the interesting case, and it only reads as interesting because the two facts are separate edges.
- **Not the set of repositories a `selected` organisation secret reaches.** GitHub exposes that at `selected_repositories_url`; it is not followed (see [`actions_secret`](actions_secret.md) Boundaries), so the fan-out of a `selected` secret is a gap, not a claim. Both organisation secrets observed on this estate are `visibility: all`.
- **Not Dependabot secrets.** A separate store, deferred with its own reason.

## Neutrality

Vendor-specific, following its node. The idea that something holds a named credential at a scope is general; the three-scope model and its sharing policy are GitHub's.

## Observability

Emitted from the same three listings that mint the node — see [`actions_secret`](actions_secret.md) Observability for the executed-call table. One edge per listed secret, sourced from whichever object the listing belonged to.

Observed 2026-09-10 on `unified-systems-com`: **5 edges** — 2 from the account (`OPENAI_API_KEY`, `XAI_API_KEY`, both `visibility: all`), 3 from `unified-systems-com/tap`, 0 from environments. All 17 environments on the estate answered 200 with `total_count: 0`: **observed-empty, not unread**, which is the distinction the whole surface is built around.

**Absence of this edge for a scope proves nothing unless that scope answered.** Read `github_workflow.tags.secret_refs.scopes_read` for what was actually readable in a given run.

## Authoritative Source

- **Source:** GitHub REST API — Actions Secrets: list organization / repository / environment secrets
- **Version:** REST API version `2022-11-28`
- **Retrieved:** 2026-09-10 (executed against `unified-systems-com` with an App installation token)

## Prior Art

- unified-systems-com/github-core-tap#104 (2026-09-10) — the build issue, including why repository-only collection produces confident wrong answers.
- [`REFERENCES_SECRET`](REFERENCES_SECRET.md) — the consumption half of the pair.
- [`DECLARES_ENVIRONMENT`](DECLARES_ENVIRONMENT.md) — how the third holder gets onto the grid in the first place.

## Endpoints

- **Sources:** `github_core__github_repository`, `github_core__github_account`, `github_core__github_environment` — the three things that can hold an Actions secret.
- **Target:** `github_core__actions_secret`.
- **Dimensions:** `git.host`, `github.surface: secrets`, `github.observation: declaration`.
- **Properties:** none. The scope lives on the node, where it is part of identity, rather than being derived a second time here.
