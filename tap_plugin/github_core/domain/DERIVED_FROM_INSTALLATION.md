# DERIVED_FROM_INSTALLATION

## Blurb

The App installation whose grant a `collection_scope` was derived from — the configuration the run read, at the moment it read it. Absent in a PAT-only run.

## Purpose

A scope is operation-side history; an installation is declaration-side configuration. The two disagree over time by design: the installation node is upserted to GitHub's current answer on every run, while each scope keeps what the grant looked like when *that* run started. This edge is the join between them — from the frozen statement to the live configuration — and it is what makes a narrowed grant *findable*: walk a run's scope to its installation, compare `scope.configuration.installation.permissions` with `installation.permissions` today, and the difference is what somebody changed in a settings page without telling the collector.

It also carries the attribution the scope exists to give. When a tier verdict flips between two runs, the two scopes each point at the installation, and their recorded grants say whether "they granted less" is the cause — or whether the grant is unchanged and the manifest, or the plan, moved instead.

## Goals

1. Join every App-credentialed run's scope to the installation it read.
2. Make grant drift a two-hop comparison rather than an archaeology exercise.
3. Never guess: no installation node this run, no edge.

## Identity

Derived: `uuid5(ns, "edge:DERIVED_FROM_INSTALLATION__github_core:<scope_uuid>:<installation_uuid>")` via `identity.edge_id`.

## Boundaries

- **Not the grant itself.** The permissions, selection and events as granted are on `app_installation`; the copy the run saw is in `scope.configuration.installation`. The edge carries neither — a property here would be a third copy.
- **Not for PATs.** A personal access token has no installation to derive from; `credential_kinds` says `pat` and this edge is simply absent. That absence is not-applicable, not unobserved.
- **Not emitted on a guess.** The edge lands with the MAIN batch, beside the installation node the App inventory mints (`req-github-core-app-installations`). When that inventory could not be read there is no target node, and the edge is not emitted rather than left dangling — the scope still says which `installation_id` it used, so nothing is lost, only the traversal.
- **Not "installed on".** `INSTALLED_ON_ACCOUNT` is the installation's own join to the account that granted it; this edge is a run's join to the installation.

## Neutrality

Vendor-specific, following its target. Other forges have App-like grants, but the installation object, its `repository_selection` and its permission map are GitHub's.

## Observability

Derived from two reads the run already makes — the installation chosen at token mint (`/app/installations`) and the App inventory (`/orgs/{owner}/installations`, falling back to `/app/installations`) — and emitted only when the second minted the node the first names. Executed 2026-09-15 on the `gc-scope-node` stack with an App credential (owner `unified-systems-com`): one edge from the run's scope to `app_installation` 157103378 (`git-serious-exploratory @ unified-systems-com`, `repository_selection: all`), stamped `github.surface: apps` / `github.observation: execution`, landed in the main batch after the scope's own batch.

**Absence shape:** absent under a PAT (not applicable), absent when the App inventory was refused (target unobserved — the run record carries `APP_INVENTORY_FAILED`), present otherwise. Read `credential_kinds` on the scope before reading anything into its absence.

## Authoritative Source

- **Source:** GitHub REST API — Apps: "List installations for the authenticated app" (`GET /app/installations`), "List app installations for an organization" (`GET /orgs/{org}/installations`)
- **Version:** REST API version `2022-11-28`
- **Retrieved:** 2026-09-15 (edge proven by a live run on the `gc-scope-node` stack; the endpoints measured on PR# 144 - github-core, 2026-09-14)

## Prior Art

- unified-systems-com/github-core-tap#145 (2026-09-14) — the build issue.
- [`collection_scope`](collection_scope.md) — the source node, and the recorded grant it compares against.
- `specs/spec-github-core-v0.md` (`req-github-core-app-installations`) — the target node and which endpoint answers for it.
- `INSTALLED_ON_ACCOUNT` (`edges/INSTALLED_ON_ACCOUNT.edge.json`) — the installation's own join to its account, kept distinct.

## Endpoints

- **Source:** `github_core__collection_scope`.
- **Target:** `github_core__app_installation`.
- **Dimensions:** `git.host`, `github.surface: apps`, `github.observation: execution` — the layer follows the source (a run's statement), the surface follows the target.
- **Properties:** none. The grant as read lives on the scope; the grant as it is lives on the installation.
