# GitHub Repository

## Blurb

A repository — the single most-modelled concept in this domain, and the unit almost every control, permission and workflow is scoped to.

## Purpose

Fifteen of the sources surveyed for the vocabulary corpus model a repository; nothing else in the domain comes close. That is not because a repository is interesting in itself but because it is the **join point**: rulesets target it, workflows live in it, runners register to it, secrets are scoped to it, Apps are installed on it, and OIDC federation is claimed by its `full_name`. A question about CI/CD security is nearly always a question about one repository or a set of them.

In this plugin it holds the containment middle: owned by an account via [`OWNS_REPO`](OWNS_REPO.md), defining workflows via [`DEFINES_WORKFLOW`](DEFINES_WORKFLOW.md), and federating outward via [`FEDERATES_VIA_PROVIDER`](FEDERATES_VIA_PROVIDER.md).

## Goals

- Anchor every repository-scoped observation to one node, so a finding can be attributed.
- Carry `visibility` and `default_branch`, the two fields that change what a condition *means* rather than merely describing the repo.
- Be reachable by name, so a workflow reference, an OIDC subject claim or a hand-written GRIFT node lands on the same entity.

## Identity

Natural key: **`full_name`** — `owner/repo`. Entity id is `uuid5(ns, "github_core__github_repository:<full_name>")`.

`full_name` is load-bearing far beyond this node. It is the string in every API path, in `uses: owner/repo@ref`, and — critically — inside the **OIDC subject claim** (`repo:owner/repo:ref:...`) that the [`FEDERATES_VIA_PROVIDER`](FEDERATES_VIA_PROVIDER.md) link matches on. Keying on it means all of those resolve to the same node without a lookup.

The cost is the same as for the account: a **transfer or rename produces a new node**, and `github_id` is what joins the old to the new. GitHub redirects the old path, so both names keep resolving in the API while only one resolves on the grid — a known and accepted asymmetry, recorded here so it is not rediscovered as a bug.

## Boundaries

- **Not the repository as a Git object.** Since github-core#76 that is the neutral `git_core__git_repository` this record links to with `HOSTS_REPOSITORY`; refs and stored commits hang off the neutral node. This record keeps the hosting facts.

Deliberately **not** covered:

- **Contents.** This is not a code model. The only file this plugin reads is `.github/workflows/*`, and it is held in memory, parsed, and retained as text on the workflow node (`req-github-core-workflow-parse-5`) — never as a repository tree.
- **Branches and tags.** `git_ref` is a corpus concept at the *self* tier, reshaped from a never-built `git_branch` to cover branch **and** tag in one type because tag movement is the detection for three incidents. It is not built here; `default_branch` is a string on this node, not an edge to a ref.
- **Forks.** The corpus rules a fork to be an edge (`FORKED_FROM`) between two repositories, not a node property, and it is not built yet.
- **Pull requests, releases, environments, rulesets.** All named in the corpus, all separate types, none of them fields here.
- **Change history.** The grid provides field-level history and provenance; the corpus explicitly rejects modelling change as its own type because that duplicates the substrate.

## Neutrality

**Yes — and it is the strongest neutrality claim in the plugin.** The corpus marks `github_repository` neutral: a structurally different forge, and the non-forge project used as the kernel pressure test, both populate this concept. When a neutral substrate is extracted, this is the first type to move. Doing that while a slug change is still a re-collect is cheaper than doing it as a migration later (corpus open question 4).

The slug stays `github_core__github_repository` until then, because slugs are identity and are never renamed.

## Observability

Populated from `GET /repos/{owner}/{repo}` at **`repository:metadata:read`** — the cheapest permission GitHub offers, which is worth knowing: the core of the inventory is reachable by a credential that can see almost nothing else.

The same payload's **settings** — forking, archive and template state, merge policy, features, topics — land in `configuration` under GitHub's key names since `req-github-core-settings-3`, with one exception marked separately: `security_and_analysis` (secret scanning, push protection, Dependabot updates) is returned only to an administrator, and GitHub *omits the key* rather than refusing, so its absence is stamped `security_settings_observability: unobservable` and never read as scanning being off.

Under account scope the repository list comes from `GET /orgs/{owner}/repos` (user fallback), same permission, paginated to the end of the `Link` chain with walk completeness recorded.

**What a read-only credential cannot see about a repository**, from the verified API-surface pass:

- **Ruleset `bypass_actors`** — returned only to a caller with **write** access to the ruleset. Measured: an owner-minted fine-grained PAT sees it; a GitHub App with `administration: read` gets HTTP 200 with the field simply absent. Seeing who is exempt from a control requires write access to the control. This is a limitation to publish, not to engineer around.
- **Organization-level rulesets** are documented as needing `Administration (org): write`, while **repository** rulesets read at `Administration (repo): read` — and the *effective* rules for a branch (`GET /repos/{o}/{r}/rules/branches/{b}`) need only `Metadata: read`, which is the cheapest useful control read available.
- **The audit log** is GitHub Enterprise Cloud only. For a Team-plan organisation, change over time must be derived by diffing grid snapshots.

## Authoritative Source

- **Source:** GitHub REST API — Repositories (`GET /repos/{owner}/{repo}`, `GET /orgs/{org}/repos`), Rules (`GET /repos/{o}/{r}/rules/branches/{branch}`), and the fine-grained personal-access-token permissions reference
- **Version:** REST API version `2022-11-28`
- **Retrieved:** 2026-08-27 (the `bypass_actors` write-access finding verified by execution on this date, not read from documentation)

## Prior Art

- `specs/spec-github-core-vocabulary.md` (2026-08-27) — **15 sources**, the highest count in the corpus; marked neutral and named as the first extraction candidate.
- `git-serious-tap/docs/doc-git-serious-cicd-security-prior-art.md` §3.9 (2026-08-27) — the per-endpoint permission table this Observability section is built from.
- `git-serious-tap/docs/doc-git-serious-linux-kernel-pipeline.md` (2026-08-27) — the non-forge pressure test that supports the neutrality claim.
- GitHub REST API, version `2022-11-28` — Repositories and Rules endpoints.

## Fields

- `full_name` — `owner/repo`, the natural key and only required field. Also the string OIDC subject claims and `uses:` references carry, which is why it and not the numeric id is the key.
- `owner_login` — the owner half, stored separately so a query can group by account without parsing the key. A derived value, kept because splitting a string in every query is worse than storing it once.
- `name` — the repository half, for the same reason.
- `github_id` — GitHub's numeric repository id. Not the key; carried so a rename or transfer can be recognised as continuity rather than as a new repository.
- `default_branch` — the branch most controls default to targeting. Load-bearing in analysis rather than descriptive: a cache written on the default branch is restorable by workflows on it, and a ruleset that protects `main` protects nothing if the default branch is not `main`.
- `visibility` — `public`, `private` or `internal`. Changes what a condition *means*: a self-hosted runner on a private repository is ordinary, and on a public one it is one of the strongest findings in the corpus.
- `html_url` — the browser URL, for linking out.
- `outputs_observability` — three states per OUTPUT surface (github-core#31): `{"releases": "observed"|"unobservable", "artifacts": ..., "packages": ..., "notes": {surface: why}}`. Lives here rather than on the output nodes because a property that qualifies an absence belongs on the node the absence is about, never on the nodes that failed to appear — the same ruling as `github_ruleset.bypass_observability`. The machinery view reads it to tell "no releases" from "could not look"; `{}` means the collector never ran the output surfaces, which is itself not "none".
- `custom_properties` — `{"criticality": "critical", "lifecycle": null, ...}`: one key per custom property the owning organization DECLARES ([`github_custom_property`](github_custom_property.md)), the value as GitHub reports it (a string, an array for `multi_select`) or null when the repository has not set it. Built over the declared names first, so a declared-but-unset property is observed-unset (null) rather than an absent key. Lives here because the value is a fact about the repository and the column a table needs; the definition is the node. An empty `{}` with observability `observed` means the organization declares no properties.
- `custom_properties_observability` — three states, the `bypass_observability` ruling applied here: `observed` (the organization's values listing answered — an empty map is then a fact), `unobservable` (the credential could not read the definitions or the values — the map means nothing and must not render as "none set"), `""` (the collector never asked: a repos-only scope, or a user account, where custom properties do not exist).
- `pull_requests_observability` — three states for the pull-request surface ([`pull_request`](pull_request.md)): `observed` (the config layer answered `pullRequests` — zero rows is then a fact), `unobservable` (the field degraded and was pruned — no row means nothing), `""` (a repos-only scope runs no config-layer query: never asked).
- `pull_requests_total` — GitHub's `totalCount` of pull requests, kept beside the collected window (the thirty most recently updated) so a window is never read as all of them; null until the surface was observed.
- `code_scanning_observability` — **four states** for the code-scanning surface ([`code_scanning_alert`](code_scanning_alert.md), [`code_scanning_analysis`](code_scanning_analysis.md), and the `compliance_finding` nodes minted from the alerts; github-core#89): `observed` (the alerts and analyses listings answered 200 — zero of either is then a fact), `unobservable` (403: the App lacks `security_events: read`, or it was added after installation and not yet accepted by an organisation owner — no row means nothing, and the run warns per repository), `not_enabled` (GitHub answered that code scanning, or GitHub Advanced Security on a private repository, is not enabled here — a fact about the repository's configuration, not about the credential, and the state a public repository nothing has ever uploaded to sits in), `""` (never asked: a repos-only scope, or the surface not in the run). The fourth state exists because GitHub distinguishes *the product is off* from *you may not look*, and folding the first into `observed` would render an unscanned repository as clean while folding it into `unobservable` would blame the credential for a configuration choice. One field for both listings because they share an endpoint family and a permission. Lives here, on the node the absence is about, by the `bypass_observability` ruling.
- `dependabot_observability` — **four states** for the Dependabot alert surface ([`dependabot_alert`](dependabot_alert.md), and the `compliance_finding` nodes minted from the alerts; github-core#68), the same shape and for the same reason as `code_scanning_observability`: `observed` (the listing answered 200 and the walk reached the end — zero alerts is then a fact), `unobservable` (403/404 not explained by the feature being off, or a walk cut off at the page cap — the credential could not look, or could not look at all of it, so no row means nothing), `not_enabled` (GitHub says Dependabot alerts are disabled for this repository — a fact about the repository, not about us), `""` (never asked).
- `configuration` — JSONB for repository detail not yet promoted to a column; also the honest home for repository-level Actions policy when collected.
- `tags` — TAP's tag map.
