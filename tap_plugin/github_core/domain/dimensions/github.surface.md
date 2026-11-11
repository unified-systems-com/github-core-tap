# `github.surface`

## Blurb

Names which part of GitHub an observation came from — and, because GitHub's surfaces have different permissions and different APIs, which credential could see it.

## Purpose

GitHub is not one API. Actions, Apps and rules are separate product surfaces with separate endpoints, separate fine-grained permissions, and — as this plugin learned by executing calls rather than reading documentation — genuinely different reachability. Actions data is REST-only and reads at `repository:actions:read`. App installations are GitHub-App-only and return 404 to any personal access token. Ruleset detail strips its bypass-actor list unless the caller has *write* access.

`github.surface` records which of those worlds a node or edge came from. That makes it more than a tidy label: it is the closest thing the grid has to a machine-legible statement of *why a set of nodes might be empty*, because emptiness on a surface almost always traces to the credential that surface demanded.

## Goals

- Partition observations by product surface, so a query can scope to one API's world.
- Keep the "which permission produced this" question answerable at the dimension level.
- Use GitHub's own vocabulary for its own surfaces rather than inventing parallel words.

## Identity

The key is `github.surface`, in the `github.` namespace this plugin owns; effectively immutable, as every dimension key is.

**Values follow GitHub's own subcategory names for the endpoints they cover** — `actions`, `apps`, `rules` — rather than a taxonomy of our own. That is the corpus's Naming rule applied to dimensions: where the source system already has a word, use its word. It also means a reader who knows GitHub's API docs can predict the value without consulting this article.

## Boundaries

- **Not the tenant.** Which GitHub instance is [`git.host`](git.host.md).
- **Not declared-versus-executed.** That is [`github.observation`](github.observation.md), and the two are orthogonal: `actions` covers both a workflow definition and a run.
- **Not carried by everything.** The containment spine deliberately omits it. A platform, an account, a repository and the `HOSTS_ACCOUNT` / `OWNS_REPO` edges are not facts about any one surface, so stamping them would assert a scope they do not have.
- **Not a permission record.** The surface *implies* the permission that reads it, and this article names those implications, but the dimension does not encode a credential, a grant, or whether the read succeeded.
- **Not exhaustive.** The value set grows as the plugin reaches new surfaces; runner groups remain a corpus concept whose surface is not yet collected.

## Neutrality

**Vendor-specific, and unusually so.** Both the key and every value name GitHub's own product structure. Another forge would not have `actions`, `apps` and `rules`; it would have its own surfaces. When neutral types are extracted this dimension does not travel with them — it is precisely the part that stays behind.

## Observability

**Declared, never fetched**, and applied at creation from type and edge-type defaults, so the stamp itself is never ambiguous.

What the *values* imply about observability is the useful part, and each was established by executing a call:

- `actions` — reads at `repository:actions:read`, except workflow YAML, which needs `repository:contents:read`. **REST only: GitHub's GraphQL API exposes no Actions runs or jobs at all**, so there is no batched alternative. A credential with `actions:read` but not `contents:read` yields workflow nodes that are real and nearly empty.
- `apps` — installed Apps come from an endpoint that is **GitHub-App-only and returns 404 to any PAT**, whatever its permissions. A PAT-based collection produces an apps population of first-party services only, and it looks complete, because a 404 is not an error the way a 403 is.
- `rules` — the ruleset list and detail read at `administration: read`, but the detail **silently strips `bypass_actors`** unless the caller has write access to the ruleset, and version history for an organization-sourced ruleset is unreachable by the repository path.

The pattern across all three: an empty surface is ambiguous, and the ambiguity resolves in the reassuring direction. Any view built per-surface owes its reader three states — none, some, and not-observable — not two.

## Authoritative Source

- **Source:** `specs/spec-github-core-v0.md` `req-github-core-dimensions` (surface on Actions models); GitHub REST API subcategory names for Actions, Apps and Rules; the fine-grained personal-access-token permissions reference
- **Version:** REST API version `2022-11-28`; declarations as of commit `46a34b8` plus the in-flight ruleset work
- **Retrieved:** 2026-08-27 (the App-only 404, the `bypass_actors` strip and the GraphQL absence all verified by execution, not read from documentation)

## Prior Art

- `specs/spec-github-core-v0.md` `req-github-core-dimensions` (2026-08-27) — the dimension strategy.
- `git-serious-tap/docs/doc-git-serious-cicd-security-prior-art.md` §3.9 (2026-08-27) — the verified per-endpoint permission table these implications are drawn from.
- `specs/spec-github-core-vocabulary.md` (2026-08-27) — the Naming rule: use the source's own word where one exists, which is why the values are GitHub's subcategory names.

## Values

- `actions` — the GitHub Actions surface: workflow definitions, runs, jobs and self-hosted runners, plus the edges among them. The plugin's largest surface by both node count and analytical weight.
- `apps` — the GitHub Apps surface: registered applications and their reach onto repositories. Also carries the Actions OIDC issuer, which is not an App but reaches a repository through the same "enabled here" relationship.
- `rules` — the rulesets surface: the enforcement gates on a repository's refs. GitHub's own subcategory name for these endpoints, chosen over inventing a parallel word for the same thing.
- `releases` — the releases surface: published releases and their joins to tags and runs. GitHub's REST subcategory name. Reads at `contents: read`; arrives on the GraphQL config-layer transport, which is a transport fact, not a surface one.
- `custom-properties` — the custom-properties surface: the definitions an organization declares for its repositories. GitHub's subcategory name (`orgs/custom-properties`). Reads at the "Custom properties" organization permission (`organization_custom_properties`, read); the values themselves are fields on the repository, which carries no surface stamp, so the dimension marks the definitions only.
- `pulls` — the pull-requests surface: the proposals and the edges from them to their author and onto the neutral refs and commits. GitHub's REST subcategory name for the endpoints. Reads at `pull_requests: read`, with the head commit's check rollup needing `checks: read` and `statuses: read` besides; arrives on a GraphQL query of its own, paged at five repositories because the config-layer query has no node budget left for it and a larger page exceeds GitHub's execution time limit.
- `secrets` — the Actions secrets surface: the NAMES of secrets held at organisation, repository and environment scope, and the edges that say which scope holds each. GitHub's subcategory name (`actions/secrets`). Reads at `secrets: read` for the repository and environment listings and `organization_secrets: read` for the account one, so an estate can be half-visible here in a way no other surface is: a credential holding one and not the other resolves workflow references against an incomplete set and reports working references as broken. Measured 2026-09-10, the response carries `name`, `created_at`, `updated_at` and (organisation only) `visibility` — **there is no value field**, which is what makes this the one credential surface safe to put on a graph. A 404 on the organisation listing means the owner is a user account with no such surface — nothing to ask, not refused — while 401/403 is a refusal and the scope reads as not observed; `github_workflow.tags.secret_refs.scopes_read` carries which scopes a given run actually reached.
- `packages` — the GitHub Packages surface: packages and their versions. GitHub's subcategory name. **Not enabled for GitHub Apps** per GitHub's OpenAPI description (`enabledForGitHubApps: false`), measured 2026-09-02 as a 400 on the container listing and a 200 `[]` on the others — an empty population here is unobservable under the product credential, and `github_repository.outputs_observability.packages` says so.
- `security` — the security-alert surfaces GitHub groups under *Security* in its API reference: code scanning (alerts and analyses, `github.surface: security` on `code_scanning_alert`, `code_scanning_analysis` and their edges, 2026-09-09, github-core#89), Dependabot alerts (`github.surface: security` on `dependabot_alert`, 2026-10-13, github-core#68), and, when built, secret-scanning alerts. Not one of GitHub's subcategory names — those are `code-scanning`, `dependabot` and `secret-scanning` — but the one word GitHub's own navigation and App-permission review table use for the group, chosen because the three share a property the dimension exists to name: each reads at a **sensitive** permission of its own (`security_events`, `vulnerability_alerts`, `secret_scanning_alerts`), and each answers 403 as a per-repository NOT OBSERVABLE state and a product-off state (`not_enabled`) distinct from it. The generic `compliance_finding` nodes this surface mints are compliance_core's and carry its `compliance: finding` marker, not this stamp; the detail nodes and github_core's edges carry it. Reads at `repository:security_events:read` for code scanning, measured 2026-09-09 with the installed App: 200 on `unified-systems-com/tap`; at `repository:vulnerability_alerts:read` for Dependabot, measured 2026-10-13: 200, 48 alerts.
