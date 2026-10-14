# GitHub Core Plugin Specification

## Plugin Identity

- **Slug:** `github_core`
- **Display name:** TAP GitHub Core
- **Collector:** `GitHubCollector` — `CollectorBase` subclass; two-phase run (collection + enrichment). See `req-github-core-collector` and `req-github-core-grid-links`.
- **Secret kind:** `github_pat` — Personal Access Token. See `req-github-core-secret`.
- **v0 target:** `notgeorge/samsite` (configured via the secret's `repos` array).
- **Repo shape:** In-tree under `plugins/github_core/` for v0. No standalone git repo or submodule; may be split later if external consumers appear.
- **Default dimensions** (see `req-github-core-dimensions`):
  - `git.host = "github.com"` on all plugin-owned nodes and edges, and on every neutral `git_core` node this plugin mints
  - `github.owner` + `github.repo` on repo-scoped objects (set by the collector per envelope)
  - `github.surface = "actions"` on Actions-related objects
  - `github.observation` on every plugin-owned node and edge: `"execution"` on runs and
    jobs, `"declaration"` on everything else. Both layers are stated positively — the
    config layer is never encoded as the absence of the dimension

## Philosophy

`github_core` models the GitHub side of the samsite deployment on the TAP
grid. The v0 target is deliberately narrow: make the plumbing from repository
content to live site visible for `notgeorge/samsite`, especially GitHub Actions
workflows, workflow runs, jobs, and runners. Variables and secret references
are deferred to a backlog requirement (`req-github-core-backlog-references`).

This is not a full GitHub inventory product. Broad repository introspection,
organization-wide governance, issue/PR modeling, permissions audits, Sigstore,
and Rekor all remain future work. v0 exists because the Sam demo needs to show
how the static site and compliance machinery move through GitHub Actions into
the running AWS-backed site.

## Roadmap Alignment

Governing step: `step-rampart-sam-demo` in `plan/road-rampart.md`.

This work directly supports the active Done-Test by making Sam's reproduced
deployment legible as a connected system: GitHub repo -> workflow -> run -> job
-> runner -> referenced AWS resources. The minimum useful version is a collector
that populates the graph for `notgeorge/samsite`; everything else is deferred.

## Prior Art

Cartography's GitHub Actions module models workflows, environments, actions,
secrets, variables, and parsed workflow content as graph data. The useful
pattern for TAP is: fetch API resources, parse workflow YAML for permissions /
references, transform into typed graph objects, and preserve source payloads.
TAP does not copy Cartography's per-loader implementation or Neo4j schema; the
collector is clean-room and GRIFT-based.

CloudQuery and Steampipe both expose broad GitHub table/plugin surfaces. They
confirm the mainstream inventory categories: repositories, Actions workflows,
runs/jobs, self-hosted runners, repository variables, and repository secrets.
They also show the scope cliff. TAP v0 intentionally avoids their full table
surface and takes only the Actions plumbing path needed for samsite.

## Goals

|   |   |   |
| :---: | --- | --- |
| 1. | Plumbing-Visible | Show the path from repo content to GitHub Actions execution and referenced deployment resources. |
| 2. | Collector-Driven | Populate GitHub state through a `tap_cares` collector that emits GRIFT batches. |
| 3. | Manifest-Declared | Keep API/file collection and grid-link resolution declarative enough to inspect without reading collector code. |
| 4. | Scoped | Target `notgeorge/samsite` first; defer full GitHub account introspection. |
| 5. | Dimensioned | Use GitHub-specific dimensions so the GitHub platform can be sliced as its own environment. |

## Requirements

| RID | Name | Status | Notes |
| --- | --- | :---: | --- |
| req-github-core-scope | [Plugin Scope](#plugin-scope) | Implemented | Actions plumbing for a configured scope: an account (org/user, enumerated — `req-github-core-org-scope`) or an explicit repo list |
| req-github-core-app-auth | [GitHub App Authentication](#github-app-authentication) | In Development | 2026-08-27: the App is the product credential — its permissions are DERIVED from the collection manifest, it is created per-instance from a manifest so the operator holds their own key, and two surfaces git-serious needs are App-only (organization PAT grants, installed Apps) |
| req-github-core-org-scope | [Account Scope](#account-scope) | Implemented | 2026-08-26 (pulled by git-serious): the envelope names an `owner`; the collector enumerates its repositories (org, user fallback), `repos` becomes an optional include-filter, and the run records the enumeration incl. walk completeness. Repos-only envelopes remain valid as the degenerate run config |
| req-github-core-models | [Model Set](#model-set) | Implemented | account/repo/workflow/run/job/runner (0001) + synthesized `github_platform` (0002) — seven tables. `oidc_issuer` was extracted to the `identity_core` substrate plugin (dropped here in 0004); github still mints the issuer node via `identity_core.issuer`. |
| req-github-core-rule-suites | [Rule Suites — Who Actually Bypassed](#rule-suites--who-actually-bypassed) | In Development | 2026-08-28 (settled empirically): enumeration of bypass ACTORS has a documented write-access ceiling, but rule suites answer the adjacent question — who actually bypassed a gate — and return 200 to a read-only App with actor names. Detection where enumeration is refused. |
| req-github-core-releases | [Releases — The First Output](#releases--the-first-output) | In Development | 2026-09-02 (github-core#31): `github_release` from the config-layer GraphQL query at no extra request, keyed on `owner/repo` + release id; `PUBLISHES_RELEASE` containment, `TARGETS_REF` onto the tag, and a DERIVED `BUILDS_RELEASE` whose `match_kind` labels its own evidence. Three states on the repository node (`outputs_observability`). |
| req-github-core-packages | [GitHub Packages — The Collection Seam](#github-packages--the-collection-seam) | In Development | 2026-09-02 (github-core#31): `github_package` / `github_package_version` carrying a purl, so `supply_chain_core` (vocabulary decision 4) can claim them by identity. **Not observable with the product credential**: GitHub marks the packages endpoints `enabledForGitHubApps: false`; measured as a 400 on the container listing. Recorded as `unobservable`, never zero. Adds `organization:packages:read` to the derived permission set — existing installations must re-accept. |
| req-github-core-ruleset | [Ruleset Collection](#ruleset-collection) | In Development | 2026-08-27 (pulled by git-serious): `github_ruleset` node keyed on GitHub's global `databaseId`, sourced from the config-layer GraphQL query that already returned rulesets but discarded them. The id is the prerequisite for every other ruleset surface — bypass actors, rule suites, version history — all of which are keyed by it. Attachment edge deferred pending its slug. |
| req-github-core-edges | [Edge Vocabulary](#edge-vocabulary) | Implemented | Platform/account/repo/workflow/run/job/runner spine (incl. `HOSTS_ACCOUNT`) plus cross-grid `REFERENCES_RESOURCE` and `FEDERATES_VIA_PROVIDER` — eight edge files registered. `TRUSTS_ISSUER` is now the generic `identity_core`-owned edge (wildcard source); github's enrichment still emits it. |
| req-github-core-actions-used | [Actions Used](#actions-used) | In Development | 2026-09-02 (github-core#45, ranked first by `build-github-corpus`): `github_action` node keyed on the action path, shared across the scope, plus `USES_ACTION` carrying the pin. The parser no longer labels every non-SHA ref `tag`; a mutable name is resolved only against an in-scope repository's refs and is otherwise `unresolved` / `unobservable`. |
| req-github-core-workflow-chains | [Workflow Chains](#workflow-chains) | In Development | 2026-09-02 (github-core#29, #52): `CALLS_WORKFLOW` (job → reusable workflow, the `USES_ACTION` pin grammar + `secrets_inherit`) and `TRIGGERS_WORKFLOW` (completing → triggered, from `on.workflow_run`), both resolved in a post-pass over the whole scope; an unresolved callee or name is recorded on the node, never fabricated. |
| req-github-core-artifacts | [Artifacts](#artifacts) | In Development | 2026-09-02 (github-core#55): `actions_artifact` from the repository listing (newest first, capped, total reported) joined by `UPLOADS_ARTIFACT` from the producing run when it is in the batch; `expired` observed, never inferred (shape C). Declared upload/download steps on the job; no download edge — GitHub keeps no record of downloads. |
| req-github-core-commits | [Commits](#commits) | Implemented | 2026-09-08 (github-core#76/#78): the commit's INTRINSIC half is the neutral `git_core__git_commit` (identity `sha1:oid`, one node however many hosts store it; `STORES_COMMIT` from the neutral repository, `RESOLVES_COMMIT` from the ref); GitHub's OBSERVED half — resolved logins, signature verdict in three states — is `commit_observation`, keyed per host + repository stable id + commit (`OBSERVES_COMMIT`, `OBSERVED_IN_REPOSITORY`). Sliced from a `CommitSlice` fragment on the config-layer refs query at no extra request. |
| req-github-core-refs | [Refs](#refs) | Implemented | Branches and tags, one type. Since github-core#76/#78 the ref is the neutral `git_core__git_ref` (identity = neutral repository id + full path; `DECLARES_REF__git_core` from the neutral repository this record `HOSTS_REPOSITORY`); this plugin emits it and targets it from `PROTECTS` / `SCOPED_TO_REF` / `EVALUATED_ON_REF` / `TARGETS_REF`. Row added per github-core#69. |
| req-github-core-status-checks | [Status Checks](#status-checks) | In Development | 2026-09-02 (github-core#61): `status_check` keyed `<owner>#<context>` from the ruleset detail's `required_status_checks` parameters; `REQUIRES_CHECK` with the rule's qualifiers; `PRODUCES_CHECK` derived from job display names with stated confidence, only toward required contexts an Actions job may produce. A refused detail is counted as not observable, never as no requirement. |
| req-github-core-custom-properties | [Custom Properties](#custom-properties) | Implemented | 2026-09-08 (github-core#77; live-verified the same day with the App credential alone): `github_custom_property` keyed `<owner>#<property_name>` from the organization's schema endpoint; every repository's values stamped as `github_repository.custom_properties` built over the declared names (null = observed-unset) with a three-state `custom_properties_observability`. No edge — the value lives once, on the repository. Adds nothing to the App: `organization:custom_properties:read` was already granted, now derived. |
| req-github-core-pull-requests | [Pull Requests](#pull-requests) | In Development | 2026-09-08 (github-core#82): `pull_request` keyed `<owner/repo>#<number>` from the config-layer `pullRequests` field, joined to git_core's neutral head/base ref and head commit (`PROPOSES_REF`, `TARGETS_BASE_REF`, `PROPOSES_COMMIT`) and to its author (`OPENS_PULL_REQUEST`); build status = the head commit's check rollup flattened onto the node, App-produced checks included. Lives in github_core, not git_core: a forge object, ruled 2026-09-08. |
| req-github-core-code-scanning | [Code Scanning Alerts](#code-scanning-alerts) | In Development | 2026-09-09 (github-core#89): the first security-axis surface, under the ruling **one generic finding type, source-specific data behind an edge**. The generic type is compliance_core's existing `compliance_finding` (v0.2.2; its placement edge is `CARRIES_COMPLIANCE_FINDING` since v0.3.0, github-core#97), which this collector MINTS one-per-alert and places with compliance_core's `CARRIES_COMPLIANCE_FINDING` (repository always, workflow when the path is one); `code_scanning_alert` is the DETAIL behind it via `DETAILS_FINDING`; `code_scanning_analysis` is the record that a scan RAN (`ANALYZES_REPOSITORY`, conditional `ANALYZES_COMMIT`). Four observability states on the repository. `security_events` recommended → requested. |
| req-github-core-settings | [Settings — Organization, Repository, Environment](#settings--organization-repository-environment) | Implemented | 2026-09-11 (github-core#110, the BloodHound parity pass): the policy blocks GitHub already returns — org 2FA / default permission / member privileges / security defaults / Actions policy, repository forking / archive / merge / security settings, environment reviewers / admin bypass / branch policy — copied verbatim into `configuration` with a three-state observability marker beside each surface. No new types; 20 of the 87 BloodHound saved queries become field filters. Live done-test 2026-09-11 on the demo grid: org `observed` (39 keys, 2FA on, default permission none, Actions policy `selected`), 25/25 repositories and 18/18 environments `observed` |
| req-github-core-app | [GitHub Apps](#github-apps) | Implemented | Generic `github_app` type + `ENABLED_ON_REPOSITORY` edge; Dependabot detected from the synthetic Actions entry and reclassified at collection time |
| req-github-core-dimensions | [Dimension Strategy](#dimension-strategy) | Implemented | All four dimensions emitted: platform on every node/edge, repo on collector envelopes, surface on Actions models, observation on runs/jobs |
| req-github-core-secret | [Collector Secret Kinds](#collector-secret-kinds) | Implemented | One `github` envelope carrying an App and/or a read-only token, additionalProperties: false; legacy kinds fold forward |
| req-github-core-collector | [Collector Runtime](#collector-runtime) | Implemented | Two-phase run + degraded-runner + no-delete + single-attempt + incremental + non-terminal refresh + empty-body-404 retry + per-run-/jobs degrade |
| req-github-core-manifests | [Collection And Link Manifests](#collection-and-link-manifests) | Implemented | Two manifests + JSON Schemas, validated at load; link manifest is data-driven |
| req-github-core-workflow-parse | [Workflow File Parsing](#workflow-file-parsing) | Implemented | YAML parse + raw retention + in-memory fetch + scope-bound ref extraction + local-action detection |
| req-github-core-runner | [Runner Semantics](#runner-semantics) | Implemented | Durable runner nodes + matchable EXECUTED_ON_RUNNER + observed-runner-on-job + no-ephemeral-runner-nodes |
| req-github-core-grid-links | [Existing Grid Links](#existing-grid-links) | Implemented | Enrichment phase + exact-only + warn-only failures + Gryphon read path (via `=~` regex operator); OIDC link verified end-to-end against samsite + AWS |
| req-github-core-python-deps | [Plugin Python Dependency](#plugin-python-dependency) | Implemented | `PyYAML` is plugin-owned via root uv workspace; first proof of `req-plugin-arch-python-deps` |
| req-github-core-dependabot-alerts | [Dependabot Alerts](#dependabot-alerts) | In Development | 2026-10-13 (github-core#68): GitHub's own vulnerable-dependency findings, per repository, under the one-generic-finding ruling of `req-github-core-code-scanning`: `dependabot_alert` is the DETAIL behind a `compliance_core__compliance_finding` minted one-per-alert (all four lifecycle states), placed with `CARRIES_COMPLIANCE_FINDING` from the repository, the workflow whose path is the alert's manifest and the action whose path is its package. Four observability states on the repository. `vulnerability_alerts` recommended → requested. Measured 2026-10-13: 48 alerts on `unified-systems-com/tap`, all `pip`; the Actions ecosystem is still unobserved. |
| req-github-core-backlog-references | [Variables And Secret References (Backlog)](#variables-and-secret-references-backlog) | Backlog | Two-source-of-truth model, hotlink contract implication, provenance shape; pick up when critical path |
| req-github-core-backlog-run-attempts | [Multi-Attempt Run Observation (Backlog)](#multi-attempt-run-observation-backlog) | Backlog | Per-attempt run + job fan-out, re-run-failed-jobs subtlety, RUNS_JOB lifecycle; pick up when critical path |
| req-github-core-backlog-grid-vocab-links | [Grid-Vocabulary Reference Resolution (Backlog)](#grid-vocabulary-reference-resolution-backlog) | Backlog | Replace the parser's regex shape-guessing with matching against the known grid vocabulary (regions/zones/dist-ids); removes junk refs, recovers `${{ }}`-embedded matches, needs confidence markers |
| req-github-core-backlog-app-relationships | [GitHub App Relationships (Backlog)](#github-app-relationships-backlog) | Backlog | Model what apps *do* beyond being enabled — e.g. Dependabot opens dependency-bump PRs against the repo, code scanning posts alerts. Edges like `OPENS_PR` / `RAISES_ALERT` once there's a consumer |
| req-github-core-nongoals | [v0 Non-Goals](#v0-non-goals) | Implemented | Full GitHub inventory, Sigstore/Rekor, deletion/reaping, schedules, references, multi-attempt runs — boundaries hold |

### Plugin Scope
----
RID: `req-github-core-scope`

Status: `Implemented`

`github_core` models GitHub platform objects that matter to deployment and
compliance plumbing. The target is a configured scope — an account whose
repositories the collector enumerates (`req-github-core-org-scope`), or an
explicit repo list (the original `notgeorge/samsite` shape). It does not attempt
to inventory every organization setting, issue, pull request, or permission
surface; those arrive as further manifest sources behind the same scope.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-scope-1 | Target Scope | Implemented | The collector target is configured in the `github_pat` envelope: an `owner` (account scope, enumerated) and/or an explicit `repos` list. | Was `notgeorge/samsite` by repo list; account scope added 2026-08-26 (`req-github-core-org-scope`). |
| req-github-core-scope-2 | Actions Plumbing Focus | Implemented | v0 focuses on repository, workflow, run, job, and runner data needed to explain deployment flow. | Variables and secret references are deferred (`req-github-core-backlog-references`). |
| req-github-core-scope-3 | No Broad Introspection | Implemented | Full GitHub account/org/repo introspection is deferred. | Collector touches only the documented endpoints; no broad walk. |

### GitHub App Authentication
----
RID: `req-github-core-app-auth`

Status: `Implemented`

A personal access token is a *person's* power in token form: it inherits their role, expires on
someone's calendar, and dies when they leave. A GitHub App is its own principal with its own
declared permissions, and two surfaces this plugin needs are **App-only** — the organization's
fine-grained PAT grants and the list of installed Apps both return `404` to any token (verified
2026-08-27). The App is therefore the product credential; `github_pat` remains supported because a
token is the right tool for pointing an instance at one repository in ten minutes.

**The permission set is derived, never hand-written.** Every source in the collection manifest
declares the canonical triple it needs (`<surface>:<key>:<level>`), and the App's permissions are
the union over sources — the same declaration the collector obeys, so the published claim about
what we ask for cannot drift from what we use. Anything requested beyond that union must be passed
explicitly and is rendered as `EXPLORATORY`, because silently over-requesting permission in a
security product is the behaviour the product exists to find in other people.

**Creation is per-instance and operator-held.** GitHub offers no API for creating an App — a
logged-in human must confirm in a browser — so the flow renders a manifest, serves a review page
from a short-lived listener on `127.0.0.1`, and catches GitHub's redirect locally. The operator's
own machine performs the exchange and writes the envelope. This is not a preference: **the instance
mounts its secrets root read-only and cannot write its own credentials.** The operator provisions;
the instance consumes. A hosted variant, where one App is installed into many accounts, is
explicitly rejected — it would route adopters' data through infrastructure we run.

**Signing adds no crypto provider.** The JWT is minted with `cryptography` against the system
OpenSSL the FIPS posture validates (`spec-fips.md`); no JWT library is introduced.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-app-auth-1 | Both Credentials Held, Chosen Per Source | Implemented | `GithubAuth` holds whichever credentials the envelope carries. A caller names the one that answers ITS question — `token(prefer=PREFER_PAT)` for the ruleset detail (bypass actors), `app_jwt()` for the App-only inventory — and a caller that does not care asks for `token()`. No global preference order. | `collectors/github_collector/auth.py`. The one PAT-preferring call is the ruleset detail, and the reason is recorded at the call site so it is not "simplified" back into a preference order. |
| req-github-core-app-auth-11 | A Gap Names Its Missing Credential | Implemented | When the credential that would answer better is absent, `absent_note(prefer)` supplies the operator-facing reason, carried onto the ruleset node, the run warning, and a self-test row. It is empty when that credential IS present, so it never becomes noise. | This is what turns `bypass_observability = unobservable` from a dead end into "an owner PAT would show these". |
| req-github-core-app-auth-2 | Permissions Derived | Implemented | The App manifest's permissions are the union of the collection manifest's per-source permission triples. Extras require an explicit flag and render as `EXPLORATORY`. | `skills/create-github-app/manifest.py`. |
| req-github-core-app-auth-3 | Surfaces Namespaced | Implemented | Repository and organization permissions are namespaced before emission, and a key collision raises rather than silently overwriting. | Found in review: `repository:administration` and `organization:administration` collapsed onto one key and one was dropped. |
| req-github-core-app-auth-4 | Operator Holds The Key | In Development | Creation happens on the operator's machine; the private key is written to their secret store at `0600` and never printed, logged, or transmitted. The instance never writes a credential. | Enforced by the read-only secrets mount, not only by convention. |
| req-github-core-app-auth-5 | Host Flow Is Stdlib-Only | Implemented | The creation flow runs outside the container and imports only the standard library, per the `tap/git_invocation.py` discipline. The verification half additionally needs `cryptography`, and path-imports the SAME `app_jwt.py` the collector uses rather than carrying its own copy — so the credential it proves is minted the way the collector will mint it. | Asserted by test, including that `verify_app.py` defines no `mint_jwt` of its own and that neither script defines a `normalize_credentials` of its own — the envelope fold (`credential_shape.py`, stdlib-only) is path-loaded the same way (github-core#25). |
| req-github-core-app-auth-6 | Redirect Is State-Checked | Implemented | The manifest carries a random `state`; a redirect whose state does not match is refused and no exchange is attempted. | |
| req-github-core-app-auth-7 | Token Lifecycle | Implemented | The private key signs a JWT (≤10 min) exchanged for an installation token (~1 h). The token is held on the auth INSTANCE — never at module or class scope — and the envelope's `owner` selects which installation to mint for; an App installed into several accounts with no `owner` is refused rather than guessed at. | The failure mode is cross-account leakage that produces plausible results, which is why the ambiguous case raises instead of taking the first installation. |
| req-github-core-app-auth-8 | No Webhook By Default | Implemented | The generated App subscribes to no events and declares no webhook. Receiving events is a separate capability decision. | `tap_cares`'s receiver half is not yet built. |
| req-github-core-app-auth-9 | Verified Before Trusted | In Development | A placed credential is proven end-to-end — key → JWT → installation → token → one probe per reachable surface — before the collector relies on it. | `skills/create-github-app/verify_app.py`. Reads the envelope through the collector's own fold, so the combined `github` kind `create_app.py` writes verifies; until github-core#25 the script kept a private `kind == "github_app"` check and refused every placed credential with "nothing to verify" — a verifier that passed by never looking. Regression pinned in `tests/test_credential_shape.py`. |
| req-github-core-app-auth-10 | Public Apps Rejected | Implemented | The per-instance model never marks an App public; a public App implies a hosted, centralized deployment that routes adopters' data through our infrastructure. | The flag exists only to keep the shape describable. |

### Account Scope
----
RID: `req-github-core-org-scope`

Status: `Implemented`

Pulled by git-serious (git-serious-tap#17, 2026-08-26): a product that observes an
organization's CI/CD must not hardcode the repositories it pulls. The collector's
scope is therefore an **account** — the `owner` login of a GitHub organization or
user — and the collector enumerates that account's repositories itself
(`GET /orgs/{owner}/repos?type=all`, falling back to `GET /users/{owner}/repos` on
404, paginated to the end of the Link chain). An explicit `repos` list, when present
alongside `owner`, is an include-filter over the enumeration; without `owner` it is
the scope itself. That second form is the **degenerate run config** — the same code
path with a fixed list, never a parallel path (the tap#142 ruling).

Two edges laid while the surface is open:

- **The run records its enumeration.** Absence must be proven, not inferred
  (tap#140): before a future reconcile can tombstone what is gone, a run has to
  assert it completely enumerated a scope. `SCOPE_ENUMERATED` carries the owner,
  account kind, counts, whether a filter applied, and `complete` — false when the
  paginated walk stopped at the page cap with a next link pending.
- **Every manifest source declares the PAT permission it needs**
  (`permission`, e.g. `Actions: read`), so the least-privilege permission set for the
  credential is derived as the union over sources by the provisioning skill, never
  hand-listed.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-org-scope-1 | Account Enumeration | Implemented | With `owner` set, the collector enumerates the account's repositories (org endpoint, user fallback on 404) and collects each. | `GithubCollector._resolve_repos`; manifest source `owner_repos`. |
| req-github-core-org-scope-2 | Repos As Filter | Implemented | With `owner` and `repos` both set, only enumerated repositories named in `repos` are collected; names not found under the owner are recorded as `SCOPE_FILTER_UNMATCHED` warnings, not errors. | |
| req-github-core-org-scope-3 | Enumeration Recorded | Implemented | The run records `SCOPE_ENUMERATED` with owner, account kind, enumerated/collecting counts, filter flag, and walk completeness; an incomplete walk is labelled, never silently treated as complete. | `GithubClient.last_walk_complete`; batch dimensions carry `github.owner`. |
| req-github-core-org-scope-4 | Degenerate Repo List | Implemented | A `repos`-only envelope (no `owner`) collects exactly that list through the same run path with no enumeration. | Existing samsite envelopes keep working unchanged. |
| req-github-core-org-scope-5 | Scope Self-Test | Implemented | `self_test()` proves the PAT can enumerate the owner (`GITHUB_OWNER_ACCESS:<owner>`, one bounded listing walk) and still probes each explicit repo individually. | |
| req-github-core-org-scope-6 | Source Permissions Declared | Implemented | Every collection-manifest source carries a `permission` naming the fine-grained PAT permission it needs; the schema admits the field and the provisioning skill derives the least-privilege set from it. | |

### Model Set
----
RID: `req-github-core-models`

Status: `Implemented`

The v0 model set is intentionally small but node-granular. Values that deserve
identity, edges, queryability, history, and graph-visible lifecycle become
dedicated node types rather than being jammed into workflow JSON.

Models:

- `github_platform` — the platform instance (github.com today, a GHES host tomorrow); the top of the `platform → account → repo → workflow` tree. Synthesized as a singleton by the collector (one per run) rather than fetched — no GitHub API enumerates "the platform." Natural key is the host, so a self-hosted GHES tenant becomes a second instance rather than a special case.
- `github_account` — owner/user/org account.
- `github_repository` — repository shell; v0 only needs enough fields to show it exists and anchor Actions objects.
- `github_workflow` — workflow definition discovered from GitHub Actions API and parsed workflow file content.
- `github_actions_run` — one workflow run (latest observed state; multi-attempt tracking deferred to `req-github-core-backlog-run-attempts`).
- `github_actions_job` — one job within a workflow run. Step details live in `configuration` in v0.
- `github_runner` — durable registered self-hosted runner configuration when visible through the API.
- `github_app` — a GitHub App or first-party platform app (e.g. Dependabot) enabled on a repository. Generic across GitHub's app surface (managed apps, third-party apps, OIDC token-issuing apps); keyed by app slug so one node is shared across every repo that enables it, with `ENABLED_ON_REPOSITORY` edges fanning in. See [GitHub Apps](#github-apps). **The application only** — one account's installation of it is `app_installation`.

The **self-tier vocabulary** (added 2026-08-27, `spec-github-core-vocabulary.md`):

- `workflow_job` — a job as WRITTEN: `permissions`, `runs-on`, `if`, the environment it deploys to, the ref it checks out. See [Declared Jobs](#declared-jobs).
- `git_ref` — a branch or a tag, and the commit it points at. One type for both. See [Refs](#refs).
- `github_ruleset` — the gate a commit must pass to land on a ref, with its rules and its bypass *observability*. See [Rulesets](#rulesets).
- `github_environment` — a named deployment target and the protection rules in front of it. See [Environments](#environments).
- `actions_cache` — a stored cache entry and the ref scope that produced it. See [Caches](#caches).
- `app_installation` — one account's installation of an App, with the permissions that account granted. See [App Installations](#app-installations).
- `collection_scope` — one per collection run, on the operation side: what THIS run's credential was allowed to weigh in on. See [Collection Scope](#collection-scope).

The OIDC issuer (`oidc_issuer`) is **no longer a github_core model** — it was
extracted to the `identity_core` substrate plugin as the cross-cutting
federated-identity convergence node (`identity_core__oidc_issuer`; see
`plugins/identity_core/specs/spec-identity-core-v0.md`). github_core still mints
the GitHub Actions issuer node during collection, but through
`identity_core.issuer.oidc_issuer_node_envelope` — the vocabulary and the id/URL
normalization live in identity_core, and any other observer (AWS, Sigstore,
samsite) converges on the same node by its canonical-URL id. github enables the
issuer on each repo (`ENABLED_ON_REPOSITORY`, source now `identity_core__oidc_issuer`).

Variables (`github_actions_variable`) and secret references
(`github_actions_secret_ref`) are deferred to
`req-github-core-backlog-references`.

#### Identity

Natural-key inputs:

| Model | Natural Key |
| --- | --- |
| `github_platform` | host (`github.com`) |
| `github_account` | account login or GitHub numeric id |
| `github_repository` | `owner/repo` |
| `github_workflow` | `owner/repo` + workflow id/path |
| `github_actions_run` | `owner/repo` + run id |
| `github_actions_job` | `owner/repo` + job id |
| `github_runner` | `owner/repo` + runner id for durable registered runners |
| `github_ruleset` | owner login + GitHub's ruleset id — **not** repo-scoped |
| `github_app` | app slug (`dependabot`) — singleton across repos |
| `workflow_job` | `owner/repo` + workflow id + the job's YAML key |
| `git_ref` | `owner/repo` + the FULL ref path (`refs/heads/main`) — git_core's type, minted there |
| `github_environment` | `owner/repo` + environment name |
| `actions_cache` | `owner/repo` + cache id |
| `actions_artifact` | `owner/repo` + GitHub's artifact id |
| `actions_secret` | scope + owner login + `owner/repo` + environment name + secret name |
| `app_installation` | GitHub's installation id (unique platform-wide) |
| `collection_scope` | the `collection_job` entity id — one scope per run |
| `pull_request` | the BASE `owner/repo` + the PR number |
| `github_custom_property` | owner login + the property name as reported |
| `status_check` | owner login + the context string (case-sensitive) |
| `rule_suite` | GitHub's suite id (unique platform-wide) |
| `code_scanning_alert` | `owner/repo` + GitHub's alert number |
| `code_scanning_analysis` | `owner/repo` + GitHub's analysis id |
| `github_release` | `owner/repo` + GitHub's release id — **not** the tag name |
| `github_package` | owner login + package type + package name |
| `github_package_version` | owner login + package type + package name + GitHub's version id |
| `github_action` | the `uses:` path with the ref stripped — platform-global |
| `commit_observation` | the repository's numeric id + hash algorithm + the commit sha |

The `github_ruleset` row previously appeared TWICE in this table, once saying "ruleset
`databaseId` **alone**" and once saying "owner login + GitHub's ruleset id". The code has
always been owner-scoped (`identity.py::ruleset_id(owner, ruleset_id_int)`), so the
owner-scoped row is the true one and the `databaseId`-alone row has been removed
(Issue# 162). The Ruleset Collection section below still narrates the verification that the
bare id WOULD have keyed correctly; the owner prefix is belt-and-braces, not a correction.

**Entity ids are ASSIGNED, not derived** (`req-grid-entity-natural-key`). Each model declares
its key above as a `NATURAL_KEY` tuple of FIELD names; the collector names each node with a
batch-local `ref` (`<entity_type>:<natural key>`) and the GRIFT importer resolves it —
`find_existing` on the declared fields under a transaction-scoped advisory lock, a fresh
UUIDv7 on a miss.

**Three types are HELD BACK** — declared, but still addressed by an explicit derived UUIDv5, so
nothing resolves against their declaration and it stays free to change. A natural key is a
one-way door only once a node's id has been assigned under it.

| Type | Why | Ruling |
| --- | --- | --- |
| `compliance_core__compliance_finding` | Another plugin's type; it declares no `NATURAL_KEY`, so a ref to it is refused outright. | Flips when compliance_core adopts. |
| `commit_observation` | Its recipe keys on the platform HOST; the model has no `host` field, so the declared key is narrower. Inert while the host is the constant `github.com`; a GHES tenant sharing the grid could collide on repository id. | Issue# 164 |
| `actions_secret` | Its key case-folds the name (GitHub secret names are not case-sensitive); the declared search filters the stored name, which is the name GitHub returned, so the two disagree. Under a ref a second canonical spelling would mint a second node behind an unchanged edge. | Issue# 165 |

Every `git_core__*` and `identity_core__*` node this collector emits likewise keeps the id its
own plugin's identity module derives.

#### Configuration Field Shape

`github_workflow.configuration` and `github_actions_job.configuration` are
JSON fields holding parser output and observation data:

```
github_workflow.configuration = {
    "triggers":    [...],
    "permissions": {...},
    "raw_yaml":    "<full workflow file text as fetched>",
    ...
}

github_actions_job.configuration = {
    "name":     "...",
    "runs_on":  "...",
    "needs":    [...],
    "uses":     [...],
    "steps":    [...],   # structured per-step data; no node per step in v0
    ...
}
```

`raw_yaml` on `github_workflow` is the full workflow YAML body as fetched by
the collector during the collection phase (per `req-github-core-workflow-parse-5`).
Retaining the raw body lets parser logic evolve without re-fetching from
GitHub, and lets future panel work surface the actual workflow text inline.
This follows Cartography's "preserve source payloads" pattern called out in
this spec's Prior Art section.

**Caveat.** `raw_yaml` is the *current* workflow definition at collection
time, not the YAML that any specific historical run actually executed. A
run's `head_sha` field links to the commit that triggered it; fetching per-
run YAML snapshots from `/repos/{owner}/{repo}/contents/.github/workflows/<name>?ref=<head_sha>`
is a future enhancement, not v0. Panel work that surfaces "this run's YAML"
must not conflate the two.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-models-1 | V0 Models Declared | Implemented | The plugin declares the seven v0 model types listed above. | The original six landed via 0001_initial; `github_platform` via 0002. `oidc_issuer` (originally 0003) was extracted to `identity_core` and dropped here in 0004. |
| req-github-core-models-8 | Platform Singleton Synthesized | Implemented | `github_platform` is a synthesized singleton (one per run, keyed on the host), not fetched from any API; re-runs and hand-written GRIFT nodes with the same host upsert cleanly onto it. | Collector emits it before the per-repo walk; mirrors `aws_core`'s `aws_account_singleton` pattern. |
| req-github-core-models-9 | OIDC Issuer Synthesized (via identity_core) | Implemented | The collector still synthesizes the GitHub Actions issuer node, but the type and vocabulary live in `identity_core` (`identity_core__oidc_issuer`); github mints it through `identity_core.issuer.oidc_issuer_node_envelope`. Any observer (samsite, AWS enrichment) converges on the same node by canonical-URL id regardless of run order. | Extracted 2026-07-08; see spec-identity-core-v0.md (req-identity-core-migration). |
| req-github-core-models-3 | Job Steps Blobbed | Implemented | Workflow job steps remain structured data in `github_actions_job.configuration` in v0. | Future visualization target. |
| req-github-core-models-4 | Assigned Identity, Declared Search | Implemented | Every model declares `NATURAL_KEY` over the fields named in the table above, and the collector emits a batch-local `ref` rather than a minted id, so `Entity.id` is assigned by core (`req-grid-entity-natural-key`). | Was "Deterministic Identity": every model minted a UUIDv5 from `(entity_type, natural_key)`. Adopted 2026-09-20 (Issue# 162 - tap-plugin-github-core); github_core is core's first adopter. `identity.py` now returns `Ref` strings; edge ids stay UUIDv5 AND keep their exact pre-adoption values (the importer finds an edge only by the supplied id, so a shifted edge id would double every existing grid's edges on first re-collect — `_endpoint_token` re-derives what each ref used to be). Edge identity under assigned nodes is Issue# 690 - tap. Three types keep derived ids and do not emit refs: `compliance_core__compliance_finding` (another plugin's type, undeclared), `commit_observation` (Issue# 164) and `actions_secret` (Issue# 165). |
| req-github-core-models-7 | Raw Workflow YAML Retained | Implemented | `github_workflow.configuration.raw_yaml` stores the full workflow YAML body fetched at collection time. | Parser stores raw bytes; collector base64-decodes the Contents-API `content` field and writes it. |

### Ruleset Collection
----
RID: `req-github-core-ruleset`

Status: `In Development`

A **ruleset** is GitHub's enforcement gate on a set of refs — required status checks,
required pull requests, non-fast-forward and deletion protection. It is the object that
answers "is this branch actually protected," so a CI/CD projection that omits it is
describing a pipeline while silently ignoring its gate.

**One node per ruleset, not per attachment.** An organization-sourced ruleset is a single
rule set that GitHub projects onto every repository in scope, and it is returned by each of
those repositories' ruleset lists. Measured on `unified-systems-com`: **6 rulesets, 60
attachments, 19 repositories** — three org rulesets accounting for 57 of the attachments.
Modelling one node per attachment would derive the same ruleset's facts nineteen times and
let the copies drift, so the collector dedupes on the ruleset id for the whole run, the way
`github_app` dedupes on slug.

**The id is the point.** The config-layer GraphQL query has always requested rulesets, but
selected only `name`, `enforcement` and `target` — no id — and the result was discarded
without being emitted. Every *other* ruleset surface is keyed by that id: the bypass-actor
list (`/rulesets/{id}`), rule suites (`/rulesets/rule-suites`, the bypass *events*), and
version history (`/rulesets/{id}/history`). Collecting the id is therefore the prerequisite
for all of them, and is the whole of this requirement's scope; those surfaces are separate
work.

#### Identity

The natural key is owner login + GitHub's ruleset `databaseId`, deliberately not scoped by
REPOSITORY. The verification below (2026-08-27) established that the bare `databaseId` would
also have keyed correctly — the owner prefix is belt-and-braces, kept because a natural key
cannot be changed once nodes exist:

- **Organization- and repository-sourced rulesets share one sequence.** Sorted, the six
  observed ids interleave by source — an org ruleset, then three repo rulesets, then two more
  org rulesets — so there are not two sequences that could collide.
- **The sequence is global to GitHub, not per-organization.** Id order matches `created_at`
  order exactly, two rulesets created 0.44s apart hold consecutive integers, and an
  organization owning six rulesets holds ids near **20.6 million**; a per-org sequence would
  have numbered them 1–6.

Should GitHub ever change this, the fallback that preserves the 60→6 collapse while
disambiguating is `<source_type>:<source_name>#<ruleset_id>`.

#### Source type is a node property

`source_type` (`Organization` | `Repository`) is a fact about the ruleset, not about any one
attachment — putting it on the attachment would derive the same fact 57 times. It is also
operationally load-bearing rather than descriptive: **version history for an
organization-sourced ruleset is not reachable by the repository path** (it 404s) and requires
organization scope. On the fixture org that is 57 of 60 attachments, so for any organization
doing protection at the org level, history is an org-scope operation.

#### Observability

`bypass_actors` — *who may skip this gate* — is **not collected by this requirement**, and
cannot be by a read-only credential. GitHub returns the field only to a caller with write
access to the ruleset, documented as: *"To prevent leaking sensitive information, the
`bypass_actors` property is only returned if the user making the API request has write access
to the ruleset."* A read-only caller receives HTTP 200 with the field simply absent. The
consequence for any consumer is that **a blank "who can bypass" must never render as "nobody
can bypass"** — three states are required (none / some / not-observable). Bypass *detection*
has no such ceiling: rule suites are readable by a read-only credential.

The attachment edge (`repository` → `github_ruleset`) is deferred pending its slug in the
vocabulary corpus; the node stands alone until then.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-ruleset-1 | Ruleset Model Declared | In Development | The plugin declares a `github_ruleset` model carrying `ruleset_id`, `name`, `enforcement`, `target`, `source_type`, `source_name`, `configuration` and `tags`. | `models/github_ruleset.py`. |
| req-github-core-ruleset-2 | Identity Is The Bare Database Id | In Development | `ruleset_id()` mints identity from GitHub's ruleset `databaseId` alone, unscoped by repository, so every repository reporting one organization ruleset resolves to a single node. | Verified globally unique before minting — see Identity above. |
| req-github-core-ruleset-3 | Deduped Across The Run | In Development | The collector emits at most one node per ruleset id per run, regardless of how many repositories report it. | `_emitted_ruleset_ids`, mirroring `_emitted_app_ids`. |
| req-github-core-ruleset-4 | Sourced From The Config Layer | In Development | Rulesets are read from the GraphQL config-layer response, which now selects `databaseId` and `source`. No additional REST call is made, and a scope with no GraphQL enumeration emits no rulesets rather than falling back to REST. | Measured: 1 rate-limit point for 19 repositories / 60 attachments. |
| req-github-core-ruleset-5 | Idless Rulesets Are Skipped | In Development | A ruleset returned without a `databaseId` is not emitted, because no bypass-actor, rule-suite or history surface can be reached from it. | Landing an unfollowable node would assert coverage the collector does not have. |
| req-github-core-ruleset-6 | Closed Sets Validated, Empty Permitted | In Development | `enforcement`, `target` and `source_type` validate against GitHub's closed sets, with `""` permitted so a partially-read ruleset still lands. | A degraded field must not discard the whole ruleset. |

### Edge Vocabulary
----
RID: `req-github-core-edges`

Status: `Implemented`

Edges express the GitHub Actions execution spine and dependency references.

V0 edge types:

| Edge | Direction | Meaning |
| --- | --- | --- |
| `HOSTS_ACCOUNT` | `github_platform` -> `github_account` | Platform instance hosts an account (top-of-tree containment). Synthesized alongside the platform singleton. |
| `OWNS_REPO` | `github_account` -> `github_repository` | Account owns repo. |
| `DEFINES_WORKFLOW` | `github_repository` -> `github_workflow` | Repo contains workflow definition. |
| `EXECUTES_WORKFLOW` | `github_actions_run` -> `github_workflow` | Run executes workflow. |
| `RUNS_JOB` | `github_actions_run` -> `github_actions_job` | Run contains job. v0 reflects the latest-attempt job set; multi-attempt tracking deferred. |
| `EXECUTED_ON_RUNNER` | `github_actions_job` -> `github_runner` | Job executed on a durable runner node when matchable. (Distinct from `computing_core.RUNS_ON`, which models program-on-compute-environment.) |
| `REFERENCES_RESOURCE` | GitHub node -> external grid node | Conservative exact-match link to existing AWS nodes (resolved in the enrichment phase). |
| `FEDERATES_VIA_PROVIDER` | `github_repository` -> `aws_iam_oidc_provider` | Repo federates into AWS through the GitHub Actions OIDC provider (URL `token.actions.githubusercontent.com`). Chains with the AWS-side `FEDERATES_INTO` (provider -> deploy role). Derived link resolved in the enrichment phase. |
| `TRUSTS_ISSUER` | `aws_iam_oidc_provider` -> `identity_core__oidc_issuer` | The AWS IAM OIDC provider registers trust in an OIDC issuer — its scheme-less `url` matches the issuer's `host`. **The edge type is the generic `identity_core`-owned `TRUSTS_ISSUER__identity_core`** (wildcard source — trusting an issuer is a cross-cloud federation relationship, not AWS-specific); github_core no longer owns it, but its enrichment phase still *emits* it (edge types resolve globally, and github is today the plugin that runs a grid-link engine + mints the issuer in the same run). Derived link resolved in the enrichment phase (not hotlink-backed). |
| `DEFINES_JOB` | `github_workflow` -> `workflow_job` | A workflow file declares a job. Properties `{job_key, order}`. |
| `DEPENDS_ON_JOB` | `workflow_job` -> `workflow_job` | The `needs:` graph — what a job compromised early can reach later. Property `{condition}`. |
| `HAS_REF` | `github_repository` -> `git_ref` | Repo contains a branch or tag. |
| `PROTECTS` | `github_ruleset` -> `github_repository` \| `git_ref` | A ruleset gates a repository (`match_kind: declared`) or a specific observed ref (`match_kind: resolved`, with the `ref_pattern` that matched). |
| `BYPASSES` | `github_account` \| `github_app` \| `app_installation` -> `github_ruleset` | An actor may bypass a ruleset. **Absence of this edge is not absence of bypass** — see `req-github-core-rulesets`. |
| `DECLARES_ENVIRONMENT` | `github_repository` -> `github_environment` | Repo declares a deployment environment. |
| `USES_ENVIRONMENT` | `workflow_job` -> `github_environment` | A declared job deploys through an environment's protection rules. Its absence beside a deploying job is the finding. |
| `STORES_CACHE` | `github_repository` -> `actions_cache` | Repo holds a stored cache entry. |
| `SCOPED_TO_REF` | `actions_cache` -> `git_ref` | A cache entry belongs to an observed ref's scope; absence usually means a pull-request ref. |
| `REGISTERS_INSTALLATION` | `github_app` -> `app_installation` | The application, and one installation of it. |
| `INSTALLED_ON_ACCOUNT` | `app_installation` -> `github_account` | The account that granted the installation. |
| `SCOPES_RUN` | `collection_scope` -> `collection_job` | The statement about one run — the target is tap_cares' core run record, addressed by its `ENTITY_TYPE` string. See [Collection Scope](#collection-scope). |
| `DERIVED_FROM_INSTALLATION` | `collection_scope` -> `app_installation` | The grant a run's scope was derived from. Absent under a PAT, and absent (never guessed) when the App inventory could not be read. |
| `ENABLED_ON_REPOSITORY` | `github_app` \| `app_installation` \| `identity_core__oidc_issuer` -> `github_repository` | A GitHub App, platform app, or the Actions OIDC issuer is enabled on the repo. Emitted during the per-repo walk. The issuer source type lives in `identity_core`. See [GitHub Apps](#github-apps). |

Secret and variable reference edges (`REFERENCES_SECRET`, `REFERENCES_VARIABLE`)
are deferred to `req-github-core-backlog-references`.

`REFERENCES_RESOURCE` is intentionally conservative. It means "this GitHub
plumbing names or depends on this resource" and does not claim deployment,
ownership, or runtime control.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-edges-1 | Containment + Execution Spine | Implemented | The platform/account/repo/workflow/run/job/runner edges (`HOSTS_ACCOUNT`, `OWNS_REPO`, `DEFINES_WORKFLOW`, `EXECUTES_WORKFLOW`, `RUNS_JOB`, `EXECUTED_ON_RUNNER`) are declared and constrained. | `HOSTS_ACCOUNT` is the top-of-tree containment edge synthesized with the platform singleton. |
| req-github-core-edges-2 | Cross-Grid Edges | Implemented | The v0 cross-grid edges github owns are `REFERENCES_RESOURCE` (conservative resource reference) and `FEDERATES_VIA_PROVIDER` (repo -> AWS OIDC provider federation). The enrichment phase also emits `TRUSTS_ISSUER` (AWS OIDC provider -> `identity_core__oidc_issuer`), the generic `identity_core`-owned type. All resolve in the enrichment phase. | Secret/variable reference edges deferred. |
| req-github-core-edges-3 | Conservative Resource Semantics | Implemented | `REFERENCES_RESOURCE` is used only for exact, unambiguous matches and does not overstate deployment semantics. | Enforced by the link-manifest schema (`match_mode: exact`-only enum) and the resolver's one-candidate-only emission rule. |

### Declared Jobs
----
RID: `req-github-core-declared-jobs`

Status: `Implemented`

A job as **written** and a job as **run** are different objects, and the vocabulary corpus found
that almost nobody models both: the published GitHub graph schemas model the declaration only, and
of sixteen surveyed sources only eight model a pipeline run at all. `github_actions_job` is an
execution — it keys on GitHub's job id and carries `status`/`conclusion`. `workflow_job` is the
declaration — `permissions`, `runs-on`, `if`, the environment it deploys to, and the ref it checks
out. **Every privilege decision in CI is made at the declared level**, which is why ~20 of the 35
incidents in the corpus need this node and why it was the largest gap in the model set.

Identity keys on the workflow id plus the YAML job key, not on `name:`: a renamed file keeps its
jobs, and a retitled job stays the same job.

**`permissions` distinguishes three states, and must.** No `permissions:` block means the job
inherits the workflow's (`null` — unobserved at this level). `permissions: {}` means the job's
token is granted nothing. Collapsing those two reads the most locked-down job in a repository as
the most permissive one, and the field history would show a change that never happened.

`checkout_ref` is a column rather than a key inside a steps blob because it is half of the
most-cited shape in the corpus: a `pull_request_target` workflow that checks out
`github.event.pull_request.head.sha` runs a contributor's code with the base repository's secrets.
The other half — the trigger — is carried onto the job's `configuration` alongside the workflow's
own permissions, so the question can be adjudicated at one node instead of by walking up.

Steps remain structured data rather than nodes (`step` was rejected on the node test: nothing
points at a step). Cache usage is extracted onto the job's `configuration` now;
`WRITES_CACHE`/`RESTORES_CACHE` are a later wave. Action pins became `USES_ACTION` edges in
`req-github-core-actions-used`.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-declared-jobs-1 | Declaration Node Exists | Implemented | Every job declared in a collected workflow file lands as a `workflow_job` with a deterministic id over `owner/repo` + workflow id + job key, joined to its workflow by `DEFINES_JOB`. | The declaration and the execution are never merged. |
| req-github-core-declared-jobs-2 | Inherited And Empty Permissions Differ | Implemented | An absent `permissions:` block stores `null`; `permissions: {}` stores `{}`. The two are never collapsed. | Asserted at both the parser and the model layer. |
| req-github-core-declared-jobs-3 | Checkout Ref Is First-Class | Implemented | The ref passed to `actions/checkout` is a queryable column, and the workflow's triggers and permissions ride on the job's `configuration` so a single node answers the `pull_request_target` question. | |
| req-github-core-declared-jobs-4 | Needs Graph Emitted | Implemented | `needs:` becomes `DEPENDS_ON_JOB` edges carrying the dependent's `if:`. A `needs:` naming a job that does not exist emits no edge and keeps the name visible on the node. | Emitted after all jobs in a file are known, since a job may need one declared below it. |
| req-github-core-declared-jobs-5 | Runner Declaration Canonicalized | Implemented | `runs-on` is stored as a list whichever of the three written forms was used (string, list, `{group, labels}`); a job that declares none stores `null`, not `[]`. | One query shape for "which jobs run on a self-hosted label". |

### Actions Used
----
RID: `req-github-core-actions-used`
Status: `In Development`

A `uses:` line hands a job's token, its checkout and every secret in scope to code in someone
else's repository, at whatever commit the written ref resolves to on the day. The corpus's
tag-repoint compromises are that sentence, and until this wave the action was text inside
`workflow_job.configuration.action_refs` — parsed, present, and unreachable from any other node
(github-core#45).

`github_action` is keyed on the **action path** (`owner/repo[/subdir]`, or `docker://image`)
and is platform-global, like `github_app`: `actions/checkout` is one node that every job in scope
points at. A subdirectory action is its own node (`actions/cache/restore` is not `actions/cache`).
The ref is not identity — the same action is pinned differently by different jobs — so the pin
rides on `USES_ACTION`, one edge per (job, action, declared ref), with every step position that
shares the ref folded into `step_indexes`.

**The pin is stated in three states, never two.** `pin_kind` is `sha` or `digest` when the string
proves immutability; `tag` or `branch` only when the action's own repository is inside the observed
scope and the name was matched against its refs (config layer, `req-github-core-refs`, no extra
request); otherwise **`unresolved`**, with `resolution: unobservable` when the repository is out of
scope and `resolution: in_scope` when it was in scope and the name matched nothing. The previous
parser called every non-SHA ref `tag`, which was a declaration that existed and was false —
presence is not correctness — and `resolution` exists so a reader can tell "pinned to a tag" from
"pinned to a name nobody looked up". An out-of-scope
action repository IS looked up (2026-09-03, PR #67): `GET /repos/{o}/{r}/git/ref/tags/{ref}` then
`.../heads/{ref}` on 404 — the order a runner resolves — with an annotated tag peeled to its commit
via `GET .../git/tags/{sha}`; a hit is `resolution: rest` with the commit as `resolved_sha`, a miss
at both paths is `unresolved` (the ref does not exist as written), a refusal or failure is
`unobservable` and warned, and past the per-run cap the edge says `not_attempted` and the run says
how many. Both endpoints ride `repository:contents:read`, already in the union, and answer any
credential on a public repository. One lookup per distinct (repository, ref) per run.

`is_pinned` is carried explicitly (true iff `sha` or `digest`) so the one-bit control every
action-pinning check asks is not re-derived per view. `resolved_sha` — the SHA itself, or an
in-scope ref's head commit — has field history, which is the tag-repoint detection, in the same way
`git_ref.head_sha` history is tag-movement detection.

Absence shapes (github-core#14): the edge is **git-provable** (a commit removing the `uses:` line is
positive evidence); the node is **derived absence** — relevant while any edge points at it, never
tombstoned on its own observation. `DEFINED_IN` (action → repository) and `resolves_to_fork` are
the corpus's next items on this surface and are not built here.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-actions-used-1 | Action Node Is Shared | In Development | Every non-local `uses:` in a collected workflow lands as one `github_action` per action path, platform-global, with no owner/repo dimension. | Same fan-in shape as `github_app`. |
| req-github-core-actions-used-2 | The Pin Lives On The Edge | In Development | `USES_ACTION` (job → action) carries `declared_ref`, `pin_kind`, `is_pinned`, `resolution`, `step_indexes` and, when known, `resolved_sha`; a job calling the same action at two refs emits two edges. | Edge id includes the declared ref for that reason. |
| req-github-core-actions-used-3 | A Name Is Never Called A Tag Without Evidence | In Development | A non-SHA ref parses as `unresolved`; it becomes `tag` or `branch` only by matching the in-scope repository's refs (`in_scope`) or by a REST lookup of an out-of-scope one (`rest`); it is `unobservable` only when no lookup answered. | Asserted at the parser and the collector. |
| req-github-core-actions-used-4 | Docker Steps Are Actions Too | In Development | `docker://image[:tag|@sha256:digest]` lands as a `kind: docker` node; a digest is `digest` and pinned, an image tag is `tag` and not. | |
| req-github-core-actions-used-5 | The Run Says What It Saw | In Development | The run records the distinct-action count, the usage count, how many usages were unpinned and how many of those were unobservable, so a zero reads as a count and not a silence. | `ACTIONS_USED`, extended 2026-09-03 with the REST states and lookups spent. |
| req-github-core-actions-used-6 | Out-Of-Scope Refs Resolved Over REST | Implemented | A `tag` or `branch` pin on an out-of-scope action carries the commit it pointed at when observed (`resolution: rest`), tags before heads, an annotated tag peeled; a ref at neither path is `unresolved`; a refused lookup, or an annotated tag whose commit cannot be established (refused, or nested deeper than three tag objects), is `unobservable` and warned — never a blank that reads as unpinned, never a tag object's SHA dressed as the commit. A repository that is not exactly `owner/repo`, or a ref with `..`, an empty segment or a leading slash, is `unresolved` without a request — untrusted `uses:` text never shapes an API path. | `test_action_ref_resolution.py`. OBSERVED 2026-09-03 on `unified-systems-com/git-serious-fixtures`: `actions/download-artifact@v3` → `tag`/`rest`/9bc31d5c…, `actions/checkout@v4` → `tag`/`rest`/11d5960a…; the run record: "5 usage(s) pinned to a mutable name or nothing, of which 2 resolved over REST … 2 REST lookup(s) spent". The fixture's own `actions/hello@does-not-exist` is an IN-scope miss (`pin_kind: unresolved`, `resolution: in_scope`); the REST `unresolved` and `unobservable` states are unit-verified only. |
| req-github-core-actions-used-7 | REST Budget Bounded And Stated | Implemented | Lookups are cached per (repository, ref) for the run and capped (`_ACTION_REF_RESOLUTION_CAP`); past the cap edges carry `not_attempted` and the run warns with the count; `ACTIONS_USED` reports lookups spent and counts per state. | `test_one_lookup_per_distinct_ref_and_a_cap`. The cap path is unit-verified only. |
| req-github-core-actions-used-8 | Drift Is Queryable | Proposed | After two observations across which a tag was re-pointed, the `USES_ACTION` edge's `resolved_sha` history shows the move under an unchanged `declared_ref`. | The observation is its own issue, github-core#71, on the fixture's `v1` tag. |
| req-github-core-actions-used-9 | Publishing Repository Linked | Backlog | `DEFINED_IN` joins the action to a `github_repository` carrying `archived` and `fork`, so an archived or transferred action is a query. | Corpus row; named as the next item. |
| req-github-core-actions-used-10 | Canonical-Repository Membership | Backlog | A SHA pin is checked to belong to the action's canonical repository rather than a fork in its network (`resolves_to_fork`). | Needs reachability from a branch or tag head; `commits/{sha}` answers for the whole fork network. |

### Workflow Chains
----
RID: `req-github-core-workflow-chains`
Status: `In Development`

Two ways one workflow reaches another, both declared in YAML, both invisible until this wave. A
**reusable-workflow call** (`jobs.<id>.uses: owner/repo/.github/workflows/x.yml@ref`, or the
same-repository `./` form) brings another file's jobs, runners and permissions into the caller's
run and receives whatever secrets the caller passes — every one of them under `secrets: inherit`.
A **`workflow_run` trigger** (`on: workflow_run: workflows: [<name>]`) fires one workflow on the
completion of another, in base-repository context, which is GitHub's own recommended shape for
handling untrusted input and therefore the edge along which a fork's output reaches a workflow that
holds secrets (github-core#29, #52).

`CALLS_WORKFLOW` sources from the **job**, not the workflow the corpus row named: the call is written
on the job, the job carries the `permissions` and `secrets` every privilege question needs, and two
jobs in one file may call two workflows. It carries the `USES_ACTION` pin grammar
(`req-github-core-actions-used-3`) — a same-repository call is `pin_kind: local`, pinned by
construction — plus `same_repository` and `secrets_inherit`. `TRIGGERS_WORKFLOW` points from the
completing workflow to the triggered one (the initiator is the source), resolves display names
within the repository only, fans out to every workflow sharing the name, and carries `types`,
`branches` and `branches-ignore` **only as written** — GitHub's `types` default is not filled in.
The corpus's `conclusion_filter` is not carried: GitHub has no such key, and reading the check out
of job `if:` expressions would be a guess.

**Resolution is a post-pass**, after every repository in scope is walked, because a callee is named
by path in a repository that may be walked later, and workflow nodes are keyed on GitHub's numeric
id. A callee or a name that resolves to nothing produces **no edge and no invented node**; the state
is recorded on the node the absence is about — `workflow_job.configuration.call_resolution` ∈
`resolved | unresolved_in_scope | out_of_scope`, `github_workflow.configuration.trigger_resolution`
— and the run reports the counts (`WORKFLOW_CALLS`, `WORKFLOW_TRIGGERS`). At repos-only scope every
cross-repository call is `out_of_scope`, and the summary is what keeps that from reading as an estate
without reusable workflows.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-workflow-chains-1 | Calls Resolve Across The Scope | In Development | A job-level `uses:` naming a workflow collected anywhere in the scope becomes `CALLS_WORKFLOW` job → workflow, resolved after the full walk. | |
| req-github-core-workflow-chains-2 | An Unresolved Callee Is Recorded, Not Invented | In Development | A callee not on the grid yields no edge and no node; the job's `configuration.call_resolution` states `unresolved_in_scope` or `out_of_scope`, and the run counts both. | Three states, never two. |
| req-github-core-workflow-chains-3 | The Call Carries Its Pin And Its Secrets Posture | In Development | The edge states `declared_ref`, `pin_kind` (incl. `local`), `is_pinned`, `resolution`, `same_repository`, `secrets_inherit`, and `resolved_sha` when known; the calling job's configuration lists the named secrets passed. Names only, never values. | Pin grammar shared with `USES_ACTION`. |
| req-github-core-workflow-chains-4 | Triggers Point The Way The Event Flows | In Development | `on.workflow_run.workflows` on B yields `TRIGGERS_WORKFLOW` A → B for every workflow A in the same repository whose stored display name matches; an unmatched name lands on B's `configuration.trigger_resolution` and warns. | |
| req-github-core-workflow-chains-5 | Filters As Written Only | In Development | `types`, `branches`, `branches_ignore` appear on the edge only when the file declares them; GitHub's defaults are never written. | |

### Artifacts
----
RID: `req-github-core-artifacts`
Status: `In Development`

The output side of a run. `actions_artifact` is collected from the **repository** listing
(`GET /repos/{o}/{r}/actions/artifacts`, `actions:read`) rather than per run — one call per page
instead of one per run, and every item names its producing run — newest first, capped per
repository with the total reported (github-core#55). `UPLOADS_ARTIFACT` (run → artifact) is emitted
when that run is in the same batch and is exact; artifacts of runs outside the collected window are
counted and carry `run_id` for a later join, never dropped silently by the dangling-edge guard.

**Expiry is observed, not inferred.** GitHub keeps an expired artifact listed with `expired: true`.
An artifact is an immutable event with a retention window (github-core#14, shape C): absence from
the listing — under the cap, or after retention — is never grounds for a tombstone, and a reconciler
must refuse this type.

**There is no `DOWNLOADS_ARTIFACT`, and the reason is recorded.** GitHub records who uploaded and
nothing about who downloaded. A declared download (`actions/download-artifact` with `name:` or
`pattern:`) names a pattern that matches a different artifact on every run; joining it to a concrete
node would be the inference `req-github-core-caches-4` refuses for caches. The declared upload and
download steps land on `workflow_job.configuration.artifact_steps`, and the corpus's
`cross_workflow` is carried there — a `run-id:` or `repository:` input means the step reaches into
another run's outputs — so the security-relevant bit survives without a guessed edge.

**Reachable, and three states on the repository** (github-core#31). `STORES_ARTIFACT` (repository →
artifact) is emitted for every artifact that lands, so one whose run is outside the window stays
reachable from its repository without the `UPLOADS_ARTIFACT` join. A refused listing (403/404) lands
nothing and records `github_repository.outputs_observability.artifacts = unobservable` with the status
in `notes.artifacts` — on the node the absence is about, never rendered as a repository that uploads
nothing — the same three-state field the releases and packages surfaces stamp.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-artifacts-1 | Artifacts Collected From The Repository Listing | In Development | Each item lands as `actions_artifact` keyed on `owner/repo` + artifact id, with name, size, digest, retention state and the producing run's id, head SHA and branch. | Degrades with a warning on 403/404, like caches. |
| req-github-core-artifacts-2 | Upload Join Is Exact And Batch-Honest | In Development | `UPLOADS_ARTIFACT` is emitted from `workflow_run.id` only when that run is in the batch; the run records linked and unlinked counts. | |
| req-github-core-artifacts-3 | Expiry Observed, Never Inferred | In Development | `expired` is stored as GitHub reports it; absence from the listing is stated as non-evidence in the truncation warning. | Shape C. |
| req-github-core-artifacts-4 | Declared Steps Kept, Not Joined | In Development | `actions/upload-artifact` and `actions/download-artifact` steps land on the job's `configuration.artifact_steps` with mode, name/pattern and `cross_workflow`; no edge is emitted from a declaration to an artifact instance. | The gap is named, not papered over. |
| req-github-core-artifacts-5 | Refused Is Not Empty | In Development | A 403 or 404 records `outputs_observability.artifacts = unobservable` with the status in `notes.artifacts`, warns, and lands nothing. | `tests/test_outputs.py::TestArtifactsLand`. |
| req-github-core-artifacts-6 | Reachable From The Repository | In Development | Every artifact that lands is joined to its repository by `STORES_ARTIFACT`, in or out of the run window. | `tests/test_artifacts.py`. |

### Commits
----
RID: `req-github-core-commits`

Status: `Implemented`

The commit at every collected ref's head, in two halves (github-core#76, rulings 0.1/0.2; built
in #78). **The neutral half is git_core's**: `git_core__git_commit` holds what Git records — object
id, dates, author and committer name and email — under the global identity `(hash_algorithm, oid)`
minted by `tap_plugin.git_core.identity.git_commit_id`, so the same commit observed from any host
is one node; `STORES_COMMIT__git_core` from the neutral repository says this repository holds it,
`RESOLVES_COMMIT__git_core` from the ref says the ref peels to it. **The observed half is ours**:
`github_core__commit_observation` holds the login GitHub resolved each email to (empty is
observed-absent) and GitHub's signature verification verdict, keyed on the host, the repository's
stable id and the commit identity — because GitHub persists the verification record per repository
network (GitHub docs, retrieved 2026-09-02), the same commit in two unrelated networks can carry two
verdicts, and a per-commit verdict field would let one overwrite the other. `OBSERVES_COMMIT` links
the observation to the commit, `OBSERVED_IN_REPOSITORY` to the hosting record. A stable record updated in
place; TAP field history carries change. The cross-fork join on the network root stays a follow-on
once `Repository.parent` is collected.

**Collected at no additional cost.** A `CommitSlice` fragment on the config-layer refs query's
targets (and on `Tag.target` for annotated tags) — scalar fields on nodes already requested,
measured at `rateLimit.cost: 1` on 2026-09-02 — under `repository:contents:read`, the `refs`
source's own triple. The manifest declares `commits` (neutral) and `commit_observations` (ours)
as two sources on that one fragment.

**The signature has three states, never two.** GitHub's verification `state` when a signature
exists; `unsigned` when GitHub returned `signature: null`, which is an observed value, with
`signature_valid: null` rather than false; and `unobservable` when the field was not answered. A
degraded GraphQL field arrives as `null` beside an `errors[]` entry — indistinguishable from an
unsigned commit — so the config layer **prunes the key at every errored path** before shaping, an
absent key lands as `unobservable`, and a body whose `committedDate` was pruned emits nothing.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-commits-1 | One Neutral Commit Per Oid, One Observation Per Repository | Implemented | Every ref carrying a commit slice yields a `git_core__git_commit` keyed `sha1:oid` (shared across refs and repositories) with `STORES_COMMIT` from the neutral repository and `RESOLVES_COMMIT` from the ref, plus a `commit_observation` keyed host + repository stable id + commit with `OBSERVES_COMMIT` and `OBSERVED_IN_REPOSITORY`. | The verification record is network-scoped, so the OBSERVATION is per repository; the commit is not. |
| req-github-core-commits-2 | Signature In Three States | Implemented | The observation stores GitHub's `state`, kind, validity and signer; `signature: null` stores `unsigned` with `signature_valid: null`; a `signature` key pruned for a field error stores `unobservable`; a ref whose commit slice is absent emits no commit, no observation and no edge. | Never false for unsigned or unobservable. |
| req-github-core-commits-3 | Identity As Observed | Implemented | `author_login` / `committer_login` on the observation are set only when GitHub resolved the email to an account; the raw name and email live on the neutral commit. | |
| req-github-core-commits-4 | No Extra Request Or Permission | Implemented | Both sources ride the config-layer refs query; the manifest declares `repository:contents:read`, already in the union, and the conformance extract carries the traversed `Commit`, `GitActor` and `GitSignature` fields. | |
| req-github-core-commits-5 | Nothing Observed On The Neutral Commit | Implemented | The neutral commit envelope carries only intrinsic fields and `{"git.host": <host>}` — git_core's own key, the same one this plugin's records carry; no login, verdict or `github.*` dimension. | `tests/test_commits.py`. |

### Status Checks
----
RID: `req-github-core-status-checks`
Status: `In Development`

The convergence node between the gate and the machinery (github-core#61). A ruleset's
`required_status_checks` rule names contexts that must pass; a workflow's job, named the same,
produces them. `status_check` is keyed **`<owner>#<context>`** — owner-scoped like the ruleset,
because an organization requirement spans every repository it protects — and **a check nobody
requires has no node**: every job produces a check run, and one node per job would drown the
convergence in leaves. The node is the requirement's target; producers are derived toward it.

`REQUIRES_CHECK` (ruleset → check) carries the rule's own qualifiers — `integration_id` (null means
any source may satisfy it), `strict` and `do_not_enforce_on_create` — and not the corpus's
`enforcement`, which is a field on the ruleset node. `PRODUCES_CHECK` (workflow → check) is
**derived from job display names and says so**: `confidence: exact` when the declared name equals
the context, `matrix_template` when the context is the declared name plus a parenthesised matrix
expansion. It is emitted only where a requirement admits an Actions-produced check (`integration_id`
null or 15368); an App's check has the node and the requirement and no producer, pending the App's
numeric id on the grid.

**The type-only fallback is the state that must not read as "none".** The ruleset detail is
administration-gated and degrades; when refused, `rules` come from the GraphQL config layer with
types only, so the contexts are NOT observable. Such a ruleset mints no node, warns
`REQUIRED_CHECKS_UNOBSERVABLE`, and is counted in the `STATUS_CHECKS` summary — which also lists the
Actions-producible contexts with no declared producer anywhere in scope. Both resolve in the
post-pass after the whole scope is walked.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-status-checks-1 | One Node Per Required Context | In Development | Every context named by any ruleset's `required_status_checks` parameters lands as one `status_check` per (owner, context) with a `REQUIRES_CHECK` from each ruleset naming it, carrying the rule's qualifiers. | |
| req-github-core-status-checks-2 | Unreadable Requirements Are Counted | In Development | A `required_status_checks` rule with no parameters (the type-only fallback) mints nothing, warns per ruleset, and is counted in the run summary. | Shape E. |
| req-github-core-status-checks-3 | Producers Derived With Stated Confidence | In Development | `PRODUCES_CHECK` from a workflow whose job display name equals the context (`exact`) or is its matrix template (`matrix_template`), only where a requirement admits an Actions check; the summary lists producible contexts with no producer. | |
| req-github-core-status-checks-4 | No Extra Request Or Permission | In Development | Both edges derive from the `rulesets` and `workflow_yaml` sources already in the manifest. | |

### Custom Properties
----
RID: `req-github-core-custom-properties`

Status: `Implemented`

The organization's own metadata over its repositories (github-core#77). GitHub gave every one of
its repositories a durable owner not with a built-in field but with custom properties —
`ownership-type`, `ownership-name` — declared by the organization and validated by an App. That is
the mechanism a console groups, filters and orders repositories by, and it is where `criticality`,
`lifecycle` and `repository-role` live for the organization that builds TAP (git-serious-double-tap#2).
The collector hard-codes none of those names: it lands whatever the organization declares.

Two objects. The **definition** is a node, `github_custom_property`, keyed **`<owner>#<property_name>`**
— owner-scoped like the ruleset, because one organization declares the property once and every
repository's value is read against that one declaration. The **value** is a field on the repository,
`github_repository.custom_properties`, a map keyed by property name exactly as GitHub reports it. No
edge joins them: a repository with any value would point at every definition, so the edge would carry
nothing, and a value on the edge would be a second copy of the value. The definition passes the node
test as an independently-edited declaration with its own history and its own table, not by fan-in.

**Unset is a fact, and it is on the wire.** The values listing reports every declared property per
repository with `value: null` when unset (measured 2026-09-08). The map is nonetheless built over the
declared names first, so an entry the listing omitted for a reported repository is still null. A
collected repository the listing did not report at all is `unobservable` with an empty map and is
named in a warning — an omitted row is a row we did not get, not five unset values. Three states on the repository,
`custom_properties_observability`, the `bypass_observability` ruling applied: `observed` (an empty
map is then a fact), `unobservable` (the definitions or the values were refused — no definition node
is minted when the schema is refused, and the map must not render as "none set"), `""` (never asked:
a repos-only scope, or a user account, where custom properties do not exist and a refusal would be
a false claim).

Both reads are one organization-scoped call each after the repository walk, at
`organization:custom_properties:read` — GitHub's "Custom properties" organization permission,
already granted on the product App and now derived from the manifest rather than held as an
exploratory grant.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-custom-properties-1 | Definitions Land As Nodes | Implemented | Every property the organization's schema endpoint reports lands as one `github_custom_property` per (owner, name) carrying its type, allowed values, required flag, default, description, editability and source. | Names never normalized. |
| req-github-core-custom-properties-2 | Values Stamped On The Repository | Implemented | Every collected repository the listing reports carries `custom_properties` with one key per declared property, the reported value or null when unset, and `custom_properties_observability = observed`; a collected repository the listing omits is `unobservable` with an empty map and a warning naming it. | The map is built over the declared names first; an omitted row is never promoted to all-unset. |
| req-github-core-custom-properties-3 | Refused Is Not Empty | Implemented | A refused schema read mints no definition and marks every collected repository `unobservable` with an empty map and a warning; a refused values read lands the definitions and marks the values `unobservable`. | Shape E. |
| req-github-core-custom-properties-4 | Not Asked Is Not Refused | Implemented | A user-owned scope or a repos-only scope skips the surface with an information record; repositories keep `""`, never `unobservable`. | Three states, never two. |
| req-github-core-custom-properties-5 | Permission Derived From The Manifest | Implemented | Both sources declare `organization:custom_properties:read`; the ledger entry is `requested` citing exactly those two sources; the OpenAPI extract carries both paths. | No new grant on the App. |

### Pull Requests
----
RID: `req-github-core-pull-requests`

Status: `In Development`

The forge's proposal to merge one ref into another, and what stands between it and merge
(github-core#82). It is what git-serious's *why isn't this merging* and *what is waiting on me*
read, and the demo's PR list with per-PR build status. **It lives here, not in git_core**: Git has
branches and commits and no pull request; git_core's v0 non-goals exclude it as forge collaboration
(github-core#76), and the vocabulary's neutral-capable mark (every forge has a merge request) is a
future extraction, not a home. The node is GitHub's, keyed **`<owner/repo>#<number>`** on the
base repository, and it points at git_core's neutral nodes the way `commit_observation` does:
`PROPOSES_REF` (the head branch, only when it lives in the base repository — a fork's head is
`head_repository` on the node and no edge), `TARGETS_BASE_REF` (the branch whose rulesets gate
the merge, `PROTECTS_REF` landing on the same node) and `PROPOSES_COMMIT` (the head commit).
Edge ids are computed from names; an endpoint not observed in the batch leaves the edge dangling
and it is dropped, so the fact is on the node and the edge is the join when both ends were seen.
`OPENS_PULL_REQUEST` comes from the author: an account, or the App when GitHub says `Bot`,
carrying `author_association` — inside or outside the trust boundary is a property of the act.

**Build status is the head commit's check rollup, flattened onto the pull request.** GitHub keeps
`statusCheckRollup` on the commit; the question it answers is the pull request's. The one-word
verdict is `checks_rollup_state` (GitHub's `StatusState`), the evidence is `checks`: every check
run (Checks API — GitHub Actions and most Apps, naming the producing App) and every commit status
(the older API Codacy and SonarCloud still post, naming its creator), in one list because a
required context may be either. A head that carries no rollup is `""` — nothing ran — which is
not `SUCCESS` and must not render green; and `checks_observability` says whether that blank was
GitHub's answer (`observed`) or a refused read the pruning left behind (`unobservable`), because
a permission failure on the rollup must not serialize like nothing having run. Check runs are not minted as nodes here; a `check_run`
node joined to `status_check` is the follow-on that github-core#75 names for the App-produced half.

Everything rides **one GraphQL query of its own**, paged at five repositories: `pullRequests`
per repository, most recently updated first, capped (thirty) with GitHub's total on the repository
node as `pull_requests_total` and a truncation warning, so a window is never read as the whole.
It is a second query and not more fields on the config layer because GitHub caps a query at
500,000 possible nodes, computed from the page sizes multiplied down the tree: the config layer
already asks for about 460,000 across its hundred-repository page, and fifty pull requests with
labels, reviews and a hundred check contexts each put it at 1,269,100 (measured 2026-09-08,
`MAX_NODE_LIMIT_EXCEEDED`). The node budget is not the only ceiling: GitHub also stops a query
at about ten seconds of execution (HTTP 502/504), and measured the same day twenty repositories
a page timed out every time and ten sat at the edge, with no single field to blame — so five a
page, about five seconds and eight rate-limit points each, five requests for this organization
instead of one, still nothing beside the REST walk. Three states on the repository, `pull_requests_observability`: `observed` (zero rows is a
fact), `unobservable` (the field degraded and was pruned, or the query failed), `""` (a
repos-only scope runs no account query). GraphQL is chosen over REST because it is the only
transport carrying `reviewDecision`, `mergeable` and the rollup in the same read; REST needs two
further calls per pull request for the checks alone. `mergeable` is stored as GitHub's string (`MERGEABLE|CONFLICTING|UNKNOWN`) —
it is computed lazily and a first read often says `UNKNOWN`, which a boolean would lie about.

Permissions derived from the manifest: `repository:pull_requests:read` (the rows),
`repository:checks:read` (the check-run half of the rollup), `repository:statuses:read` (the
status half) — all three already granted on the product App as recommended reads, now requested
by their sources; an App installed earlier re-accepts nothing.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-pull-requests-1 | One Node Per Pull Request | In Development | Every pull request in the window lands as one `pull_request` per (base repository, number) carrying state, draft flag, author, head and base refs and SHAs, review decision, mergeability, timestamps, sizes, labels, outstanding review requests and latest reviews. | |
| req-github-core-pull-requests-2 | Joined To The Neutral Nodes | In Development | `PROPOSES_REF` onto the head ref when the head lives in the base repository, `TARGETS_BASE_REF` onto the base ref, `PROPOSES_COMMIT` onto the head commit — each only when the endpoint was observed in the batch; a fork head draws no ref edge. | Dangling edges dropped, facts kept on the node. |
| req-github-core-pull-requests-3 | Author Is An Edge | In Development | `OPENS_PULL_REQUEST` from the author's account, or from the `github_app` when the actor is a Bot, carrying `author_association`. | |
| req-github-core-pull-requests-4 | Build Status From The Rollup | In Development | `checks_rollup_state` equals the head commit's `statusCheckRollup.state` and `checks` itemises every check run and commit status it counted with its producer and, for a check run, GitHub's `check_run_id` (a rerun mints a higher id for the same name); a head with no rollup is `""` with `checks_observability = observed`, never `SUCCESS`; a rollup or contexts GitHub refused (pruned) is `checks_observability = unobservable` with a warning, never the same blank; a rollup wider than the page is marked truncated. | Includes App-produced checks no workflow in scope produces. |
| req-github-core-pull-requests-5 | Refused Is Not Empty | In Development | A degraded `pullRequests` field marks the repository `unobservable` with a warning and mints nothing; a repos-only scope leaves `""`; the window's cap is visible as `pull_requests_total` and a truncation warning. | Three states, never two. |
| req-github-core-pull-requests-6 | Permissions Derived | In Development | The three sources declare `repository:pull_requests:read`, `repository:checks:read`, `repository:statuses:read`; the ledger entries are `requested` citing exactly those sources; the GraphQL extract covers every traversed type and field. | No new grant on the App. |

### Code Scanning Alerts
----
RID: `req-github-core-code-scanning`

Status: `In Development`

GitHub aggregates every SARIF-emitting scanner an organisation runs — CodeQL, SonarCloud, Trivy,
Grype, zizmor when uploaded — into one alert stream per repository with one lifecycle, and keeps a
second object, the analysis, that records each upload whether or not it found anything. This
requirement lands both (github-core#89): the first surface on the security axis, and the one that
turns the CodeQL dynamic workflow, the Trivy and Grype lanes already on the grid from producers of
nothing into producers of something.

**The ruling (operator, 2026-09-09, session double-tap-git-serious): ONE generic finding type,
source-specific data behind an edge.** The generic type is the EXISTING
`compliance_core__compliance_finding` (compliance_core v0.2.2: `name` / `summary` / `description` /
`status open|resolved`) — NOT a new github_core type. github_core adds `depends_on compliance_core`
and its collector MINTS `compliance_finding` nodes, becoming the first collector to do so (the
substrate's own spec records "no collector mints `compliance_finding`" as its v0 reality, and that
sentence is now false in the right direction). The dependency direction is why the generic node is
compliance_core's: it is a substrate with `depends_on = []`, depended on downward by every regime
and every scanner; zizmor depends on github_core, so a github_core-owned generic finding would put
the generic type ABOVE a consumer that already needs it, and zizmor's spec has been carrying its
scanner-shaped finding as "a compliance-level node in disguise" since 2026-09-02 for want of exactly
this ruling. The source-specific node — `code_scanning_alert` — is github_core's, and points at the
finding through a github_core-owned edge, `DETAILS_FINDING`, detail → finding, because the substrate
cannot name a github_core type as a target and the finding must not know its sources.

**Mapping, alert → finding.** The finding is named by a REF and its identity is
compliance_core's to declare (Issue# 8 - tap-plugin-compliance-core, 2026-09-20): that model
declares `NATURAL_KEY = ("source", "source_key")`, so this collector writes `source = "github_core"`
and `source_key = <owner/repo>#code_scanning#<number>` and core assigns the id. The key string is
unchanged from the one github_core's uuid5 namespace used to hash — the source segment is still what
keeps a Dependabot finding on the same repository from colliding, and re-hashing the ref is what
keeps every edge id byte-identical. What changed is WHO decides: under derived ids the producer did,
because only it held the values; now the owning plugin declares and the producer owes the values.
A producer that wrote neither field would get a fresh node every run rather than an error. `name` = `"<tool_name> <rule_id>"` (`SonarCloud pythonsecurity:S6350`); `summary` =
the rule description; `description` = the message plus `path:line`; `status` = `open` when the
alert's state is `open`, else `resolved` — **dismissed and fixed both map to resolved**, and the true
lifecycle (`state`, `dismissed_reason`, `dismissed_comment`, `dismissed_by_login`, `fixed_at`,
`dismissed_at`) lives on the detail node, one hop away. The finding carries compliance_core's
`compliance: finding` marker and no regime dimension: this collector is not a regime.

| Alert (detail) | Finding (generic) |
| --- | --- |
| `full_name` + `number` | `source` = `github_core`, `source_key` = `<owner/repo>#code_scanning#<number>` (the ref, and the declared key) |
| `tool_name`, `rule_id` | `name` = `"<tool_name> <rule_id>"` |
| `rule_description` | `summary` |
| `message`, `location.path`, `location.start_line` | `description` = message + `path:line` |
| `state = open` | `status = open` |
| `state = dismissed` or `fixed` (or `""`) | `status = resolved` |
| everything else | stays on the detail |

**Asset placement** uses compliance_core's existing wildcard-source edge
`CARRIES_COMPLIANCE_FINDING__compliance_core`, never a github_core rival: `github_repository` → finding
always, and `github_workflow` → finding when the alert's `location.path` is a collected workflow
file (`githubactions:S6506` and `S8544` on tap are exactly this). One finding, two assets, one verb.

**The analysis** is the record that a scan RAN: `code_scanning_analysis`, one per SARIF upload
GitHub accepted, keyed `<owner/repo>#<analysis_id>` (GitHub's id, not `sarif_id` — one upload can
yield several analyses, one per SARIF `run`), carrying tool, version, ref, commit, category,
`results_count`, `rules_count`, processing `warning` / `error`. `ANALYZES_REPOSITORY` always;
`ANALYZES_COMMIT` onto `git_core__git_commit` **only when the commit is on the grid** — a
`refs/pull/N/merge` analysis never is, so most analyses carry no commit edge, and **absence ≠ not
analysed**: `commit_sha` on the node is the fact, the edge is the join. Zero alerts beside zero
analyses is unscanned, not clean; that is why the second node exists.

**Four observability states** on the repository, `code_scanning_observability`, because this
surface has one more way to be empty than the others: `""` (never asked — repos-only scope, or the
surface not in the run), `observed` (the listings answered 200, zero included), `unobservable` (403:
the credential lacks `security_events: read`, or it was added after installation and an organisation
owner has not accepted it — `CODE_SCANNING_UNOBSERVABLE`, per repository), `not_enabled` (GitHub says
code scanning, or Advanced Security on a private repository, is not enabled — a fact about the
repository, not the credential; `CODE_SCANNING_NOT_ENABLED`). Folding `not_enabled` into `observed`
renders an unscanned repository clean; folding it into `unobservable` blames the credential for a
configuration choice. One field for both listings because they share an endpoint family and a
permission. Truncation is warned per listing (`CODE_SCANNING_ALERTS_TRUNCATED`,
`CODE_SCANNING_ANALYSES_TRUNCATED`) and a successful pass records `CODE_SCANNING_COLLECTED` with
the counts.

**Sources and permission.** `code_scanning_alerts` — `GET /repos/{owner}/{repo}/code-scanning/alerts`,
all states, paginated to the end; `code_scanning_analyses` — `GET /repos/{owner}/{repo}/code-scanning/analyses`,
the most recent 100 per repository (GitHub reports no total), truncation warned. Both at
**`repository:security_events:read`**, a sensitive read; the ledger entry `security_events` moves
`recommended` → `requested` in this change citing exactly those two sources — the first flip of the
sensitive-read tier (`req-github-core-app-permissions-recommended-1`). The installed App already held
it as an exploratory grant, so no re-acceptance on this organisation; an adopter's App minted from
the manifest gains *Code scanning alerts: Read-only* from the declaration alone.

**Measured 2026-09-09** with the installed App token (`git-serious-exploratory`, installation
157103378, 33 read permissions): `unified-systems-com/tap` — 9 open alerts, all SonarCloud (2 high,
7 medium; `pythonsecurity:S6350` ×3, `S2083` ×2, `S6549`, `Web:S5247`, `githubactions:S6506`,
`S8544`), 0 CodeQL / Trivy / Grype open; analyses in the last 100: CodeQL 72 (`/language:actions`,
`/language:javascript-typescript`, `/language:python`), SonarCloud 24 (category `""`), Trivy 2
(`trivy-tap-web`, `trivy-tap-db`), Grype 2 (`grype-declared-tap-web`, `-db`). Alerts are NOT tied to
analysis ids — the alert carries `analysis_key` + `category`, the analysis the same two, and the
join is loose (tool + category). `rule.severity` is `note|warning|error`; `security_severity_level`
may be absent (Sonar sets it, CodeQL sometimes not) and an absent level is `""`, never `low`. A
dismissed sample: reason `false positive`, 2026-08-31.

**Deliberately NOT built here, so it is not re-litigated:**

- **No `REPORTED_BY` (analysis → finding) edge.** The data does not support it; a loose tool +
  category match is a field-level join, and an edge would assert a precision GitHub lacks.
- **No `FLAGS_ACTION` here.** A code-scanning alert names a path and a rule, not a package; the
  action join is Dependabot's and stays in `req-github-core-dependabot-alerts`.
- **Secret scanning and Dependabot ride `DETAILS_FINDING` later**, each with its own detail node
  behind its own `compliance_finding` (the Dependabot block is amended below to say so); this
  requirement builds the code-scanning detail only and does not pre-declare the others as sources.
- **The compliance_core extension is a separate issue — the open design, L rule.** A rule that needs
  severity, rule id or location today must cross `DETAILS_FINDING`; putting a severity, a rule
  reference and a location ON the generic finding so rules need not cross the edge is a change to
  compliance_core's model, to be filed against tap-plugin-compliance-core with this requirement as
  its evidence. It carries an unresolved question (which fields are generic across CodeQL, Sonar,
  Dependabot, zizmor and a conjunction finding; whether `severity` is one scale or two) and so does
  not enter a sprint until that is settled. Nothing here is blocked on it: the detail node holds
  every field either way.
- **No default-setup / configuration surface.** Whether code scanning is configured, with which
  languages, is a separate endpoint; `not_enabled` is the only configuration state recorded.
- **No alert instances.** One `most_recent_instance` per alert; the rest are behind `instances_url`.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-code-scanning-1 | Alert Shape Accepted | In Development | Every alert the listing returns for a repository in scope lands as one `code_scanning_alert` per (repository, number), in every lifecycle state, carrying state, timestamps, dismissal (reason, comment, login), rule (id, name, severity, security severity, description, tags), tool (name, version, guid), the most recent instance's analysis key, category, environment, ref, commit, location, message and classifications, with the raw alert in `configuration`. | A fixed alert is history; an absent `security_severity_level` is `""`, never `low`. |
| req-github-core-code-scanning-2 | Analysis Shape Accepted | In Development | Every analysis in the most recent page lands as one `code_scanning_analysis` per (repository, GitHub analysis id) carrying ref, commit, analysis key, category, environment, tool, created time, result and rule counts, SARIF id, deletable flag, processing warning and error, with the raw analysis in `configuration`. | Keyed on GitHub's id, not `sarif_id`. |
| req-github-core-code-scanning-3 | Four Observability States | In Development | `github_repository.code_scanning_observability` is `observed` after a 200 (zero rows included), `unobservable` after a 403 with a per-repository warning and nothing minted, `not_enabled` when GitHub reports code scanning or Advanced Security off for the repository with an information record and nothing minted, and `""` when the surface was not asked; no two of these ever serialize alike. | Never two states where GitHub offers four. |
| req-github-core-code-scanning-4 | One Finding Per Alert | In Development | Every landed alert mints exactly one `compliance_core__compliance_finding`, named by a ref and carrying `source` = `github_core` + `source_key` = `<owner/repo>#code_scanning#<number>` (the key compliance_core's model declares), with `name = "<tool_name> <rule_id>"`, `summary` = rule description, `description` = message + `path:line`, and `status = open` iff the alert's state is `open`, else `resolved` (dismissed and fixed alike); re-collection updates the same finding, never a second. | The true lifecycle stays on the detail. |
| req-github-core-code-scanning-5 | Placed On Repository And Workflow | In Development | Every finding carries `CARRIES_COMPLIANCE_FINDING__compliance_core` from its `github_repository`, and additionally from the `github_workflow` whose path equals the alert's `location.path` when that workflow was collected; no github_core-owned placement edge exists. | compliance_core's wildcard-source edge, reused. |
| req-github-core-code-scanning-6 | Detail Behind The Finding | In Development | Every finding has exactly one inbound `DETAILS_FINDING__github_core` from its `code_scanning_alert`, property-free; no finding minted by this collector lacks a detail and no detail points at two findings. | 1:1 by construction. |
| req-github-core-code-scanning-7 | Analyses Land With Their Edges | In Development | Every landed analysis carries `ANALYZES_REPOSITORY__github_core` to its repository, and `ANALYZES_COMMIT__github_core` to `git_core__git_commit` only when that commit is on the grid in the same batch; an analysis whose commit is absent lands with no commit edge and `commit_sha` intact. | Absence ≠ not analysed. |
| req-github-core-code-scanning-8 | Permission Declared And Derived | In Development | Both sources declare `repository:security_events:read`; the ledger entry `security_events` is `requested` citing exactly `code_scanning_alerts` and `code_scanning_analyses`; the OpenAPI extract carries both paths; the rendered App manifest gains *Code scanning alerts: Read-only* from the declaration alone and the review table marks it sensitive. | The first recommended → requested flip of Tier B. |
| req-github-core-code-scanning-9 | Truncation Warned | In Development | An alert walk that does not reach the end of the `Link` chain records `CODE_SCANNING_ALERTS_TRUNCATED` with the count landed; an analyses page that is full records `CODE_SCANNING_ANALYSES_TRUNCATED` naming the repository; neither is ever presented as the whole. | GitHub reports no analysis total. |

### Refs
----
RID: `req-github-core-refs`

Status: `Implemented`

A ref is a name and the commit it points at. Branches (`refs/heads/`) and tags (`refs/tags/`) are
the same structure under different prefixes; what differs is a social contract — a branch is
expected to move, a tag is expected to be frozen. **One type covers both** (ruled 2026-08-27,
`spec-github-core-vocabulary.md` decision 2), because tag movement is the detection for three
incidents and a ruleset's target is one enum spanning `branch|tag|push`, so a split type would fan
that join across two types and two edges. The slug is a modelling name; views render "Branches"
and "Tags".

Identity is the NEUTRAL repository's id plus the full ref path, minted by git_core (github-core#76/#78): the
ref is `git_core__git_ref`, declared by the neutral `git_core__git_repository` this record `HOSTS_REPOSITORY`
(`DECLARES_REF__git_core`), and it carries only `{"git.host": <host>}` — no `owner/repo`, no `github.*`. A branch
and a tag may share a short name, so the path is the key.

**Tag-movement detection is not implemented and does not need to be.** `head_sha` is a field on a
node with a deterministic id, so the grid's own field history records the move; detection is a
query over history rather than a diff the collector keeps. `target_sha` is kept apart from
`head_sha` because an annotated tag's ref points at a tag object which points at the commit — a
re-tag that swaps only the tag object moves one and not the other.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-refs-1 | Branches And Tags Are One Type | Implemented | Both land as `git_core__git_ref` with `ref_type` ∈ `branch`\|`tag`, keyed on the neutral repository id + full ref path, joined to the neutral repository by `DECLARES_REF__git_core`; the hosting record reaches them through `HOSTS_REPOSITORY`. | Was `github_core__git_ref` + `HAS_REF` until github-core#78. |
| req-github-core-refs-2 | Annotated Tags Keep Both SHAs | Implemented | `target_sha` is what the ref holds; `head_sha` is the commit it resolves to. They differ for an annotated tag. | |
| req-github-core-refs-3 | Truncation Is Reported | Implemented | When the per-repository page cap leaves refs uncollected, the run records a warning naming the count and stating that absence in the batch is not evidence of deletion. | Same discipline as the scope-enumeration assertion (`req-github-core-org-scope-3`). |
| req-github-core-refs-4 | Config Layer Only | Implemented | Refs arrive in the GraphQL config layer at no extra request. A repos-only scope, which runs no GraphQL enumeration, collects none — and says so rather than reporting a repository with no branches. | |

### Rulesets
----
RID: `req-github-core-rulesets`

Status: `Implemented`

A ruleset is the gate: what must be true for a commit to land on a ref. It is a node because many
repositories point at one — an organization ruleset applies to every repository it matches — where
an organization *policy* object is a field (nothing points at one). Identity is therefore owner +
ruleset id, never repo-scoped.

**Two transports, because neither is sufficient.** GraphQL says which rulesets apply to a
repository and answers `bypassActors`; REST's ruleset detail is the only place the rules'
*parameters* live — including the required check contexts, without which a gate view knows that a
repository requires some status check but not which. REST detail is fetched once per ruleset per
run and cached, since one organization ruleset would otherwise be the same call once per
repository.

#### Bypass observability

GitHub returns a ruleset's bypass-actor list only to a caller with **write access to the ruleset**.
Measured against our own organization on 2026-08-27: an owner-minted fine-grained PAT sees it; a
GitHub App with `administration: read` does not — REST omits the `bypass_actors` key entirely
(HTTP 200), while **GraphQL answers with a truthful `totalCount` and every node redacted to
`null`** (corrected 2026-09-02 from "an empty connection", which the #11 probe disproved — #22
item 2). Our own rulesets genuinely have empty bypass lists, so the distinguishing case — a truthful
zero versus a silently filtered connection — could not be measured against them without changing
our security posture. It was measured instead on **a probe ruleset carrying one bypass actor,
created on a personal repository, read with every available credential, and deleted** (#11,
2026-08-27; the domain article `github_ruleset.md` §Observability records the table): the read-only
App received `totalCount: 0` on the control rulesets and `totalCount: 1` on the probe, with every
node `null`. That is the evidence behind treating a counted zero as a fact.

The derivation that follows:

```
observed = REST detail carried `bypass_actors`  OR  GraphQL returned AT LEAST ONE NON-NULL node
counted  = neither, AND GraphQL carried `bypassActors.totalCount` (every node null, or none)
```

A GraphQL answer with a real actor node in it proves itself — a filtered connection cannot invent
actors — and `[null]` is not such an answer: a list of redactions is `counted`, never `observed`.
A redacted one still carries its `totalCount`, and that count is truthful: the #11 probe read `0` on the
controls and `1` on a ruleset carrying exactly one actor. **False presence is impossible here;
false absence is the entire risk** — and discarding a known count is a false absence.

**The `counted` state (decided 2026-09-02; #22 item 1 is the collector work).** A read-only
credential learns *how many* may bypass, never *who*. That is most of the security value of the
question, and the client currently throws it away (it filters the null nodes and never reads
`totalCount`), degrading a known number to "we could not tell". `bypass_observability` therefore
takes three values:

| State | Meaning | `bypass_actor_count` |
| --- | --- | --- |
| `observed` | The list was read by a credential clearing the write bar. An empty list is then a fact. | The list length. |
| `counted` | GraphQL answered `totalCount` with the identities redacted. | `totalCount`. **A zero here is a truthful zero**, distinguishable from unobservable for the first time. |
| `unobservable` | Neither transport answered. | `null`. |

Two invariants a consumer may rely on: the count is non-null **if and only if** the state is
`observed` or `counted`, so nobody can see a number beside the word "unobservable" and believe
both; and the count lives on the **ruleset node**, never on a node of its own — it is a fact
about the ruleset, and a node type for a number would be a second copy of a fact that already has
a home (derive-a-fact-once). The three states live on the ruleset (`bypass_observability`), not on
the `BYPASSES` edge, because when the answer is *none* or *unknown* there are no edges to carry
anything and a view reading only edges would render both as an empty list. Generalized: *a
property that qualifies an absence belongs on the node the absence is about, never on the edges
that failed to appear.*

Views render the three states distinctly — git-serious's bypass badge
(`req-git-serious-branch-protection-tiers-bypass-badge`: grey unobservable, yellow counted, neutral
observed, and red reserved for a bypass that *happened*, which is the rule-suite surface) — and
the guidance "a credential with write access to the ruleset would name them" rides `absent_note`
(`req-github-core-app-auth-11`), machine-legible for the third player. `counted` is enough to make
it work with a read-only credential; gathering and managing the identities under a properly scoped
credential is the *make-it-right* task (#39 — same collector with a second envelope, or a separate
collector, is the open question).

**The read-only posture has a hard ceiling here**, and it is published rather than engineered
around: seeing the exemption list requires write access to the thing being audited, and we do not
request write.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-rulesets-1 | One Node Per Ruleset | Implemented | A ruleset is one node keyed on owner + ruleset id however many repositories it protects, applied by `PROTECTS` edges. | |
| req-github-core-rulesets-2 | Rule Parameters Retained | Implemented | The rules array carries each rule's parameters as returned (required check contexts among them), falling back to the type-only GraphQL list when the REST detail is unreadable — and warning when it does. | The gate view needs the contexts, not just the rule types. |
| req-github-core-rulesets-bypass | Bypass Observability Is Recorded | Implemented | `bypass_observability` is `observed` only when REST carried the key or GraphQL returned a non-empty list; otherwise `unobservable` with a **null** actor count. A run warns per unobservable ruleset. | The failure guarded against is rendering "we could not look" as "nobody can bypass". Superseded in part by `-bypass-2`: the redacted-nodes case becomes `counted`, not `unobservable`. |
| req-github-core-rulesets-bypass-2 | Counted Is A State | Approved for Development | When GraphQL returns `bypassActors.totalCount` with the nodes redacted, `bypass_observability` is `counted` and `bypass_actor_count` equals `totalCount` — stored as `0` when it is zero, never `null`. The model enum and both schemas gain the value. | #22 item 1. Fixture: `{"totalCount": 1, "nodes": [null]}` → counted, 1. |
| req-github-core-rulesets-bypass-3 | Count Never Beside Unobservable | Approved for Development | `bypass_actor_count` is non-null if and only if `bypass_observability` is `observed` or `counted`; a test asserts the invariant over every emitted ruleset. | The reader must not be able to see a number and the word "unobservable" and believe both. |
| req-github-core-rulesets-3 | Unmodelled Actors Are Counted | Implemented | Bypass actors with no node type yet (teams, organization-admin roles) are kept as data on the ruleset and counted, never dropped. | Understating who can bypass is the one direction that must never happen. |
| req-github-core-rulesets-4 | Ref Resolution Is Additive | Implemented | Condition patterns are stored verbatim (`~DEFAULT_BRANCH`, `~ALL`, globs) AND resolved against observed refs into `PROTECTS` edges with `match_kind: resolved`. A pattern matching nothing is an answer, not a failure. | Intent and effect are both queryable. |

### Environments
----
RID: `req-github-core-environments`

Status: `Implemented`

A deployment environment is where protection rules — required reviewers, wait timers, branch
policies — stand in front of a deployment. Its value is mostly in the *absence*: a job that deploys
with no environment beside it is a deployment with no gate, which is why `USES_ENVIRONMENT` links
the declared job to it.

The GraphQL config layer carries the environment and its protection rules but not its branch
policy; that field is left `null` (unobserved) rather than defaulted, because defaulting it to
"none" would assert an absence this transport never looked for.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-environments-1 | Environments Collected | Implemented | Each repository's environments land as `github_environment` joined by `DECLARES_ENVIRONMENT`, with their protection rules. | Free from the config layer. |
| req-github-core-environments-2 | Declared Jobs Link To Them | Implemented | A job declaring `environment:` (in either written form) gets a `USES_ENVIRONMENT` edge to that environment. | |
| req-github-core-environments-3 | Unobserved Fields Stay Null | Implemented | `deployment_branch_policy` and `can_admins_bypass` are null until a transport that reads them is added. | Null is unobserved; a default would be a claim. The transport arrived with `req-github-core-settings-4` (REST environment detail); null now means that call was refused or not made, and `configuration.detail_observability` says which. |

### Settings — Organization, Repository, Environment
----
RID: `req-github-core-settings`

Status: `Implemented`

Most of what a posture scanner asks about a GitHub organization is not a graph question at all. It
is a checkbox: is two-factor required, what is the default repository permission, may members
create public repositories or fork private ones, are secret scanning and Dependabot on for new
repositories, which actions may workflows use, may this repository be forked, is it archived, who
must approve a deployment to production. The 2026-08-27 audit of the BloodHound GitHub corpus found
that **17 of its saved queries are exactly such filters on the organization node and 3 more on the
repository and environment** — and that this collector fetched every one of those payloads and
copied only the identity fields out of them, writing `configuration: {}` at every mint site.

This requirement closes that with **no new types**. The settings land on the `configuration` JSON
the three models already carry, under **GitHub's own key names, unrenamed**, so a reader can hold a
node against the API reference and the conformance lane can hold the manifest against GitHub's
published schema without a rename table. Copying is by allow-list (`_ORG_SETTING_KEYS_*`,
`_REPO_SETTING_KEYS`), so contact and billing data never travel.

**The observability marker is the point, not a nicety.** Each surface has a credential ceiling
below which GitHub does not refuse — it answers with fewer keys. `/orgs/{org}` returns the public
half to anyone and the policy half only to an owner or an organization-administration reader;
`/repos/{r}` omits `security_and_analysis` for a non-admin; `/orgs/{org}/actions/permissions` is
refused outright with 403. Each is recorded beside the values it governs — `settings_observability`
∈ `observed | public_only | unobservable | not_applicable`, `security_settings_observability`,
`actions_policy_observability`, `configuration.detail_observability` on the environment — so a
node without `two_factor_requirement_enabled` reads as *not allowed to look*, never as *2FA off*.
Nothing is defaulted; an absent key stays absent.

Costs: one `/orgs/{owner}` and one `/actions/permissions` call per run (cached across the
per-repository account mints), one `/repos/{r}` call per repository when the config layer supplied
the identity half, one `/environments/{name}` call per environment. The Actions policy and the
environment detail widen the derived permission set — `organization:administration:read` was
already requested for installations; `repository:environments:read` is new, and moves from
*recommended* to *requested* in the App-permission ledger because it is now used.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-settings-1 | Organization Policy Block Verbatim | Implemented | An organization's `github_account.configuration` carries the `/orgs/{org}` policy keys under GitHub's names; `settings_observability` is `observed` when a policy key arrived, `public_only` when the payload answered with none, `unobservable` when refused, `not_applicable` for a user account. The org detail is fetched once per run, not once per repository. | `GithubCollector._account_configuration`, `_fetch_org_detail`; manifest source `org_settings`. |
| req-github-core-settings-2 | Actions Policy Recorded Or Refused | Implemented | `configuration.actions_policy` holds `enabled_repositories`, `allowed_actions`, `sha_pinning_required` and, for a `selected` policy, the allow-list; a 403 leaves no policy and stamps `actions_policy_observability: unobservable`. | `_collect_org_actions_policy`; source `org_actions_permissions`. A refused policy must never render as "all actions allowed". |
| req-github-core-settings-3 | Repository Settings With The Admin Block Marked | Implemented | `github_repository.configuration` carries the `/repos/{r}` settings keys verbatim; `security_settings_observability` is `observed` only when `security_and_analysis` was in the payload, `unobservable` when GitHub omitted it; a refused payload records only `settings_observability: unobservable`. | `_repository_configuration`, `_fetch_repository_settings`; `repository` source fields extended. |
| req-github-core-settings-4 | Environment Gatekeepers From The REST Detail | Implemented | `deployment_branch_policy`, `can_admins_bypass` and `html_url` are filled from `/repos/{r}/environments/{name}`; required reviewers (users and teams), `prevent_self_review` and `wait_timer` land in `configuration`; a refusal keeps the fields null and stamps `configuration.detail_observability: unobservable`, one warning per repository naming the environments. | `_fetch_environment_detail`, `_environment_configuration`; source `environment_detail`. Supersedes `req-github-core-environments-3`'s "until a transport is added". Reviewers stay data until the people graph (github-core#111) gives `GATED_BY` a node to point at. |
| req-github-core-settings-6 | The Method Question Is Not Answered By The Requirement Boolean | Implemented | An organization's configuration carries `two_factor_secure_methods_required: null` and `two_factor_methods_observability: unobservable` beside `two_factor_requirement_enabled`: GitHub's "only allow secure two-factor methods" setting has no API field at any tier (tap#157), and an organization can require 2FA while permitting SMS. | Peer measurement 2026-09-11: 68 keys on `/orgs/{org}` with an owner App token, none about methods; enterprise consumed-licenses returns the same boolean; per-member factor type is never published. |
| req-github-core-settings-5 | Nothing Defaulted, Nothing Extra | Implemented | Only allow-listed keys are copied (no billing or contact data); an absent key is absent on the node; the seeded tests assert the refused branch of every surface writes the marker and no value. | `tests/test_settings.py`. |

### Caches
----
RID: `req-github-core-caches`

Status: `Implemented`

Five incidents turn on the Actions cache, including the two most recent: an entry written by a job
an outsider can reach and restored by a job that holds publish rights. It is a convergence node
between two trust levels rather than a performance detail, and the `ref` is the load-bearing
field — it says which side of the trust boundary the entry came from.

**The declared and the observed cache are different objects and are not joined in v0.** A declared
key is an expression (`${{ runner.os }}-node-${{ hashFiles('**/lock') }}`); resolving it would mean
implementing GitHub's expression language, and a guessed key that happened to be wrong would link a
job to another job's entry. So the declared side lives on `workflow_job.configuration.cache_steps`
(step index, action, mode, key expression, restore keys) and the observed side is `actions_cache`.
The join is a named gap. `WRITES_CACHE` / `RESTORES_CACHE` wait for it.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-caches-1 | Entries Collected | Implemented | Stored cache entries land as `actions_cache` joined by `STORES_CACHE`, carrying key, version, ref, size and access times. | Degrades with a warning on 403/404 like runners. |
| req-github-core-caches-2 | Ref Scope Resolved | Implemented | `SCOPED_TO_REF` links an entry to an observed `git_ref`. Its absence is informative — usually a pull-request ref — and is not treated as an error. | |
| req-github-core-caches-3 | Truncation Reported | Implemented | The per-repository cap is stated with the total, since entries are returned most-recently-accessed first. | |
| req-github-core-caches-4 | Declared Usage Not Guessed | Implemented | Cache key expressions are stored as written and never evaluated; no edge claims a declared step wrote a particular entry. | The gap is named rather than papered over. |

### App Installations
----
RID: `req-github-core-app-installations`

Status: `Implemented`

The registered application and its installation into an account are different objects: one App is
installed into many accounts, each installation carrying its own approved permissions, its own
repository selection, and its own suspension state. Merged — as they were before this split — an
account's granted permissions would hang off a node shared by every account that installed the
same App.

This is an **App-only surface**: the installed-App inventory answers `404` to any personal access
token. In PAT mode nothing is emitted and nothing is *claimed* — the run records that the surface
was unreachable, because an empty inventory from a token means "could not look", not "no Apps are
installed".

**Which endpoint answers this matters more than it looks.** `/app/installations` answers "where is
THIS App installed" — one row, about ourselves. `/orgs/{owner}/installations` answers "which Apps
can reach this account's repositories", which is the question the product exists to ask. The
collector asks the account first and falls back to its own installation, recording which it got:
an inventory of one is not an inventory, and the two must not be reported as if they were the same
answer.

**This widens the derived permission set, deliberately and once.** The account-wide list requires
`organization:administration:read`, the first organization-surface permission the collection
manifest declares. It is named here rather than left as an "exploratory" extra on the App because
it is now *used*: the alternative is a product that promises to show you which Apps reach your
repositories and then shows you one row about itself. Read-only, like everything else in the set.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-app-installations-1 | Split From The Application | Implemented | `app_installation` holds installation id, granted permissions, repository selection, events and suspension; `github_app` keeps the application. Joined by `REGISTERS_INSTALLATION`, and to the account by `INSTALLED_ON_ACCOUNT`. | |
| req-github-core-app-installations-2 | PAT Mode Claims Nothing | Implemented | Running as a token records that the inventory is unreachable rather than emitting an empty one. | An empty inventory is otherwise indistinguishable from a clean account. |
| req-github-core-app-installations-4 | Account Inventory Preferred, Fallback Named | Implemented | The collector reads `/orgs/{owner}/installations` (which Apps reach this account) and falls back to `/app/installations` (its own installation) only when refused — warning that the absence of other Apps is then not evidence there are none, and recording which scope the answer came from. | Requires `organization:administration:read`; declared in the collection manifest so the App's permission set derives it rather than carrying it as an unexplained extra. |
| req-github-core-app-installations-3 | Repository Selection Retained | Implemented | `repository_selection: all` is stored as-is: such an installation follows the account into new repositories without anyone granting it again. | |

### Collection Scope
----
RID: `req-github-core-collection-scope`

Status: `Implemented`

A collector that did not see something has two different things to say about it — *it is not
there*, or *I could not look* — and the grid renders both as an absent node. The tombstone
candidate rule (tap#140) is *fan-out from the account, minus observed this run, minus outside the
installation's selection*, and the third term is a fact about THIS run's reach. George ruled it a
node (2026-09-14): an App's grants can be narrowed in a settings page and nothing tells the
collector, so the reach is perceived-true-at-a-time like a runner execution, and belongs on the
operation side (`github.observation: execution`) where it is immutable history. "When did we stop
being able to see X" then falls out of the scope nodes ordered by `observed_at`.

**One per run, before the walk.** `collection_scope` is keyed on the `collection_job` entity id
and landed in its own GRIFT batch right after the installation selection is recorded, so it EXISTS
while the run is in progress — reliability 1b patches a tier verdict onto it at each tier's end,
and a run that dies mid-way leaves the earlier verdicts behind. `SCOPES_RUN` joins it to the run
(a core type, named by its `ENTITY_TYPE` string in the edge's `targets`; the job exists before the
collector starts, so the edge resolves under strict dangling-edge mode). `DERIVED_FROM_INSTALLATION`
joins it to the installation whose grant it read, and lands with the main batch beside the
installation node — absent under a PAT, and absent rather than dangling when the inventory was
refused.

**Three inputs, each versioned.** The scope is derived from the collection manifest (what TAP
asked for), the installation grant (what the account allowed) and the account's plan (a scope
input: the audit log is Enterprise-only). `configuration` records the manifest's version and
SHA-256, the grant's permission map / selection / events / suspension as read, and where the plan
came from — so a verdict that changes between two runs is attributable to "we asked for more"
versus "they granted less" versus "the plan changed". `selection` is the `INSTALLATION_SELECTION`
record verbatim: ONE dict, built once, placed on the run record and on the node.

**Two declared, empty seams.** `visibility` (per entity type: `reachable` / `degraded` /
`unreachable` / `unknown` + the failing permission triple) is where the visibility assessment
(github-core#15) lands; `tiers` (per tier: `complete`, `reason`, `prerequisite`, `decided_at`,
`count_check`, `surfaces`) is where reliability 1b's Confirm writes, through the service layer,
once per tier. Both are emitted `{}` with their shape described in `FIELD_CRUD_SCHEMA`, and
`reason` is a closed vocabulary — complete · truncated · forbidden · errored · filter_unverified ·
count_mismatch · prerequisite_incomplete · not_attempted — verbatim, so that
`WHERE s.tiers.T2.reason = "count_mismatch"` is a stable Gryphon question before either writer
exists.

This node is not the run. Scope facts never go on `collection_job`.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-collection-scope-1 | One Per Run, Before The Walk | Implemented | A run lands exactly one `collection_scope`, keyed on its `collection_job` id, in its own batch after the installation selection and before any repository is read; `selection` equals the `INSTALLATION_SELECTION` record. | `tests/test_collection_scope.py::TestEmission`; proven live on the fixtures org 2026-09-15. |
| req-github-core-collection-scope-2 | Joined To Run And Grant | Implemented | `SCOPES_RUN` targets the core `collection_job`; `DERIVED_FROM_INSTALLATION` targets the installation the App token was minted for, only when that installation's node was minted this run. | A PAT-only run has no installation edge — not applicable, not unobserved. |
| req-github-core-collection-scope-3 | Seams Declared, Empty | Implemented | `visibility` and `tiers` are emitted `{}` with their shapes described per key; the tier `reason` enum is the agreed closed vocabulary. | A tier verdict in the agreed shape validates against the schema; a stray reason does not. |
| req-github-core-collection-scope-4 | Inputs Versioned | Implemented | `configuration` carries the manifest version + digest, the grant as read, and the plan's provenance, so a changed verdict has an attributable cause. | `plan` is `unknown` with `plan_source` saying why whenever it could not be read. |

### A 404 Is Judged Against The Credential's Reach
----
RID: `req-github-core-falsifier-reach`

Status: `In Development`

GitHub answers `404` for an object that is gone **and** for an object that is there and this
credential may not see. A falsifier that reads the status line alone therefore cannot tell a
deletion from a narrowed grant, and under retirement authority the two have opposite consequences:
one records a fact, the other retires a live node.

Ruled by George on 2026-09-20 (option D on github-core#155): the 404 is judged against the
credential's **reach** — what it can demonstrably see right now — and never taken at face value.

**The reach, per credential kind.** What is observable differs, and where it is not observable the
record says so rather than assuming the credential could look:

- **App** — observable. `repository_selection` says `all` or `selected`; `GET /installation/repositories`
  walks the selected list.
- **Classic token** — observable from the token's own `X-OAuth-Scopes` response header (github-core#158).
- **Org-owned fine-grained token** — observable only from the organization side, and only by an App:
  `GET /orgs/{org}/personal-access-tokens` (github-core#159).
- **User-owned fine-grained token** — **not observable, permanently.** A fine-grained token cannot
  introspect itself, and with no organization there is no org-side listing. Every 404 it receives
  stays undetermined, by design.

**The residual, named rather than implied.** The reach is read at two points in a run and the
source can change after the second one. Nothing a probe can do closes that: any check happens at
some instant and the world moves afterwards. What the design does is make the last reading later
than every probe it judges, so a change that could have caused any of the run's 404s is caught.
A change that happens after the final reading is not caught, and the honest statement is that
this is bounded rather than eliminated. The reconcile verb's own fence does not help here, for
the reason recorded at `NOT_FOUND_DETAIL`.

**Known gap, and the gate it must pass before arming.** Repository membership does not prove
permission to read what is INSIDE the repository. An installation can keep `metadata` and lose
`actions`, and where GitHub conceals that with a 404 rather than a 403, the parent probe answers
200 while the child answers 404 — and this design would read the child as gone. The permission
axis is github-core#160, and it is a **precondition for switching retirement authority on for this
plugin**, not a later improvement. Recorded here rather than left to the pull request, because the pull request is not what somebody reads before arming.

**The judgement.** A `not_found` becomes `DROPPED_FROM_OBSERVATION` only when the object's
repository is provably in reach. Where the reach could not be read, or was read and does not hold
the repository, the verdict is `UNDETERMINED(scope_unknown)` with a note saying which of the two it
was. For an object inside a repository the tie-breaker is one probe of that repository under the
same credential, cached per run: parent answers → the child's absence is the child's; parent 404 or
refused → the child says nothing.

| RID | Requirement | Status | Behaviour | Verification |
| --- | --- | --- | --- | --- |
| req-github-core-falsifier-reach-1 | Reach Resolved Per Run | In Development | The falsifier resolves the credential's reach once per run; an App reads `repository_selection` and, when `selected`, walks `/installation/repositories`. A refused or failed walk is `unknown`, never an empty set — an empty listing is an observation and a refusal is not, and the two must not resolve alike. | `tests/test_falsifiers.py::TestReachWalk`: a refused walk and a raising walk each yield `unknown` with no repository set; an empty successful walk yields `selected` with an empty set that answers no rather than cannot-say; a walked listing compares by numeric id and by lower-cased `owner/name`. |
| req-github-core-falsifier-reach-2 | Outside The Reach Never Drops | In Development | A `not_found` on a repository the reach does not hold is `UNDETERMINED(scope_unknown)`, never `DROPPED_FROM_OBSERVATION`. | `tests/test_falsifiers.py::TestReachJudgement::test_out_of_reach_a_404_is_undetermined_not_dropped`. |
| req-github-core-falsifier-reach-3 | An Unobservable Reach Never Drops | In Development | Where the reach could not be read at all — a PAT run today, a user-owned fine-grained token forever — every 404 is `UNDETERMINED(scope_unknown)`, with the reason on the note. | `TestReachJudgement::test_an_unobservable_reach_never_drops`; `::test_a_falsifier_with_no_credential_behind_its_client_has_no_reach` proves the default is fail-closed. |
| req-github-core-falsifier-reach-5 | `all` Is One Account's Boundary | In Development | An installation reporting `repository_selection: all` holds every repository of the account it is installed on, and no other. A repository under a different owner is outside the installation, so its 404 is not evidence of absence. An installation that reports `all` but names no account has no boundary to test and its reach is `unknown`. | `tests/test_falsifiers.py::TestReachBoundary`. Introduced on PR# 161. |
| req-github-core-falsifier-reach-6 | Reach Belongs To The Run | In Development | A reach resolved from the credential is cached against the lifecycle batch id, not the falsifier instance: an installation narrowed between two runs must be re-read, never carried forward. | `tests/test_falsifiers.py::TestReachIsScopedToTheRun` reuses one falsifier across two runs and narrows the installation between them. Introduced on PR# 161. |
| req-github-core-falsifier-reach-7 | A Repository's Reach Is Read Again After Every Probe | In Development | A repository has no parent to probe, so the reach is its only gate and gets a second reading from a freshly minted credential, taken after EVERY probe of the run — not at the first absence. That ordering is what makes it complete: a narrowing that could have caused any of the run's 404s necessarily precedes the reading, so it is caught for all of them. A narrowing downgrades every retirement in the run, including ones that may genuinely be gone, because once the reach has moved no evidence separates them. One extra read per run, on that path only. Core's verb cannot cover this: it rejects a verdict whose target was re-observed, and a repository that left the reach is the one this run cannot observe. | `tests/test_falsifiers.py::TestReachIsReadAgainAfterTheProbe`: a narrowing refuses the retirement; a narrowing after the FIRST absence still refuses both candidates; a stable installation still drops; two absences cost one extra read. Introduced on PR# 161. |
| req-github-core-falsifier-reach-4 | Parent Probe, Once Per Run | In Development | A 404 on an object inside a repository is judged against one probe of that repository; the answer is cached per run and shared across every falsifier of that run. An absence resting on a file the credential just READ is not reach-gated — the read already answered whether it could look. | `TestReachJudgement::test_a_child_404_under_a_gone_parent_is_undetermined`; `::test_the_parent_is_probed_once_per_run_however_many_children` proves one probe for three children and a re-probe on a new run. |

### Rule Suites — Who Actually Bypassed
----
RID: `req-github-core-rule-suites`

Status: `In Development`

`req-github-core-ruleset` records **who may bypass** a gate, and hits a documented ceiling: GitHub
returns `bypass_actors` only to a caller with **write** access to the ruleset, "to prevent leaking
sensitive information". A read-only App is refused (REST omits the key; GraphQL returns a truthful
`totalCount` with `nodes: [null]`), and so is a fine-grained PAT on the history endpoint. That is a
limitation to publish, not to engineer around — the rationale tracks, since naming who may bypass a
control turns those accounts into targets.

**A different question is fully answerable.** `GET /repos/{owner}/{repo}/rulesets/rule-suites`
returns **200 to a read-only App installation token** and names the actor of every push evaluated
against the repository's rulesets — including the ones whose result was `bypass`. Measured against
`unified-systems-com/tap` on 2026-08-28: ten bypass events in a month, each carrying `actor_name`,
`actor_id`, `ref`, `before_sha`/`after_sha`, `pushed_at`, and per-rule evaluations naming the
ruleset gone around.

So the product can say **who did, when, on which ref, and which control they went around**, even
where it cannot say who is permitted to. Enumeration and detection are different facts, and the
second is the one a security product is usually asked for.

**The actor is a `github_account`, deliberately.** The API gives a login and a numeric id, and
nothing more: it may be a person, a bot, or a machine account, and the collector does not know
which. `github_account` is exactly that primitive — an account, user-or-organization merged on
purpose (`req-github-core-account`) — so claiming more would be inventing an identity we did not
observe. `identity_core__principal` may later carry the human-versus-robot distinction; this does
not pre-empt it.

**A rule suite is an occurrence, not a change.** The vocabulary corpus rejects
"change / snapshot / audit-event types" because the grid already carries field-level history — and
that ruling is right and does **not** apply here. It governs changes to objects we collect ("this
ruleset's enforcement moved to `evaluate`"), which history handles. A rule suite is an event in the
world that we observed, in the same category as `github_actions_run`: it has GitHub-assigned
identity, a timestamp, and facts that point at it. Modelling it duplicates nothing.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-rule-suites-1 | Suite Model Declared | In Development | A `github_rule_suite` node carries GitHub's suite `id`, `result`, `ref`, `before_sha`, `after_sha`, `pushed_at`, `actor_login`, and the evaluations that failed or were bypassed. | Keyed on the suite id, which is GitHub-assigned and stable. |
| req-github-core-rule-suites-2 | Actor Is An Account, Not An Identity | In Development | The pusher is emitted as a `github_account` keyed on `actor_name`, joined by `TRIGGERED_EVALUATION`. The collector does not classify it as human or machine, because the API does not say. | `actor_id` rides as a field so a login rename is detectable, matching `req-github-core-account`. |
| req-github-core-rule-suites-3 | The Bypassed Control Is Named | In Development | Each evaluation whose `rule_source.type` is `ruleset` produces a `BYPASSED` edge from the suite to that `github_ruleset`, carrying the `rule_type` that was gone around. | This is the join that makes the event actionable rather than a log line. |
| req-github-core-rule-suites-4 | Bypass Is The Collected Subset | In Development | Collection filters to `rule_suite_result=bypass`. A passing suite is a routine push and lands nothing; the `result` field is kept so the model can widen without a migration. | ~47 suites/day on one repository — collecting every push evaluation would swamp the grid for no finding. |
| req-github-core-rule-suites-5 | The Window Is Explicit, Always | In Development | Every call sets `time_period` explicitly. Omitting it silently defaults to `day`, so a repository with a month of bypasses reads as a quiet one. | Measured: `day` 47, `week` 100+, `month` 100+ on one repository. An absence rendering as a finished answer, arriving through a query default. |
| req-github-core-rule-suites-6 | Refused Is Not Empty | In Development | A refusal degrades with a warning and records that the surface was unreachable; it never lands zero bypass events as though none occurred. | Same three-state discipline as `bypass_observability`. |

### Releases — The First Output
----
RID: `req-github-core-releases`
Status: `In Development`

The machinery view (git-serious-tap#35) has an OUTPUT column — what the pipeline produces — and
until github-core#31 no node existed for any output. The column rendered **"artifacts: not yet
collected"**: an explicit NOT-OBSERVABLE state, never an empty column, and that placeholder was
the issue's tracking marker in the UI. This requirement retires it for releases.

**Transport.** `Repository.releases` is selected inside the config-layer GraphQL query
(`req-github-core-graphql-config`) at no extra request — measured 2026-09-02: five releases on
`unified-systems-com/tap`, the whole query moving from 64 to 66 rate-limit points. The REST
`/releases` endpoint exists and is not called; George's ruling (2026-09-02) is GraphQL wherever
GitHub offers it, REST where it does not.

**A release is a product of execution riding the declaration transport.** It is stamped
`github.observation: execution` because it exists only because someone published it. Transport
is not layer.

**Identity is the release id, not the tag.** A release can be deleted and re-cut on the same
tag; a tag can be moved under a release. Keyed on the id, the first is a new node and the second
is the same node whose `target_sha` changed — which field history records for free.

**The producer is derived, and says so.** GitHub records who published a release (an account —
`tap-release-please[bot]` on the product repository) but never which run. `BUILDS_RELEASE` is
inferred from the run window already in hand, and its `match_kind` names the evidence: `tag_ref`
when the run's `head_branch` is the release's tag (a tag-push build), `same_commit` when the
run's `head_sha` is the commit the tag resolves to (co-location, shared by every workflow that
ran on that push). Runs triggered *by* the release (`event: release`) are consumers and are
excluded. Measured on the product repository: every release matches `same_commit` only, because
release-please cuts them on a push to `main` — the honest answer, and why the property exists.

**Three states live on the repository.** `github_repository.outputs_observability` carries
`releases` / `artifacts` / `packages` ∈ `observed` | `unobservable` with a `notes` map, because a
property that qualifies an absence belongs on the node the absence is about (the
`bypass_observability` ruling). The view reads it to tell "no releases" from "did not look".

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-releases-1 | Release Model Declared | In Development | A `github_release` node keyed on `owner/repo` + release id carries `tag_name`, `name`, the three GitHub flags (nullable), `author_login`, `target_sha`, timestamps, `asset_count` and `assets`; joined to its repository by `PUBLISHES_RELEASE`. | `models/github_release.py`; `tests/test_outputs.py::TestReleasesLand`. |
| req-github-core-releases-2 | Tag Joined When Observed | In Development | `TARGETS_REF` joins a release to `refs/tags/<tag_name>` when that ref was collected; an unobserved tag carries no edge and no error, and `tag_name` remains the record. | Both ends carry the commit they resolved to; a re-tag is a query over two fields. |
| req-github-core-releases-3 | Producer Derived And Labelled | In Development | `BUILDS_RELEASE` is emitted per collected run matching by `tag_ref` or `same_commit`, carrying `match_kind` and `head_sha`; runs with `event == release` are never joined as producers. | The only place a run→release claim is made, and it names its own evidence. |
| req-github-core-releases-4 | Refused Is Not Empty | In Development | A repos-only scope, or a GraphQL response without the `releases` field, records `outputs_observability.releases = unobservable` with the reason, warns, and lands no release nodes; truncation past the page cap is reported with the total. | Same three-state discipline as `bypass_observability`. |

### GitHub Packages — The Collection Seam
----
RID: `req-github-core-packages`
Status: `In Development`

**Decision 4 stands; this is the seam.** The vocabulary corpus homes `package` /
`package_version` in a future `supply_chain_core`, keyed on a purl. That ruling is about
IDENTITY and is not re-litigated here. GitHub Packages is nevertheless a GitHub surface — its
API, its permission, its App-support matrix are GitHub's — so the COLLECTION belongs in
github_core. The plugin therefore emits github_core-owned `github_package` and
`github_package_version` nodes carrying a `purl` field (`pkg:docker/ghcr.io/<owner>/<name>@<digest>`
for the container registry; the ecosystem's purl type with `?repository_url=<host>.pkg.github.com`
for npm/maven/rubygems/nuget; `pkg:github/...` otherwise) so the substrate can later claim or
alias them by the identity the corpus chose. Recorded in the vocabulary spec's decisions.

**Not observable with the product credential, and that is the fact to carry.** GitHub's OpenAPI
description marks every packages endpoint `enabledForGitHubApps: false`. Measured 2026-09-02
with a read-only App installation token against `unified-systems-com`:

- `GET /orgs/{org}/packages?package_type=container` → **400 `Invalid argument.`** — while the
  organization's ghcr.io images (`tap-web`, `tap-db`) exist.
- `package_type=npm` / `maven` / `docker` → **200 `[]`** — which proves nothing.
- `GET /orgs/{org}/packages/container/tap-web` and `/versions` → **200**, `version_count: 1973` —
  the per-package endpoints answered for a *public* package. A measurement, not a guarantee, and
  the collector does not guess package names to exploit it (an inventory of one is not an
  inventory).
- GraphQL `Repository.packages` / `Organization.packages` → `totalCount: 0`, no `errors`, same
  organization. The container registry is not on that transport.

The rule is the bypass-actor asymmetry: a filtered listing cannot invent a package, so a
**non-empty** answer proves itself and an **empty** answer under an App credential is
`unobservable`. Whether granting `organization_packages: read` turns the 400 into a listing is
**unmeasured** — the App has not been re-accepted. The credential GitHub documents is a classic
personal access token with `read:packages`, which the envelope does not model; the token, when
placed, is routed to this surface first (per-source routing, `req-github-core-app-auth-1`).

**Permission.** The manifest declares `organization:packages:read` on both package sources, so
the derived App manifest now requests `organization_packages: read` (George, 2026-09-02:
accepted). **An existing installation must re-accept the new permission** — GitHub prompts the
account's admins; until then the App carries the old set and this surface stays unobservable.
That is the ordinary consequence of `req-github-core-app-auth-2`, recorded here so nobody
reads "unobservable" as a defect.

**`BUILDS_PACKAGE_VERSION` — its absence is the finding, after reading `match_kind`.** GitHub
records nothing about which run pushed a version. The edge is derived from the `sha-<short>`
tag convention `publish-images` (and `docker/metadata-action`'s default) applies, matched
against the head commit of a collected run; `attested` is null until an attestation surface
reads it. A version tagged any other way, on an unlinked package, older than the run window, or under an
unobservable listing, carries no edge for a reason that is a limit before it is a finding. And the
edge's presence is a claim by the tagger — anyone with registry push can tag a digest
`sha-<any commit>` — which is why it carries `attested: null` rather than reading as provenance.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-packages-1 | Package And Version Declared With Purls | In Development | `github_package` (keyed owner + type + name) and `github_package_version` (keyed under it on GitHub's version id) each carry a `purl` minted once by `identity.package_purl`; versions carry `container_tags`; joined by `PUBLISHES_PACKAGE_VERSION`. | `tests/test_outputs.py::TestPackagesLand`, `TestIdentity::test_purl_per_package_type`. |
| req-github-core-packages-2 | Owner Always, Repository When Linked | In Development | `PUBLISHES_PACKAGE` runs from the owner account (`link_kind: owner`) for every package, and from the repository (`link_kind: repository`) only when GitHub links one that was collected. Under a `repos` include-filter, packages not linked to a collected repository are counted in the note and not emitted. | GitHub's link, never inferred from the name. A repo-scoped envelope asked for those repositories' outputs, not the account's inventory (PR #50 review). |
| req-github-core-packages-3 | Unobservable Is Never Zero | In Development | Every package type is asked for; a 400/403/404, or a 200 `[]` under an App-only credential, records that type as unobservable; `outputs_observability.packages` on every collected repository is `observed` only when every type answered with proof, else `unobservable` with the per-type reasons; a non-empty answer proves itself. | The captured 400 + `[]` shape is the fixture. |
| req-github-core-packages-4 | Build Join Derived And Labelled | In Development | `BUILDS_PACKAGE_VERSION` is emitted only from a run of the repository GitHub links the package to, when a `sha-<7..40 hex>` container tag is a prefix of that run's `head_sha`, with `match_kind: tag_sha` and `attested: null`; an unlinked package carries no edge; `sha256-` (cosign) and non-hex tags never match. | The edge is a claim by whoever tagged the image, forgeable by anyone with registry push, and says so; an attestation surface upgrades it (PR #50 review). |
| req-github-core-packages-5 | Versions Degrade To The Package | In Development | A refused versions listing lands the package alone and warns; a capped listing warns against GitHub's `version_count`. | 1,973 versions on one image at capture. |

### GitHub Apps
----
RID: `req-github-core-app`

Status: `Implemented`

A `github_app` node models a GitHub App or first-party platform app enabled on
a repository, linked by `ENABLED_ON_REPOSITORY`. The type is generic so the same shape
covers GitHub's managed apps (Dependabot, code scanning), third-party apps, and
OIDC token-issuing apps; the node is a singleton keyed by app slug, with one
`ENABLED_ON_REPOSITORY` edge per repo that enables it.

#### Detection

GitHub surfaces an enabled platform app in the repo's Actions workflow list
under a synthetic `dynamic/<app>/...` path (e.g. Dependabot appears as
`dynamic/dependabot/dependabot-updates`). These are not repo CI workflows — they
are platform apps enabled on the repo. The collector recognizes the synthetic
path prefixes (a small declared map) during the per-repo workflow walk and emits
a `github_app` + `ENABLED_ON_REPOSITORY` instead of a `github_workflow` + `DEFINES_WORKFLOW`,
skipping the YAML fetch (no real file exists at the dynamic path). Detection is
thus a side effect of collection that already happens — no extra API calls, and
consumers (e.g. samsite) get the app node for free without doing anything.

The app node carries no `app_id` from this signal (the synthetic entry does not
expose one); `slug`, `name`, `html_url`, and `description` come from the declared
prefix map.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-app-1 | Generic App Type | Implemented | `github_app` is a generic type (slug-keyed singleton) covering managed, third-party, and token-issuing apps; `ENABLED_ON_REPOSITORY` links it to repositories. | Reused beyond Dependabot. |
| req-github-core-app-2 | Dependabot Detected At Collection | Implemented | The collector reclassifies the synthetic `dynamic/dependabot/...` Actions entry into a `github_app` (`slug=dependabot`) + `ENABLED_ON_REPOSITORY` edge, not a `github_workflow`. | Declared synthetic-path prefix map; no extra API calls. |
| req-github-core-app-3 | App Node Deduped | Implemented | The `github_app` node is emitted once per run (deduped by slug) even when enabled on multiple repos; `ENABLED_ON_REPOSITORY` edges still fan in per repo. | Run-level dedup set. |

### Dimension Strategy
----
RID: `req-github-core-dimensions`

Status: `Implemented`

GitHub is treated as its own platform environment. The plugin uses flat,
GitHub-specific dimensions:

| Key | Example | Applies To |
| --- | --- | --- |
| `git.host` | `github.com` | All GitHub nodes and edges, **and** every neutral `git_core` node and edge this plugin mints |
| `github.owner` | `notgeorge` | Repo-scoped nodes and edges |
| `github.repo` | `samsite` | Repo-scoped nodes and edges |
| `github.surface` | `actions` | Actions workflows, runs, jobs, runners, caches |
| `github.surface` | `rules` | Rulesets and the edges that apply them |
| `github.surface` | `deployments` | Environments |
| `github.surface` | `apps` | Apps and app installations |
| `github.observation` | `execution` | Runs, jobs, caches — what happened |
| `github.observation` | `declaration` | Declared workflow jobs — what is written. The dimension that separates `workflow_job` from `github_actions_job` without renaming either slug. |
| `github.ref_type` | `branch` \| `tag` | Refs. One type carries both, so the partition that matters is a dimension rather than a type boundary. |

Static model defaults should include only dimensions that are true for all
instances, such as `git.host = "github.com"`. The collector supplies
repo-specific dimensions in GRIFT envelopes.

**`github.owner` and `github.repo` are deliberately NOT model defaults, on any type.**
`DEFAULT_DIMENSIONS` is a class-level constant applied verbatim at creation, so a
locator there could only name ONE owner and ONE repository for every node of that type.
That declaration would be present on every node and true of almost none — the exact
shape of a presence check passing over a false fact, and worse than the absent stamp it
replaces, because nobody re-checks a value that is written down. The locator is per-node
data and is stamped by whatever mints the node; the collector does so in
`_collect_repo` (`req-github-core-dimensions-2`). A second mint path owes the same
stamp, and the remedy if one ever forgets is to derive the locator from the node's own
containment rather than to hardcode a default that cannot be right.

**`git.host` is git_core's key, written here on purpose.** github_core depends on
git_core and therefore legitimately writes git_core's vocabulary, so this plugin's own
27 types carry `git.host` exactly as the neutral nodes do — one key, one meaning, both
layers, so "every node on `ghe.acme.com`" is a single filter rather than a union of two
spellings. It replaced `github.platform`, which held a HOST under a key named for the
vendor and could never have been the neutral layer's spelling (github-core#168,
git-core-tap#11). The neutral rows carry `git.host` and nothing else: `git.object` is
gone (it duplicated the entity type) and so is `github.surface: git`, whose only purpose
was marking github's write to a layer that no longer carries github's vocabulary.

**`github.observation` is the DCOM layer axis, and both of its values are stated
positively.** An observation is either a record of what the pipeline *is configured
to be* (`declaration` — workflows, repositories, apps, runners, and the edges among
them) or a record of what it *did* (`execution` — runs, jobs, and the edges among
them). The distinction is the join that makes config-versus-operation comparison
possible at all, so it is carried on every node and edge rather than on the
execution side alone.

The rule that forces this: **a missing fact and a negative fact must never render
the same way.** If only executions declared the dimension, "the config layer" would
be expressible only as `NOT observation = "execution"` — which silently swallows
every object whose dimension was never set, including objects landed by a future
collector that forgot to set it. Both values present makes the layer a fact the
grid asserts, and makes an object with no observation a detectable defect rather
than an invisible member of the config layer.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-dimensions-1 | Forge Host Dimension | Implemented | All plugin-owned nodes and edges carry `git.host = "github.com"`, and so does every neutral `git_core` node and edge this plugin mints; no node or edge carries `git.object`, and no node carries `github.surface: git`. | Set in `DEFAULT_DIMENSIONS` on every model and `default_dimensions` on every edge; passed on the neutral envelopes by the collector, derived from `_PLATFORM_HOST`. A search on one host returns both layers in one filter — `tests/test_commits.py::TestOneHostIsOneFilter`. |
| req-github-core-dimensions-2 | Repo Scope Dimensions | Implemented | Collector-created repo-scoped objects carry `github.owner` and `github.repo`. | Set on every node/edge envelope in `GithubCollector._collect_repo`. |
| req-github-core-dimensions-3 | Actions Surface Dimension | Implemented | Actions-related objects carry `github.surface = "actions"`. | Set on workflow/run/job/runner model defaults and Actions edge defaults. |
| req-github-core-dimensions-4 | Execution Observation Dimension | Implemented | Run and job observations carry `github.observation = "execution"`. | Set on run/job model defaults. |
| req-github-core-dimensions-5 | Declaration Observation Dimension | Implemented | Every plugin-owned node and edge that is NOT a run or job observation carries `github.observation = "declaration"`. | Set on the remaining model defaults and edge `default_dimensions`. The config layer must be a positive fact, not the absence of a dimension: a query for it reads `observation = "declaration"`, never `NOT observation = "execution"`. |
| req-github-core-dimensions-6 | Layer-Spanning Link Edges | Implemented | An edge type whose sources span both observation layers declares no default `github.observation`; the collector sets it per emitted edge from the source model's own default. | `REFERENCES_RESOURCE` only. Derived in `enrichment._dimensions_for_rule` by reading the source model's `DEFAULT_DIMENSIONS` through the registry — one derivation, no second map. |

### Collector Secret Kinds
----
RID: `req-github-core-secret`

Status: `Implemented`

The first credential mode is a Personal Access Token. `github_core` owns the
`github_pat` secret kind data schema and validates it consumer-side via
`tap_cares` `require_secret_kind(..., data_schema=...)`.

The bare kind name (`github_pat`, not `github_core.github_pat`) follows the
established TAP convention — kind names describe the credential type itself,
not the owning plugin. See `plugins/aws_core/specs/spec-aws-core-secrets.md`
for the `aws_static_access_key` precedent.

Data fields:

| Field | Required | Default | Meaning |
| --- | :---: | --- | --- |
| `token` | Yes |  | GitHub PAT. Secret material; never logged or stored on grid. |
| `api_base_url` | No | `https://api.github.com` | GitHub API base URL. Rides with the credential because GitHub Enterprise Server (GHES) tenants have different base URLs and different PATs. |
| `owner` | One of `owner`/`repos` |  | Login of the organization or user whose repositories are the scope. The collector enumerates them (`/orgs/{owner}/repos`, `/users/{owner}/repos` on 404). |
| `repos` | One of `owner`/`repos` |  | Explicit `owner/repo` targets. With `owner`: an include-filter over the enumeration. Without: the scope itself (the legacy/degenerate form, e.g. `["notgeorge/samsite"]`). |
| `initial_run_limit` | No | `10` | Number of latest workflow runs to seed on first collection. |

GitHub App authentication is future work.

#### Pruned Knobs (Behavioral Decisions)

Earlier drafts included `collect_runner_config`, `collect_workflow_files`, and
`collect_grid_links`. All three are removed from the data shape because none
earned their keep:

- **`collect_workflow_files`** — workflow YAML parsing is the entire point of
  v0 for the Sam demo. Mandatory, not configurable. If the operator doesn't
  want it, they don't install the plugin.
- **`collect_runner_config`** — `req-github-core-collector-5` already
  specifies that runner-config collection auto-graceful-degrades with a
  structured warning on permission failure. "Always try; degrade on 403" is
  functionally identical to an explicit `false`, just with less ceremony.
- **`collect_grid_links`** — links are always attempted. When the grid has
  zero matching candidates (e.g., first install before `aws_core` lands its
  first batch), the existing zero-candidate warnings under
  `req-github-core-grid-links` provide the "off" affordance for free. An
  explicit kill-switch adds no value beyond what the resolver's no-match
  behavior already covers.

#### Credential vs Behavior Separation (Future Concern)

Mixing credential material and behavioral knobs on the same secret couples
PAT rotation to operational config — rotating a token means re-typing or
copy-preserving the knobs. For v0 the cost is small (one operator, one
behavioral knob, rare rotation), so the secret carries both. Re-evaluate
when *either*:

- the behavioral knob set grows past two or three flags, *or*
- the rotation cost actually bites (multiple operators rotating, or knobs
  that operators want to change without touching the credential).

The likely landing place is the same hypothetical on-grid plugin-config
model the `feedback_no_plugin_config_in_core_infra` memory item points at.
Do not pre-build it; wait for the trigger.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-secret-1 | One Envelope, Both Credentials | Implemented | The current kind is `github`: one envelope carrying an `app` block, a `pat` block, or both (`anyOf` requires at least one). An unrecognized kind is refused BY NAME rather than by schema failure, because "kind 'x' is not one this collector accepts" is fixable where a wall of schema errors is not. | `SCHEMA_BY_KIND` in `collectors/github_collector/secret.py`. Replaced the either/or dispatch on 2026-08-27, the same day it was written — see `req-github-core-secret-3`. |
| req-github-core-secret-3 | Legacy Kinds Fold Forward | Implemented | `github_pat` and `github_app` envelopes still validate and are folded into the current shape by one `normalize_credentials` function, so nothing above the auth seam branches on which kind arrived. | samsite's shipped record declares `github_pat`; breaking its boot to tidy a kind name would be a poor trade. Transition support, not a permanent second path. The fold is `collectors/github_collector/credential_shape.py` — stdlib-only so the host-side skill scripts path-load the SAME function (github-core#25); `secret.py` re-exports it. |
| req-github-core-secret-4 | Placement Merges, Never Overwrites | Implemented | The App-creation flow writes into the envelope's `app` slot and carries any existing `pat` block (or legacy bare `token`) forward, saying so; the previous file is still copied aside. | Without it, standing up an App on an instance that already had a token would destroy the token silently, and the operator would meet it as a permanently blank column rather than an error. |
| req-github-core-secret-2 | Plugin Owns Schema | Implemented | `github_core` ships and validates the JSON Schema for both kinds, strictly (`additionalProperties: false`), so a PAT pasted into a `github_app` envelope fails at load rather than at 401. | `GITHUB_PAT_SCHEMA` / `GITHUB_APP_SCHEMA` in `secret.py`; validated via `require_secret_kind`. |
| req-github-core-secret-3 | Scope Fields | Implemented | The secret carries the collection scope: `data.owner` (account login) and/or `data.repos` (explicit `owner/repo` list — the filter when `owner` is present, the scope when it is not). At least one is required. | Schema `anyOf`; every field described (`GITHUB_PAT_SCHEMA`). Amended 2026-08-26. |
| req-github-core-secret-4 | GitHub App Deferred | Proposed | GitHub App auth is deferred. | |
| req-github-core-secret-5 | Minimal Knob Set | Implemented | The only behavioral knob is `initial_run_limit`; `collect_workflow_files`, `collect_runner_config`, and `collect_grid_links` are not data fields. | Schema is `additionalProperties: false`; the three pruned names trigger validation errors at load. |

### Collector Runtime
----
RID: `req-github-core-collector`

Status: `Implemented`

The collector is a standard `CollectorBase` subclass registered by
`github_core`. It resolves one `github_pat` secret, validates its shape, and
runs in two sequential phases per execution:

1. **Collection phase** — fetch GitHub data for each configured repo, assemble
   a GRIFT batch, submit via `CollectorBase.submit_grift`. This is the main
   batch; on commit, GitHub nodes and execution-spine edges land.
2. **Enrichment phase** — once the main batch is committed, query the
   just-landed GitHub nodes for the configured repos, run the grid-link
   manifest rules against existing grid candidates, and submit a second small
   GRIFT batch containing only `REFERENCES_RESOURCE` edges. Detailed timing
   semantics live with `req-github-core-grid-links`.

Collection policy:

- First population per repo collects the latest `initial_run_limit` workflow runs.
- Later runs collect workflow runs created since the latest
  `github_actions_run.run_started_at` already on the grid for that repo
  (`req-github-core-collector-3`; `created_at` became a column in github-core#47
  and the boundary deliberately did not move with it).
- The collector always refreshes previously non-terminal runs/jobs until they
  reach a terminal state.
- Runner-config collection degrades with a structured warning on permission
  failure; workflows/runs/jobs still collect.
- Missing repo/workflow/run access fails the run visibly.
- Runs and jobs are historical observations. v0 has no deletion/reaping:
  absence from a future GitHub response never deletes a node.
- v0 does not model multiple run attempts. The collector uses GitHub's default
  jobs endpoint (`GET /runs/{run_id}/jobs`, not `/attempts/{n}/jobs`), which
  returns the latest-attempt snapshot. If a re-run happens between collections,
  the run node is upserted with the latest state and RUNS_JOB reflects the
  newest job set — but old job nodes from the prior attempt persist (per the
  no-deletion rule) and can produce graph clutter. Multi-attempt tracking is
  deferred to `req-github-core-backlog-run-attempts`.
- The enrichment phase re-resolves links against all configured-repo GitHub
  nodes on every run, not just newly-changed ones, so AWS data landing later
  heals link coverage organically.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-collector-1 | CollectorBase | Implemented | The collector subclasses `CollectorBase` and uses the normal `tap_cares` runtime. | `GithubCollector` registered via `register_collector(key="github_core")` in `apps.py`. |
| req-github-core-collector-2 | First Run Seeds Ten | Implemented | Initial collection defaults to the latest 10 runs per repo. | Default from `initial_run_limit(data)` (returns 10 when absent); applied via `per_page` query + `[:run_limit]` slice. |
| req-github-core-collector-3 | Incremental Later Runs | Implemented | Later runs collect runs created since the latest on-grid `run_started_at` for the repo via GitHub's `?created=>ISO` filter. First-ever population (no on-grid runs) falls back to the `initial_run_limit` cap. | `_fetch_run_window` in `collector.py`. Records an `INCREMENTAL_WINDOW` info per run showing the boundary timestamp. |
| req-github-core-collector-4 | Non-Terminal Refresh | Implemented | Non-terminal prior runs (any `status` not in `_TERMINAL_RUN_STATUSES = {"completed"}`) are re-fetched on each collection via the single-run endpoint and re-emitted so OCC upserts pick up the terminal state. | `_fetch_non_terminal_refresh` in `collector.py`. Per-run 404 on the single-run endpoint graceful-degrades with a `RUN_NOT_FOUND` warn (mirrors the per-run /jobs degrade pattern). Terminal-set is enumerated explicitly so GitHub adding a new in-flight status (`waiting`/`pending`/etc.) is correctly treated as non-terminal until proven otherwise. |
| req-github-core-collector-5 | Runner Permission Degrades | Implemented | Runner-config permission failures record warnings and do not abort run/job collection. | Collector catches `GithubAPIError.status == 403` on `/actions/runners` and emits a structured `RUNNER_CONFIG_FORBIDDEN` warn. |
| req-github-core-collector-6 | No Deletion Semantics | Implemented | v0 never deletes GitHub nodes based on absence from API responses. | Collector emits only upserts; no `deletes`/`purges` sections in batch. |
| req-github-core-collector-7 | Two-Phase Run | Implemented | Each collector run executes a collection phase followed by an enrichment phase, in that order. | `GithubCollector.run()` calls `submit_grift` twice; enrichment runs only if the first batch lands. |
| req-github-core-collector-8 | Single-Attempt v0 | Implemented | v0 does not model multiple run attempts; collector uses the default jobs endpoint returning the latest-attempt snapshot. | Uses `/runs/{run_id}/jobs` (no `/attempts/{n}/`). Multi-attempt tracking deferred to `req-github-core-backlog-run-attempts`. |
| req-github-core-collector-9 | Empty-Body 404 Retry | Implemented | The HTTP client retries GitHub's intermittent empty-body 404 responses with exponential backoff (0.5s → 8s, up to 5 retries). Real 404s — carrying a JSON `{"message": "..."}` body — propagate immediately. | GitHub docs for `/actions/runs` and `/list-jobs-for-workflow-run` document only `200 - OK`. Secondary rate limits are documented to return 403/429, not 404. Empty-body 404 with valid `X-GitHub-Request-Id` is observed and undocumented; the body presence is the discriminator. See `api_client.py` module docstring for the evidence trail. |
| req-github-core-collector-10 | Per-Run /jobs Graceful-Degrade | Implemented | When `/runs/{id}/jobs` returns a real (body-bearing) 404 for a specific run, the collector records a structured `RUN_JOBS_MISSING` warn including the response-body excerpt and continues with the next run rather than aborting the whole collection. | Mirrors `req-github-core-collector-5`'s degrade pattern for runner-config 403s. |
| req-github-core-collector-11 | Operator-Facing Self-Test | Implemented | `GithubCollector.self_test()` runs four bounded readiness checks: GITHUB_SECRET_PRESENT (file exists), GITHUB_SECRET_VALID (schema validates), GITHUB_API_REACHABLE (`GET /rate_limit` within `SELF_TEST_LIVE_CHECK_TIMEOUT_SECONDS`), GITHUB_REPO_ACCESS (`GET /repos/{owner}/{repo}` per configured repo). | Per-repo specificity surfaces which repo(s) fail by name rather than a generic "collector run will fail." Empty-body-404 retry is intentionally disabled for self-test paths (`GithubClient(..., retry_empty_404=False)`) so real auth/access 404s surface immediately. Readiness ladder: UNCONFIGURED (secret missing) → MISCONFIGURED (schema fails) → ERROR (API unreachable or per-repo 404) → READY (all green). Account-scoped envelopes add `GITHUB_OWNER_ACCESS:<owner>` (req-github-core-org-scope-5). |

### Collection And Link Manifests
----
RID: `req-github-core-manifests`

Status: `Implemented`

The collector uses two declarative JSON manifests, both schema-validated at
load. Invalid manifests fail the run visibly.

`github_collection_manifest.json` declares GitHub sources: REST endpoints,
workflow file fetches, item paths, target entity types, projected fields, and
edge rules within the GitHub graph. The source primitive set may include:

- `rest_endpoint`
- `repo_file`
- `custom_fn`

`github_grid_link_manifest.json` declares conservative cross-plugin link rules:
which collected GitHub fields may be matched against which existing TAP entity
types and fields, and which edge type to emit on exact unambiguous match.

Separating the files keeps "how to collect GitHub" apart from "how this
installation interprets GitHub data against the grid."

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-manifests-1 | Collection Manifest | Implemented | GitHub API/file collection is declared in a schema-validated JSON manifest. | `github_collection_manifest.json` + `.schema.json`; validated at load by `manifest.load_collection_manifest()`. v0 manifest is an inspection document; the engine is procedural. Driving the engine off the manifest is a future refactor. |
| req-github-core-manifests-2 | Link Manifest | Implemented | Cross-grid link rules are declared in a separate schema-validated JSON manifest. | `github_grid_link_manifest.json` + `.schema.json`; loaded by `manifest.load_link_manifest()`. Resolver in `enrichment.py` is fully data-driven off this manifest. |
| req-github-core-manifests-3 | No Code Loading From Manifest | Implemented | `custom_fn` names resolve through a plugin-local registry; manifests never import code dynamically. | v0 doesn't use `custom_fn` (schema permits it but no rule references it). When/if added, the registry will live alongside the loader. |

### Workflow File Parsing
----
RID: `req-github-core-workflow-parse`

Status: `Implemented`

Workflow parsing is v0 because the demo needs to explain the deployment
plumbing inside the workflow file. The plugin parses `.github/workflows/*.yml`
and `.github/workflows/*.yaml` using `PyYAML`, scoped as a plugin-owned Python
dependency.

#### Fetch Shape

Workflow YAML bytes are fetched via the GitHub Contents API
(`GET /repos/{owner}/{repo}/contents/.github/workflows/`) and decoded from the
inline base64 `content` field of each file response. Bytes are held in memory
for the duration of one repo's collection pass, parsed with `yaml.safe_load`,
and persisted on the `github_workflow` row as `configuration.raw_yaml` per
`req-github-core-models-7`. No working copy, no on-disk write, no temp file.

This is sized for v0: workflow YAML for a single repo is bounded — a handful
of files at low tens of KB total — so in-memory parsing is the obvious shape.

The collector's fetch helper should be named explicitly
(`_fetch_workflow_yaml(owner, repo, path) -> bytes`) so the body can be swapped
later — e.g., shallow clone + tempdir-walk — without disturbing callers, if a
future fetch shape demands it.

**Future-work seam (Backlog, no implementation in v0).** When a future TAP
collector needs on-disk file layout — broader repo introspection
(terraform parsing, vendored config audits), payloads too large for memory,
or tools that expect a working tree (`terraform validate`, OPA bundle eval) —
define a small temp-file strategy at that time using Django/stdlib primitives
(`tempfile.TemporaryDirectory`, `django.core.files.storage.FileSystemStorage`
for the testable layer). Author a dedicated cross-cutting spec when the demand
signal arrives; do not pre-build the seam. v0 has none of these triggers and
deliberately ships without temp-file infrastructure.

**Future-work seam (per-run head_sha YAML snapshot).** v0's `raw_yaml`
captures the *current* workflow definition at collection time, not the YAML
that any specific historical run actually executed. Per-run snapshots would
fetch `/repos/{owner}/{repo}/contents/.github/workflows/<name>?ref=<head_sha>`
once per run — bounded but multiplies API calls. Pick this up when a panel
or compliance check actually needs per-run YAML fidelity; defer until then.

The v0 parser extracts:

- workflow triggers
- top-level and job-level permissions
- job ids, names, `runs-on`, and `needs`
- `uses:` actions

Extraction of `secrets.*` and `vars.*` references is deferred to
`req-github-core-backlog-references` — the design analysis (two-source-of-truth
shape, hotlink contract implications, scope rules) is captured there.

Composite/local action parsing under `.github/actions/**/action.yml` is not v0.
If the collector detects local/composite action references, it records a
structured info/warning that the shape was detected but not parsed, and the spec
flags it as a near-soon implementation target for the next GitHub-focused pass.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-workflow-parse-1 | Workflow YAML Parsed | Implemented | The collector parses `.github/workflows/*.yml|*.yaml` files. | `parser.parse_workflow_yaml` using PyYAML's `safe_load`; YAML 1.1 `on:` boolean gotcha handled. |
| req-github-core-workflow-parse-3 | Local Actions Deferred Warning | Implemented | Local/composite action references (`uses: ./path/to/action`, NOT `uses: ./.github/workflows/x.yml` which is a reusable-workflow call) produce a visible `LOCAL_ACTION_DEFERRED` warn per detected reference. | `_detect_local_action_refs` in `parser.py` returns each ref's `{job_id, path, uses}`; `_collect_repo` emits one warn per ref via `self.record_warn`. The reusable-workflow-call carve-out is explicit (path ends in `.yml`/`.yaml`) so an operator isn't told to investigate something that's a different category entirely. |
| req-github-core-workflow-parse-4 | Steps Not Nodes | Implemented | Step-level details remain in job/workflow configuration in v0. | Parser preserves the `steps` list verbatim under `configuration.jobs[i].steps`. |
| req-github-core-workflow-parse-5 | In-Memory Fetch | Implemented | Workflow YAML is fetched via the Contents API and parsed in memory; v0 writes no temp file and creates no working copy. | `GithubCollector._fetch_workflow_config` calls `/repos/{owner/repo}/contents/{path}`, decodes inline base64, never writes to disk. |

### Runner Semantics
----
RID: `req-github-core-runner`

Status: `Implemented`

GitHub runners have two relevant shapes:

- Durable registered self-hosted runner configuration, available through the
  runner API when the PAT has sufficient repo administration permissions.
- Observed runner execution data attached to workflow jobs.

v0 creates `github_runner` nodes only for durable registered runner
configuration. Workflow jobs always retain observed runner fields in
`configuration`. If a job's observed runner id matches a durable runner node,
the collector emits `EXECUTED_ON_RUNNER`; otherwise the job remains self-contained.

GitHub-hosted ephemeral runner observations do not become durable runner nodes
in v0.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-runner-1 | Durable Runner Nodes | Implemented | Registered self-hosted runners become `github_runner` nodes when visible. | Collector iterates `/actions/runners` response; one node per runner. |
| req-github-core-runner-2 | Job Runner Observation | Implemented | Every job stores observed runner fields in configuration when present. | `runner_id`, `runner_name`, `runner_group_id`, `labels` persisted on `github_actions_job.configuration`. |
| req-github-core-runner-3 | Matchable EXECUTED_ON_RUNNER | Implemented | `EXECUTED_ON_RUNNER` is emitted only when an observed job runner matches a durable runner node. | Collector keeps `runner_uuid_by_id` from collected runners and emits `EXECUTED_ON_RUNNER` only when `job.runner_id` is in that map. |
| req-github-core-runner-4 | GitHub-Hosted Blobbed | Implemented | GitHub-hosted ephemeral runner observations do not become runner nodes in v0. | No node creation in the job loop; observed runner data stays in `job.configuration`. |

### Existing Grid Links
----
RID: `req-github-core-grid-links`

Status: `Implemented`

The collector always attempts to resolve exact links from collected GitHub
data to existing TAP nodes using the canonical graph read/query surface. Raw
ORM graph queries are not the collector's normal path. There is no kill-switch
knob — when the grid has zero matching candidates (e.g., first install before
`aws_core` lands its first batch), the resolver emits no edges and the
zero-candidate rule below provides the "links are off" affordance for free.

The link manifest supports two source-side shapes:

- `source_field_path` — extract from the source node's nested attribute/JSON
  (the original shape, used by the YAML-ref rules: domain names, AWS regions,
  CloudFront distribution ids).
- `source_constant` — literal value applied to every source node, for
  structural rules where the join key isn't node-specific. First user:
  `repo_federates_with_github_oidc_provider` matches every collected
  `github_repository` against the canonical GitHub Actions OIDC issuer URL
  on `aws_iam_oidc_provider.url`, emitting a `FEDERATES_VIA_PROVIDER` edge. (A rule's
  `edge_type` is declared in the manifest; the federation rule is the one
  structural rule that emits `FEDERATES_VIA_PROVIDER` rather than `REFERENCES_RESOURCE`.)

Rules may also declare a `near_match_pattern` (case-insensitive regex). When
exact resolution returns zero candidates AND the target field of any row
matches the pattern, the resolver records a structured `LINK_NEAR_MATCH`
warn per row and emits no edge — surfacing "looks like what you meant but
isn't quite it" rows (URL scheme variants, GHES tenants, typos) so the
operator can investigate rather than silently miss the link.

#### Timing: Enrichment Phase

Link resolution runs as a **follow-on enrichment phase within the same
collector run**, executing *after* the main GitHub GRIFT batch has been
submitted and committed. A collector run has two phases:

```
GitHubCollector.run():
    1. Collection phase  — fetch API + workflow YAML, build GitHub GRIFT batch
    2. Submission        — submit_grift(github_batch); committed
    3. Enrichment phase  — query landed GitHub nodes for the configured repos,
                            run link manifest rules against grid candidates,
                            emit cross-grid link edges (REFERENCES_RESOURCE,
                            FEDERATES_VIA_PROVIDER, TRUSTS_ISSUER) as a second GRIFT batch
                            (edges only — sources and targets already exist)
```

This timing is deliberate:

- **GitHub batch is independent of grid state.** It succeeds even if no AWS
  data exists yet. Zero edges materialize that run, which is the correct
  observation.
- **Heals over re-runs.** Every `github_core` run re-resolves links against
  *all* configured-repo GitHub nodes — not just newly-changed ones — so AWS
  data landing later picks up links on the next `github_core` execution
  without needing GitHub data to have changed.
- **No new core infra.** Two sequential `CollectorBase.submit_grift` calls
  through the standard path. The pre-commit consistency phase
  (`req-grid-service-batch-precommit-consistency`) is *not* a v0 host for
  enrichment — its spec explicitly defers adding a second consumer.
- **Enrichment failures don't abort the run.** The GitHub batch is already
  committed; enrichment problems emit warnings only. Transient multiple-
  candidate warnings on flaky grid state self-heal on the next run.

`REFERENCES_RESOURCE` is **not** hotlink-backed. Hotlinks are for embedded
references that must match edges (the source node's own data is authoritative).
REFERENCES_RESOURCE is a *derived* link — the GitHub node has no embedded
knowledge of which AWS nodes exist; the link manifest plus grid state are
the authority. It is an enrichment derivation, not a source-of-truth
declaration. This is the structural distinction between v0's
`REFERENCES_RESOURCE` and the deferred hotlinked reference edges in
`req-github-core-backlog-references`.

#### Link Rules

V0 link rules are conservative:

- only manifest-declared fields may be used for matching
- only exact matches are allowed
- one candidate emits one edge
- zero candidates records an optional warning/info, depending on the rule
- multiple candidates records a warning and emits no edge

Expected initial AWS-oriented link examples:

- `DOMAIN_NAME` -> Route 53 hosted zone `name`
- `AWS_REGION` -> AWS region `region_code`
- visible CloudFront distribution ids/domains -> CloudFront distribution fields

Resolving collected GitHub Actions variable values against AWS nodes is a
future capability deferred with the rest of variable/secret-ref work in
`req-github-core-backlog-references`.

#### Future Work (Not v0)

- **Cross-collector triggering.** Today, fresh AWS data landing via
  `aws_core` does not ping `github_core` to re-resolve; links materialize
  organically on the next `github_core` run. Building a cross-collector
  dependency / trigger system is a real complexity bump and not justified by
  current demand. Revisit when an operator-visible "stale links" problem
  actually appears.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-grid-links-1 | Search/Gryphon Read Path | Implemented | Link resolution uses TAP's canonical search/Gryphon read surfaces. | `enrichment.py` runs four Gryphon Searches per rule: source-node fetch (`MATCH (n:<source_type>) WHERE n.data.full_name IN [...]`), exact-match candidate (`WHERE n.data.<field> = $value`), near-match (`WHERE n.data.<field> =~ $pattern AND NOT n.data.<field> = $exact`), and the labelless target-name lookup falls out of the spine envelope's `name` field (no extra query needed). The `=~` operator landed in `req-grid-traversal-lang-regex` on 2026-05-28. |
| req-github-core-grid-links-2 | Exact Match Only | Implemented | Links are emitted only for exact unambiguous matches. | Manifest schema constrains `match_mode` to the `exact` enum value; resolver emits only when `len(candidates) == 1`. |
| req-github-core-grid-links-3 | Ambiguity Warns | Implemented | Multiple matches produce a structured warning and no edge. | Resolver records a `LINK_AMBIGUOUS` warn per multi-candidate hit. |
| req-github-core-grid-links-4 | Enrichment Phase | Implemented | Link resolution executes as a follow-on phase after the main GitHub GRIFT batch commits, emitting a second GRIFT batch containing only cross-grid link edges (`REFERENCES_RESOURCE`, `FEDERATES_VIA_PROVIDER`, `TRUSTS_ISSUER`). | `GithubCollector.run()` submits collection batch, then `resolve_links()` runs, then a second `submit_grift` if any edges resolved. The `TRUSTS_ISSUER` rule has an AWS-node source (`aws_iam_oidc_provider`), proving the resolver is not github-source-only. |
| req-github-core-grid-links-5 | Re-Resolve Every Run | Implemented | Every collector run re-resolves links against all configured-repo GitHub nodes, not just newly-changed ones. | `_source_queryset_for_repos` filters by `full_name__in=repos` and walks every matching landed node every run. |
| req-github-core-grid-links-6 | Enrichment Failures Warn Only | Implemented | Enrichment-phase failures emit structured warnings; they do not roll back the already-committed GitHub batch. | Enrichment has no abort path; missing target models log + skip, multi-candidate hits warn + skip. |
| req-github-core-grid-links-7 | Not Hotlink-Backed | Implemented | The enrichment-resolved edges (`REFERENCES_RESOURCE`, `FEDERATES_VIA_PROVIDER`, `TRUSTS_ISSUER`) are derived links, not hotlinks: no `HOTLINKS` declaration, no pre-commit consistency-phase participation. | `TRUSTS_ISSUER` is deliberately derived: its source `aws_iam_oidc_provider` is written by aws_core, which neither knows about nor emits the edge — a hotlink there would fail on every provider write (see AGENTS.md "apply mechanisms by fit"). |
| req-github-core-grid-links-8 | Missing Target Vocabulary Degrades | Implemented | A link rule whose source or target entity type is not registered in the running composition is skipped and recorded (`LINK_RULE_SKIPPED` warning + `skipped_rules` on the result); enrichment never aborts because another plugin is absent. | Found by git-serious composing github_core without aws_core (2026-08-26). |

### Plugin Python Dependency
----
RID: `req-github-core-python-deps`

Status: `Implemented`

`PyYAML` is approved for this plugin's workflow-file parser and should be
declared as a plugin-owned dependency. `github_core` is the first proof of the
`req-plugin-arch-python-deps` seam (Status: In Development): plugin-local
`pyproject.toml`, root uv workspace/member wiring already in place, one
resolved environment, and no dependency entries in `tap-plugin.toml`.

This is dependency ownership, not runtime isolation. The TAP Python environment
will contain the package when the plugin is installed, but the dependency is
justified by and documented with `github_core`.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-python-deps-1 | PyYAML Approved | Implemented | `PyYAML` is approved specifically for `github_core` workflow parsing. | Declared in `plugins/github_core/pyproject.toml`. |
| req-github-core-python-deps-2 | Plugin-Owned Declaration | Implemented | The dependency is declared in plugin-local Python dependency metadata, not `tap-plugin.toml`. | First proof of `req-plugin-arch-python-deps`; landed via root `[tool.uv.workspace]`. |
| req-github-core-python-deps-3 | No Isolation Claim | Implemented | The spec does not claim runtime isolation from other installed Python packages. | |

### Dependabot Alerts
----
RID: `req-github-core-dependabot-alerts`

Status: `In Development`

GitHub already computes one class of finding for us: a Dependabot alert names a package in a
manifest, the advisory that affects it, the vulnerable range and the first patched version, and
its lifecycle (`open`, `dismissed` with a reason, `fixed`, `auto_dismissed`). For the Actions
ecosystem the "package" is an action and the "manifest" is a workflow file — exactly the two nodes
`req-github-core-actions-used` put on the grid. The prior-art verdict is CONSUME
(`doc-git-serious-cicd-security-prior-art.md` §2.11): land them in the same finding shape zizmor
uses, with the scanner as a dimension, so two sources' disagreement about one workflow is a query.

**Shape.** One `dependabot_alert` node per (repository, alert number), all states — a fixed alert
is history, not noise, and "no open alerts" is only meaningful beside "N fixed". Fields carry the
alert's own facts (state, ecosystem, package, manifest path, scope, advisory ids and severity,
vulnerable range, first patched version, the lifecycle timestamps, dismissal reason and comment)
with the raw alert kept in `configuration`. Two edges, property-free by construction: `FLAGS_ACTION`
(alert → `github_action`, joined on the package name being the action path) and `FLAGS_WORKFLOW`
(alert → `github_workflow`, joined on `manifest_path` being the workflow's path). An alert whose
package is not on the grid as an action (a pip package, say) lands with no `FLAGS_ACTION` edge and
its ecosystem as the reason. Dimensions: the repository's, plus `github.surface: security` (a new
value, documented in the surface dimension article when built).

**Endpoint and permission.** `GET /repos/{owner}/{repo}/dependabot/alerts` (all four states,
paginated) at **`repository:vulnerability_alerts:read`** — the App permission GitHub labels
*Dependabot alerts*, and the first permission this plugin adds beyond the union it held on
2026-09-03. `permission_failure: degrade_with_warning`: a 403 is a per-repository NOT OBSERVABLE
state, recorded and warned, never an empty list — the three-state rule (`none` / `some` / `not
observable`) applies per repository. The organization endpoint (`GET /orgs/{org}/dependabot/alerts`)
would cost one request per hundred alerts instead of one per repository, but GitHub documents it for
an owner or security manager and the App's standing there is unverified; the per-repository call
is the v0 path and the org call an optimisation to measure.

**Two facts to state rather than discover later.** (1) GitHub raises Actions alerts only for
actions referenced by a *version tag*, never for SHA pins ("alerts are only generated for actions
that use semantic versioning, not SHA versioning" — the alerts page, retrieved 2026-09-03). An
absent alert on a SHA-pinned action is therefore no evidence about that action, and the panel that
shows alerts beside `USES_ACTION` pins must say so. (2) The REST documentation's `ecosystem` enum
lists `composer, go, maven, npm, nuget, pip, pub, rubygems, rust` and no Actions value, while the
product documentation says Actions alerts exist. Our own organization carried 29 alerts on
2026-09-03, all `pip`, all `fixed` — the Actions value has NOT been observed. So the collector must
not filter server-side on an ecosystem value nobody has seen: it collects every alert, records the
ecosystem values it observed, and joins `FLAGS_ACTION` on the package name. The first run against
a repository with an Actions alert settles the enum, and that observation is pinned into the
collection manifest at that point, not before.

**Done-test needs an alert to exist — the fixture is in place.** `unified-systems-com/git-serious-fixtures`
(created 2026-09-03, topic `tap-fixture`, Dependabot alerts on, automated security fixes off so
nothing "fixes" the fixture) references `actions/download-artifact@v3` by tag in a job that never
runs; the Actions-ecosystem alert it produces is the known answer for ACID 8, and the same repository
carries the tag-drift fixture for `req-github-core-actions-used-8`. Until the alert is observed on a
running instance, this requirement does not leave `Proposed`.

**App permission — already held, not yet declared.** The installed `git-serious-exploratory` App
(installation 157103378 on `unified-systems-com`, read 2026-09-03 via `GET /orgs/{org}/installations`)
already carries `vulnerability_alerts: read` — along with `security_events: read` and
`secret_scanning_alerts: read` — as *exploratory* grants from the App's creation. What is missing is
the declaration: the collection manifest source must name `repository:vulnerability_alerts:read` so
the permission becomes *derived* rather than exploratory, and any adopter's App minted from the
manifest gains it. For an adopter whose App predates the declaration, the installation does not
receive a new permission silently — an organization owner approves it under the App's installation
settings — and until then the collector reads 403 and reports the surface as not observable.
Code-scanning alerts (`repository:security_events:read`, also already held) are the same shape one
step later and are NOT declared here.

**Amended 2026-09-09 under the one-generic-finding ruling (`req-github-core-code-scanning`,
github-core#89).** The finding is no longer `dependabot_alert` itself: `dependabot_alert` becomes
the DETAIL node behind a `compliance_core__compliance_finding` (keyed
`<owner/repo>#dependabot#<number>` under github_core's namespace, `status` open iff the alert is
`open`, else `resolved`), joined to it by `DETAILS_FINDING`, and the `FLAGS_ACTION` / `FLAGS_WORKFLOW`
asset edges above become `CARRIES_COMPLIANCE_FINDING__compliance_core` pairs from the `github_action`
and the `github_workflow` to that finding — the same joins (package name = action path, manifest
path = workflow path), through the substrate's verb, so a finding list is one query across code
scanning, Dependabot and zizmor. The Actions-only join to `github_action` stays as designed, as does
everything else in this block (all-states collection, the SHA-pin blind spot, the ecosystem enum,
the fixture). The ACIDs below were rewritten on 2026-10-13 (github-core#68), when the build began, to
this amended shape; the `FLAGS_ACTION` / `FLAGS_WORKFLOW` edges were never built.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-dependabot-alerts-1 | One Node Per Alert, All States | In Development | Every alert the endpoint returns for a repository in scope lands as one `dependabot_alert` per (repository, number), in every lifecycle state (`open`, `fixed`, `dismissed`, `auto_dismissed`), carrying state, the lifecycle timestamps, dismissal (reason, comment, login), the dependency (ecosystem, package, manifest path, scope, relationship), the advisory (GHSA and CVE ids, summary, description, severity, CVSS v3 vector and score, CWEs) and the vulnerable range and first patched version, with the raw alert in `configuration`. | A fixed alert is history. An absent score is null, never 0. |
| req-github-core-dependabot-alerts-2 | Four Observability States | In Development | `github_repository.dependabot_observability` is `observed` after a 200 (zero rows included), `unobservable` after a 403 or 404 that does not say the feature is off, with a per-repository warning and nothing minted, or after a walk cut off at the page cap (what it read lands, with `DEPENDABOT_TRUNCATED`), or when an item came back with no alert number and could not be keyed (`DEPENDABOT_UNREADABLE`), `not_enabled` when GitHub says Dependabot alerts are disabled for the repository, with an information record and nothing minted, and `""` when the surface was not asked; no two of these ever serialize alike. | A refusal is never an empty set that reads as clean. |
| req-github-core-dependabot-alerts-3 | One Finding Per Alert | In Development | Every landed alert mints exactly one `compliance_core__compliance_finding`, named by a ref and carrying `source` = `github_core` + `source_key` = `<owner/repo>#dependabot#<number>`, with `name = "<package> <ghsa_id>"`, `summary` = the advisory summary, `description` = the summary plus manifest, vulnerable range and first patched version, and `status = open` iff the alert's state is `open`, else `resolved`; re-collection updates the same finding, never a second. | The true lifecycle stays on the detail. |
| req-github-core-dependabot-alerts-4 | Placed On Repository, Workflow And Action | In Development | Every finding carries `CARRIES_COMPLIANCE_FINDING__compliance_core` from its `github_repository`; additionally from the `github_workflow` whose path equals the alert's manifest path when that workflow was collected, and from the `github_action` whose action path equals the alert's package name when that action was used in the run. A package that is not such an action (a pip package, say) lands with the repository edge only. | Replaces the `FLAGS_ACTION` / `FLAGS_WORKFLOW` edges of the 2026-09-03 design; compliance_core's wildcard-source edge, reused. |
| req-github-core-dependabot-alerts-5 | Detail Behind The Finding | In Development | Every finding has exactly one inbound `DETAILS_FINDING__github_core` from its `dependabot_alert`, property-free; no detail points at two findings. | 1:1 by construction. |
| req-github-core-dependabot-alerts-6 | Walked To The End, Truncation Warned | In Development | The listing asks for all four states by name at `per_page=100` and follows the `Link` header to its end, never sending a `page` parameter (the endpoint rejects it with a 400); a walk that does not reach the end records `DEPENDABOT_TRUNCATED` with the count landed, lands what it read, and records the repository as `unobservable`, so it is never presented as the whole. | Measured 2026-10-13: 48 alerts in one page on `unified-systems-com/tap`. |
| req-github-core-dependabot-alerts-7 | Permission Declared And Derived | In Development | The collection manifest source declares `repository:vulnerability_alerts:read` with `permission_failure: degrade_with_warning`; the ledger entry `vulnerability_alerts` is `requested` citing exactly `dependabot_alerts`; the OpenAPI extract carries the path; the App manifest the skill renders gains *Dependabot alerts: Read-only* from that declaration alone. | Never hand-listed. The installed App already holds it. |
| req-github-core-dependabot-alerts-8 | Ecosystem Observed, Not Assumed | In Development | No server-side ecosystem filter until the GitHub Actions value has been observed on a real alert; each run records the set of ecosystem values it saw on its information record. | The documented enum omits Actions; 2026-10-13: all 48 on our org are `pip`. |
| req-github-core-dependabot-alerts-9 | SHA-Pin Blind Spot Stated | Proposed | Wherever alerts are shown beside `USES_ACTION` pins, a SHA-pinned action with no alert is rendered as "not covered by Dependabot", never as clean. | Product documentation, retrieved 2026-09-03. Not built: no panel shows both yet. |
| req-github-core-dependabot-alerts-10 | Observed On A Running Instance | Proposed | At least one Actions-ecosystem alert lands with its action and workflow placement on a running instance. | The done-test for the Actions join; needs a repository that carries one. The pip population is observed (2026-10-13). |

### Variables And Secret References (Backlog)
----
RID: `req-github-core-backlog-references`

Status: `Backlog`

GitHub Actions variables (`vars.X`) and secret references (`secrets.X`) are
deferred. The Sam demo path does not need them on critical path, and shaping
them properly tangles with TAP's hotlink contract, multi-source provenance,
and the future env/org scope vocabulary. Picking this up before it's
load-bearing risks shipping a half-baked shape that bakes assumptions we
won't be able to easily back out.

This requirement preserves the design analysis already performed so the next
pass starts from "here is what we figured out" rather than "what should we
even build." Pick it up when secret/variable visibility becomes critical
path — most likely when the second customer's deployment needs ref-tracing,
or when the Sam KSI scoreboard requires linking secret refs to compliance
controls.

#### Goal Shape (When Picked Up)

The end state is two models and two reference edges, hotlink-enforced for
correctness:

- `github_actions_variable` — repo-scoped Actions variables, with values when
  API-collected.
- `github_actions_secret_ref` — repo-scoped secret references. Values are
  never collected (GitHub API never returns them). The node is a target of
  reference edges only.
- `REFERENCES_SECRET`: workflow/job → `github_actions_secret_ref`
- `REFERENCES_VARIABLE`: workflow/job → `github_actions_variable`
- Both reference edges are hotlink-backed with `mode: exact` per
  `tap_grid/specs/spec-grid-hotlink.md`. The authoritative embedded view
  lives in `<source_node>.configuration.refs.{secrets,variables}`; the edge
  set must agree exactly, enforced by the pre-commit consistency phase.

#### What We Figured Out (Carry-Forward Notes)

**Two sources of truth per kind.** Each is independent and authoritative for
different aspects of identity/state:

| | API source | YAML source |
| --- | --- | --- |
| `github_actions_variable` | `GET /repos/{owner}/{repo}/actions/variables` — returns names **and values** | `vars.X` parsed from workflow/job/step YAML |
| `github_actions_secret_ref` | `GET /repos/{owner}/{repo}/actions/secrets` — returns names **only** | `secrets.X` parsed from workflow/job/step YAML |

**Hotlink contract forces every YAML-referenced name to become a node.**
Because `mode: exact` requires every name in `refs.secrets[]` / `refs.variables[]`
to map to an edge, and every edge needs a target node, the design choice
"warning-only, no node for unresolved YAML refs" is structurally incompatible
with the hotlink play. Options must be variants of "create the node, mark
provenance."

**Proposed provenance shape: `discovered_via: list[str]` on each node.**
Sorted array of strings; v0 values `["api"]`, `["yaml"]`, or `["api", "yaml"]`.
Array-not-enum so future sources (`org_api`, `env_api`, GraphQL) plug in
without a migration. `github_actions_variable.value` is nullable: populated
when API observation lands, null when only YAML-referenced — the
`discovered_via` array is the trustworthiness flag. `github_actions_secret_ref`
never has a value field.

**Reset each collection, do not accumulate.** `discovered_via` reflects the
current pass. If a secret was `["api", "yaml"]` last run and the operator
removed it from GitHub, next run finds it only in YAML and the field becomes
`["yaml"]`. Historic transitions live in node history (django-simple-history),
not on the current row.

**Natural-key uniqueness.** YAML reference and API observation for the same
`owner/repo + scope + name` resolve to the same node — different sources,
same identity.

**No deletion in v0** (per `req-github-core-collector-6`). A node observed
once persists if later collections don't see it; the `discovered_via` field
may shrink to `[]` for a fully-orphaned name. Deletion semantics are
themselves future work.

**Scope vocabulary.** For v0 of this backlog, the only valid value of "scope"
in the natural key is `repo`. Future env/org scopes add `env:<env-name>` and
`org` when those collection paths come online. Pin this explicitly when
shipping so the field doesn't sit ambiguous.

**Reference extraction scope rules (parser semantics).**

| Refs go onto... | ...when the textual reference appears at... |
| --- | --- |
| `github_workflow.configuration.refs` | top-level `env:`, top-level `permissions:` RHS, top-level `on.workflow_call.secrets:` / `.inputs:` (reusable workflows) |
| `github_actions_job.configuration.refs` | `job.env`, `job.with`, `job.secrets:` (when calling a reusable workflow), `step.env`, `step.with`, `step.run` body, `step.if` |

- Workflow-scope refs do **not** propagate to job `refs` lists.
- Job-scope refs do **not** propagate to workflow `refs` lists.
- Step-level refs roll up to their parent `github_actions_job` (Steps Not
  Nodes; the parent job is the smallest node that owns the reference).
- Each `refs` list is deduplicated at extract time — multiple textual
  references to the same name at the same scope produce one entry, hence
  one edge. Dedupe is structural, not policed.

The "no inheritance, no roll-down" rules fall out structurally: workflow node's
`refs.secrets` is extracted only from workflow-scope YAML positions; job
node's `refs.secrets` only from job+step positions. Wrong scope = wrong
field = no extraction. GitHub Actions resolves inheritance at runtime; the
grid models the textual YAML source-of-truth only.

**Collector warnings (when picked up).** When extracting a YAML ref name
that wasn't in the corresponding API list for that repo's pass, emit a
structured info/warning per-ref. Mirrors the existing
`req-github-core-workflow-parse-3` local-actions-deferred warning pattern.

**Consumer-side disclosure complement.** Secret-ref / variable panels should
surface `discovered_via` as ✓/✗ pills (api present, yaml referenced). Mirrors
the producer-side `feedback_disclose_shortcuts_machine_readably` /
consumer-side `feedback_consumer_side_disclosure_complement` discipline —
distinguish unknown (predates the field) from explicit `["yaml"]` (definitely
not in API). Future panel work, not part of model shape.

#### Discarded Options

- **"YAML ref → warning only, no node, no edge."** Breaks the `mode: exact`
  hotlink contract on the very first batch. Rejected.
- **"Single-source nodes — API-only, no YAML synthesis."** Same problem:
  YAML extraction populates `refs` lists; without target nodes for those
  refs, the hotlink validation fails.
- **Accumulated provenance (union-of-all-observations forever).** Lossy when
  observations actually disappear; node history already captures the timeline.
  Reset-per-pass is more truthful.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-backlog-references-1 | Two-Model Set | Backlog | `github_actions_variable` and `github_actions_secret_ref` are added with the natural keys and v0 scope vocabulary (`repo`) defined above. | |
| req-github-core-backlog-references-2 | Two-Edge Set | Backlog | `REFERENCES_SECRET` and `REFERENCES_VARIABLE` are added as workflow/job → ref-node edges. | |
| req-github-core-backlog-references-3 | Hotlink Enforcement | Backlog | Both reference edges are hotlink-backed (`mode: exact`) with HOTLINKS declarations on `github_workflow` and `github_actions_job` targeting `configuration.refs.secrets[*]` and `configuration.refs.variables[*]`. | Drift impossible by construction. |
| req-github-core-backlog-references-4 | Provenance Field | Backlog | Each ref-node carries `discovered_via: list[str]` reflecting the current collection pass. | Array-not-enum so future sources extend without migration. |
| req-github-core-backlog-references-5 | Variable Value Nullable | Backlog | `github_actions_variable.value` is nullable, populated only on API observation. | |
| req-github-core-backlog-references-6 | Secret Values Never Stored | Backlog | `github_actions_secret_ref` has no `value` field. | GitHub API never returns secret values. |
| req-github-core-backlog-references-7 | Parser Scope Rules | Backlog | Parser populates each node's `refs` lists per the scope-rule table above; step refs roll up to the parent job; no inheritance fan-out. | |
| req-github-core-backlog-references-8 | Collector Warning | Backlog | YAML-referenced names absent from the API list emit a structured info/warning per-ref. | |
| req-github-core-backlog-references-9 | No Deletion | Backlog | Reference nodes persist when no longer observed; `discovered_via` may shrink to `[]`. | Inherits from `req-github-core-collector-6`. |

### Multi-Attempt Run Observation (Backlog)
----
RID: `req-github-core-backlog-run-attempts`

Status: `Backlog`

GitHub workflow runs can be re-run, producing multiple "attempts" — each
attempt has its own job_ids (GitHub mints new job_ids per attempt) and its
own per-job lifecycle. v0 collapses this to a single observation per `run_id`
because the Sam demo path doesn't involve re-runs, and modeling attempts
adds non-trivial complexity around RUNS_JOB lifecycle, "re-run failed jobs"
semantics, and orphan handling.

Pick this up when re-run visibility becomes critical path — most likely
during a real assessment where a customer's CI/CD involves frequent re-runs
and the operator wants to see "which attempt succeeded" or "which jobs were
re-run vs. inherited."

#### Goal Shape (When Picked Up)

The end state models each attempt as a distinct execution observation:

- `github_actions_run` natural key: `owner/repo + run_id + run_attempt`
- `github_actions_job` natural key remains `owner/repo + job_id` (job_ids
  are per-attempt at GitHub source, so they're naturally distinct without
  TAP-side synthesis)
- Each per-attempt run node has its own `RUNS_JOB` fan-out to its own per-
  attempt job nodes
- Same logical-job-across-attempts query pattern via `job.name + run.run_id`
  (e.g., "all attempts of the deploy job for this run")

#### What We Figured Out (Carry-Forward Notes)

**GitHub mints new job_ids per attempt.** Re-running a workflow keeps the
same `run_id` but creates new `job_id` values for every job in the new
attempt. Job names are stable across attempts (e.g., both attempts' "deploy"
jobs are named `deploy`), but job_ids are not. The natural-key shape
(`owner/repo + job_id`) therefore needs no TAP-side synthesis to keep
attempts distinct.

**Two GitHub re-run UIs with different semantics.**

| UI mode | Behavior |
| --- | --- |
| Re-run all jobs | Every job gets a fresh attempt; attempt N's jobs endpoint returns the full fan-out |
| Re-run failed jobs only | Only failed jobs re-execute; attempt N's jobs endpoint returns only the re-run jobs, with previously-successful jobs staying attached to attempt N-1 |

A faithful model just records what each `/runs/{run_id}/attempts/{n}/jobs`
endpoint returns for that attempt — no synthesis, no "fill in the missing
successful jobs from earlier attempts onto the latest attempt." The "full
state of this run including the latest attempt of each job" is a derived
query (`GROUP BY job.name WHERE run.run_id == X ORDER BY run.run_attempt
DESC LIMIT 1 per name`), not a model concern.

**API endpoints:**
- `GET /runs/{run_id}/jobs` — returns latest-attempt jobs only (what v0 uses)
- `GET /runs/{run_id}/attempts/{n}/jobs` — returns that specific attempt's
  jobs (what the multi-attempt model uses per attempt)

**RUNS_JOB lifecycle on re-collection.** With per-attempt run nodes, each
attempt's RUNS_JOB edges are static — once observed, the attempt and its
jobs don't change. There's no "swap the edge set on re-run" problem because
each attempt is its own run node. This is structurally simpler than the v0
shape, which has the messy edge-clutter issue described in
`req-github-core-collector-8`.

**Same logical job across attempts.** Querying "which attempts of the deploy
job ran" is `job.name == "deploy" AND job.run.run_id == X`. No new model
machinery — `name` is already a queryable field on job nodes. Future panel
work might surface "this job has had 3 attempts" inline, but that's panel
concern, not model.

**v0's documented gap.** Under v0, a re-run between collections leaves the
graph in a slightly confusing state: the run node is upserted with the
latest-attempt status, RUNS_JOB picks up the new attempt's jobs, but old
attempt-1 jobs persist (no deletion). The operator sees a run with more jobs
than ran in any single attempt. This is a known limitation, not a bug —
the demo doesn't hit it, and the fix lives here.

#### Discarded Options (For v0 Of This Backlog)

- **"Single shared job node across attempts" (synthetic key like
  `owner/repo + run_id + job_name`).** Rejected: GitHub's source-of-truth
  uses per-attempt job_ids. Inventing a shared identity loses per-attempt
  history (start/end times, conclusions) and misrepresents the upstream
  model.
- **"Latest-attempt-wins, drop old job nodes on re-run."** Rejected: violates
  `req-github-core-collector-6` (no deletion semantics). History matters
  for compliance / audit use cases — successful and failed attempts are
  both load-bearing observations.
- **"Build cross-attempt RUNS_JOB edges so the run node fan-outs to all
  attempts' jobs."** Rejected for the per-attempt-run-node model: each
  attempt is its own run node, so RUNS_JOB is naturally scoped. Cross-
  attempt navigation is a query, not a structural edge.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-backlog-run-attempts-1 | Per-Attempt Run Nodes | Backlog | `github_actions_run` natural key includes `run_attempt`; each attempt is a distinct node. | |
| req-github-core-backlog-run-attempts-2 | Per-Attempt Job Fan-Out | Backlog | Each per-attempt run node has its own `RUNS_JOB` edges to that attempt's job nodes. | Job natural key stays `owner/repo + job_id`; GitHub job_ids are per-attempt. |
| req-github-core-backlog-run-attempts-3 | Attempts Endpoint | Backlog | Collector queries `GET /runs/{run_id}/attempts/{n}/jobs` per attempt instead of the default jobs endpoint. | |
| req-github-core-backlog-run-attempts-4 | Re-Run Failed Semantics | Backlog | The collector records exactly what each attempt's endpoint returns; no synthesis to fill in successful jobs from earlier attempts. | "Latest full state" is a derived query, not a stored shape. |
| req-github-core-backlog-run-attempts-5 | Static Per-Attempt Edges | Backlog | Once an attempt's RUNS_JOB edges land, they are not modified by re-collection of that attempt. | Each attempt is immutable once terminal. |
| req-github-core-backlog-run-attempts-6 | v0 Graph Clutter Resolved | Backlog | Implementing this requirement resolves the documented v0 limitation in `req-github-core-collector-8` where re-runs cause RUNS_JOB to span attempts. | |

### Grid-Vocabulary Reference Resolution (Backlog)
----
RID: `req-github-core-backlog-grid-vocab-links`

Status: `Backlog`

The v0 parser (`_categorize_refs` in `parser.py`) extracts grid-link candidates
by flattening every string value in the workflow YAML and shape-guessing each
against a domain / region / CloudFront-id regex. This is the wrong tool for two
reasons, surfaced while wiring the samsite landing GitHub lane (2026-05-28):

- **It fabricates.** The loose domain regex ("dotted alphanumeric token") tags
  version pins (`0.57.0`, `1.10.2`) and scan-output filenames
  (`checkov-results.sarif`) as `domain_names`. No edge results (they find no
  grid candidate), but the *node* persists false data under a field that
  claims to hold domains — an undetectable lie to any downstream query.
- **It's lossy.** The regex matches whole strings only, so it skips the values
  that actually carry the references: `${{ vars.AWS_REGION || 'us-east-2' }}`,
  `${{ vars.DOMAIN_NAME || '...' }}`, and `terraform output -raw
  cloudfront_distribution_id`. The samsite deploy workflow parameterizes every
  resource through repo variables / Terraform outputs / comments, so the
  shape-regex found *zero* real references and only the junk above.

The deeper point: the **targets** are documented or enumerable and we already
have them — AWS regions are a closed published set (botocore
`get_available_regions` / its `endpoints.json`, and the 34 `aws_region` nodes
already on the grid), and the relevant zones / distributions are concrete facts
collected by `aws_core`. The right question is not "does this string *look* like
a domain?" but "is this string one of the regions / zones / dist-ids we
actually know about?" The **source** side (what a workflow references) has no
upstream contract — GitHub workflows don't declare resource dependencies — so
extraction stays inference; the fix is to *ground* that inference in the known
target vocabulary rather than guess shapes.

#### Goal Shape (When Picked Up)

Invert the pipeline. Instead of shape-classify-then-match:

- Pull the known vocabulary *from the grid* (region codes, Route53 zone names,
  CloudFront distribution ids — small, authoritative sets) and search the
  workflow text for those exact values, substring-aware.
- This removes the junk structurally (`1.10.2` is not a region or a zone on the
  grid, so it can never be mislabeled) and recovers the matches the whole-string
  regex misses (the known code `us-east-2` is *found* inside the `${{ }}`
  fallback expression).

#### What We Figured Out (Carry-Forward Notes)

- **Confidence / context markers are required.** A substring search also hits a
  domain mentioned only in a comment (the samsite deploy YAML names
  `samsite.unified-systems.com` only in a comment) and finds the *fallback*
  region (`us-east-2`), not the operative `vars.AWS_REGION` value. Matches must
  carry context (active config vs. comment vs. fallback-literal) rather than be
  asserted as fact — per the disclose-shortcuts-machine-readably discipline. Do
  not emit a bare edge that implies certainty the source can't support.
- **CloudFront dist-id links have an upstream dependency.** `aws_core` currently
  leaves `aws_cloudfront_distribution.distribution_id` null on the grid, so even
  a correct YAML ref has nothing to match. That gap must close first (or in
  tandem) for dist-id links to resolve.
- **The enrichment phase already trusts the grid** (it queries Gryphon for exact
  matches). The vestigial mistake is only the parser's *pre-classification*; the
  redesign brings phase 1 into line with what phase 2 already does.
- **Land it with a parser/Gridkin test.** This is a behavior change to extraction
  quality, not a one-line tweak — exactly the class of change that needs a
  locked-in test, per the testing discipline.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-backlog-grid-vocab-links-1 | Vocabulary From Grid | Backlog | Region / zone / dist-id candidate sets are read from the grid (and/or botocore for the canonical region list), not hand-rolled regexes. | Region set is a closed published vocabulary; zones/dist-ids are `aws_core` facts. |
| req-github-core-backlog-grid-vocab-links-2 | No Fabricated Refs | Backlog | The parser no longer stores strings that merely match a shape; a value is only recorded as a domain/region/dist-id if it corresponds to a known grid resource. | Kills the `0.57.0` / `checkov-results.sarif` junk class. |
| req-github-core-backlog-grid-vocab-links-3 | Embedded-Value Recovery | Backlog | Known vocabulary is matched substring-aware, recovering references inside `${{ }}` expressions and shell commands. | Recovers `us-east-2` from the `${{ vars.AWS_REGION || 'us-east-2' }}` fallback. |
| req-github-core-backlog-grid-vocab-links-4 | Context Markers | Backlog | Each resolved reference carries a context/confidence marker (active config vs. comment-only vs. fallback-literal); edges do not assert certainty the source can't support. | Disclose-shortcuts-machine-readably. |
| req-github-core-backlog-grid-vocab-links-5 | CloudFront Dependency Noted | Backlog | Dist-id resolution is gated on `aws_core` populating `aws_cloudfront_distribution.distribution_id`. | Cross-plugin dependency; close first or in tandem. |

### GitHub App Relationships (Backlog)
----
RID: `req-github-core-backlog-app-relationships`

Status: `Backlog`

`req-github-core-app` models that an app is *enabled on* a repo (`ENABLED_ON_REPOSITORY`).
It does not model what apps *do*. Future work, once a consumer needs it:

- **Dependabot opens dependency-bump PRs** against the repo — a `github_app -OPENS_PR-> github_pull_request` (and a `github_pull_request` model) story, distinct from the deploy-time alerts fetch.
- **Code scanning / secret scanning raise alerts** — a `github_app -RAISES_ALERT->` story.
- App→workflow consumption (e.g. a deploy workflow querying the Dependabot alerts API as a VDR gate input) — a `FETCH_ALERTS`-style edge, if it can be detected from the workflow body or the alerts API rather than guessed.

These are deferred until there is a concrete graph consumer; v0 stops at presence (`ENABLED_ON_REPOSITORY`).

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-backlog-app-relationships-1 | App Action Edges | Backlog | Model app *behaviors* (PR authoring, alert raising, alert serving) as distinct edges once a consumer needs them, rather than overloading `ENABLED_ON_REPOSITORY`. | Keeps presence separate from behavior. |

### v0 Non-Goals
----
RID: `req-github-core-nongoals`

Status: `Implemented`

Out of scope for v0:

- full GitHub account or organization inventory
- issue, pull request, branch, collaborator, team, package, release, or
  discussion modeling
- environments, environment variables, organization variables, and organization
  secrets
- repository Actions variables and secret references (deferred to
  `req-github-core-backlog-references` with full design analysis preserved)
- multi-attempt run observation (deferred to
  `req-github-core-backlog-run-attempts`; v0 collects the latest-attempt
  snapshot only)
- Sigstore, Fulcio, Rekor, signed-artifact, or transparency-log models
- GitHub App authentication
- local/composite action parsing beyond visible deferred warnings
- `github_actions_step` nodes
- deletion/reaping of old runs/jobs
- scheduled automatic runs
- temp-file or working-copy fetch strategy (see Workflow File Parsing
  future-work seam)

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-nongoals-1 | Broad Inventory Deferred | Implemented | v0 does not attempt full GitHub introspection. | Boundary holds — collector touches only documented endpoints. |
| req-github-core-nongoals-2 | Provenance Plugins Deferred | Implemented | Sigstore/Rekor belong to separate future plugin work. | No Sigstore/Rekor code in github_core. |
| req-github-core-nongoals-3 | No Schedule | Implemented | v0 registers the collector capability but does not seed an automatic schedule. | Manual/demo run only; no schedule GRIFT seeded. |

## Status Vocabulary

Standard TAP states: `Proposed`, `Approved for Development`, `In Development`,
`Implemented`, `Verified`, `Refactoring`, `Deprecating`, `Deprecated`,
`Backlog`.
