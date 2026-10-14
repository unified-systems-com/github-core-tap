# GitHub Core — App Permissions: the ledger, the recommendations, and the drift check

> Written 2026-09-02 from George's pass over GitHub's App-permission catalogue in the context of
> what git-serious observes — the CI/CD system and whether it is secure. The catalogue is
> **documented** (GitHub's OpenAPI description, `components.schemas.app-permissions`); the
> installed App's grants are **observed** (`GET /orgs/{owner}/installations`, 2026-09-02); the
> classifications are decisions and say why.

## Philosophy

The App asks for exactly what the collection manifest's sources declare (`req-github-core-app-auth`):
the requested set cannot drift from the use. That rule is silent about two other things, and both are
absences that read as decisions: the permissions we chose **not** to request, and the permissions GitHub
**adds** after we last looked. A granted permission with no source behind it is a claim nobody checks
(the installed App holds two such today); a new permission nobody classified is a blind spot that grows
without anyone deciding it should.

So the ledger: every permission GitHub publishes, in exactly one of six states, with a reason. The
catalogue it is held against is machine-readable and pinned; a key GitHub adds fails a test until a
human classifies it. That is "query GitHub every now and then to see whether they added permissions we
should consider", made mechanical and fail-closed.

Read-only, always. Every state that carries a level carries `read`. The App observes; it does not act.

## Goals

| # | Goal | Description |
| --- | --- | --- |
| 1. | Complete | Every key in GitHub's catalogue is classified; an unclassified key is a test failure, never a skip. |
| 2. | Consistent | `requested` ⇔ derived from a manifest source. Neither the ledger nor the manifest may claim what the other does not. |
| 3. | Read-only | No entry, in any state, asks for more than `read`. |
| 4. | Reasoned | Every classification carries its why; exploratory and deferred entries name what resolves them. |
| 5. | Drift-aware | The catalogue is refreshed deliberately from GitHub's description and the refresh is a reviewable diff, then a scheduled check notices when it is stale. |

## Requirement Status

| RID | Name | Status | Notes |
| --- | --- | :---: | --- |
| req-github-core-app-permissions-ledger | [The Ledger](#the-ledger) | Implemented | `collectors/github_collector/github_app_permissions.json`; `tests/test_app_permission_ledger.py`; catalogue in the OpenAPI extract |
| req-github-core-app-permissions-recommended | [What To Add, Read-Only, And Why](#what-to-add-read-only-and-why) | Proposed | 20 recommended reads in two tiers; each enters the manifest only with its consuming source |
| req-github-core-app-permissions-drift | [Noticing New Permissions](#noticing-new-permissions) | Proposed | scheduled `refresh_openapi_extract.py --check`; a stale extract opens an issue, never a silent regenerate |

## Requirements

### The Ledger
----
RID: `req-github-core-app-permissions-ledger`
Status: `Implemented`

`github_app_permissions.json` classifies every key of GitHub's App-permission catalogue.

#### Implementation

**Catalogue.** `scripts/refresh_openapi_extract.py` extracts `components.schemas.app-permissions`
(key → allowed levels, description) into `github_openapi_extract.json` under `app_permissions`, pinned
to the same upstream commit as the REST paths. The refresh is a maintainer's act that rides a PR (the
extract's own rule); the catalogue is never fetched in a test.

**States** (exactly one per key):

| State | Meaning | Carries |
| --- | --- | --- |
| `requested` | Derived from a manifest source — the ONLY way into the App's manifest. | `level: read`, `sources: [...]` naming the manifest sources that need it |
| `exploratory` | Granted on the installed App without a manifest source (observed: `members`, `organization_personal_access_tokens`). Must gain a source or be dropped. | `level: read`, `until` naming the resolver |
| `recommended` | Read we should hold; enters the manifest when its consuming source lands. | `level: read` |
| `deferred` | A real need behind a feature not yet on the fence. | `level: read`, `until` |
| `declined` | Not what this product observes; granting widens a leaked key's blast radius for nothing. | reason only |
| `not_applicable` | Write-only, user-to-server, or enterprise surfaces an organisation-observing installation never uses. | reason only |

**The catalogue is incomplete — two sources, not one.** GitHub's OpenAPI schema omits keys its
App-settings UI exposes (*observed* 2026-09-02: `repository_advisories`, present in the UI and on the
App, absent from `app-permissions`). So the ledger has two sources of truth: the pinned catalogue
(offline, tested) and the **live App's own requested set** (`GET /app` with the App JWT — the
`verify_app` skill prints the diff: unclassified keys, keys the ledger says not to ask, keys in the
ask not on the App, and any write level). A key known only from the App carries `catalogue_absent`
with its evidence.

**Invariants the test enforces:** every catalogue key is classified (fail closed on novelty); every
ledger key exists in the catalogue or carries `catalogue_absent` evidence (no decisions about nothing); every entry has a reason; levelled
states are `read` and GitHub offers `read` for that key; `requested` ⇔ the skill's `derive_permissions`
over the manifest (loaded from the skill so there is one derivation of manifest keys); requested
entries cite real manifest sources.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-app-permissions-ledger-1 | Unclassified Fails | Implemented | A key present in the catalogue and absent from the ledger fails the suite naming the key. | The novelty check. |
| req-github-core-app-permissions-ledger-2 | No Decisions About Nothing | Implemented | A ledger key absent from the catalogue fails unless it carries `catalogue_absent` evidence; a key in the catalogue may not carry the marker. | The OpenAPI schema is incomplete; the live App is the second source. |
| req-github-core-app-permissions-ledger-6 | The Live App Is Diffed | Implemented | `verify_app` prints the App's requested permissions against the ledger: write levels, unclassified keys, keys the ledger declined, keys in the ask not yet on the App. | Observed 2026-09-02: 24 on the App, 0 write, 0 unclassified after `repository_advisories` was added. |
| req-github-core-app-permissions-ledger-3 | Well-Formed, Read-Only | Implemented | Every entry has a known state and a reason; levelled entries are `read` and GitHub offers `read`; exploratory/deferred name `until`. | |
| req-github-core-app-permissions-ledger-4 | Manifest ⇔ Ledger | Implemented | The set the skill derives from the manifest equals the ledger's `requested` set, and derives only `read`. | One derivation, reused. |
| req-github-core-app-permissions-ledger-5 | Requested Cites Sources | Implemented | Every `requested` entry names existing manifest sources. | |

---
### What To Add, Read-Only, And Why
----
RID: `req-github-core-app-permissions-recommended`
Status: `Proposed`

Twenty-three reads are recommended, in two tiers. **None enters the manifest by being recommended**: each
becomes `requested` only when a manifest source consumes it, so the App never holds a permission the
collector does not exercise. The full rationale per key is the ledger's `why`; this is the shape.

**Tier A — the machinery view's outputs and the gate.** `packages` and `organization_packages`
(the outputs column, #31 — decided 2026-09-02); `checks` and `statuses` (what the gate required and
what answered, including the older status API third parties still post); `pull_requests` and
`merge_queues` (the gate's subject and why-isn't-this-merging); `deployments` and `environments`
(what shipped where; the environment fields held as null for want of a transport,
`req-github-core-environments-3`); `attestations` (the `attested` property on
`BUILDS_PACKAGE_VERSION`, whose absence is the finding).

**Tier B — the security axis.** `security_events` (code-scanning alerts: the CodeQL dynamic
workflow's output) and `secret_scanning_alerts` (secret-in-code detection) — both **sensitive reads**
that the App's review table must name as such; `repository_hooks` and `organization_hooks` (webhooks:
third parties past the event horizon, and a hook to the wrong host is a finding);
`repository_custom_properties` and `custom_properties_for_organizations` (rulesets target by property —
without the values, which rulesets apply cannot be resolved; the organisation key is the one the UI's
'Custom properties' control grants, observed 2026-09-02 — and `organization_custom_properties`, the definitions, which explain a
property a repository has not set: 'unset' versus 'no such property'); `organization_custom_roles` and
`organization_custom_org_roles` (bypass actors are role ids — the #11 probe's `RepositoryRole 5` —
resolve them to names); `organization_self_hosted_runners`; `organization_events` (below Enterprise
there is no audit log; the activity stream is the nearest "what changed"); `organization_plan` (the
tier decides which surfaces can exist: the difference between *none* and *not observable on this plan*);
`vulnerability_alerts` (Dependabot alerts — github_core's to request, decided 2026-09-02: security
incidents are processed here, not held until a supply-chain product exists).

**A catalogue key the UI does not expose.** `organization_packages` is in GitHub's schema but
(observed 2026-09-02) has no control in the App-settings UI; repository `packages: read` on an
all-repositories installation reaches packages linked to a repository, and an unlinked organisation
package stays *not observable* until GitHub exposes the key. Recorded in the ledger, rendered as such.

**Deferred, named:** secret **names** (`secrets`, `organization_secrets`, `dependabot_secrets` — never
values; they resolve `${{ secrets.X }}` references and read as sensitive, so they wait for the
`REFERENCES_SECRET` edge and enter with the names-only fact stated); `organization_personal_access_token_requests`;
`artifact_metadata`, `code_quality` (new surfaces to understand
before asking); `pages`; `issues`.

**Blast radius, stated once.** Every read widens what a leaked App key exposes. The reads above that
change the character of a leak are the alert surfaces (`security_events`, `secret_scanning_alerts`)
and secret names; the rest expose configuration an organisation member can already see. Two mitigations
stand regardless: installation tokens live an hour, and uninstalling the App revokes everything at once
(`create-github-app` skill, Rotation and revocation).

**Measured after acceptance (2026-09-02, installation token with 29 read permissions).** Every newly
granted surface answered: code-scanning alerts 200 (1 open on tap), Dependabot alerts 200 (1), secret-scanning
alerts 200 (0), repository hooks 200 (1), organisation events 200, rule suites 200 (1 — the bypass-event
surface), artifacts 200 (3,886 on tap). The one closed door: `GET /orgs/{org}/packages?package_type=container`
answers **400 "Invalid argument"** to the App even with `packages: read` — container-package *enumeration* is
closed to GitHub Apps, while per-package detail by name (`/packages/container/{name}/versions`) answers 200. So
packages are collected by *known name*, and enumeration is recorded NOT OBSERVABLE, never "no packages"
(github-core#50). A deployment-branch-policies call on an environment with none configured answers **404**,
which the collector must read as "no policy", distinct from a refusal.

**Operator step.** A permission added to an existing App is not granted until an organisation owner
accepts it on the installation (skill failure mode: *a probe returns 403 on a permission the table
shows as granted*). GitHub offers no API for either step.

**First flip of the sensitive-read tier (2026-09-09, github-core#89).** `security_events` entered the
manifest with the sources `code_scanning_alerts` (`GET /repos/{owner}/{repo}/code-scanning/alerts`) and
`code_scanning_analyses` (`GET /repos/{owner}/{repo}/code-scanning/analyses`) — `req-github-core-code-scanning`
— and its ledger entry moved `recommended` → `requested` in the same change, citing exactly those two
sources: the rule in `recommended-1`, exercised for the first time on a Tier B key. The installed
`git-serious-exploratory` App already held it as an exploratory grant (33 read permissions on
2026-09-09), so nothing was re-accepted here; an adopter's App minted from the manifest gains *Code
scanning alerts: Read-only* from the declaration alone, and the rendered review table must mark it
sensitive (`recommended-2`). Measured the same day: 9 open alerts on `unified-systems-com/tap`, 100
analyses in the most recent page. `secret_scanning_alerts` stays `recommended` until its source lands.

**Second flip of the sensitive-read tier (2026-10-13, github-core#68).** `vulnerability_alerts` moved `recommended` →
`requested` with the source `dependabot_alerts` (`GET /repos/{owner}/{repo}/dependabot/alerts`,
`req-github-core-dependabot-alerts`), citing exactly that source. The installed `git-serious-exploratory` App already
held it (`vulnerability_alerts: read`, read from its installation 2026-10-13: 200 with 48 alerts on
`unified-systems-com/tap`), so nothing was re-accepted; an adopter's App minted from the manifest gains *Dependabot
alerts: Read-only* from the declaration alone, and the review table marks it sensitive. The same OpenAPI refresh
surfaced a new key, `organization_external_properties_for_repos`, classified `deferred` so the ledger stays complete.

**Operator-side observation (2026-09-09, Issue# 88 - github-core).** GitHub's App-settings form offers
permission controls that neither the OpenAPI `app-permissions` schema nor the ledger names — *Agent
secrets* and *Codespaces secrets* among them. The same incompleteness the `repository_advisories`
finding above established, seen from the form instead of the live App. Until the live-App diff
(`ledger-6`) or a catalogue refresh surfaces their keys, they are classified by the form label alone as
secret-*name* surfaces and fall under the deferred secret-names line; a key GitHub exposes for them
enters the ledger with `catalogue_absent` evidence, never silently.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-app-permissions-recommended-1 | Recommended Enters Only With A Source | Proposed | A recommended permission moves to `requested` in the same change that adds the manifest source consuming it, never before. | Enforced by ledger-4 once the source lands. First exercised 2026-09-09: `security_events` with `code_scanning_alerts` / `code_scanning_analyses` (github-core#89). |
| req-github-core-app-permissions-recommended-2 | Sensitive Reads Are Named | Proposed | The App's rendered review table marks `security_events`, `secret_scanning_alerts` and any secret-names permission as sensitive with the reason. | The create-github-app skill's table. |

---
### Noticing New Permissions
----
RID: `req-github-core-app-permissions-drift`
Status: `Proposed`

GitHub adds permissions without telling installers. The catalogue in the extract is pinned; a
scheduled check notices when it is stale.

#### Implementation

Two sources drift independently. **The catalogue:** a scheduled workflow in this repository
(weekly; the `nightly-plugins` shape) runs `scripts/refresh_openapi_extract.py --check`. **The App:**
`verify_app` is run after any App-side change and at boot preflight time (it needs the credential, so
it cannot be a CI job on this repository); its ledger diff is the check. On exit 1 it opens (or updates) one issue titled from
the upstream commit, carrying the diff of the `app_permissions` section — never a regenerate, never a
PR that changes expectations unreviewed. A maintainer refreshes the extract, classifies the new keys
in the ledger (ledger-1 forces this), and the PR that lands both closes the issue. The same check
already covers REST-path and GraphQL drift, so the catalogue rides an existing discipline rather than
a new one.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-app-permissions-drift-1 | Stale Catalogue Opens An Issue | Proposed | When GitHub's description adds or removes an App-permission key, the scheduled check opens an issue within a week naming the keys; the extract is unchanged until a maintainer refreshes it. | Fail closed on novelty, on a timer. |
| req-github-core-app-permissions-drift-2 | Refresh Is A Reviewed Diff | Proposed | The extract changes only through a PR produced by the refresh script; no job writes it. | The extract's own rule, restated for the catalogue. |

## Out Of Scope

- Write permissions of any kind. The App observes.
- Automating the App-side or installation-side permission change (GitHub offers no API).
