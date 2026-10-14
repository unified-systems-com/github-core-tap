# Dependabot Alert

## Blurb

One advisory that affects one package a repository's manifest names, as GitHub's Dependabot stores it: the package and manifest, the advisory and its severity, the vulnerable range, the first patched version, and the lifecycle GitHub keeps for it (`open`, `fixed`, `dismissed` with a reason, `auto_dismissed`). The source-specific DETAIL behind a generic `compliance_finding`, never the finding itself.

## Purpose

GitHub already computes one class of finding for us: for every manifest and lockfile in a repository it matches the dependencies against the advisory database and keeps an alert per match, with one lifecycle regardless of ecosystem. That is the supply-chain half of *is this pipeline secure* and the raw material of a vulnerability disclosure report: what is vulnerable, how badly, since when, whether a fix exists, and whether it has been fixed.

The ruling of 2026-09-09 (github-core#89) shapes it the same way it shapes a code-scanning alert: **one generic finding type, source-specific data behind an edge.** github_core's collector MINTS one `compliance_core__compliance_finding` per alert; this node holds what that generic shape cannot — severity, CVSS, advisory ids, package, manifest, range and patched version, dismissal. A view that lists findings across scanners reads the generic node; a view that needs the GHSA id crosses [`DETAILS_FINDING`](DETAILS_FINDING.md) to here.

## Goals

- Land every alert GitHub reports for a repository in scope, in every lifecycle state, so "no open alerts" is only ever read beside "N fixed, M dismissed".
- Carry the advisory's own words and grading — GHSA and CVE ids, summary, severity, CVSS vector and score, CWEs — without normalising them into a vocabulary GitHub did not use.
- Be the detail node behind exactly one `compliance_finding`, so findings from any source sit in one list and this node is reached from it, never the other way round.
- Keep the manifest path and package name precise enough to place the finding on a collected workflow file or a used action when they are one.

## Identity

Natural key: **`<owner/repo>#<number>`** — the repository plus GitHub's alert number. Entity id is `uuid5(ns, "github_core__dependabot_alert:<owner/repo>#<number>")` under `GITHUB_CORE_NAMESPACE` (`collectors/github_collector/identity.py`).

The number is GitHub's own identity for an alert within a repository: it is in the URL, it is what a dismissal names, and it is stable across the alert's whole lifecycle. It is NOT the advisory: the same GHSA fires as one alert per affected manifest. The paired `compliance_finding` is found again by the key compliance_core declares — `source` = `github_core`, `source_key` = **`<owner/repo>#dependabot#<number>`** — so a code-scanning alert and a Dependabot alert with the same number never collide.

## Boundaries

- **Not the finding.** The finding is `compliance_core__compliance_finding`; this node is its detail. Asset placement (`CARRIES_COMPLIANCE_FINDING` from the repository, from the workflow whose path is the alert's manifest, and from the action whose path is the alert's package) hangs off the finding, not off this node. Nothing in TAP should point at this node except `DETAILS_FINDING`.
- **Not the advisory.** `ghsa_id`, `cve_id`, `advisory_summary`, `severity` and the CVSS pair are copied onto the alert because GitHub returns them inline; an advisory node earns its place only when something needs to point at it, and nothing does yet.
- **Not the dependency.** The package is a name, an ecosystem and a manifest on the alert. The identity of the vulnerable package may later be a supply-chain purl; the alert is a GitHub fact on a GitHub repository.
- **Not coverage.** An absent alert is evidence only when the repository's `dependabot_observability` is `observed`. GitHub raises Actions alerts only for actions referenced by a version tag, never SHA pins, so a SHA-pinned action with no alert is "not covered by Dependabot", never clean.
- **Not code scanning, not secret scanning.** Each is its own detail node behind its own finding.
- **Not the true lifecycle of the finding.** `compliance_finding.status` collapses `fixed`, `dismissed` and `auto_dismissed` into `resolved`; the distinction lives here in `state`, `dismissed_reason`, `fixed_at`.

## Neutrality

**Vendor-specific.** The alert is GitHub's object — its lifecycle enum, its dismissal reasons, its ecosystem names, its severity scale. The neutral *finding* is compliance_core's, and the neutral vulnerability record is a CycloneDX VEX/VDR entry or an OSV record; the fields chosen here keep OSV's and GitHub's advisory names (`ghsa_id`, `cve_id`, `cwes`, `vulnerable_version_range`, `first_patched_version`) so that extraction of a neutral detail node, when a second source needs it, is a rename and not a re-model.

## Observability

Populated from **`GET /repos/{owner}/{repo}/dependabot/alerts`** with `state=open,fixed,dismissed,auto_dismissed` asked for by name and `per_page=100`, at **`repository:vulnerability_alerts:read`** — GitHub's *Dependabot alerts* permission, a sensitive read (`spec-github-core-app-permissions.md`). The endpoint is cursor-paginated: it rejects a `page` parameter with a 400, so the walk follows the `Link` header to its end. Measured 2026-10-13 with the installed App token (`git-serious-exploratory`): `unified-systems-com/tap` answered 200 with **48 alerts — 46 fixed, 2 open — all `pip`**, in one page. The GitHub Actions ecosystem value has still not been observed; nothing is filtered on it and the ecosystems seen are recorded on the run's information record.

**Four states on the repository**, `github_repository.dependabot_observability`:

- `observed` — the listing answered 200 and the walk reached the end of the `Link` chain; zero alerts is then a fact.
- `unobservable` — 403/404 not explained by the feature being off: the credential lacks `vulnerability_alerts: read`, or the permission was added to the App after installation and an organisation owner has not yet accepted it. No row means nothing; the run warns per repository (`DEPENDABOT_UNOBSERVABLE`).
- `not_enabled` — GitHub answered 403 `Dependabot alerts are disabled for this repository`. A fact about the repository's configuration, not about the credential (`DEPENDABOT_NOT_ENABLED`).
- `""` — never asked.

A walk that stopped early at the page cap lands the alerts it read, records `DEPENDABOT_TRUNCATED` with the count, and leaves the repository `unobservable`: `observed` is only ever a complete walk. The same holds for an item that came back with no alert number and could not be keyed: it is counted in `DEPENDABOT_UNREADABLE` and the repository is `unobservable`, never `observed` over a dropped alert.

**Absence shape** (github-core#14): **Shape E, credential-shaped**, with the added `not_enabled` state, for the reason the code-scanning alert gives. Reconciliation shape C: an immutable event — GitHub answers a fixed alert forever and only `state` and the `*_at` fields change.

## Authoritative Source

- **Source:** GitHub REST API — Dependabot alerts: "List Dependabot alerts for a repository" (`GET /repos/{owner}/{repo}/dependabot/alerts`), the `dependabot-alert` schema (`number`, `state`, `dependency {package {ecosystem, name}, manifest_path, scope, relationship}`, `security_advisory {ghsa_id, cve_id, summary, description, severity, cvss, cvss_severities, cwes, ...}`, `security_vulnerability {package, severity, vulnerable_version_range, first_patched_version}`, `url`, `html_url`, `created_at`, `updated_at`, `dismissed_at`, `dismissed_by`, `dismissed_reason`, `dismissed_comment`, `fixed_at`, `auto_dismissed_at`), https://docs.github.com/en/rest/dependabot/alerts
- **Version:** REST API version `2022-11-28`, as pinned in `github_openapi_extract.json`
- **Retrieved:** 2026-10-13 (the 48-alert population, the `state` filter and the pagination behaviour read from the live endpoint, not from documentation)

## Prior Art

- Operator ruling, session double-tap-git-serious (2026-09-09; github-core#89) — one generic finding type (compliance_core's), source-specific data behind an edge; the amended `req-github-core-dependabot-alerts` applies it here.
- [`code_scanning_alert`](code_scanning_alert.md) — the first detail node on this shape, whose collector this one follows.
- `git-serious-tap/docs/doc-git-serious-cicd-security-prior-art.md` §2.11 (2026-09-03) — the CONSUME verdict for GitHub-computed findings.
- OSV schema 1.6 (2024) and OWASP CycloneDX VDR (CycloneDX 1.6, 2024-04) — the advisory-identifier, affected-range and fixed-version vocabulary that `ghsa_id`, `cve_id`, `vulnerable_version_range` and `first_patched_version` keep.
- FIRST CVSS v3.1 specification (2019) — the vector and score `cvss_vector` and `cvss_score` carry; a v4-only advisory reports no v3 vector and so lands with a null score.

## Fields

- `full_name` — `owner/repo`; half the natural key.
- `number` — GitHub's alert number within the repository; the other half.
- `state` — GitHub's lifecycle: `open`, `fixed`, `dismissed`, `auto_dismissed`; `""` when the payload carried none. The paired finding's `status` is derived from it (`open` → `open`, anything else → `resolved`).
- `created_at`, `updated_at` — GitHub's timestamps for the alert record. `created_at` is when Dependabot opened the alert: the clock a remediation deadline runs from.
- `fixed_at` — when GitHub saw the dependency no longer vulnerable; null = unobserved or not fixed, and `state` says which.
- `dismissed_at`, `auto_dismissed_at` — when a person, or GitHub's rules, closed it; null = unobserved or never.
- `dismissed_reason` — GitHub's closed set as reported (`fix_started`, `inaccurate`, `no_bandwidth`, `not_used`, `tolerable_risk`); `""` when not dismissed.
- `dismissed_comment` — the free-text justification, verbatim; `""` when none.
- `dismissed_by_login` — the login GitHub recorded for the dismissal; `""` when not dismissed.
- `html_url` — the alert page on GitHub.
- `ecosystem` — GitHub's ecosystem word as given (`pip`, `npm`, `rubygems`, ...). Never filtered on.
- `package_name` — the package the manifest names; the join to a `github_action` when it is an action path.
- `manifest_path` — the manifest or lockfile it was found in (`uv.lock`); the join to a `github_workflow` when it is one.
- `dependency_scope` — `runtime` or `development`; `""` when GitHub gave none.
- `relationship` — `direct`, `transitive` or `unknown`; `""` when GitHub gave none.
- `ghsa_id`, `cve_id` — the advisory's identifiers; `cve_id` is `""` when the advisory has none.
- `advisory_summary` — the advisory's one-line summary; becomes the paired finding's `summary`.
- `advisory_description` — the advisory's full text, verbatim.
- `severity` — GitHub's advisory severity: `low`, `medium`, `high`, `critical`; `""` when absent. Not ours.
- `cvss_score`, `cvss_vector` — the CVSS v3 pair when the advisory carries one (else the legacy `cvss` block); null and `""` otherwise. A 0.0 with no vector is the absence of a score, not a score.
- `cwes` — the advisory's CWE identifiers (`CWE-208`).
- `vulnerable_version_range` — the affected range (`>= 3.0.0, < 4.0.0`), in the ecosystem's own syntax.
- `first_patched_version` — the first version that fixes it; `""` when no patched version exists.
- `configuration` — JSONB holding the raw alert as returned, so a field GitHub adds is on the grid before it is promoted to a column.
- `tags` — TAP's tag map.
