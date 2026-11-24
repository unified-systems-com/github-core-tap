# Code Scanning Alert

## Blurb

One scanner's assertion about one place in a repository, as GitHub stores it: the rule that fired, the tool that ran it, where it points, and the lifecycle GitHub keeps for it (`open`, `dismissed` with a reason, `fixed`). The source-specific DETAIL behind a generic `compliance_finding`, never the finding itself.

## Purpose

GitHub already aggregates every SARIF-emitting scanner an organisation runs — CodeQL, SonarCloud, Trivy, Grype, zizmor when uploaded — into one alert stream per repository, with one lifecycle and one dismissal record regardless of who found it. That stream is the security axis of *is this pipeline secure*: the finding a gate should have blocked, the dismissal nobody reviewed, the high-severity alert open since the repository was created. Before this node the grid carried the workflows that *produce* these alerts (CodeQL's dynamic workflow, the Trivy and Grype lanes) and nothing they produced.

The ruling of 2026-09-09 (operator, session double-tap-git-serious; github-core#89) shapes it: **one generic finding type, source-specific data behind an edge.** The generic type is compliance_core's existing `compliance_finding` — name, summary, description, `status` open|resolved — and github_core's collector MINTS one per alert. This node holds everything that generic shape cannot: severity, rule, tool, location, dismissal. A view that lists findings across scanners reads the generic node; a view that needs the rule id crosses [`DETAILS_FINDING`](DETAILS_FINDING.md) to here.

## Goals

- Land every alert GitHub reports for a repository in scope, in every lifecycle state, so "no open alerts" is only ever read beside "N fixed, M dismissed".
- Carry the scanner's own words — rule id, rule description, message, severity as the tool graded it — without normalising them into a vocabulary GitHub did not use.
- Be the detail node behind exactly one `compliance_finding`, so findings from any source sit in one list and this node is reached from it, never the other way round.
- Keep the location precise enough to place the finding on a collected workflow file when the path is one.

## Identity

Natural key: **`(repository_github_id, number)`** — the repository's immutable GitHub id plus GitHub's alert number, never `full_name` (github-core#209: a renamed repository would otherwise mint a second, duplicate alert row on the next collection). Entity id resolution reads these two field values directly (`tap_grid.models.find_existing`); the batch-local `Ref` string minted at collection time (`collectors/github_collector/identity.py`) still composes `full_name` for readability but plays no part in cross-run identity.

The number is GitHub's own identity for an alert within a repository: it is in the URL, it is what a dismissal names, and it is stable across the alert's whole lifecycle (an alert that closes as `fixed` and reappears is a new number). It is NOT the rule: the same rule fires at many locations and each is its own alert. Unlike run/job/artifact/cache/analysis ids, GitHub's code scanning API never gives an alert a platform-global id — only repo+number — so the repository's own id has to stand in for the missing half. The paired `compliance_finding` is found again by the key **compliance_core** declares on its own model — `source` = `github_core`, `source_key` = **`<owner/repo>#code_scanning#<number>`** — which this collector writes and core assigns an id against (Issue# 8 - tap-plugin-compliance-core). The source segment is still what keeps a Dependabot or secret-scanning finding on the same repository from colliding with it; that key is compliance_core's, not this model's, and stays `full_name`-keyed until compliance_core has its own reason to change.

## Boundaries

- **Not the finding.** The finding is `compliance_core__compliance_finding`; this node is its detail. Asset placement (`CARRIES_COMPLIANCE_FINDING` from the repository, and from the workflow when the path is a collected workflow file) hangs off the finding, not off this node. Nothing in TAP should point at this node except `DETAILS_FINDING`.
- **Not the analysis.** An alert is not tied to the SARIF upload that produced it: GitHub's alert payload carries `tool` and `most_recent_instance.analysis_key` / `category`, never an analysis id, so [`code_scanning_analysis`](code_scanning_analysis.md) is a separate node and the join between them is loose (tool name + category) and deliberately NOT drawn as an edge.
- **Not the rule.** `rule_id` / `rule_name` / `rule_description` are copied onto the alert because GitHub returns them inline; a `rule` node earns its place only when something needs to point at it (the corpus's node test), and nothing does yet.
- **Not every instance.** GitHub keeps one alert per rule-and-location with a `most_recent_instance`; the other instances (other refs, other analyses) are behind `instances_url` and are not collected.
- **Not Dependabot, not secret scanning.** Each is its own detail node behind its own `compliance_finding` via `DETAILS_FINDING` (the amended `req-github-core-dependabot-alerts`); this node is code scanning only.
- **Not the true lifecycle of the finding.** `compliance_finding.status` collapses `dismissed` and `fixed` into `resolved`; the distinction lives here in `state`, `dismissed_reason`, `fixed_at`.

## Neutrality

**Vendor-specific.** The alert is GitHub's aggregation object — its lifecycle enum, its dismissal reasons (`false positive` / `won't fix` / `used in tests`), its `security_severity_level` scale — even when the finding inside it came from a third-party tool. The neutral shape is the SARIF `result` it was built from, and the neutral *finding* is compliance_core's. GitLab's vulnerability record and Azure DevOps' advanced-security alert carry the same idea; extraction of a neutral detail node waits for a second forge, and the fields chosen here keep SARIF's names (`rule_id`, `message`, `location`, `classifications`) where GitHub kept them so that extraction is a rename, not a re-model.

## Observability

Populated from **`GET /repos/{owner}/{repo}/code-scanning/alerts`** (`state` unfiltered so every lifecycle state lands, `per_page=100`, paginated to the end of the `Link` chain) at **`repository:security_events:read`** — GitHub's *Code scanning alerts* permission, a sensitive read (`spec-github-core-app-permissions.md`, Tier B). Measured 2026-09-09 with the installed App token (`git-serious-exploratory`, installation 157103378, 33 read permissions): `unified-systems-com/tap` answered 200 with **9 open alerts, all SonarCloud** (2 `high`, 7 `medium`; rule ids `pythonsecurity:S6350` ×3, `pythonsecurity:S2083` ×2, `pythonsecurity:S6549`, `Web:S5247`, `githubactions:S6506`, `githubactions:S8544`), 0 CodeQL / Trivy / Grype open. `rule.severity` is `note|warning|error`; `security_severity_level` was set on every Sonar alert and is absent on some CodeQL alerts — an absent level is `""`, never coerced to `low`. A dismissed sample carried `dismissed_reason: "false positive"`, `dismissed_at` 2026-08-31, with `dismissed_by.login` set.

**Four states on the repository**, `github_repository.code_scanning_observability`, because this surface has one more way to be empty than the others:

- `observed` — the listing answered 200; zero alerts is then a fact.
- `unobservable` — 403: the credential lacks `security_events: read`, or the permission was added to the App after installation and an organisation owner has not yet accepted it. No row means nothing; the run warns per repository (`CODE_SCANNING_UNOBSERVABLE`).
- `not_enabled` — GitHub answered that code scanning (or GitHub Advanced Security, on a private repository) is not enabled for the repository. GitHub documents this as a 404 whose body names the product ("no analysis found" / "Advanced Security must be enabled"), distinct from a repository 404. It is a fact about the repository's configuration, not about the credential, and it is the state a public repository with no scanner uploads sits in (`CODE_SCANNING_NOT_ENABLED`).
- `""` — never asked: a repos-only scope, or a run whose sources did not include the surface.

A repository's alert set is only as complete as the walk: a `Link` chain that stopped early records `CODE_SCANNING_ALERTS_TRUNCATED` with the count landed. Each alert also carries `commit_sha` and `ref` from its `most_recent_instance`, so an alert is about a commit the grid may or may not hold; no commit edge is drawn from the alert (the analysis draws one, conditionally).

**Absence shape** (github-core#14): **Shape E, credential-shaped**, with the added `not_enabled` state because GitHub distinguishes *the product is off* from *you may not look*, and collapsing them would let a refused read render as "scanning not turned on".

## Authoritative Source

- **Source:** GitHub REST API — Code scanning: "List code scanning alerts for a repository" (`GET /repos/{owner}/{repo}/code-scanning/alerts`), the `code-scanning-alert-items` schema (`number`, `state`, `created_at`, `updated_at`, `fixed_at`, `dismissed_at`, `dismissed_by`, `dismissed_reason`, `dismissed_comment`, `html_url`, `instances_url`, `rule {id, name, severity, security_severity_level, description, tags}`, `tool {name, version, guid}`, `most_recent_instance {ref, analysis_key, category, environment, state, commit_sha, message, location, classifications}`), https://docs.github.com/en/rest/code-scanning/code-scanning
- **Version:** REST API version `2022-11-28`, as pinned in `github_openapi_extract.json`
- **Retrieved:** 2026-09-09 (the 9-alert population, the severity enums and the dismissal sample all read from the live endpoint with the App credential, not from documentation)

## Prior Art

- Operator ruling, session double-tap-git-serious (2026-09-09; github-core#89) — one generic finding type (compliance_core's), source-specific data behind an edge.
- `tap-plugin-compliance-core/specs/spec-compliance-core-v0.md` (tag v0.2.2, read 2026-09-09; re-read at v0.3.0, where `HAS_COMPLIANCE_FINDING` became `CARRIES_COMPLIANCE_FINDING`) — `compliance_finding` (name / summary / description / status), `CARRIES_COMPLIANCE_FINDING` with a wildcard source, "Regime On The Instance", and the honest note that no collector minted a finding until now.
- `zizmor-tap/specs/spec-zizmor-v0.md` `req-zizmor-finding` (2026-09-02) — "a compliance-level node in disguise": the scanner-shaped finding this ruling resolves by putting the scanner's data behind the generic node instead of beside it.
- OASIS SARIF 2.1.0 (OASIS Standard, 2020-03-27) — `result`, `rule`, `location`, `message`, `partialFingerprints`: the shape every alert here was uploaded in, and the field names kept where GitHub kept them.
- OCSF Vulnerability Finding (class 2002) and Detection Finding (class 2004), OCSF schema v1.3.0 (2024) — the finding-versus-detail split (a `finding_info` common to every finding class, a class-specific body per source) that the ruling mirrors.
- OWASP CycloneDX VDR — Vulnerability Disclosure Report, CycloneDX 1.6 (2024-04) — `vulnerabilities[].analysis.state` (`false_positive`, `not_affected`, `resolved`) as the cross-tool lifecycle vocabulary the dismissal reasons map onto.
- `specs/spec-github-core-vocabulary.md` (2026-08-27) — the node test (does anything need to point at it) that keeps the rule a field and makes the finding the node things point at.
- `git-serious-tap/docs/doc-git-serious-cicd-security-prior-art.md` §2.11 (2026-09-03) — the CONSUME verdict for GitHub-computed findings.

## Fields

- `full_name` — `owner/repo` the alert was raised in; a plain, refreshed-on-observation attribute (github-core#209) — see `repository_github_id` for the identity half.
- `repository_github_id` — the repository's immutable GitHub id; half the natural key (github-core#209). Optional at create time, like `github_repository.github_id`: a row observed with no stable id is a legitimate degraded state, not an error.
- `number` — GitHub's alert number within the repository; the other half of the natural key. Stable for the alert's whole life.
- `state` — GitHub's lifecycle: `open`, `dismissed`, `fixed`; `""` when the payload carried none. The paired finding's `status` is derived from it (`open` → `open`, anything else → `resolved`); this is the field that keeps the distinction.
- `created_at`, `updated_at` — GitHub's timestamps for the alert record.
- `fixed_at` — when GitHub stopped seeing the result in a new analysis; null = unobserved or not fixed, and `state` says which.
- `dismissed_at` — when a person dismissed it; null = unobserved or never dismissed.
- `dismissed_reason` — GitHub's closed set as reported: `false positive`, `won't fix`, `used in tests`; `""` when not dismissed or the reason was not given.
- `dismissed_comment` — the free-text justification, verbatim; `""` when none. The field a review of dismissals reads.
- `dismissed_by_login` — the login GitHub recorded for the dismissal; `""` when not dismissed. A login, not an account edge: the dismisser need not be in scope.
- `html_url` — the alert page on GitHub.
- `rule_id` — the tool's rule identifier as SARIF carried it (`pythonsecurity:S6350`, `py/path-injection`, `CVE-2025-…` for the vulnerability scanners). Tool-scoped: two tools may use the same string for different rules, which is why `tool_name` sits beside it.
- `rule_name` — the tool's short name for the rule; often equal to `rule_id`.
- `rule_severity` — the tool's SARIF level as GitHub reports it: `note`, `warning`, `error`; `""` when absent. This is the *problem* severity, not the security one.
- `security_severity_level` — GitHub's security scale `low`, `medium`, `high`, `critical`; `""` when the tool did not set one (observed on CodeQL alerts). Absent is not `low`.
- `rule_description` — the rule's description as the tool published it; becomes the paired finding's `summary`.
- `rule_tags` — the tool's tags for the rule (`security`, `external/cwe/cwe-022`, …), in the tool's order. Where the CWE lives.
- `tool_name` — the scanner GitHub attributes the alert to (`CodeQL`, `SonarCloud`, `Trivy`, `Grype`); the first half of the paired finding's `name`.
- `tool_version` — the tool version from the SARIF `driver`; `""` when the tool omitted it.
- `tool_guid` — the tool's SARIF GUID; `""` when absent (most tools omit it).
- `analysis_key` — GitHub's `most_recent_instance.analysis_key`: the workflow path and job that uploaded the result (`.github/workflows/codeql.yml:analyze`), or the upload's own key for a non-Actions upload. The loose join to the analysis, and to the producing workflow.
- `category` — GitHub's analysis category (`/language:python`, `trivy-tap-web`, or `""` for a tool that sets none — SonarCloud, measured). Together with `tool_name` the only key GitHub offers between an alert and its analyses.
- `environment` — the matrix environment string GitHub records for the instance; `""` outside a matrix.
- `ref` — the ref the most recent instance was seen on (`refs/heads/main`, `refs/pull/348/merge`). A pull-request merge ref is common and is not a branch on the grid.
- `commit_sha` — the commit the most recent instance was analysed at. A fact on the node, not an edge: the commit may not be on the grid, and an alert is about a place in the code more than about a commit.
- `location` — `{"path", "start_line", "end_line", "start_column", "end_column"}` from the instance's `location`; `path` is what places the finding on a collected workflow file. Columns null when the tool did not report them.
- `message` — the instance's `message.text`, verbatim; with `path:line` it becomes the paired finding's `description`.
- `classifications` — GitHub's list for the location (`source`, `generated`, `test`, `library`); a finding in generated or test code is read differently, and GitHub says which.
- `instances_url` — the API URL for the alert's other instances, kept so a consumer can fetch what this node deliberately does not carry.
- `configuration` — JSONB holding the raw alert as returned, so a field GitHub adds is on the grid before it is promoted to a column.
- `tags` — TAP's tag map.
