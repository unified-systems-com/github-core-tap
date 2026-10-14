# Details Finding

## Blurb

The source-specific detail node points at the generic finding it details — one per finding, from the detail to the generic, so the finding stays source-agnostic and the source's data is one hop away.

## Purpose

The ruling of 2026-09-09 (github-core#89) splits every GitHub-sourced finding into two nodes: a `compliance_core__compliance_finding` that any view of findings can list without knowing where it came from, and a source-specific detail node (`code_scanning_alert` first, then `dependabot_alert`; a secret-scanning detail later) that carries what the generic shape cannot. This edge is the join between them. It is what lets a finding list stay one query across CodeQL, Sonar, Dependabot and zizmor while a rule that needs `security_severity_level` or `dismissed_reason` still finds it in one traversal.

The direction is detail → finding, not finding → detail, because the finding must not know its sources: compliance_core is a substrate with `depends_on = []` and its edge vocabulary cannot name a github_core type as a target. A github_core-owned edge whose *source* is github_core's and whose *target* is compliance_core's respects the dependency direction; the reverse would not.

## Goals

- Reach a finding's source data in one hop without the finding carrying a source-specific field.
- Keep exactly one detail per finding, so "what is behind this finding" never fans out.
- Leave the door open for the compliance_core extension that would put severity / rule / location ON the finding (the open design named in `req-github-core-code-scanning`): if it lands, this edge still holds the full raw detail and nothing breaks.

## Identity

One edge per (source, target) pair, id minted by `identity.edge_id`; property-free. The pair is 1:1 by construction — the detail and the finding are minted from the same alert in the same batch and their natural keys share the alert number — so there is nothing for a property to disambiguate.

## Boundaries

- **Not the asset link.** Where the finding sits — which repository, which workflow file — is compliance_core's `CARRIES_COMPLIANCE_FINDING` from the asset to the finding. This edge never carries placement.
- **Not evidence.** compliance_core's `CITES_COMPLIANCE_EVIDENCE` (finding → evidence) is for artefacts that support or refute a finding; the detail node is the finding's own body, not evidence about it.
- **Not `REPORTED_BY`.** No edge from an analysis to a finding is drawn: GitHub does not tie alerts to analysis ids, and this edge is not the place to fake it.
- **Not a wildcard yet.** v0 registers `code_scanning_alert` and `dependabot_alert` as the sources; the secret-scanning detail is added to the source list when its node is built, not pre-declared.

## Neutrality

**GitHub-owned edge onto a neutral target.** The finding is compliance_core's and regime-agnostic; the detail is GitHub's. The relationship — a generic finding has a source-specific body — is what OCSF's per-class finding bodies and SARIF's `result` → `properties` bag express, and it would hold for a GitLab vulnerability record with a different source type.

## Observability

Emitted by the collector from the same alert read that minted both endpoints (`repository:security_events:read`); present whenever the alert landed, because both ends come from one payload and neither can be observed without the other. Absent only where the alert surface is `unobservable`, `not_enabled` or never asked on the repository — and then the finding is absent too, so an orphaned finding with no detail cannot arise from this collector.

## Authoritative Source

- **Source:** the collector's own emission over `GET /repos/{owner}/{repo}/code-scanning/alerts` (`collectors/github_collector/collector.py`), pairing each alert with the `compliance_finding` it mints; `tap-plugin-compliance-core` `CARRIES_COMPLIANCE_FINDING.edge.json` and `compliance_finding.py` for the target's shape
- **Version:** compliance_core tag v0.3.0 (the edge rename release; the node shape is unchanged since v0.2.2); REST API version `2022-11-28` as pinned in `github_openapi_extract.json`
- **Retrieved:** 2026-09-09

## Prior Art

- Operator ruling, session double-tap-git-serious (2026-09-09; github-core#89) — one generic finding type, source-specific data behind an edge; the edge is this one.
- `tap-plugin-compliance-core/specs/spec-compliance-core-v0.md` (tag v0.2.2, read 2026-09-09) — "Dependency Direction": the substrate depends on nothing above core, consumers depend downward; why this edge is github_core's and points at compliance_core's node.
- `zizmor-tap/specs/spec-zizmor-v0.md` `req-zizmor-finding` (2026-09-02) — the scanner-shaped finding recorded as "a compliance-level node in disguise"; the shape this edge lets a scanner keep without duplicating the generic node.
- OCSF schema v1.3.0 (2024) — every finding class shares `finding_info` and carries a class-specific body; the same generic/specific split, expressed here as two nodes and an edge.
- OASIS SARIF 2.1.0 (2020-03-27) — `result.properties`: the standard's own place for tool-specific detail beside a common result shape.

## Endpoints

- **Source:** `github_core__code_scanning_alert` and `github_core__dependabot_alert` (v0; a secret-scanning detail joins the source list when built)
- **Target:** `compliance_core__compliance_finding`
- **Dimensions:** `git.host`, `github.surface: security`, `github.observation: execution` — the alert is a scanner's recorded assertion, an event, not a declared configuration.
- **Properties:** none — 1:1 by construction; the facts are on the two nodes.
