# Collection Scope

## Blurb

One node per collection run: what **this run's credential was allowed to weigh in on** — which repositories the installation token could reach, which credential kinds the envelope held, which installation the App token was minted for, and the account's plan. The fact every absence decision reads before it trusts a missing item.

## Purpose

A collector that did not see something has two very different things to say about it: *it is not there*, or *I could not look*. The grid renders both as an absent node, and a reconciliation pass that tombstones on absence will delete real objects on the strength of a narrowed grant. The tombstone candidate rule (tap#140) is *fan-out from the account, minus observed this run, minus outside the installation's selection* — and the third term is a fact about THIS run's reach, not about the account.

George ruled it a node rather than a field on the run (2026-09-14) for one reason: **an App's grants can be narrowed in a settings page and nothing tells the collector.** The reach is perceived-true-at-a-time, like a runner execution, so it belongs on the operation side where it becomes immutable history. Two consequences fall out for free: "when did we stop being able to see X" is a query over scope nodes ordered by `observed_at`, and a verdict that changes between runs is attributable — the manifest moved (we asked for more), the grant moved (they granted less), or the plan changed — because the node records the version of each input it read.

It is also the seam two other builds land into. The **visibility assessment** (github-core#15) — per entity type, reachable / degraded / unreachable / unknown, derived from the manifest's permission triples crossed with the installation's granted permissions — writes into `visibility`. **Reliability 1b** (github-core#136) writes a per-tier completeness verdict into `tiers`, one patch per tier through the service layer as each tier's Confirm runs. Both fields are emitted EMPTY by the collector with their shape declared and described here, so neither build has to invent the node, and a Gryphon question written today against the declared shape keeps answering when the fields fill.

## Goals

- Land one scope statement per run, BEFORE the walk, in its own batch — so it exists while the run is in progress and a run that dies mid-way leaves the earlier tiers' verdicts on it.
- Carry the `INSTALLATION_SELECTION` record verbatim: one dict, built once, placed on the run record and on this node (derive a fact once).
- Join to the run it is about (`SCOPES_RUN`) and, with an App, to the installation it was derived from (`DERIVED_FROM_INSTALLATION`).
- Record the versions of the three inputs — manifest, installation grant, plan — so a changed verdict has a cause.
- Declare `visibility` and `tiers` as described, empty seams with a closed `reason` vocabulary, so `WHERE s.tiers.T2.reason = "count_mismatch"` is a stable question.

## Identity

Natural key: **the `collection_job` entity id** — `uuid5(ns, "github_core__collection_scope:<job-id>")`, minted by `identity.collection_scope_id(run_id)`.

One scope per run by construction. A re-run is a new job and therefore a new scope; nothing upserts over an earlier run's statement, which is what makes the history readable. The job id is a core (tap_cares) entity id this plugin holds as a string and never imports a model for — the join is the `SCOPES_RUN` edge, and `run_id` is the same value carried as a field so a scope can be found from its run without a traversal.

## Boundaries

Deliberately **not** covered:

- **This node is not the run.** Status, timing, results and self-test live on `collection_job`; scope facts never go there, and run facts never come here.
- **Not what was found.** The scope is the frame, not the picture — which repositories the credential could reach, not which it did read. What was read is the `github_repository` population and, once built, the tier verdicts.
- **Not the visibility assessment itself.** `visibility` is emitted empty; github-core#15 derives the per-type verdict from the manifest × grant cross and writes it here. This node stores, it does not assess.
- **Not the tier verdicts.** `tiers` is emitted empty; reliability 1b's Confirm writes each tier's verdict at the tier's end. The shape is agreed and enforced by the schema; the values are 1b's.
- **Not a PAT's reach.** A fine-grained token's grant is not introspectable through any API, and a classic token's scopes do not establish its effective reach, so `selection.kind` is `unknown` for a PAT and a falsifier treats it as cannot-weigh-in. Reliability 1a's header-exposing gather is where `X-OAuth-Scopes` could earn a classic token an `all`.
- **Not the credential.** `credential_kinds` is `["app"]`, `["pat"]` or both; a token is inspected for its prefix only, and a test asserts its value never lands on the node or in the run record.
- **Not the account's plan as a fact about the account.** `plan` is copied here because it is a scope INPUT (the audit log is Enterprise-only); the account node carries it as configuration under GitHub's own key when it can be read.

## Neutrality

**Neutral in concept, vendor-specific in every input.** Every collector against any source has a reach it should state before it weighs in on absence; the idea of a per-run scope statement belongs in a substrate one day. What is GitHub's is all three inputs: the installation's repository selection, the App permission model the manifest triples are written against, and the plan tiers that gate surfaces like the audit log. When a neutral scope type is extracted, this node's `selection`, `visibility` and `tiers` are the GitHub-shaped detail behind it, exactly as `code_scanning_alert` sits behind `compliance_finding`.

## Observability

Nothing here is read from a new endpoint. The node is DERIVED from reads the run already makes, and it inherits each one's observability:

| Input | Where it comes from | Measured |
| --- | --- | --- |
| `selection` | `GET /installation/repositories` walked to the end and reconciled against `total_count` (github-core#141, PR# 144 - github-core, executed 2026-09-14) | App: 200, ids listed; PAT: not asked — `kind: unknown` |
| `installation_id`, `configuration.installation` | the installation chosen when the App token was minted (`/app/installations`, github-core#141's `app_installation_self` source) | App only; null under a PAT |
| `plan` | `plan.name` on `GET /orgs/{login}` — the same detail the account node's settings block reads, fetched once per run | owner-only key: `public_only` when the credential is not an administrator, `unobservable` on refusal, `not_applicable` for a user account, `no_owner` for a repos-only envelope |
| `configuration.manifest` | the shipped `github_collection_manifest.json` — its `manifest_version` and SHA-256 | always |

Executed 2026-09-15 on a spawned stack (`gc-scope-node`, App credential, owner `unified-systems-com`, job `01a0a2ce-…`): the run landed exactly **one** `github_core__collection_scope` node in a batch of its own before the walk — `plan: team` (`plan_source: observed`), `credential_kinds: [app]`, `installation_id: 157103378`, `selection: {kind: all, count: 26, total_count: 26, complete: true}` — with `SCOPES_RUN` to the run's `collection_job` and, in the main batch, `DERIVED_FROM_INSTALLATION` to that installation; `selection` on the node equalled the run's `INSTALLATION_SELECTION` record (`==`, not resembled). The Gryphon question `MATCH (s:github_core__collection_scope)-[:SCOPES_RUN__github_core]->(j) RETURN s.data.selection, j.entity_id` answered on that grid over the read-only search role (per-model fields are addressed on the `data.` lane, and a RETURN mixes field paths only with field paths — `RETURN s, j` returns the two nodes and the edge instead).

**Three states, every input.** `selection.repository_ids: null` is could-not-look (a PAT, or a refused listing carried with its `status`), never an empty list; `plan: unknown` carries its reason in `configuration.plan_source`; `configuration.installation: null` is no-App, not an empty grant. `visibility` and `tiers` are `{}` until their writers run — an absent key means *not assessed*, never *reachable* or *complete*.

**Absence shape:** one per run, immutable once the run ends except for the two declared seams. A run with no scope node is a run that aborted before establishing one — on secret resolution or App authentication, the two failures that precede it — and the run record says which.

## Authoritative Source

- **Source:** GitHub REST API — Apps: "List repositories accessible to the app installation" (`GET /installation/repositories`), "List installations for the authenticated app" (`GET /app/installations`); Organizations: "Get an organization" (`GET /orgs/{org}`, the `plan` object)
- **Version:** REST API version `2022-11-28`
- **Retrieved:** 2026-09-15 (selection and installation measured by executed call on PR# 144 - github-core, 2026-09-14; the scope node itself proven by a live run on the `gc-scope-node` stack, 2026-09-15)

## Prior Art

- unified-systems-com/github-core-tap#145 (2026-09-14) — the build issue: George's ruling that scope is a node on the operation side, the field table, the two seams.
- unified-systems-com/github-core-tap#141 / PR# 144 - github-core — the `INSTALLATION_SELECTION` record whose shape this node carries verbatim.
- unified-systems-com/github-core-tap#15 — the visibility assessment, which writes `visibility`.
- unified-systems-com/github-core-tap#136 — reliability 1b, which writes `tiers`; the agreed shape and reason vocabulary are enforced by this model's schema.
- unified-systems-com/tap#140 — the repository falsifier that reads this node before trusting an absence.
- `specs/spec-github-core-v0.md` (`req-github-core-app-installations`) — `app_installation`, the grant this scope is derived from, when there is one.
- `tap_cares/specs/spec-tap-cares-collector.md` — `collection_job`, the run this is a statement about, and `CollectorConfig`, which hands the collector its job id.

## Fields

- `run_id` — the `collection_job` entity id this statement is about. Part of identity; held as a string because the job is a core type this plugin does not import.
- `observed_at` — when the scope was established: the start of the run, before anything was weighed in on. What "when did we stop being able to see X" orders by.
- `credential_kinds` — `["app"]`, `["pat"]` or both: what the envelope held. Reporting only; never a dispatch order.
- `installation_id` — GitHub's id of the installation the App token was minted for. Null in a PAT-only run — no installation, not an unknown one.
- `selection` — the `INSTALLATION_SELECTION` record verbatim: `credential`, `kind` (`all` / `selected` / `unknown`), `repository_ids`, `count`, `total_count`, `complete`, plus `token_kind` for a PAT and `status` for a refused listing. `complete` is true only when the walk finished AND GitHub's count matched it.
- `plan` — `enterprise` / `team` / `free` / `unknown`, lower-cased from the organization's `plan.name` when the credential could read it; GitHub's own name kept verbatim when it is another. A scope input, because the audit log is Enterprise-only.
- `visibility` — per entity type, `state` (`reachable` / `degraded` / `unreachable` / `unknown`) and the `failing_permission` triple. Emitted EMPTY; filled by the visibility assessment (github-core#15). An absent key is not-assessed.
- `tiers` — per tier (`T0` … `T5`, also `T3a` / `T3b`): `complete`, `reason` (exactly one of the closed vocabulary — complete · truncated · forbidden · errored · filter_unverified · count_mismatch · prerequisite_incomplete · not_attempted), `prerequisite`, `decided_at`, `count_check` (T2 only), and `surfaces` (T3a / T3b / T4: per surface, per scope). Emitted EMPTY; written once per tier by reliability 1b's Confirm through the service layer. A run that dies mid-T3 legitimately leaves T0–T2 here.
- `configuration` — the versions of the three inputs: `manifest` (`version`, `sha256`, `sources` count — what TAP asked for), `installation` (`app_id`, `permissions`, `repository_selection`, `events`, `suspended` — what the account allowed; null under a PAT), and `plan_source` (why `plan` reads as it does).
- `tags` — TAP's tag map.
