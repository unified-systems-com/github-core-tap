# Status Check

## Blurb

A check context a ruleset requires — the name a gate waits for, and the name a workflow job produces. Where the gate and the machinery meet.

## Purpose

A ruleset's `required_status_checks` rule names contexts that must pass before a matching ref can move. A workflow's job, named the same, is what makes one pass. Before this node those two facts lived in different payloads — `github_ruleset.rules[].parameters.required_status_checks[].context` on one side, `workflow_job.name` on the other — and the two questions a gate view exists to answer were string comparisons nobody ran: *which workflow satisfies this gate?* and *which required check has no producer in this repository?* (github-core#61). The corpus lists this as the convergence node between rulesets and workflows, and the `build-github-corpus` ranking scores convergence above leaf count for exactly this reason: a node many things point at unlocks questions; a thin leaf adds rows.

## Goals

- Make "what must pass" and "what runs" meet at one node with fan-in from both sides.
- Let a required Actions context with no declared producer in a repository be visible as structure — a check node with no inbound `PRODUCES_CHECK` from that repository's workflows.
- Keep the producing side honest about being derived from names.

## Identity

Natural key: **`<owner>#<context>`** — the owner login plus the context string exactly as the rule wrote it. Entity id is `uuid5(ns, "github_core__status_check:<owner>#<context>")`.

Owner-scoped, like [`github_ruleset`](github_ruleset.md), and for the same reason: an organization ruleset requires the same context across every repository it protects, and one node with fan-in is the whole point — "which workflows across the org produce `gate`" is the set of inbound `PRODUCES_CHECK` edges on one node. Case is preserved; check names are case-sensitive on GitHub. Which *integration* must produce the check is a property of the requirement, not of the context, and lives on [`REQUIRES_CHECK`](REQUIRES_CHECK.md).

## Boundaries

- **A check nobody requires has no node.** Every job produces a check run; minting one node per job across an estate would drown the convergence in leaves. This node exists because a rule references the context, and `PRODUCES_CHECK` is derived only toward such nodes. "Which checks *could* be required" is therefore not answerable from this type — it is answerable from `workflow_job.name`, where it already lives.
- **Not the check run.** The execution — a check run with a conclusion on a commit — is a Checks-API object with its own id and is not collected. This node is the declared *context*; the run's job (`github_actions_job`) is the execution that carried it.
- **Not a check from an App.** A requirement whose `integration_id` names something other than GitHub Actions (SonarCloud, Codacy) is satisfied by an App's check run, and no workflow produces it. The node exists and the requirement edge exists; no `PRODUCES_CHECK` is derived, and the corpus's `app → status_check` producer is a follow-on once [`app_installation`](../models/app_installation.py) carries the App's numeric id.
- **Reusable-workflow checks.** A job that calls a reusable workflow produces checks named `<caller job name> / <callee job name>`; that composition is not derived here and is named as a gap.

## Neutrality

**Vendor-specific**, as the corpus marks it. Required checks exist elsewhere (GitLab's pipeline-must-succeed, a Jenkins gate), but the *context string* as the join key, the `integration_id` qualifier and the matrix-name expansion are GitHub's.

## Observability

Populated from the **REST ruleset detail** (`GET /repos/{o}/{r}/rulesets/{ruleset_id}`) at **`repository:administration:read`** — the `rulesets` source already in the manifest, so this widens nothing — where each `required_status_checks` rule carries `parameters.required_status_checks[] = {context, integration_id}` plus `strict_required_status_checks_policy` and `do_not_enforce_on_create`. Observed on the fixture organization: `[{"context": "gate", "integration_id": 15368}]`, where `15368` is GitHub Actions itself.

**The type-only fallback is the state that must not read as "none."** The detail endpoint is administration-gated and degrades with a warning; when it is refused, the ruleset's `rules` come from the GraphQL config layer, which returns rule *types* only — a `required_status_checks` rule with no `parameters`. The contexts are then **not observable**: no `status_check` node is minted, the ruleset is counted in the `STATUS_CHECKS` summary as "required contexts could not be read", and the run warns `REQUIRED_CHECKS_UNOBSERVABLE` per ruleset. A gate view reading only nodes would otherwise see a ruleset with no required checks — the most reassuring possible message, produced by a credential that could not look.

The producing side is **derived, and says so**: a GitHub Actions check run is named after the job's display name, so `PRODUCES_CHECK` is drawn from `workflow_job.name` (`exact`) or from the template a matrix job expands (`matrix_template`), only when the requirement admits an Actions-produced check. See [`PRODUCES_CHECK`](PRODUCES_CHECK.md).

**Absence shape** (github-core#14): **Shape D, derived absence** — the node exists while some rule requires the context. Its inbound `REQUIRES_CHECK` is **Shape E, credential-shaped** (never proof on absence); its inbound `PRODUCES_CHECK` is **Shape A, git-provable**, conditional on the node.

## Authoritative Source

- **Source:** GitHub REST API — Repository Rulesets, "Get a repository ruleset" (`GET /repos/{owner}/{repo}/rulesets/{ruleset_id}`), the `required_status_checks` rule and its `parameters`; GitHub Actions documentation on check-run naming (the job's display name; matrix expansion)
- **Version:** REST API version `2022-11-28`; OpenAPI description commit pinned in `github_openapi_extract.json`
- **Retrieved:** 2026-09-02

## Prior Art

- `specs/spec-github-core-vocabulary.md` (2026-08-27) — `status_check`, self tier, 6 sources, "convergence node — required by rulesets, produced by workflows/apps"; `REQUIRES_CHECK` `{enforcement}` and `PRODUCES_CHECK` `{confidence}`.
- unified-systems-com/github-core-tap#61 (2026-09-02) — the bake issue: the payload anchor, the integration id, the type-only fallback, the done-test.
- [`github_ruleset`](github_ruleset.md) § Fields, `rules` — "a gate view that knows a repository requires *some* check but not *which* is not a gate view."
- OpenSSF Scorecard `Branch-Protection` check (as of 2026-09) — an independent implementation that reads required contexts as a gate input.

## Fields

- `owner_login` — the organization or user whose rulesets require the context; half the natural key.
- `context` — the context string exactly as the rule wrote it; the other half, and the name a check run must carry to satisfy the gate.
- `name` — the display name; the context. Not identity.
- `configuration` — reserved; empty.
- `tags` — TAP's tag map.
