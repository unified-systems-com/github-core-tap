# REQUIRES_CHECK

## Blurb

A ruleset requires a status-check context to pass before a matching ref can move — the gate, as an edge to the thing it waits for.

## Purpose

`github_ruleset.rules` holds the requirement as JSON; this edge makes it traversable, so a ruleset can be walked to its required contexts and from there — along [`PRODUCES_CHECK`](PRODUCES_CHECK.md) — to the workflows that satisfy them. Its properties are the parts of the requirement that change what the gate means: whether *any* source may satisfy it or only a named integration, whether the branch must be current, and whether the rule is skipped on creation.

## Goals

- Turn the required-check rule into structure with fan-in on the context.
- Carry the qualifiers that make a requirement strong or weak, and nothing the ruleset node already says.
- Never appear as an absence when the credential could not read the requirement.

## Identity

Edge id is `uuid5(ns, "edge:REQUIRES_CHECK__github_core:<ruleset id>:<check id>")`. One ruleset names a context once.

## Boundaries

Carries `integration_id`, `strict` and `do_not_enforce_on_create`, and **not** the corpus's `enforcement`: enforcement (`active` / `evaluate` / `disabled`) is a field on the ruleset node, and a copy here would be a second derivation that disagrees the day a ruleset is switched to evaluate mode.

Not covered:

- **Whether the check actually passed on a given commit.** That is a check-run, an execution-side object not collected; this edge is the declaration.
- **Which rulesets are *active*.** Read the source node's `enforcement`; the edge exists for evaluate-mode rulesets too, because the requirement is declared even when it does not yet block.

## Neutrality

**Vendor-specific**, with its endpoints.

## Observability

Derived from the REST ruleset detail at **`repository:administration:read`** (the `rulesets` source), from `rules[].parameters` on a `required_status_checks` rule. Emitted once per ruleset per run, in the post-pass, after every repository in scope is walked.

**When the detail is refused there is no edge, and that is not the same as no requirement.** The GraphQL fallback yields the rule type with no parameters; the collector counts the ruleset as "required contexts not observable" (`REQUIRED_CHECKS_UNOBSERVABLE`, and the `STATUS_CHECKS` summary) and mints nothing. A view must read that count, not the edge set, before saying a ruleset requires no checks.

**Absence shape** (github-core#14): **Shape E, credential-shaped** — absence is never proof, at any completeness.

## Authoritative Source

- **Source:** GitHub REST API — Repository Rulesets, "Get a repository ruleset"; the `required_status_checks` rule parameters (`required_status_checks[].context`, `[].integration_id`, `strict_required_status_checks_policy`, `do_not_enforce_on_create`)
- **Version:** REST API version `2022-11-28`; OpenAPI description commit pinned in `github_openapi_extract.json`
- **Retrieved:** 2026-09-02

## Prior Art

- `specs/spec-github-core-vocabulary.md` (2026-08-27) — `REQUIRES_CHECK` `{enforcement}`; the property is replaced here by the rule's own qualifiers, and the reason is recorded.
- unified-systems-com/github-core-tap#61 (2026-09-02) — the bake issue.
- [`PROTECTS`](../edges/PROTECTS.edge.json) — the ruleset's other outbound edge; together they say what is protected and what must pass.

## Endpoints

- **Source:** `github_core__github_ruleset` — the gate.
- **Target:** `github_core__status_check` — the required context.
- **Dimensions:** `git.host`, `github.surface: rules`, `github.observation: declaration`, plus `github.owner` from the ruleset's own dimensions; no `github.repo`, because an organization requirement spans repositories.
