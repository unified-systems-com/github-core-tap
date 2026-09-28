# GitHub Custom Property

## Blurb

A property an organization declares for its repositories — a durable owner, a criticality, a lifecycle — the definition against which each repository's value is read, so that "unset" is a fact and not a blank.

## Purpose

GitHub's own answer to "who owns this repository" is not a built-in field: it is a custom property the organization declares and populates, which is how GitHub gave every one of its own repositories a durable owner (the July 2026 write-up). The value is what a console groups, filters and orders by; the definition is what makes the value legible — its allowed vocabulary, whether it is required, what it means — and what makes a *missing* value an observation. Without the definition on the grid, a repository with no `criticality` and an organization that never declared one look identical.

Rulesets target repositories by custom property (`conditions.repository_property`), so the definitions are also the join a future "which rulesets apply here" question needs. That edge is not drawn yet.

## Goals

- Land every property the organization declares as one node, so the vocabulary is a table and a history rather than a comment in someone's head.
- Let each repository's `custom_properties` map be read against the declarations, so a declared-but-unset value is `null` (observed-unset) and a refused read is `unobservable` — never an empty map that reads as "nothing set".
- Keep the property name exactly as GitHub reports it, because it is the key of every repository's map and the join is by name.

## Identity

Natural key: **`<owner>#<property_name>`**. Entity id is `uuid5(ns, "github_core__github_custom_property:<owner>#<property_name>")`.

Owner-scoped, like [`github_ruleset`](github_ruleset.md): one organization declares the property once and every repository's value is read against that one declaration. The name is the key because it is the only identity GitHub gives a definition — the schema endpoint returns no numeric id — and it is never normalized (hyphens and case preserved), because it is also the key every repository's `custom_properties` map uses. An enterprise-sourced definition inherited by the organization keys under the organization that reports it, which is where its values live; `source_type` says which.

**No edge from the repository.** This node passes the corpus's node test on a different clause than the ruleset does: not fan-in, but an independently-edited declaration with its own history and its own table. An edge from every repository to every definition would carry no information — a repository with any value points at all of them — and putting the value on the edge would store it twice (derive-a-fact-once). The value lives on the repository, where the table column needs it; the join is by name.

## Boundaries

- **Not the value.** The value is a fact about the repository and lives at `github_repository.custom_properties[<property_name>]`, with `custom_properties_observability` beside it. This node carries what the value may be, not what it is.
- **Not a GitHub ownership contract.** `ownership-type`, `criticality` and the rest are one organization's convention over a generic mechanism. The collector lands whatever the organization declares and hard-codes no names.
- **Not access.** A property naming a team grants that team nothing; repository permissions are a separate surface and are not collected here.
- **Not an organization-level property.** GitHub also has custom properties *on organizations* (an enterprise feature, `custom_properties_for_organizations`); those are a different surface and are not collected.
- **Not the ruleset join.** `conditions.repository_property` on a ruleset names properties; resolving which rulesets apply to a repository through them is a follow-on.

## Neutrality

**Vendor-specific.** Other forges have labels or topics; GitLab has no organization-declared typed repository properties. The typed definition with allowed values, a required flag and an editability scope is GitHub's shape.

## Observability

Populated from **`GET /orgs/{org}/properties/schema`** (definitions) and **`GET /orgs/{org}/properties/values`** (every repository's values, paginated) at **`organization:custom_properties:read`** — GitHub's "Custom properties" organization permission, which the product App already holds. Measured 2026-09-08 on `unified-systems-com` with a classic token: five definitions; the values listing reports **every declared property per repository, with `value: null` when unset** (a repository created after the properties were declared came back with five nulls), so the unset state is on the wire and not inferred.

Organizations only: a user account has no schema endpoint, so for one the surface is **skipped** and every repository keeps `custom_properties_observability = ""` — never looked — rather than `unobservable`, which would say a credential was refused when there was nothing to ask. A refusal on an organization is `unobservable` on every collected repository, with no definition nodes minted; the definitions answering while the values refuse lands the definitions and marks the values `unobservable`.

**Absence shape** (github-core#14): **Shape E, credential-shaped** — an empty definition set under a credential that answered is a fact (the organization declares nothing); under a refusal it is not, and the repository's observability field is what says which.

## Authoritative Source

- **Source:** GitHub REST API — Organizations, "Custom properties": "Get all custom properties for an organization" (`GET /orgs/{org}/properties/schema`) and "List custom property values for organization repositories" (`GET /orgs/{org}/properties/values`); GitHub's fine-grained permission reference for the "Custom properties" organization permission
- **Version:** REST API version `2022-11-28`; OpenAPI description commit pinned in `github_openapi_extract.json`
- **Retrieved:** 2026-09-08

## Prior Art

- GitHub Engineering, "How GitHub gave every repository a durable owner" (2026-07) — custom properties (`ownership-type`, `ownership-name`) as the ownership record, validated by an App; the pattern this node exists to read.
- unified-systems-com/git-serious-double-tap#2 (2026-09-08) — the five properties declared on our own organization and the populate-first rule: no property is `required`, because a default silently asserts ownership or importance.
- unified-systems-com/github-core-tap#77 (2026-09-08) — the collection issue: unset, unobservable and observed kept distinct.
- `specs/spec-github-core-app-permissions.md` (2026-09-02) — the ledger's case for the custom-property keys under the security axis.
- [`github_ruleset`](github_ruleset.md) § Observability (2026-08-27) — the three-state ruling this node applies to values.

## Fields

- `owner_login` — the organization that declares the property; half the natural key.
- `property_name` — the name exactly as GitHub reports it, the other half of the key and the key of every repository's `custom_properties` map. Never normalized: a hyphen kept here is a hyphen a query must also write.
- `value_type` — GitHub's own enum: `string`, `single_select`, `multi_select`, `true_false`. Decides the shape of a repository's value (a string, an array, a boolean rendered as a string).
- `required` — whether GitHub requires every repository to carry a value. A required property has a `default_value`, which is exactly the silent assertion a populate-first policy avoids; `false` on every one of ours.
- `default_value` — the value GitHub assigns when `required` and unset; a string, an array for `multi_select`, or null when no default is declared. Null is the honest value for an unrequired property.
- `description` — the organization's own statement of what the property means, carried verbatim so a console can show it as the column's legend.
- `allowed_values` — the closed vocabulary for `single_select` / `multi_select`; empty for the other types. What a repository's value is read against.
- `values_editable_by` — `org_actors` or `org_and_repo_actors`: who may set a value on a repository. Governance, not access.
- `source_type` — `organization` or `enterprise`: where the definition was authored. An enterprise definition is inherited and cannot be edited at the organization.
- `url` — the definition's API URL, for linking out.
- `configuration` — JSONB for definition detail not promoted to a column; carries `require_explicit_values` (whether GitHub refuses a value outside `allowed_values` at write time).
- `tags` — TAP's tag map.
