# Actions Secret

## Blurb

The **name** of a GitHub Actions secret, and which scope holds it — an organisation, a repository, or one deployment environment. Never a value: GitHub's API cannot return one.

## Purpose

Two questions about CI credentials have no answer on this grid without this node, and both are answered by names alone.

**A reference that resolves to nothing.** A workflow writing `${{ secrets.DEPLOY_KEY }}` where no `DEPLOY_KEY` exists does not fail. GitHub substitutes the empty string, the job runs, and the step does the wrong thing quietly — an empty `Authorization` header, an unsigned artifact, a push that silently no-ops. Measured on this estate 2026-09-10: **36 references across 41 workflows resolve to nothing, 33 of them to a single name** (`TAP_CORE_RO_PAT`), which exists in no organisation, repository or environment scope that the credential could read.

**A credential nothing consumes.** The inverse, and the blast-radius half. A live secret with no reader is exposure with no benefit; it is also the shape a rotation leaves behind.

Both are joins between a name a workflow file types and a name the platform holds. Neither needs a value, which is what makes this the rare credential surface that is safe to put on a graph.

## Goals

- Hold the NAME and the scope, so a `${{ secrets.X }}` reference has something to resolve against.
- Read all three scopes, because resolution against fewer produces confident wrong answers.
- Carry `visibility` on an organisation secret — the blast-radius field, how many repositories one credential reaches.
- Never hold, log, or display a value, and make that a property of the source rather than a rule this code remembers to follow.

## Identity

Natural key: **`<scope>#<owner-or-repo-or-environment>#<NAME>`**. Entity id is `uuid5(ns, "github_core__actions_secret:<scope>#<key>#<NAME>")`, where `<key>` is `owner` for an organisation secret, `owner/repo` for a repository one, and `owner/repo/environment` for an environment one.

Two decisions are load-bearing:

**Scope is in the key.** An organisation `AWS_ROLE` and a repository `AWS_ROLE` are different credentials that happen to share a name. Collapsing them would make an organisation secret appear to live in whichever repository was collected last, and would make a repository override invisible — which is precisely the situation worth seeing.

**The name is upper-cased.** GitHub secret names are **not case-sensitive**: `${{ secrets.harness_pat }}` and `${{ secrets.HARNESS_PAT }}` read the same credential. Two of the nine names referenced on this estate are written lower-case, so a case-sensitive key would mint two nodes for one credential and report a working reference as broken.

## Boundaries

Deliberately **not** covered:

- **The value.** Not withheld by policy — unobtainable. GitHub's secrets API returns `name`, `created_at`, `updated_at` and (organisation only) `visibility`. There is no value field to omit. See Observability.
- **Nothing about reach is left assumed.** An earlier cut declared `selected_repositories_url` out of scope and routed every non-`all` organisation secret to `reach_uncertain`. That boundary was assumed rather than measured: probed 2026-09-11 against a real `selected` secret, the App installation token reads the list fine, so reach is now DERIVED (github-core#107) — `all` reaches everything, `selected` is resolved against its list at one request per such secret per run, and `private` reaches only private and internal repositories, which on an all-public estate is none. `reach_uncertain` survives for what stays undecidable: a repository list that was refused or truncated.
- **Dependabot secrets.** A separate store an Actions workflow never reads, so it can never resolve an Actions reference. Deferred in the permission ledger with that reason.
- **Variables.** `vars.X` is a sibling surface and a different (non-sensitive) object. Not modelled here.
- **What a run actually consumed.** This node and its reference edge are facts about FILES. GitHub publishes no record of which secrets a run read.
- **Who can change it.** Write access to secrets is a permission question the read-only credential cannot answer.

## Neutrality

**Neutral-capable in shape, vendor-specific as built.** Every CI system has named secrets held at a scope and referenced from a pipeline definition. What is GitHub's is the three-scope model, the case-insensitivity, the `visibility` sharing policy, and the empty-string-on-miss substitution that makes an unresolved reference silent rather than fatal.

## Observability

Three endpoints, all **names-only**, executed 2026-09-10 against `unified-systems-com` with the plugin's **App installation token** (`held: ['app']` — no PAT in the envelope):

| Call | Result | Item keys |
| --- | --- | --- |
| `GET /orgs/unified-systems-com/actions/secrets` | 200, `total_count: 2` | `name`, `visibility`, `created_at`, `updated_at` |
| `GET /repos/unified-systems-com/tap/actions/secrets` | 200, `total_count: 3` | `name`, `created_at`, `updated_at` |
| `GET /repos/unified-systems-com/tap/environments/copilot/secrets` | 200, `total_count: 0` | — (observed-empty) |
| `GET /orgs/octocat/actions/secrets` (control) | **404** | — |

**There is no value key in any response.** That is the executed proof behind every names-only claim in this plugin, and it is why this surface is safe where a credential store would not be.

Permissions: repository and environment scope read at `secrets: read`; organisation scope needs `organization_secrets: read`. Both are `requested` in the App-permission ledger, each naming its manifest sources.

**The 404 control matters.** A user account has no organisation-secrets endpoint at all, and answers 404. That is *nothing to ask*, not *refused* — recorded as information, never as a degradation. 401 and 403 are degradations, and the scope then reads as not observed.

**Three states, carried on the workflow.** `github_workflow.tags.secret_refs` holds `referenced`, `unresolved`, `reach_uncertain` and **`scopes_read`**. `unresolved` means the step will receive an empty string at runtime, which covers both a name matching nothing and a secret this repository cannot read — operationally the same failure, and the reason the reach derivation above is part of resolution rather than decoration. A name is unresolved only with respect to the scopes that were enumerated IN FULL — a refused listing and a listing truncated at the page cap both disqualify a scope, and the second is the dangerous one because it returns plausible names and looks like success. The tag is written whenever a workflow BODY was read, including when it names no secret — an empty `referenced` says "read, references none", where an absent tag says "never read". Forty of this estate's 119 workflows carry no body, and collapsing those two states would let a third of the estate read as secret-free.

Observed distribution 2026-09-10: 41 workflows carry the tag, 35 with `scopes_read: [organization, repository, environment]` and 6 with `[organization, repository]` (their repositories declare no environments).

**Absence shape:** a secret is **mutable and deletable**, and the listing is authoritative for its scope at the moment it was read. A name that disappears between runs was deleted or renamed — but only conclude that from a listing that actually answered.

## Authoritative Source

- **Source:** GitHub REST API — Actions Secrets: "List organization secrets" (`GET /orgs/{org}/actions/secrets`), "List repository secrets" (`GET /repos/{owner}/{repo}/actions/secrets`), "List environment secrets" (`GET /repos/{owner}/{repo}/environments/{environment_name}/secrets`)
- **Version:** REST API version `2022-11-28`
- **Retrieved:** 2026-09-10 (all four rows above measured by executed call, not read from documentation)

## Prior Art

- unified-systems-com/github-core-tap#104 (2026-09-10) — the build issue: three scopes, case-insensitivity, the three-states tag, and the named blind spots.
- `specs/spec-github-core-app-permissions.md` — the ledger entries for `secrets` and `organization_secrets`, each moved from `deferred` to `requested` by this work, as the deferred entries said they should be.
- [`github_workflow`](github_workflow.md) — where a reference is typed, and where `tags.secret_refs` records the resolution.
- [`github_environment`](github_environment.md) — the third scope, and one of the three holders on `DEFINES_SECRET`.

## Fields

- `scope` — `organization`, `repository` or `environment`. Which of the three holds this secret; part of identity.
- `owner_login` — the account, on every scope. The one field common to all three.
- `full_name` — `owner/repo` for repository and environment scope; empty on an organisation secret, which belongs to no repository.
- `environment_name` — the environment, on environment scope only; empty otherwise.
- `name` — the secret's name as GitHub returned it. The whole point of the node. Case is preserved here; identity folds it.
- `name_reported` — the spelling GitHub actually returned, kept verbatim beside the canonical one. `name` is upper-cased because GitHub secret names are not case-sensitive, so the fold is the identity; this column is what was reported, which is a different fact and worth keeping (Issue# 165).
- `visibility` — `all`, `private` or `selected`, on organisation secrets only. The blast-radius field. Empty on repository and environment secrets, which have no sharing policy — observed-empty, not unknown.
- `created_at` — as reported.
- `updated_at` — as reported. A secret whose value was rotated shows a new `updated_at` and nothing else; that timestamp is the only rotation signal this surface can offer.
- `configuration` — empty. Kept for shape with its siblings, and deliberately never filled: there is nothing further GitHub returns, and a blob here would be the obvious place for a value to arrive by accident.
- `tags` — TAP's tag map.
