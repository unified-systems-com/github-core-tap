# REFERENCES_SECRET

## Blurb

A workflow file names a secret that exists. The join between what CI asks for and what the platform holds — and, by its absence, the reference that asks for something that is not there.

## Purpose

`${{ secrets.DEPLOY_KEY }}` in a workflow where no `DEPLOY_KEY` exists **does not fail**. GitHub substitutes the empty string, the job runs to green, and the step does the wrong thing silently: an empty `Authorization` header, an unsigned artifact, a `git push` with no credential. There is no log line, no annotation, and no failed check. The only way to see it is to compare the names a file types against the names a platform holds, which is exactly this edge and the tag that records its misses.

The edge going the other way is the blast-radius question: a secret with no `REFERENCES_SECRET` pointing at it is a live credential nothing consumes.

## Goals

1. Join a workflow to each secret it names that actually exists — **one edge per defining scope**.
2. Leave a name that resolves to nothing WITHOUT an edge, and record it on the workflow instead.
3. Never mint a secret node from a reference — a name somebody typed is not evidence a credential exists.
4. Keep the claim honest about scope: unresolved means unresolved *in the scopes this run enumerated in full*.

## Identity

Derived: `uuid5(ns, "REFERENCES_SECRET__github_core:<workflow_uuid>:<secret_uuid>")`.

## Boundaries

This edge is an assertion about a **FILE**, not about a run. Four things are outside it, and each would be a wrong answer rather than a missing one:

- **What a run consumed.** GitHub publishes no record of which secrets a run actually read. A referenced secret in a job that was skipped was never read.
- **`secrets: inherit`.** A reusable-workflow call may pass the caller's entire secret set without naming one of them. Such a call reads here as referencing nothing, and that is not the same as consuming nothing. The single most important blind spot on this edge.
- **An expression-driven job-level `environment:`.** A job selects its environment — and therefore its secret scope — at runtime. A name resolved against environment scope means *the repository holds a secret by that name in some environment*, not that this job will receive it.
- **Unresolved names.** They get no edge, by design. Minting a node from a reference would put a credential on the graph on the evidence that somebody typed its name, and a view would then render a typo as a secret that exists.

## Neutrality

Vendor-specific. Pipeline-references-a-named-secret is general; the `${{ secrets.NAME }}` expression syntax, the case-insensitive lookup, the three-scope resolution order and the silent empty-string substitution are GitHub's.

## Observability

Derived from the collected workflow body (`github_workflow.configuration.raw_yaml`), which needs `contents: read`, joined against the three secret listings, which need `secrets: read` and `organization_secrets: read`. Names are matched **case-insensitively**, because GitHub secret names are — two of the nine names referenced on this estate are written lower-case. `GITHUB_TOKEN` is excluded: it is the per-run token GitHub injects, not a stored secret, and it exists in no listing.

Observed 2026-09-10 across `unified-systems-com` (119 workflows, 79 carrying a body):

| | |
| --- | --- |
| Workflows referencing ≥1 secret | 41 |
| Distinct names referenced | 9 |
| `REFERENCES_SECRET` edges emitted | 15 |
| References resolving to nothing | 36 |
| …of those, `TAP_CORE_RO_PAT` | 33 |

`TAP_CORE_RO_PAT` is referenced by 33 workflows across 17 repositories and exists in **no** organisation, repository or environment scope that the credential read — and every one of those listings answered 200, so this is an observed absence rather than an unread scope. That single finding is the edge earning its place.

**One edge per defining scope.** A name held at both organisation and repository scope is two credentials, and both get an edge. Resolving to the single one a run would actually receive means applying GitHub's precedence (environment, then repository, then organisation) — which requires knowing *which environment the job selects*, and that is chosen at runtime and is a named blind spot above. Picking one would manufacture a claim this collector cannot support, so it states the weaker thing it can prove: this file names a secret that exists here.

**The three-states record** lives on the workflow, not here: `github_workflow.tags.secret_refs` carries `referenced`, `unresolved`, `reach_uncertain` and `scopes_read`. Written whenever a body was READ — an empty `referenced` means "read, names none", where an absent tag means "never read". Forty of the 119 workflows carry no body at all.

Two ways a scope loses its place in `scopes_read`, and the second is the one that hides. A **refused** listing is loud: it returns nothing, and nothing is obviously nothing. A listing **truncated at the page cap** returns plausible names and looks like success — so a secret on an unfetched page would make every workflow naming it read as unresolved *under a scope the tag claimed was read*. Both disqualify the scope; the names that did come back are still real and still resolve.

**`reach_uncertain`** is the third answer for reach rather than existence. An organisation secret with `visibility: selected` names a repository list this collector does not fetch, and `private` excludes public repositories outright. A name resolved only by such a secret exists, but whether it reaches *this* repository is unknown — neither resolved nor unresolved, and it must not be rounded to either.

**Absence of this edge is ambiguous on its own** and resolves in the reassuring direction, which is the failure mode this plugin is built to refuse. Read `scopes_read` before concluding anything from a missing edge.

## Authoritative Source

- **Source:** GitHub Actions — contexts reference (`secrets` context, case-insensitive names, `GITHUB_TOKEN`), reusable-workflow `secrets: inherit`; GitHub REST API — Actions Secrets listings
- **Version:** REST API version `2022-11-28`
- **Retrieved:** 2026-09-10 (counts above measured on an executed collection, not estimated)

## Prior Art

- unified-systems-com/github-core-tap#104 (2026-09-10) — the build issue, the blind spots, and the done-test.
- [`DEFINES_SECRET`](DEFINES_SECRET.md) — the holding half of the pair.
- [`actions_secret`](actions_secret.md) — why names alone answer both questions, and why no value can cross this boundary.

## Endpoints

- **Source:** `github_core__github_workflow` — the file that types the name.
- **Target:** `github_core__actions_secret` — the secret that exists.
- **Dimensions:** `git.host`, `github.surface: actions`, `github.observation: declaration`.
- **Properties:** none. The unresolved side is a tag on the workflow, because it has no target to hang an edge from.
