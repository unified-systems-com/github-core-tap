# GitHub Action

## Blurb

A reusable action a declared job calls with `uses:` — the one piece of a repository's CI that its owner did not write, running with the job's token.

## Purpose

A `uses:` line is a trust decision made in one word. It hands whatever the job holds — its `GITHUB_TOKEN` at the declared permissions, its checkout, every secret in scope for the step — to code that lives in someone else's repository, at whatever commit the written ref resolves to on the day the run happens. The incident corpus's tag-repoint compromises are exactly that sentence: a maintainer account taken, a `v1` tag moved onto a commit that exfiltrates the runner's memory, and every job on the platform that wrote `@v1` running it on its next trigger.

This node exists so that question is a graph query rather than a grep. Before it, every action a job called was text inside `workflow_job.configuration.action_refs` — present, parsed, and unreachable from any other node. One node per action path, shared across every repository in scope, gives the fan-in: "every job that hands its token to `actions/checkout`" is the set of `USES_ACTION` edges pointing at one node, and "which of those pinned a name rather than a commit" is a property filter on those edges.

Observed on the unified-systems-com grid on 2026-09-02, before this node existed: 69 declared jobs carried 80 action usages of 18 distinct actions from 8 publishers, and all 80 were pinned to a 40-hex commit. That is the shape a clean estate has, and it is also why the tests fixture the unpinned cases rather than waiting for the grid to show one.

## Goals

- Make the third-party code in a pipeline a node that many jobs point at, so exposure to one action is one query.
- Keep the pin where it belongs — on the job's edge — so one action used well by one job and badly by another is two facts, not an average.
- Say honestly what a `uses:` string does and does not prove about the ref it names.

## Identity

Natural key: **the action path** — the `uses:` value with the ref stripped: `actions/checkout`, `actions/cache/restore`, `docker://alpine`. Entity id is `uuid5(ns, "github_core__github_action:<action_path>")`.

Platform-global rather than repository-scoped, deliberately, and for the same reason `github_app` is keyed on its slug: `actions/checkout` is one thing that every job on every repository points at, and a per-repository key would turn "who uses an unpinned checkout" into a string comparison across duplicates. A subdirectory action is its own node — `actions/cache` and `actions/cache/restore` are different `action.yml` files with different behaviour (one both restores and saves, the other only restores), which is a distinction the cache vocabulary already turns on.

The ref is **not** identity. The same action is pinned differently by different jobs, and the pin is a fact about the relationship — see [`USES_ACTION`](USES_ACTION.md).

## Boundaries

Deliberately **not** covered:

- **Local actions.** `uses: ./.github/actions/x` is the repository's own code, checked out with the job. It is not a third-party trust decision and is not a node here; the collector surfaces each one as `LOCAL_ACTION_DEFERRED` (`req-github-core-workflow-parse-3`) because their `action.yml` bodies are not yet parsed.
- **Reusable workflow calls.** `uses: owner/repo/.github/workflows/x.yml@ref` at the *job* level calls a workflow, not an action — a different object with different semantics (it brings its own jobs, runners and permissions). That is the corpus's `CALLS_WORKFLOW` edge (github-core#29), not this node.
- **The action's own definition.** What `action.yml` declares — its inputs, whether it is composite, JavaScript or Docker, what *it* in turn uses — is not fetched. The node records that a job called the action and how; the action's contents are the next wave, and would need a read of the action's repository.
- **Where the action lives, as an edge.** The corpus's `DEFINED_IN` (action → repository) is not built. `repository_full_name` is carried as a field so that edge can be derived when its consumer arrives, and so the collector can resolve pins against an in-scope repository today.
- **`resolves_to_fork`.** The corpus proposed it on the edge: does the pinned SHA belong to the canonical repository, or to a fork that a moved name now points at? Establishing that needs the action repository's fork status and a commit lookup, neither of which the string carries. Omitted rather than defaulted; named here so it is not mistaken for a decision that it does not matter.

## Neutrality

**Vendor-specific.** The concept — a pipeline step that pulls in published third-party code — is universal (GitLab's `include:` and CI components, CircleCI orbs, Tekton catalog tasks), but the object is GitHub's: the `owner/repo[/path]@ref` grammar, the `action.yml` contract, the `docker://` form and the marketplace are GitHub Actions' own, and a neutral parent would have to be invented rather than observed. The slug says `github_` for that reason. The corpus marks it `no`.

## Observability

Populated from the workflow YAML at **`repository:contents:read`** — the same fetch that already populates `github_workflow.configuration` (the config layer's inlined file bodies, or the Contents API as fallback) — so this node widens the credential union by nothing. Every `uses:` in every step of every parsed workflow file is split into the action path (this node) and the declared ref (the edge).

Three states for what the string proves, established by construction rather than by a call:

- **A 40-hex ref or a `sha256:` digest** is immutable and proves itself. Nothing was looked up.
- **A mutable name on an action whose repository is inside the observed scope** is resolved against that repository's refs, which the config layer already holds at the same permission: `refs/tags/<name>` makes it a tag with a head commit, `refs/heads/<name>` a branch. No request is made. A name matching neither — a deleted ref, or one beyond the ref page cap — stays `unresolved` and the run warns (`ACTION_REF_NOT_FOUND`).
- **A mutable name on an action outside the scope** — `actions/checkout@v4` on almost every grid — is **not observable** from what the collector holds. Whether `v4` is a tag or a branch, and which commit it points at today, would take one `GET /repos/{owner}/{repo}/git/ref/tags/{name}` per distinct ref. That call needs no permission for a public repository, but it is a call budget and a design decision (which commit is "the" answer for a name that moves?), and it is deliberately not made. The edge says `pin_kind: unresolved`, `resolution: unobservable`, and no view may render that as "pinned to a tag" or as "safe".

The previous parser called every non-SHA ref `tag`. That was a declaration that existed and was false, and it is the reason the enum carries `unresolved` as a first-class value rather than a default.

**Not observable at all:** what the action does — its `action.yml`, its transitive `uses:`, whether it was recently transferred to a new owner or archived (the corpus's owner-transfer detection, which `DEFINED_IN` would enable). The marketplace's "verified creator" badge is not in any API this plugin reads.

**Absence shape** (github-core#14): **Shape D, derived absence.** This is a shared node with no observation of its own; it is relevant while any `USES_ACTION` edge points at it and stops being relevant when the last one goes. Its `USES_ACTION` edges are **Shape A, git-provable** — a commit that removes the `uses:` line is positive proof — so the node's tombstone is a consequence of edge reconciliation, never an observation. It must not be tombstoned because one repository stopped using it.

## Authoritative Source

- **Source:** GitHub Actions workflow syntax reference — `jobs.<job_id>.steps[*].uses` (the `{owner}/{repo}@{ref}`, `{owner}/{repo}/{path}@{ref}`, `./path` and `docker://{image}:{tag}` forms); GitHub REST API Repository Contents (`GET /repos/{owner}/{repo}/contents/{path}`) and the GraphQL config layer for the file bodies
- **Version:** REST API version `2022-11-28`; workflow syntax as published 2026-09
- **Retrieved:** 2026-09-02

## Prior Art

- `specs/spec-github-core-vocabulary.md` (2026-08-27) — `github_action`, self tier, four sources, one carrying `is_pinned` independently; `USES_ACTION` with the pin properties; `DEFINED_IN` recorded and not built.
- `skills/build-github-corpus/SKILL.md` (2026-09-02) — ranked this concept first: highest incident weight among the gaps reachable with the credential union already held, and a convergence node.
- `git-serious-tap/docs/doc-git-serious-cicd-security-prior-art.md` (2026-08-27) — the tag-repoint incident family; "pinned to v4 is a promise someone else keeps".
- Octicons v19.15.1 — the `github-action` glyph is **absent** from the icons directory (retired); the icon here is TAP-drawn.
- unified-systems-com/github-core-tap#45 (2026-09-02) — the bake issue: known versus assumed, the absence shape, the done-test.

## Fields

- `action_path` — the `uses:` value with the ref stripped, and the natural key. `actions/checkout`, `actions/cache/restore`, `docker://ghcr.io/org/image`. Chosen over any resolved identity because it is what every job in the world writes and is stable across every ref the action is ever pinned at.
- `kind` — `repository` for an action that lives in a GitHub repository, `docker` for a container image run as a step. The two have different pin grammars (a commit or a name; a digest or an image tag), so the edge's `pin_kind` reads differently by kind.
- `owner` — the publishing account, `actions` or `docker` or `astral-sh`. Empty for a docker image, whose registry namespace is not a GitHub owner. What "how much of our CI runs code from publishers outside our org" groups by.
- `repository_full_name` — the `owner/repo` the action's `action.yml` lives in. What the collector resolves a mutable pin against when that repository is in scope, and what the unbuilt `DEFINED_IN` edge would target. Empty for `docker`.
- `subpath` — the path inside that repository for a subdirectory action (`restore` for `actions/cache/restore`); empty for a repository-root action. Kept apart from `repository_full_name` so the repository join is exact.
- `name` — the display name; the action path, since nothing richer is fetched. Not identity.
- `configuration` — reserved for the action's own definition when a later wave reads `action.yml`; empty today, and saying so here is what keeps an empty blob from reading as "nothing to declare".
- `tags` — TAP's tag map.
