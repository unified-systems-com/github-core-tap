# USES_ACTION

## Blurb

A declared job calls an action — and the properties say how it is pinned, which is the entire security content of the relationship.

## Purpose

The corpus's second finding is that bare edges are ruled out by the field: an edge that records only *that* a job uses an action produces confident nonsense in any view that scores risk, because the same line — `uses: actions/checkout` — is a reviewed commit in one job and a moving target in the next. This edge carries the pin, so that "which jobs hand their token to code that someone else can change tomorrow" is a property filter rather than a re-parse.

It is the join the incident corpus keeps asking for. A tag-repoint compromise reads, in graph terms, as: every `USES_ACTION` edge whose target is the compromised action and whose `pin_kind` is not `sha`, walked back to the jobs, their `permissions`, and the secrets in scope. Each of those hops is a node or property this plugin already has; this edge is what connects them.

## Goals

- Carry the pin as data — `declared_ref`, `pin_kind`, `is_pinned` — so a control ("all actions pinned to a commit") is one query and cannot be answered wrongly by a bare edge.
- Keep the honest third state: a name the collector could not resolve is `unresolved` / `unobservable`, never `tag`.
- Record every step position, since steps are not nodes and a job may call one action several times.
- Give `resolved_sha` a home whose field history *is* the tag-repoint detection, the way `git_ref.head_sha` history is the tag-movement detection.

## Identity

Edge id is `uuid5(ns, "edge:USES_ACTION__github_core:<job id>:<action id>:<declared_ref>")` — **not** the plugin's generic `(type, source, target)` edge id, and the deviation is deliberate. A job that calls `actions/checkout@v4` in one step and `actions/checkout@<sha>` in another has made two different trust decisions about the same action; an id that ignored the ref would keep only the last of them after envelope collapse, silently. Two refs, two edges. Steps that share a ref are folded into one edge's `step_indexes`.

## Boundaries

Carries no property that belongs to either endpoint. What the action *is* lives on [`github_action`](github_action.md); what the job is permitted to do lives on [`workflow_job`](../models/workflow_job.py)'s `permissions`. Putting either here would derive a fact twice.

Not covered:

- **`resolves_to_fork`** (corpus). Whether a resolved SHA belongs to the canonical repository or to a fork a moved name now points at. Needs the action repository's fork graph; not derivable from the string; omitted and named.
- **Reusable-workflow calls.** A job-level `uses: owner/repo/.github/workflows/x.yml@ref` is `CALLS_WORKFLOW` (github-core#29), a different relationship with its own pin properties.
- **Local actions** (`./...`). The repository's own code, not a trust decision; surfaced as `LOCAL_ACTION_DEFERRED`.
- **What the action does with what it is handed.** The edge says the token, checkout and secrets-in-scope crossed to the action; it does not say what the action did with them.

## Neutrality

**Vendor-specific**, with the target. The pin vocabulary — commit, tag, branch, digest, unresolved — is git's and OCI's and would survive in a neutral substrate; the `uses:` grammar it is parsed from is GitHub Actions' own. The edge moves with `github_action` if that node ever gets a neutral parent, and not before.

## Observability

Derived from the workflow YAML at **`repository:contents:read`**, in the same parse that mints `workflow_job` — one edge per `(job, action path, declared ref)` across the job's steps. No additional call and no additional permission.

The properties are established in three ways, and `resolution` records which:

- **`literal`** — read off the string. A 40-hex ref is `sha`; a `sha256:` digest is `digest`; a docker `:tag` is `tag` (the registry's own word, and mutable); no ref at all is `unpinned`. `resolved_sha` is the SHA itself for a `sha` pin and absent otherwise.
- **`in_scope`** — the action's repository is inside the observed account scope, so its refs are already in hand from the config layer (`req-github-core-refs`, same permission). The name is matched as a token against `refs/tags/<name>` then `refs/heads/<name>`; a hit yields `tag` or `branch` and the ref's head commit as `resolved_sha`. A miss — a deleted ref, or one beyond the ref page cap — leaves `pin_kind: unresolved` with `resolution: in_scope`, meaning "we looked and did not find it", and the run warns `ACTION_REF_NOT_FOUND`.
- **`rest`** — the action's repository is outside the scope (`actions/checkout@v4` on nearly every grid) and the name was looked up over REST, once per distinct (repository, ref) per run: `GET /repos/{o}/{r}/git/ref/tags/{name}` at **`repository:contents:read`**, then `.../heads/{name}` on 404 — the order a runner resolves — and an annotated tag's object (type `tag`, not a commit) peeled with `GET .../git/tags/{sha}`, because the SHA a runner checks out is the commit. A hit yields `tag` or `branch` and the commit as `resolved_sha`. Public repositories answer any credential, which is what almost every action repository is; no new permission enters the union.
- **`unresolved`** — looked up over REST and found at neither `refs/tags/` nor `refs/heads/`: the action, or the ref as written, does not exist, and a workflow using it fails at run time.
- **`unobservable`** — no lookup answered: the repository is out of scope and the lookup was refused or failed (a private action repository, a 403, a transport error; warned per (repository, ref)), or the walk was driven without a client. `pin_kind` is `unresolved` and `resolved_sha` is absent. **This is the state a view must never render as reassurance**: it is not "pinned to a tag", it is "pinned to a name nobody could look up", and it is not evidence about the pin.
- **`not_attempted`** — the run's REST resolution cap (`_ACTION_REF_RESOLUTION_CAP`, 400 distinct pairs) was spent before this ref's turn; the run warns with the count. A budget fact, not an observation.

Observed on the unified-systems-com grid on 2026-09-02, from the pre-edge `action_refs` data: 80 usages, all `sha`. So on that grid every edge is `literal` and `is_pinned: true`, and the other states are exercised on the fixture repository `unified-systems-com/git-serious-fixtures` (2026-09-03): its own `actions/hello@v1` and `@main` resolve `in_scope`; `actions/download-artifact@v3` and `actions/checkout@v4` resolve `rest` to the commits behind those tags; `actions/hello@does-not-exist` is `unresolved`. The run's `ACTIONS_USED` summary says how many usages were unpinned, how many resolved over REST, how many were unresolved, unobservable or not attempted, and how many lookups were spent, so a clean count is a claim about the scope and not a silence.

**Not observable:** which commit a ref pointed at *between* observations. History is sampled at collection cadence; a tag moved and moved back inside one interval is invisible.

**Absence shape** (github-core#14): **Shape A, git-provable.** The edge is derived from a file at HEAD; a commit that removes or changes the `uses:` line is positive evidence, and reconciling this edge on a complete parse of the current file is safe. Its target's tombstone follows from this edge's, never the reverse.

## Authoritative Source

- **Source:** GitHub Actions workflow syntax reference — `jobs.<job_id>.steps[*].uses`, including the guidance that a full-length commit SHA is the only immutable pin; GitHub REST API Repository Contents and Git References (`GET /repos/{owner}/{repo}/git/ref/{ref}`, the call this wave deliberately does not make)
- **Version:** REST API version `2022-11-28`; workflow syntax as published 2026-09
- **Retrieved:** 2026-09-02

## Prior Art

- `specs/spec-github-core-vocabulary.md` (2026-08-27) — `USES_ACTION` `{pin_kind, pinned_sha, declared_ref, resolves_to_fork}`; finding 2, bare edges are ruled out by the field. `pinned_sha` became `resolved_sha` here because the value is what a name resolved *to*, not what was pinned.
- `git-serious-tap/docs/doc-git-serious-cicd-security-prior-art.md` (2026-08-27) — the action-pinning observable conditions the static analysers already check, all of which read from this edge's properties.
- OpenSSF Scorecard `Pinned-Dependencies` check (as of 2026-09) — an independent implementation of the same one-bit question `is_pinned` carries; the reason that bit is explicit rather than re-derived per view.
- unified-systems-com/github-core-tap#45 (2026-09-02) — the bake issue and done-test.

## Endpoints

- **Source:** `github_core__workflow_job` — the declared job whose step calls the action. The declaration, not the execution: the edge says what the file *hands over*, not what any run did.
- **Target:** `github_core__github_action` — the shared, platform-global action node.
- **Dimensions:** `git.host`, `github.surface: actions`, `github.observation: declaration`. The collector additionally stamps the *calling* repository's `github.owner` / `github.repo` on the edge — the usage is that repository's fact, even though the target node carries neither, because the target belongs to no one repository in scope.
