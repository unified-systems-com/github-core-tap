# CALLS_WORKFLOW

## Blurb

A declared job calls a reusable workflow — the edge that makes "one gate, thirteen callers" a structure instead of thirteen strings.

## Purpose

A reusable workflow is a whole pipeline stage that lives in someone else's file: it brings its own jobs, its own `runs-on`, its own `permissions`, and it receives whatever secrets the caller chooses to pass. Until this edge, a call was `workflow_job.uses` — a string, parsed and present, reachable from nothing. The two structures *The Shape of a Pipeline* names as invisible were exactly this: every plugin repository's `ci.yml` calling one `plugin-ci` gate, and the AI-review capture stage handing off into a privileged review machinery. github-core#29 records both.

The edge carries the pin in the same grammar as [`USES_ACTION`](USES_ACTION.md) — the same question applies (does the caller run the file it reviewed, or whatever a name points at today?) — plus the one property specific to workflows: `secrets: inherit`, which passes *every* secret of the caller to the callee. That single boolean is the difference between a reusable gate and a secret-forwarding one.

## Goals

- Make reusable-workflow fan-in visible: a callee's inbound edges are its callers.
- Carry the pin, so `@main` callers (the accepted moving-target trade-off) are distinguishable from SHA-pinned ones without re-parsing.
- Say whether the call forwards the caller's secrets.
- Leave an unresolved call *visible on the job*, in three states, rather than absent.

## Identity

Edge id is `uuid5(ns, "edge:CALLS_WORKFLOW__github_core:<job id>:<workflow id>")` — the generic (type, source, target) form, because a job has exactly one `uses:` and so exactly one call. (Compare `USES_ACTION`, whose id includes the ref because a job may call one action at several refs in several steps.)

**Source is the job, not the workflow.** The corpus row wrote workflow → workflow; #29 asked for the decision to be recorded. The call is written on the job (`jobs.<id>.uses`), the job is what carries `permissions`, `secrets`, `with` and `if`, and two jobs in one file can call two different reusable workflows. A workflow-level edge would collapse those and lose the job's own permission block, which is the input every privilege question needs. The corpus inventory is corrected.

## Boundaries

- **Only calls whose callee is on the grid become edges.** A callee in a repository outside the observed scope is *not observable*; no node is invented and no edge is drawn. The state lives on the calling job's `configuration.call_resolution` — `resolved`, `unresolved_in_scope` (the callee's repository was walked and has no workflow at that path), `out_of_scope` — because a property that qualifies an absence belongs on the node the absence is about, never on the edges that failed to appear.
- **Not the callee's inputs.** `with:` values are on the job's configuration; the callee's `on: workflow_call: inputs/secrets` contract is on the callee's node. This edge records the call, not the interface.
- **Not the executed instance.** A run's `referenced_workflows` (the SHAs GitHub actually resolved and executed) is on [`github_actions_run`](github_actions_run.md)'s configuration. That is the execution-side answer to this declaration-side edge, and joining them is a later wave.
- **Not `USES_ACTION`.** A step-level `uses:` is an action; a job-level `uses:` is a workflow. Different objects, different edges, same pin grammar.

## Neutrality

**Vendor-specific**, with its endpoints. Pipeline inclusion exists everywhere (GitLab `include:`, CircleCI orbs, Azure templates), but the `owner/repo/.github/workflows/x.yml@ref` grammar, the `secrets: inherit` semantics and the `workflow_call` contract are GitHub's.

## Observability

Derived from the caller's workflow YAML at **`repository:contents:read`**, in the same parse that mints the job. The callee is resolved in a **post-pass after every repository in scope has been walked**, against the (repository, path) index of collected workflows, because workflow nodes are keyed on GitHub's numeric id and the file names a path.

Pin resolution is `USES_ACTION`'s, verbatim: `sha` is `literal`; a mutable name is `tag`/`branch` with a head commit only when the callee's repository is in scope (`in_scope`, from refs already held, no request); otherwise `unresolved` / `unobservable`. A same-repository call (`./.github/workflows/x.yml`) takes no ref and runs at the caller's own commit — `pin_kind: local`, `is_pinned: true`, because it cannot be repointed independently of the caller.

Observed on the unified-systems-com grid on 2026-09-02 (pre-edge, from `workflow_job.uses`): the org's plugin repositories call `unified-systems-com/tap/.github/workflows/plugin-ci.yml@<sha>` and the AI-review shims call `unified-systems-com/unified-ai-review/.github/workflows/capture.yml@<sha>` / `review.yml@<sha>`. All observed cross-repository calls were SHA-pinned; the `@main` form #29's done-test names is what a caller *outside* this org typically writes, and it resolves as `branch` only when that caller's callee is in scope.

**At repos-only scope** (an envelope naming `repos:` rather than an owner) there is no config layer and only the named repositories are walked, so every cross-repository call is `out_of_scope`. The run's `WORKFLOW_CALLS` summary states the three counts so that reads as a scope limit, not as an estate with no reusable workflows.

**Absence shape** (github-core#14): **Shape A, git-provable** — the edge is derived from a file at HEAD, and a commit that removes the `uses:` line is positive proof.

## Authoritative Source

- **Source:** GitHub Actions workflow syntax reference — `jobs.<job_id>.uses`, `jobs.<job_id>.secrets` (including `inherit`), and the reusable-workflows guide (the two written forms, the same-repository rule that a `./` call runs at the caller's commit)
- **Version:** workflow syntax as published 2026-09; REST API version `2022-11-28` for the file fetch
- **Retrieved:** 2026-09-02

## Prior Art

- `specs/spec-github-core-vocabulary.md` (2026-08-27) — `CALLS_WORKFLOW` `{pin_kind, ref}`, self tier; the source-end correction is recorded there on 2026-09-02.
- unified-systems-com/github-core-tap#29 (2026-09-02) — the two invisible structures, the three-state rule for an unresolved callee, and the done-test (`plugin-ci` ≥ 13 inbound).
- `git-serious-tap` *The Shape of a Pipeline* §6 (2026-08) — "one reusable gate, thirteen callers" and the untrusted→privileged handoff.
- [`USES_ACTION`](USES_ACTION.md) (2026-09-02) — the pin grammar this edge reuses rather than re-deriving.

## Endpoints

- **Source:** `github_core__workflow_job` — the calling job, whose `uses` field holds the string and whose `configuration.call_resolution` holds the three-state verdict.
- **Target:** `github_core__github_workflow` — the reusable workflow, on the grid, in the same or another repository in scope.
- **Dimensions:** `git.host`, `github.surface: actions`, `github.observation: declaration`, plus the *calling* repository's `github.owner` / `github.repo` from the job's own dimensions — the call is that repository's fact even when the callee belongs to another.
