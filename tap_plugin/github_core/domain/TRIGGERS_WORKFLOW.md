# TRIGGERS_WORKFLOW

## Blurb

The completion of one workflow fires another — the edge along which a fork's data reaches a workflow that holds secrets.

## Purpose

`on: workflow_run:` is how GitHub tells you to handle untrusted input: run the `pull_request` stage with no secrets, then let its *completion* fire a second workflow that runs in the base repository with the real credentials and reads the first stage's output as data. Every instance of that pattern is two workflows and this edge between them. Our own repositories carry the canonical case — `AI review capture` (unprivileged) → `AI review` (privileged, vendor keys) — and it existed on the grid only as `workflow_run` in a flat trigger list, with the `workflows:` names dropped by the parser.

The edge is the structure the machinery view needs (github-core#52, git-serious-tap#6) and the join a reviewer needs: "which privileged workflow consumes the output of a workflow that ran contributor code" is one hop along it.

## Goals

- Draw the `workflow_run` chain as structure, in the direction the event flows.
- Keep the declared name, so a renamed upstream reads as drift on the edge rather than as a trigger that silently stopped firing.
- Carry the filters as written and nothing GitHub defaults in.

## Identity

Edge id is `uuid5(ns, "edge:TRIGGERS_WORKFLOW__github_core:<source id>:<target id>")`. One edge per (upstream, downstream) pair; a downstream naming the same upstream twice is one fact.

**Direction is the event's, not the declaration's.** The `workflow_run` block is written on the workflow that *runs second*, but the workflow that completes is what initiates it — so the edge points completing → triggered, per the add-edge rule that the initiator is the source. `A TRIGGERS_WORKFLOW B` reads correctly; `B` is where you look for the file.

## Boundaries

- **Same repository only.** `workflow_run` cannot cross repositories (GitHub's rule), so resolution is scoped to the declaring workflow's repository and never searches beyond it.
- **Names, not paths.** `workflows:` lists display names. Several workflows may share one; GitHub fires on all of them, and so does this edge (one per match). A name matching nothing is recorded on the declaring workflow's `configuration.trigger_resolution` and warned — a renamed or deleted upstream, or a trigger that can never fire.
- **No `conclusion_filter`.** The corpus row proposed one. GitHub has no such key on `workflow_run`; the conclusion check lives in the downstream's job `if:` expressions (`github.event.workflow_run.conclusion == 'success'`), and reading it out is expression parsing — a guess. Not carried; the jobs' `if_condition` fields hold the text.
- **Not the other cross-workflow triggers.** A job that calls the API to `workflow_dispatch` another workflow, or `repository_dispatch`, is a runtime act, not a declaration; `trigger_event` is an enum of one so those can join later without a rename.
- **Not the executed chain.** Which run actually fired which is execution-side (`github_actions_run.event == workflow_run` and its payload) and is not joined here.

## Neutrality

**Vendor-specific.** Chaining on completion exists elsewhere (GitLab pipeline triggers, Jenkins upstream/downstream), but the `workflow_run` event, its base-repository context and its name-based resolution are GitHub's.

## Observability

Derived from the *downstream* workflow's YAML at **`repository:contents:read`** — the config layer's inlined file bodies, or the Contents API — by a parser addition that keeps `on.workflow_run.workflows`, `types`, `branches` and `branches-ignore` as written (`workflow_run` on `github_workflow.configuration`). Nothing new is fetched. Resolution runs in the post-pass after the repository's workflows are all known, against their stored display names — the same `name` field the node carries, which already falls back to the path for a workflow that declares no `name:`.

Only the keys the author wrote are carried. GitHub defaults `types` to `[requested, completed]` when omitted; writing that default onto the edge would record a declaration the file does not make, so an absent `types` means absent.

Observed on the unified-systems-com grid on 2026-09-02 (pre-edge, from `configuration.raw_yaml`): every repository carrying the AI-review pair declares `on: workflow_run: workflows: ["AI review capture"], types: [completed]` on `AI review`, and the name resolves to exactly one workflow per repository.

**Absence shape** (github-core#14): **Shape A, git-provable** — the edge is derived from the target's file at HEAD; a commit removing the block is positive proof.

## Authoritative Source

- **Source:** GitHub Actions — events that trigger workflows, `workflow_run` (name-based, same-repository, `types` / `branches` / `branches-ignore` filters, base-repository context); GitHub Security Lab, "Keeping your GitHub Actions and workflows secure: preventing pwn requests" (the two-stage pattern this edge draws)
- **Version:** docs as published 2026-09
- **Retrieved:** 2026-09-02

## Prior Art

- `specs/spec-github-core-vocabulary.md` (2026-08-27) — `TRIGGERS_WORKFLOW` `{trigger_event, conclusion_filter}`; the `conclusion_filter` drop is recorded there on 2026-09-02.
- unified-systems-com/github-core-tap#52 (2026-09-02) — the bake issue: the dropped parser key, direction, done-test.
- unified-systems-com/tap `specs/spec-cicd-ai-review.md` (2026-08) — the capture → review handoff, our own instance of the shape.
- `git-serious-tap` *The Shape of a Pipeline* §6 (2026-08) — the untrusted→privileged handoff as one of the two invisible structures.

## Endpoints

- **Source:** `github_core__github_workflow` — the workflow whose completion fires the event.
- **Target:** `github_core__github_workflow` — the workflow declaring `on: workflow_run`, whose `configuration.workflow_run` holds the block and whose `configuration.trigger_resolution` holds the unmatched names.
- **Dimensions:** `git.host`, `github.surface: actions`, `github.observation: declaration`, plus the repository's `github.owner` / `github.repo` — both ends are in one repository by construction.
