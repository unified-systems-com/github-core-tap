# Pull Request

## Blurb

The forge's proposal to merge one ref into another — what it proposes, where it targets, who opened it, and what stands between it and merge, including the combined check verdict on its head commit.

## Purpose

Every question git-serious asks about admission converges here. *Why isn't this merging* is a per-pull-request account of required checks, reviews and mergeability; *what is waiting on me* is a queue of pull requests with a review request outstanding; the demo's PR list is this node with its build status. Before this node those facts lived on GitHub's PR page and nowhere on the grid — the runs were collected, the rulesets were collected, and the object that ties a proposal to the gate it must pass through was missing.

Ten sources in the vocabulary survey model it. It is the highest-fan-out node in the forge: it points at a branch, a commit and a base, it is pointed at by an author, and its head commit is what every check run and status is a verdict about.

## Goals

- Put the proposal on the grid as one node per pull request with the state a gate view needs: draft, review decision, mergeability, outstanding review requests, latest reviews.
- Join it to the neutral ref and commit nodes rather than copying them, so "what runs executed on this proposal" is a traversal from the head commit and "what rulesets gate it" is a traversal from the base ref.
- Carry build status as GitHub computes it — the check rollup on the head commit — including checks produced by Apps that no workflow in scope produces.

## Identity

Natural key: **`<owner/repo>#<number>`** — the base repository plus the pull request number. Entity id is `uuid5(ns, "github_core__pull_request:<owner/repo>#<number>")`.

Scoped to the BASE repository: a fork's pull request is a fact about the repository it targets, and the head repository is a field. The number is GitHub's own identity for a pull request within a repository and is what every URL, commit message and review names it by; `github_id` (GitHub's `databaseId`) is carried for continuity across a repository transfer, not as the key.

## Boundaries

- **Not a Git object.** Git has branches and commits; the pull request is GitHub's conversation and admission gate wrapped around them, which is why it lives in github_core and git_core's v0 non-goals exclude it (github-core#76). The vocabulary's neutral-capable mark — every forge has a merge request — is a future extraction, not a home.
- **Not the ref or the commit.** `head_sha`, `head_ref`, `base_ref` are what the pull request said when observed; the neutral nodes are [`git_ref`](../../git_core/domain/git_ref.md) and [`git_commit`](../../git_core/domain/git_commit.md), reached by `PROPOSES_REF`, `TARGETS_BASE_REF` and `PROPOSES_COMMIT`, drawn only when that endpoint was observed in the same batch.
- **Not the check run.** The rollup is data on this node; a `check_run` node joined to `status_check` is the follow-on github-core#75 names for the App-produced half.
- **Not the review conversation.** Comments, threads and review bodies are not collected; `latest_reviews` carries each reviewer's latest verdict and `review_requests` who has been asked and has not answered.
- **Not every pull request.** A window of the thirty most recently updated per repository; `github_repository.pull_requests_total` and a truncation warning say how many were left.

## Neutrality

**Vendor-specific.** The shape — draft flag, review decision, `authorAssociation`, `mergeable` as a lazily computed tri-state, the check rollup — is GitHub's. GitLab's merge request and Gerrit's change carry the same idea with different fields; extraction to a neutral `merge_request` waits for a second forge.

## Observability

Populated from **a GraphQL query of its own** (`Repository.pullRequests`, most recently updated first, five repositories a page, thirty pull requests each) at **`repository:pull_requests:read`**, with the head commit's `statusCheckRollup` at **`repository:checks:read`** (check runs) and **`repository:statuses:read`** (commit statuses). Not the config-layer query: GitHub caps a query at 500,000 possible nodes and the config layer already sits near 460,000 across its hundred-repository page; adding pull requests to it measured 1,269,100 (`MAX_NODE_LIMIT_EXCEEDED`, 2026-09-08). Five a page because GitHub also stops a query at about ten seconds: twenty repositories timed out every time and ten sat at the edge, with `mergeable`, the diff sizes and the rollup each costing a second or two and none of them decisive. Measured 2026-09-08 on `unified-systems-com/tap`: 178 pull requests, each open one carrying eight check runs from `github-actions`, `reviewDecision: REVIEW_REQUIRED`, `mergeable: MERGEABLE`; a merged one `mergeable: UNKNOWN` (computed lazily — stored as the string, never coerced).

GraphQL is chosen over REST because it is the only transport that carries `reviewDecision`, `mergeable` and the rollup in one read; REST needs two further calls per pull request for the checks alone.

**Three states on the repository**, `pull_requests_observability`: `observed` (the field answered — zero rows is a fact), `unobservable` (the field degraded and was pruned by `prune_errored_paths` — no row means nothing, and the run warns per repository), `""` (a repos-only scope runs no config-layer query: never asked). On the node, `checks_rollup_state = ""` means the head commit carries no rollup — nothing ran — which is not `SUCCESS`.

**Absence shape** (github-core#14): **Shape E, credential-shaped** for the rows; the rollup is **Shape C, observed** — `""` is the wire's own answer, never inferred.

## Authoritative Source

- **Source:** GitHub GraphQL API — `Repository.pullRequests`, `PullRequest` (`state`, `isDraft`, `author`, `authorAssociation`, `headRefName`, `headRefOid`, `headRepository`, `baseRefName`, `baseRefOid`, `mergeable`, `reviewDecision`, `reviewRequests`, `latestReviews`, `commits`), `Commit.statusCheckRollup` with `CheckRun` and `StatusContext` contexts
- **Version:** GraphQL schema as pinned in `github_openapi_extract.json` (octokit/graphql-schema)
- **Retrieved:** 2026-09-08

## Prior Art

- `specs/spec-github-core-vocabulary.md` (2026-08-27) — `pull_request`, self tier, 10 sources, neutral-capable; `OPENS_PULL_REQUEST` `{author_association}`.
- unified-systems-com/github-core-tap#82 (2026-09-08) — the bake issue and the github_core-not-git_core ruling.
- unified-systems-com/github-core-tap#76 rev 2 (2026-09-08) — git_core's scope; pull requests named as a forge-collaboration non-goal.
- `git-serious-tap/specs/spec-git-serious-why-not-merging.md` and `spec-git-serious-waiting-on-me.md` (2026-09-02) — the two consumers this node exists for.
- GitHub Docs, "About status checks" (as of 2026-09) — check runs versus commit statuses, and why a required context may be either.

## Fields

- `full_name` — `owner/repo` of the base repository; half the natural key.
- `number` — the pull request number within it; the other half.
- `github_id` — GitHub's `databaseId`, for continuity across a transfer; not the key.
- `title` — the title as written.
- `state` — `OPEN`, `CLOSED` or `MERGED`, GitHub's own enum; `MERGED` is not a kind of `CLOSED` here.
- `is_draft` — whether the author marked it not ready; a draft is not waiting on anyone.
- `author_login` — who opened it, as GitHub reports the login.
- `author_type` — GitHub's actor kind: `User`, `Bot`, `Organization`, `Mannequin`. `Bot` is what routes the author edge to a `github_app`.
- `author_association` — the author's relationship to the repository at the time (`OWNER`, `MEMBER`, `COLLABORATOR`, `CONTRIBUTOR`, `FIRST_TIME_CONTRIBUTOR`, `FIRST_TIMER`, `NONE`); also carried on `OPENS_PULL_REQUEST`, where the act is.
- `head_ref` — the proposed branch name, without `refs/heads/`.
- `head_sha` — the commit at the head when observed; the commit the rollup is a verdict about, and the join to the runs that executed on it.
- `head_repository` — `owner/repo` the head lives in; differs from `full_name` for a fork, in which case no `PROPOSES_REF` edge is drawn.
- `base_ref` — the branch it asks to land on; the ref whose rulesets gate the merge.
- `base_sha` — the base's commit when observed.
- `review_decision` — `APPROVED`, `CHANGES_REQUESTED`, `REVIEW_REQUIRED`, or `""` when no review is required or GitHub did not report one.
- `mergeable` — GitHub's `MergeableState` verbatim: `MERGEABLE`, `CONFLICTING`, `UNKNOWN`. Computed lazily; a first read often says `UNKNOWN`, which a boolean would lie about.
- `merge_commit_sha` — the merge commit once merged; `""` before.
- `created_at`, `updated_at`, `closed_at`, `merged_at` — GitHub's timestamps; null when the event has not happened.
- `commit_count`, `additions`, `deletions`, `changed_files` — size, as GitHub counts it.
- `labels` — label names, in GitHub's order.
- `review_requests` — `[{"kind": "user"|"team", "login"}]`: who has been asked and has not answered. The *waiting on me* queue reads this — after checking `configuration.lists_truncated`, since the page holds ten.
- `latest_reviews` — `[{"login", "state", "submitted_at"}]`: each reviewer's latest verdict (`APPROVED`, `CHANGES_REQUESTED`, `COMMENTED`, `DISMISSED`).
- `checks_rollup_state` — GitHub's combined verdict on the head commit (`SUCCESS`, `FAILURE`, `PENDING`, `ERROR`, `EXPECTED`) or `""` when no rollup exists: nothing ran, which must not render green.
- `checks_observability` — whether the rollup was READ: `observed` (GitHub answered, possibly `null` — the blank above is then a fact), `unobservable` (the rollup or its contexts were refused and pruned — the blank means nothing, and the run warns per repository), `""` (never asked). The `bypass_observability` ruling applied to the rollup: a refused read must not serialize like "nothing ran".
- `checks` — the rollup's contexts: `[{"kind": "check_run"|"status", "check_run_id", "name", "status", "conclusion", "app", "url"}]`. A check run names the producing App's slug and carries GitHub's `check_run_id` — a rerun mints a new, higher id for the same (app, name), so a consumer keeps the latest by id instead of guessing from the url; a commit status names its creator's login, which is what the older API records, and has no id (null). Both kinds in one list because a required context may be either.
- `html_url` — the pull request page.
- `configuration` — JSONB for detail not promoted to a column; carries `checks_total` (the rollup's own count) and `checks_truncated` (whether the page held fewer than that), and the same pair for the three capped lists — `labels_total`, `review_requests_total`, `latest_reviews_total` beside one `lists_truncated` flag — so a page of ten is never read as everyone who was asked.
- `tags` — TAP's tag map.
