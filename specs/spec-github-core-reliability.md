# github_core Reliability Specification

**GitHub is not a trustworthy dependency.** It times out, drops connections mid-body, returns empty 404s, rate-limits in two different ways, and degrades individual GraphQL fields while returning 200. Every collector action in this plugin that touches the REST or GraphQL API follows the rules in this document, so that one bad byte never becomes a failed run, and a failed fetch never reads as a fact about the organization.

Cross-cutting: this spec governs `spec-github-core-v0.md`'s collector requirements wherever they reach the network, and any future GitHub-facing collector in this plugin. Where this spec and a per-surface requirement disagree about failure handling, this spec wins and the per-surface requirement is corrected.

**Sibling, not overlap:** this spec's job is *what to do when a call fails*. `tap_cares/specs/spec-tap-cares-progressive-collection.md` (2026-09-29) is the sibling spec for a different question this plugin's own `req-github-core-reliability-conditional` correctly flagged and declined to answer here — *which calls this collector should not be making at all*, because the object they'd fetch is already on the grid and known not to have changed. `req-github-core-reliability-conditional` is generalized there rather than duplicated; see that requirement's entry below for the concrete mapping.

## Philosophy

Three afternoons of evidence, 2026-09-11 and 2026-09-14 (github-core#128): a 504 "we couldn't respond to your request in time" fourteen seconds into a run; a connection GitHub closed after 186 seconds; a response body cut off at 219 of 248 kilobytes. Each aborted the whole collection. The collector had exactly one retry, for the empty-body 404 quirk, and the GraphQL client had none. Meanwhile a job orphaned by a worker restart sat in RUNNING for four days and blocked a dependent collector's every run, each skip recorded as green (tap#454, zizmor-tap#41).

The collector already does one of the three things reliability needs, and does it well: **three states, never two** — a refused read lands as `unobservable` with the status in a note, page and resolution caps are reported as budget facts, a degraded GraphQL field is pruned so a null never reads as an observation. What it lacks are the other two: **retry within a budget**, and **degrade per layer** — land what arrived, mark what did not as unobserved, continue.

Prior art shaped the rules (surveyed 2026-09-14): GitHub's own guidance (wait for `x-ratelimit-reset`; honor `Retry-After`; shrink GraphQL pages on "couldn't respond in time"); Octokit's retry and throttling plugins (retry 5xx and network errors, an explicit do-not-retry list, throttling kept separate from retry); AWS SDK standard retry mode (exponential backoff with full jitter and a retry budget so an outage does not amplify load); Google SRE practice (retry at one layer only); and Kubernetes controllers (level-triggered, idempotent reconcile — a failed pass is harmless because the next one re-observes, which tap#322 already rules for the grid: re-observation is not change). Retries turned out to be the smallest part. The larger parts are a budget so a bad day ends, and per-layer degradation so a run lands what it got.

One property this spec exists to protect for the work that follows it: **degradation is never absence.** Tombstoning — recording that a thing was confirmed removed — can only be trusted if a thing we failed to fetch is never mistaken for a thing that is gone (`req-github-core-reliability-absence`). A Monday like 2026-09-14, under a collector that tombstones on "not in the listing", would have deleted half the organization.

**Provenance markers.** Claims marked *observed* were measured on the demo-dev instance on 2026-09-14; the client comparison is from PyPI metadata and the libraries' source on that date; everything else is *designed*.

## Goals

| # | Name | Description |
| --- | --- | --- |
| 1 | One Bad Byte Never Fails A Run | Transient failures are retried within a budget; a layer that still fails degrades; only a foundation failure ends a run. |
| 2 | Degradation Is Never Absence | Anything not observed this run is marked not observed, per item and per surface, so no downstream pass reads a fetch failure as a removal. |
| 3 | Said Out Loud | Every retry, degradation and page change is a structured run record, and the run's summary counts them, so a flaky day is visible in the job and not only in a log. |
| 4 | One Seam | Every network call in the plugin goes through one client and one retry policy; callers never retry and never sleep. |
| 5 | Gather, Confirm, Process | The collector gathers, confirms the gather is reliable, then hands it to the processing layers above, which never touch the network and can run against stored gathers. |
| 6 | Professionals Maintain The Transport | The HTTP transport, typed endpoints, pagination, App auth and rate-limit detection come from GitHub's ecosystem client (githubkit); this plugin keeps only the policy and the semantics that are the product. |

## Requirements

| RID | Name | Status | Notes |
| --- | --- | :---: | --- |
| req-github-core-reliability-taxonomy | [Failure Taxonomy](#failure-taxonomy) | Proposed | Three classes — transient, terminal, partial — and the signal-to-class table |
| req-github-core-reliability-layers | [Gather, Confirm, Process](#gather-confirm-process) | Proposed | Three layers: the seam returns gathers; a gate admits only complete or pruned-partial gathers; processing imports no client and handles no transport failure |
| req-github-core-reliability-client | [The Access Client](#the-access-client) | Proposed | The recorded decision: githubkit through a thin seam; the three seams kept; the migration |
| req-github-core-reliability-retry | [Retry Policy](#retry-policy) | Proposed | Bounded retry with exponential backoff and full jitter, honoring GitHub's headers, covering the read, in the client only |
| req-github-core-reliability-budget | [Per-Run Budget](#per-run-budget) | Proposed | A retry budget and a wall-clock ceiling per run; exhaustion degrades, never spins |
| req-github-core-reliability-degrade | [Degrade Per Layer](#degrade-per-layer) | Proposed | Foundation layers abort; every other layer marks its surface unobserved and the run continues; a partial page lands what arrived |
| req-github-core-reliability-absence | [Degradation Is Never Absence](#degradation-is-never-absence) | Proposed | The contract tombstoning relies on: not fetched ≠ not present; incomplete surfaces are named on the run |
| req-github-core-reliability-adaptive-pages | [Adaptive GraphQL Pages](#adaptive-graphql-pages) | Proposed | Page halving on timeout with a floor, recorded |
| req-github-core-reliability-ratelimit | [Rate Limits](#rate-limits) | Proposed | Primary and secondary per GitHub's guidance; never burn to zero |
| req-github-core-reliability-observability | [Observability](#observability) | Proposed | Every retry, degrade and page change as a run record; counts in the summary |
| req-github-core-reliability-outcome | [Run Outcome](#run-outcome) | Proposed | What SUCCESSFUL and FAILED mean under degradation; single-flight per collector |
| req-github-core-reliability-proof | [Proof](#proof) | Proposed | A fake GitHub that emits every failure class; every layer proven to degrade |
| req-github-core-reliability-breaker | [Cross-Run Circuit Breaker](#cross-run-circuit-breaker) | Backlog | Stop calling a dependency that is down; needs state across runs |
| req-github-core-reliability-conditional | [Conditional Requests](#conditional-requests) | Backlog | Generalized into `tap_cares/specs/spec-tap-cares-progressive-collection.md`; this entry now names github_core's own per-entity application |

### Failure Taxonomy
----
RID: `req-github-core-reliability-taxonomy`

Status: `Proposed`

Every failure a network call can produce is one of three classes. The class decides what happens next; nothing else does.

| Class | Meaning | Signals |
| --- | --- | --- |
| **transient** | GitHub or the network failed to answer this time; the same request may succeed shortly | HTTP 500, 502, 503, 504; HTTP 429; **HTTP 403 carrying any rate-limit signal** — `x-ratelimit-remaining: 0`, a `Retry-After` header, or a rate-limit body (see the 403 rule below); connection refused / reset / closed without response; a truncated body (`IncompleteRead`, `RemoteProtocolError`); a client-side timeout; a GraphQL body whose only error is "couldn't respond to your request in time" or a `RATE_LIMITED` type; an HTTP 404 with an **empty** body (GitHub's undocumented quirk on `/actions/*` — a real 404 always carries `{"message": …}`) |
| **terminal** | The answer is an answer; asking again changes nothing | HTTP 400, 401, **403 carrying no rate-limit signal at all** (a permission refusal — see the 403 rule below), 404 with a body, 410, 422, 451; a GraphQL `FORBIDDEN` / `NOT_FOUND` / `INSUFFICIENT_SCOPES` error on a path |
| **partial** | GitHub answered, and part of the answer is missing or degraded | A 200 GraphQL response with `data` beside `errors[]` (a field the credential could not read arrives as `null` with an error entry); a REST listing whose walk stopped at the page cap |


#### The 403 rule (classifier precedence)

A 403 is the one status GitHub overloads across two unrelated meanings — *rate limited* and *not
permitted* — so the classifier states its own precedence rather than leaving it to be inferred from
two tables that can disagree.

**`Retry-After` is not the discriminator.** GitHub sends `Retry-After` on *secondary* rate limits.
A **primary** rate limit is `403` (or `429`) with `x-ratelimit-remaining: 0` and an
`x-ratelimit-reset`, and it typically carries **no** `Retry-After` at all. An implementation that
keys the split on `Retry-After` alone therefore classifies the ordinary primary-limit 403 as a
permission refusal: never retried, never waited on, surfaced as `unobservable`. That is the common
case rendered as the rare one, and it silently produces an absence claim from a credential that was
merely throttled.

Classify a 403 in this order, first match wins:

| # | Signal present | Class | Then |
| --- | --- | :---: | --- |
| 1 | `x-ratelimit-remaining: 0` (with or without `Retry-After`) | **transient** | Primary limit — the Rate Limits table's Primary row governs the wait |
| 2 | `Retry-After`, or a secondary-limit body | **transient** | Secondary limit — the Secondary row governs the wait |
| 3 | A **rate-limit body** (defined below) with no rate-limit header | **transient** | Treat as secondary; wait ≥ 60 s |
| 4 | None of the above | **terminal** | A genuine permission refusal |

**"Rate-limit body" is defined**, because an undefined term in a classifier is a decision left to
whoever implements it: a JSON body whose `message` contains `rate limit exceeded`,
`secondary rate limit`, or `abuse detection mechanism` — GitHub's three documented phrasings.
Matching is case-insensitive and substring-based; anything else is not a rate-limit body.

**Precedence is explicit:** where this rule and the [Rate Limits](#rate-limits) table could both
apply, this rule decides the *class* and the Rate Limits table decides the *wait*. They cannot
disagree, because they are no longer answering the same question.

Rules:

1. A **transient** failure is retried by the client under `req-github-core-reliability-retry` and, when the budget is spent, becomes a layer-level degradation under `req-github-core-reliability-degrade`.
2. A **terminal** failure is never retried. It is recorded with its status and body, and the surface it refused lands as `unobservable` with the status in its note — the existing three-state discipline (`spec-github-core-v0.md`, refused is not empty).
3. A **partial** answer lands what arrived; the degraded paths are pruned (never left as `null`) and recorded as notes, exactly as `graphql_client.prune_errored_paths` does today; a capped walk is reported as incomplete with the count left behind.
4. The classification lives in one function in the client seam and nowhere else. A caller that inspects a status code to decide whether to retry is a defect.
5. **The table is closed by defaults, not by omission.** Anything not listed maps as follows: an unlisted HTTP status is **terminal** (asking again is not known to help); an unlisted transport exception is **transient** once and then terminal (one retry proves it is not a blip); an unlisted GraphQL error type is **partial** when `data` is present and **terminal** when it is not; an exception the seam did not anticipate at all is neither — it propagates and fails the run closed (`req-github-core-reliability-outcome`), and the run record names the exception type so the table can grow.
6. **GraphQL error types, mapped.** `RATE_LIMITED` → transient (rate-limit path); "couldn't respond to your request in time", `MAX_NODE_LIMIT_EXCEEDED`, `EXCESSIVE_PAGINATION` → transient with page reduction (`req-github-core-reliability-adaptive-pages`); `FORBIDDEN`, `NOT_FOUND`, `INSUFFICIENT_SCOPES`, `UNPROCESSABLE` on a path → partial when `data` is present (the path is pruned and noted), terminal when the whole response has no `data`. **Precedence:** a 200 with `data` and `errors[]` is partial regardless of the error types, except that a `RATE_LIMITED` entry makes the *next* request subject to the rate-limit rule.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-reliability-taxonomy-1 | One Classifier | Proposed | A single function maps any exception or response the client can produce to `transient` / `terminal` / `partial`; every signal in the table has a unit test. | |
| req-github-core-reliability-taxonomy-2 | Empty-404 Folded In | Proposed | The empty-body 404 is one row of the transient class, retried by the general policy; the bespoke `_EMPTY_404_*` loop in `api_client.py:36–143` is removed. | Its detection rule (empty body vs `{"message"}` body) survives as the classifier's rule. |
| req-github-core-reliability-taxonomy-3 | Terminal Never Retried | Proposed | A 401, a bodied 404, a 422 and a permission 403 (one carrying **no** rate-limit signal) each produce exactly one request in the proof harness. | |
| req-github-core-reliability-taxonomy-5 | Primary-Limit 403 Is Transient | Proposed | A 403 with `x-ratelimit-remaining: 0` and `x-ratelimit-reset` and **no** `Retry-After` is classified transient and waits to the reset — it is never recorded as a permission refusal. | The common primary-limit shape; the failure this rule exists to prevent |
| req-github-core-reliability-taxonomy-6 | Rate-Limit Body Recognised | Proposed | A 403 with no rate-limit header whose JSON `message` contains `rate limit exceeded`, `secondary rate limit` or `abuse detection mechanism` is classified transient. | Case-insensitive substring |
| req-github-core-reliability-taxonomy-7 | Foundation Terminal Aborts | Proposed | A terminal 401 on credential resolution, and a permission 403 on the repository listing, each end the run FAILED — never a completed run reporting zero repositories. | The absence-contract hole |
| req-github-core-reliability-taxonomy-4 | Closed By Defaults | Proposed | An unlisted status (e.g. 418), an unlisted transport exception and an unanticipated exception each take the default path in rule 5, and the run record names the unmapped signal. | |
| req-github-core-reliability-taxonomy-5 | GraphQL Types Mapped | Proposed | Each GraphQL error type in rule 6 classifies as stated; a 200 with data and a `FORBIDDEN` path lands the data with the path pruned. | |

### Gather, Confirm, Process
----
RID: `req-github-core-reliability-layers`

Status: `Proposed`

George, 2026-09-14: "bake this as a layered approach — the collector gathers data, confirms it's reliable, then hands that data to the processing layers above it which act on it." Today fetching and shaping interleave: a method calls GitHub, shapes the answer into envelopes and moves on, so a transport failure surfaces in the middle of processing code and a shaper has to know what a 504 is. Under this requirement the run is three layers with one job each:

| Layer | Job | Owns | Never |
| --- | --- | --- | --- |
| **Gather** | Talk to GitHub through the seam and return a **gather**: the exact bytes received, the parsed body, and the facts about the fetch — `surface`, `scope` (account or repository), `endpoint` template, `complete` (walk ran to the end, no degradation, no cap), `degraded_paths` (pruned GraphQL paths with their notes), `class` of any terminal failure, `status`, `digest` (sha256 of the bytes), `observed_at`, `credential_kind`, `rate_limit` snapshot | The only code in the plugin that imports the client or sees a transport exception | Shapes anything |
| **Confirm** | The gate between gather and process: admit a gather that is `complete`, or partial with every degraded path pruned and named; refuse an incomplete or failed gather, marking its surface not observed this run (`req-github-core-reliability-absence`) and recording why | The completeness check, the `INCOMPLETE_SURFACES` record | Lets a refused gather reach a shaper |
| **Process** | Shapers and decomposers turn admitted gathers into node and edge envelopes and the GRIFT batch | Identity, decomposition, three-state fields on nodes | Imports a client, catches an HTTP or transport exception, sleeps, or reads the network |

Consequences that fall out, and are the reason for the shape:

1. **Replay.** Processing runs unchanged against stored gathers — a regression corpus from real responses (the zizmor corpus pattern), an offline re-derivation for stale-edge reassessment (tap#447), a diagnosis of a bad day from the bytes rather than a traceback.
2. **Evidence for free.** A gather *is* the audit record: bytes plus digest plus request facts. Retaining gathers is a storage decision (a tap_cares capability, its own spec), not a collector change; the hook is the gather object.
3. **The dcom line in code.** A gather is an `operation` — it happened once and is immutable; processing is a derivation from it. What the reliability rules protect (retry, budget, degrade) is entirely inside Gather; what the absence contract protects is entirely at Confirm.
4. **Foundation stays foundation.** The account and repository listings are gathers like any other, but Confirm refuses a partial one absolutely (`req-github-core-reliability-degrade` rule 1's exception): the run aborts rather than processing a shrunken set.

#### Implementation

`collectors/github_collector/gather.py` — the `Gather` dataclass and the seam's return type; `github_call.py` returns gathers. `collector.py`'s run becomes, per layer: gather → confirm → process, with the confirm step one function (`admit(gather) -> Admitted | Refused`) that writes the absence records. Existing shapers (`graphql_client.py`'s `refs` / `rulesets` / `environments` / `releases` / `workflow_files`, `parser.py`, `enrichment.py`, the per-surface builders in `collector.py`) move behind the gate and lose every `try/except GithubAPIError` and every status-code branch they carry today; those branches become Confirm's job.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-reliability-layers-1 | Gather Carries Its Facts | Proposed | Every gather the seam returns has `surface`, `scope`, `endpoint`, `complete`, `degraded_paths`, `digest`, `observed_at`, `credential_kind`; the digest equals sha256 of the stored bytes. | |
| req-github-core-reliability-layers-2 | Processing Is Network-Blind | Proposed | A test walks every processing module and fails if one imports the client, `urllib`, `httpx` or githubkit, or catches `GithubAPIError` / `GithubGraphQLError` / an HTTP exception. | Mechanical; runs in CI. |
| req-github-core-reliability-layers-3 | Only Admitted Gathers Are Processed | Proposed | In the proof harness an incomplete gather never reaches a shaper (the shaper is a spy), its surface is marked not observed, and `INCOMPLETE_SURFACES` names it; a partial gather reaches the shaper with its degraded paths pruned. | |
| req-github-core-reliability-layers-4 | Replayable | Proposed | The processing layer, fed the gathers recorded from one harness run, produces a byte-identical GRIFT batch (ids and content) to the live run. | The replay corpus is the evidence store's first consumer. |

### The Access Client
----
RID: `req-github-core-reliability-client`

Status: `Proposed`

**Decision (George, 2026-09-14): githubkit, through a thin seam of this plugin's own.** Recorded here with the comparison, per the build-collector skill's Step 1.5, because the previous choice — two hand-rolled clients on `urllib` — was made by default under the no-new-dependency rule and never written down, and three weeks later the collector had grown its own pagination, App-JWT exchange and (one) retry, with zero retries where it mattered.

| Axis | Ours (`api_client.py`, `graphql_client.py`, `app_jwt.py`) | githubkit 0.16.1 | PyGithub 2.10.0 |
| --- | --- | --- | --- |
| Three-state fidelity | Purpose-built; GraphQL partial errors pruned so data survives | REST exceptions carry status, headers, body. GraphQL helper raises on any error and discards partial data — bypassable by posting raw | Object layer wraps 404 into typed exceptions with status and body; GraphQL minimal |
| Free of charge | Empty-body-404 retry only | 5xx retry (3, quadratic backoff, no jitter); rate-limit detection (primary vs secondary, typed, with the wait); pagination; App auth (JWT mint, cache, installation exchange); typed REST from GitHub's OpenAPI; sync + async. Retry hook pluggable | 5xx and Retry-After 403 via urllib3 Retry; rate-limit waits; App auth; sync only |
| Coverage | Exactly what we wrote | Full REST, GraphQL with pagination, GHES base URL | Full REST object model; GraphQL barely |
| Dependencies | `cryptography` | httpx, httpcore, anyio, certifi, idna, hishel, msgpack, pydantic, pydantic-core, typing-extensions, githubkit-schemas; `+ pyjwt[crypto]` → `cryptography` for App auth (~12) | requests, urllib3, pyjwt, `cryptography`, typing-extensions, **pynacl** |
| FIPS | Clean | Clean: httpx uses the stdlib `ssl` module; pydantic-core is Rust without crypto; pyjwt signs through `cryptography` on the validated system-OpenSSL path this plugin already uses | **pynacl bundles libsodium** — a non-validated provider, never called by us, but a declared posture and a `ci` waiver would be required |
| Maintenance | Us | MIT; 345 stars, 29 contributors, 25 commits / 90 d, pushed 2026-09-13, 7 open issues; Octokit-inspired; schemas regenerated from GitHub's API description | LGPL-3.0; 7,772 stars, 100 contributors, 22 commits / 90 d, 405 open issues |
| Supply chain | n/a | dist `githubkit` on PyPI ↔ `yanyongyu/githubkit` (verified 2026-09-14); pin `>=0.16,<1` in `pyproject`, Renovate-tracked; advisory check: none open on the dist or its set as of 2026-09-14 — **re-check at adoption** | dist `PyGithub` ↔ `PyGithub/PyGithub` |
| Async | No | Yes | No |

gidgethub (async-only, no retry, last release 2025-06) and ghapi (REST-only, own HTTP stack) were considered and dropped.

**The three seams this plugin keeps**, because they are the product and a library rightly does not have them:

1. **GraphQL is posted through githubkit's generic request, not its GraphQL helper**, and this plugin's `prune_errored_paths` keeps doing partial-error handling: the helper raises when any error is present and throws the data away. (Upstream contribution candidate: a flag returning `data` beside `errors`.)
2. **The retry decision function is ours** (`req-github-core-reliability-retry`), handed to githubkit's `auto_retry` hook: its default covers 5xx and rate limits only, without jitter, and does not retry network errors or truncated reads.
3. **Three-state semantics stay in the collector**, unchanged: the library changes how bytes arrive, not what refused means.

#### Implementation

Migration, one PR per step, each behind the proof harness (`req-github-core-reliability-proof`) so behaviour is pinned before the engine changes:

1. Land the seam: a `github_call` module owning the classifier, the retry decision function, the budget and the run-record hooks — over the existing `urllib` clients first.
2. Swap the REST transport to githubkit (`api_client.py` → thin adapter or deletion); pagination and App auth (`app_jwt.py`) move to githubkit's `AppAuth`.
3. Swap the GraphQL transport (`graphql_client.py` keeps its queries, shapers and pruning; `_post` becomes a githubkit raw request).
4. `pyproject`: `githubkit[auth-app]>=0.16,<1`; manifest `[fips]` re-verified by `validate_plugin --strict`'s crypto-providers scan; `ci` record unchanged unless the scan says otherwise.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-reliability-client-1 | Decision Recorded | Implemented | The comparison table above, with the losers named and the supply-chain row dated. | This section. |
| req-github-core-reliability-client-2 | One Transport | Proposed | After migration no module in the plugin imports `urllib.request`; every request goes through githubkit under the seam. | |
| req-github-core-reliability-client-3 | Seams Hold | Proposed | GraphQL partial responses still land pruned data (proof harness); the retry decision function in use is this plugin's; refused / absent / degraded remain distinguishable on every surface `spec-github-core-v0.md` marks three-state. | |
| req-github-core-reliability-client-4 | FIPS Clean After | Proposed | `validate_plugin --strict` reports `[fips] compatible` with no non-validated provider found after the dependency lands. | |

### Retry Policy
----
RID: `req-github-core-reliability-retry`

Status: `Proposed`

Retry happens in exactly one place — the client seam — for exactly one class — transient — and always within the run's budget.

| Parameter | Value | Why |
| --- | --- | --- |
| Attempts per call | 4 (1 + 3 retries) | Octokit and AWS both settle at three retries; more masks an outage rather than surviving a blip |
| Backoff | Exponential, base 1 s, cap 30 s, **full jitter** (`random(0, min(cap, base·2ⁿ))`) | AWS standard mode; jitter keeps a fleet from retrying in lockstep |
| Header override | `Retry-After` (seconds or HTTP date) and `x-ratelimit-reset` win over the computed backoff when present — **if the wait fits the run's remaining wall clock**; otherwise the call degrades with reason `rate_limited_until <time>` instead of sleeping | GitHub's own instruction beats our guess; the run's deadline beats GitHub's |
| Per-request timeouts | Connect 10 s, read 60 s, and a whole-call ceiling of `min(120 s, remaining wall clock)` | A hung body read must not eat the run (today: 30 s REST / 60 s GraphQL with no read ceiling) |
| Sleeps are bounded | Every sleep is `min(computed, remaining wall clock)`; a sleep that would cross the deadline is not taken — the call degrades | The 20-minute ceiling is a deadline, not a hope |
| Scope | Wraps the request **and the read** of the body | 2026-09-14's `IncompleteRead` escaped the client entirely: it is an `http.client.HTTPException`, not a `URLError` |
| Idempotency | Every call this plugin makes is a read; re-issuing is safe. A future write goes through the seam with `retries=0` unless idempotent by construction | tap#322: re-observation is not change |
| Callers | Never retry, never sleep. A `for attempt in` outside the seam is a defect | One layer only (SRE practice) |

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-reliability-retry-1 | Transient Retried, Bounded | Proposed | A call that fails transiently three times then succeeds returns the success; one that fails four times raises to the layer as exhausted. | Proof harness. |
| req-github-core-reliability-retry-2 | Jittered Backoff | Proposed | Across 1,000 simulated retries at attempt n the sleeps are distributed over `[0, min(30, 2ⁿ)]`, never a constant. | |
| req-github-core-reliability-retry-3 | Headers Win | Proposed | A 403 with `Retry-After: 7` sleeps 7 s (±jitter policy: none — the header is exact); a 429 with `x-ratelimit-reset` sleeps to the reset. | |
| req-github-core-reliability-retry-4 | The Read Is Covered | Proposed | A body truncated mid-stream is classified transient and retried; it never escapes as a raw `http.client` or `httpx` exception. | Regression for 2026-09-14. |
| req-github-core-reliability-retry-5 | Deadline Wins | Proposed | A `Retry-After: 1800` arriving with 5 minutes of wall clock left produces no sleep and a degradation with `rate_limited_until`; a body read stalled 90 s is timed out and classified transient. | |

### Per-Run Budget
----
RID: `req-github-core-reliability-budget`

Status: `Proposed`

A bad day must end. Two ceilings per run, both recorded on the job:

| Budget | Value | On exhaustion |
| --- | --- | --- |
| Retries per run | 30 | Further transient failures are not retried; each becomes an immediate layer degradation (`req-github-core-reliability-degrade`) with reason `budget_exhausted` |
| Wall clock per run | 20 minutes (healthy runs *observed* 4–9 min on 26 repos, 2026-09-14) | The layer in flight degrades; remaining layers are skipped and marked not observed; the run ends and says so |

Both values are module constants for v0, read by the seam alone, and reported in the run's `RUN_STARTED` record so a reader knows the ceilings that applied.

**The ceiling is enforceable, not advisory.** The seam computes `remaining = deadline − now` before every request, every sleep and every read, and caps each of them by it (`req-github-core-reliability-retry`); no single operation may run past the deadline by more than the per-request read timeout. A run therefore ends within `wall_clock + 60 s` in the worst case, and the single-flight orphan threshold (`req-github-core-reliability-outcome`) is set above that bound so a live run at its ceiling is never mistaken for an orphan.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-reliability-budget-1 | Retry Budget Ends Retrying | Proposed | After 30 retries in one run the next transient failure produces one request and a degradation record, not a sleep. | |
| req-github-core-reliability-budget-2 | Wall Clock Ends The Run | Proposed | A run whose layers stall past 20 minutes ends within 60 s of the ceiling with every unfinished surface marked not observed; a sleep or read that would cross the deadline is not started. | |

### Degrade Per Layer
----
RID: `req-github-core-reliability-degrade`

Status: `Proposed`

The collector's run is a sequence of layers (auth; repository listing; GraphQL config layer; GraphQL pull-request layer; per-repository REST surfaces — workflows, runs, jobs, artifacts, packages, rulesets, secrets, environments, alerts …). Today an exhausted failure in any of them aborts the run (`collector.py:830` `_abort`, called from `_fetch_config_layer` and `_fetch_pull_request_layer` among others). Under this requirement:

| Layer kind | Members | On exhausted transient failure |
| --- | --- | --- |
| **Foundation** | Credential resolution / App token; the account and repository listing | Abort the run (`_abort`). Nothing downstream can be placed without them, and a partial repository listing would silently shrink the org — see `req-github-core-reliability-absence`. |
| **Everything else** | Every other layer and every per-repository surface | Mark the surface `unobservable` for this run with reason and status in the note (per repository where the surface is per-repository), record a `LAYER_DEGRADED` warning, and **continue**. |

Rules:

1. A layer that fails **after landing some pages** keeps what arrived: those repositories' data is observed, the rest are marked not observed for that surface. A cursor position is a fact; the run records how far it got. **Except foundation:** a partial account or repository listing is never persisted and never used to scope the run — a listing that did not complete aborts (`degrade-1`), because a shrunken repository set would read as repositories gone (`req-github-core-reliability-absence`).
2. Layers are independent: the pull-request layer failing does not prevent the REST surfaces from running.
3. Degradation is per run. The next run re-observes from scratch; nothing is remembered as "known bad" (that is the Backlog breaker).

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-reliability-degrade-1 | Foundation Aborts | Proposed | A repository listing that fails after budget produces a FAILED run with one error record and no partial repository set. | |
| req-github-core-reliability-degrade-2 | Others Continue | Proposed | Each non-foundation layer, failed after budget in the proof harness, yields a run that completes, marks that surface unobservable with a reason, and lands every other layer. | One test per layer. |
| req-github-core-reliability-degrade-3 | Partial Page Lands | Proposed | A GraphQL walk that fails on page 3 of 5 lands pages 1–2's repositories as observed and marks the remainder not observed for that layer, with the cursor position in the record. | |

### Degradation Is Never Absence
----
RID: `req-github-core-reliability-absence`

Status: `Proposed`

The contract every downstream pass — tombstoning first among them — relies on:

1. **Not fetched is not not-present.** An item the run did not observe because its surface degraded, its walk was capped, its layer was skipped by the wall clock, or its read was refused is marked *not observed this run*; it is never omitted silently and never marked absent, removed or empty.
2. **Absence is a positive observation.** Only a surface whose listing **completed** (walk complete, no degradation, no cap) may assert that an item is not in it. The run record carries, per surface, `complete: true|false` — the field a tombstone pass reads before it trusts a missing item.
3. **Surfaces incomplete this run are named** in the run's summary and in a structured `INCOMPLETE_SURFACES` record listing each `(surface, scope, reason)`, so a reader or an agent can skip them without parsing prose.
4. **A FAILED run asserts nothing about absence.** Its partial batches, if linked, are additive observations only.

This requirement is the seam between this spec and the tombstoning design (George, double-tap session, 2026-09-14): a removal is confirmed only against a complete listing, never against a degraded one.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-reliability-absence-1 | Completeness Per Surface | Proposed | Every listing surface the run touches reports `complete: true|false` with a reason when false, in a structured run record. | |
| req-github-core-reliability-absence-2 | No Silent Omission | Proposed | In the proof harness, a degraded surface leaves every previously-known item of that surface marked not-observed-this-run, never absent; the batch contains no deletion or "empty" assertion for it. | |
| req-github-core-reliability-absence-3 | Incomplete Surfaces Listed | Proposed | The run summary names the count of incomplete surfaces and the `INCOMPLETE_SURFACES` record lists them. | |

### Adaptive GraphQL Pages
----
RID: `req-github-core-reliability-adaptive-pages`

Status: `Proposed`

GitHub's "couldn't respond to your request in time" is a statement about the query's cost, and its documented remedy is smaller pages. The config layer asks for 100 repositories per page with nested rulesets, rules, bypass actors, environments, 100 refs, 50 releases with assets and the full workflow-file tree (`graphql_client.py:50` `_REPO_PAGE_SIZE = 100`, `:99–190`); the pull-request layer asks 5 repositories × 30 PRs × checks. On a 504 or timeout classified transient for a GraphQL call, the seam halves the outermost page size before the retry — 100 → 50 → 25 → 10 (floor) — keeps the reduced size for the rest of that layer in that run, and records the change. The floor exhausted is a transient failure like any other and degrades per `req-github-core-reliability-degrade`.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-reliability-adaptive-pages-1 | Halve On Timeout | Proposed | Two consecutive 504s on a 100-repository page yield the third request at 25; a fake that serves 25-repository pages then completes the layer SUCCESSFUL. | |
| req-github-core-reliability-adaptive-pages-2 | Recorded | Proposed | The run carries a `PAGE_SIZE_REDUCED` record per reduction with layer, from, to. | |

### Rate Limits
----
RID: `req-github-core-reliability-ratelimit`

Status: `Proposed`

Per GitHub's guidance, which githubkit's detection already distinguishes:

| Limit | Signal | Behaviour |
| --- | --- | --- |
| Primary | 403/429 with `x-ratelimit-remaining: 0` | Wait until `x-ratelimit-reset` if that is within the run's remaining wall clock; otherwise stop the layer with reason `rate_limited_until <reset>` and degrade — never spin, never burn |
| Secondary | 403/429 with `Retry-After`, or a secondary-limit body | Wait `Retry-After` (else ≥ 60 s), **at most twice per run**; a third is `budget_exhausted` |
| Approaching | `x-ratelimit-remaining` below 5 % of `x-ratelimit-limit` on any response | Record `RATE_LIMIT_LOW` once; the seam may pause until reset if within wall clock |

Every response's `remaining` / `cost` (GraphQL `rateLimit`) is read and the run's final record reports the points spent (the config layer already reports cost).

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-reliability-ratelimit-1 | Primary Waits Or Stops | Proposed | A primary limit with reset in 40 s waits then continues; one with reset in 40 min degrades the layer with the reset time in the reason. | |
| req-github-core-reliability-ratelimit-2 | Secondary Twice | Proposed | Two secondary limits in a run are waited; the third degrades. | |

### Observability
----
RID: `req-github-core-reliability-observability`

Status: `Proposed`

Every decision the seam makes is a structured record on the run (`record_info` / `record_warn` with `message_code` and `message_data`), never only a log line:

| Code | Level | When | Data |
| --- | --- | --- | --- |
| `RETRY` | info | Each retry | layer, endpoint template, class, attempt, sleep_seconds, status |
| `PAGE_SIZE_REDUCED` | info | Each halving | layer, from, to |
| `LAYER_DEGRADED` | warn | A layer or per-repo surface gives up | layer, scope, reason (`budget_exhausted` / `wall_clock` / `rate_limited_until` / `terminal <status>`), pages_landed |
| `INCOMPLETE_SURFACES` | warn | End of run when any | list of (surface, scope, reason) |
| `RATE_LIMIT_LOW` | warn | Once per run | remaining, limit, reset |
| `RUN_BUDGET` | info | Run start and end | attempts_per_call, retry_budget, wall_clock, retries_used, seconds_used, points_spent |

**Redaction is part of the record shape.** Records name the **endpoint template** (`/repos/{owner}/{repo}/actions/runs`, `graphql:config_layer`), never a full URL with its query string; GraphQL variables are never recorded except `login` and a cursor; error bodies are recorded as GitHub's `message` field only, truncated to 200 characters, or as `<non-JSON body, N bytes>`; no header is ever recorded (`Authorization`, `Retry-After` and rate-limit values are copied into typed fields, not as header dumps); a URL that carries a signature or token (artifact download redirects) is recorded as its template plus `signed_url: true`. The same rule already governs the existing `record_*` callers; this makes it a requirement the proof harness checks.

The run's `summary` ends with the counts: `… ; N retries, M surfaces degraded` (omitted when both are zero), so the collector table reads a flaky day at a glance.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-reliability-observability-1 | Records Present | Proposed | The proof harness's degraded run carries every applicable code above with the listed data keys. | |
| req-github-core-reliability-observability-2 | Summary Counts | Proposed | A run with 3 retries and 1 degraded surface ends its summary with `; 3 retries, 1 surface degraded`; a clean run's summary is unchanged. | |
| req-github-core-reliability-observability-3 | Redacted | Proposed | With the fake emitting a signed redirect URL, a 500 with a 5 KB HTML body and a 403 with a JSON message, the run's records contain the endpoint template, `signed_url: true`, `<non-JSON body, 5120 bytes>` and the 403's `message` — and no query string, header or token anywhere in `results`. | |

### Run Outcome
----
RID: `req-github-core-reliability-outcome`

Status: `Proposed`

Composes with tap_cares' failure-mode convention (`req-tap-cares-collector-failure-mode-1..7`): `record_error` + raise is how a run fails; one terminal write; the collector sets `summary`.

| Outcome | When | Summary |
| --- | --- | --- |
| **SUCCESSFUL** (clean) | Every layer complete | As today |
| **SUCCESSFUL** (degraded) | Any non-foundation layer degraded, or any surface incomplete | Today's counts plus `; N retries, M surfaces degraded` and the `INCOMPLETE_SURFACES` record. No new `CollectionJob` status — a distinct status would touch tap_cares for every plugin; the count and the record are the marker |
| **FAILED** | A foundation layer failed **for any reason** — terminal, exhausted-transient, or partial; or an unclassified exception | `_abort` as today; partial batches linked additively; asserts nothing about absence |

**Foundation failure aborts regardless of class.** This is the one place the taxonomy does *not*
decide what happens next, and it is stated here because reading the taxonomy alone gives the wrong
answer. A terminal failure normally means "record it, mark the surface unobservable, carry on" — but
on a foundation layer (credential resolution, the account listing, the repository listing) there is
no surface left to carry on with. An unusable token (`401`), or a permission refusal on the
repository listing (a `403` that reaches rule 4 of [The 403 rule](#the-403-rule-classifier-precedence)),
would otherwise produce a run that lands zero repositories, completes, and reports `SUCCESSFUL
(degraded)` — a run asserting the absence contract over data it never had the right to read. That is
the most reassuring possible output from a credential that simply could not look.

So: on a foundation layer, every failure class ends the run. `exhausted transient` aborts (Goal 1),
`partial` aborts (`degrade` rule 1), and `terminal` aborts by this rule. A foundation layer has no
degraded state, because there is no such thing as a partly-known repository set that is safe to
scope a run with.


**Single-flight, acquired atomically.** Mutual exclusion is an *acquisition*, not a check: at run start the seam takes a database lock on the collector's own row (`SELECT … FOR UPDATE` on the `Collector` node via the service layer) and, inside that lock, looks for a sibling job in `RUNNING` younger than the **orphan threshold** (`wall_clock + 5 min`, above the enforceable bound in `req-github-core-reliability-budget`). A fresh sibling → this run records `RUN_SKIPPED_CONCURRENT` and exits SUCCESSFUL with that summary. A sibling older than the threshold is presumed orphaned (tap#454): the skip is recorded with its age and this run proceeds. Two runs starting simultaneously serialize on the lock, so exactly one proceeds. The lock is held only for the check, never for the run. *Observed 2026-09-14:* a manual and a scheduled run overlapped for two minutes with no guard. If tap_cares lands a generic single-flight (tap#454), this requirement delegates to it and keeps only the threshold.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-reliability-outcome-1 | Degraded Is Successful And Says So | Proposed | A run with one degraded layer ends SUCCESSFUL, its summary carries the counts, and the `INCOMPLETE_SURFACES` record is present. | |
| req-github-core-reliability-outcome-2 | Foundation Fails The Run | Proposed | A listing failure after budget ends FAILED with one error record. | |
| req-github-core-reliability-outcome-3 | Single-Flight | Proposed | With a fresh RUNNING sibling the run skips and says so; with a stale one (older than the orphan threshold) it proceeds and records the presumed orphan. | |
| req-github-core-reliability-outcome-4 | Mutual Exclusion Under Simultaneous Start | Proposed | Two runs started in the same second against a locked test database yield exactly one proceeding and one `RUN_SKIPPED_CONCURRENT`, in either order. | |

### Proof
----
RID: `req-github-core-reliability-proof`

Status: `Proposed`

A fake GitHub (`tests/fake_github.py`) — an in-process HTTP server or a githubkit transport stub — scripted per test to emit each taxonomy signal at a chosen call: 504, 502, 429 with headers, 403 with and without `Retry-After`, empty-body 404, bodied 404, connection reset, truncated body, timeout, GraphQL "couldn't respond in time", GraphQL partial errors, a capped walk. The collector runs against it (via `__new__` construction as the existing tests do) and every acceptance criterion above that names the proof harness is a test in `tests/test_reliability.py`. The harness records every gather a run produces so `req-github-core-reliability-layers-4` can replay them. It is also the acceptance test for the githubkit migration: the same tests pass before and after each step of `req-github-core-reliability-client`.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-github-core-reliability-proof-1 | Every Signal Scripted | Proposed | The fake can emit every signal in the taxonomy table on demand, at a chosen call index. | |
| req-github-core-reliability-proof-2 | Every Layer Degrades | Proposed | One test per non-foundation layer proves it degrades and the run continues. | |

### Cross-Run Circuit Breaker
----
RID: `req-github-core-reliability-breaker`

Status: `Backlog`

When GitHub is down, every scheduled run spends its full budget discovering that. A breaker remembers the last run's outcome per layer and, after N consecutive exhausted failures, skips the layer for a cooling period with a `LAYER_SKIPPED_BREAKER` record, probing again after it. Needs state across runs (a fact on the collector node, or the last job's records) that the collector does not read today. Enter a sprint after two flaky days have been observed under the v0 rules.

### Conditional Requests
----
RID: `req-github-core-reliability-conditional`

Status: `Backlog`

`If-None-Match` / ETag on the REST surfaces: a 304 costs no rate-limit points. This was correctly named here as "an efficiency edge, not a reliability one" and left unbuilt; it is now specified generally at `tap_cares/specs/spec-tap-cares-progressive-collection.md`, whose mutability classification (`req-tap-cares-progressive-classification`) this plugin is the first concrete consumer of. githubkit's cache layer (hishel) may give a form of this for free once `req-github-core-reliability-client`'s migration lands — measure the points a healthy run spends first, per that spec's instrumentation requirement (`req-tap-cares-progressive-instrumentation`), before assuming it does.

**github_core's own entities, classified** *(observed against the `git-serious` dev stack,
2026-09-29 — see `github-core-tap#209`'s sibling investigation for the corpus this is sized
against)*:

| Entity | `MUTABILITY_CLASS` | Applicable mechanism |
| --- | --- | --- |
| `github_actions_run`, `github_actions_job` | `FROZEN_AT_TERMINAL` (`status="completed"`) | Already implemented, unlabeled: `req-tap-cares-progressive-watermark`'s two-part shape (`collector.py:6864-6952`) |
| `code_scanning_analysis`, `rule_suite`, `commit_observation` | `FROZEN` | `req-tap-cares-progressive-watermark` — not yet adopted; each still re-walks its full (capped) listing every run |
| `actions_artifact` | `FROZEN_CONTENT_REVOCABLE`, `SORT_KEY_MONOTONIC=True` (newest-first by creation) | `req-tap-cares-progressive-cutoff` — safe once adopted; content is immutable and the listing order is creation-based |
| `actions_cache` | `FROZEN_CONTENT_REVOCABLE`, `SORT_KEY_MONOTONIC=False` (most-recently-*accessed*-first) | Cutoff is **not safe** here — needs a true watermark (`req-tap-cares-progressive-watermark`) instead; this is the taxonomy's own worked counter-example |
| `github_workflow` (YAML body) | `VERSIONED_CONTENT` (`FINGERPRINT_FIELD` = the Contents API's blob `sha`, not yet stored) | `req-tap-cares-progressive-secondary-skip` — the single cheapest win available: 250 workflows *(observed)*, each unconditionally refetched in full today (`collector.py:6987`) |
| `pull_request` | `MUTABLE`, with `updated_at` as an existing freshness ordering (`graphql_client.py:233`, already `orderBy: {field: UPDATED_AT, direction: DESC}`) | Not skippable, but the existing ordering is exactly what a freshness-bounded re-check (`req-tap-cares-progressive-cutoff`'s freshness-field variant) would key on once wired up |
| `code_scanning_alert` | `MUTABLE` (state can legitimately change: open/dismissed/fixed) | Not a candidate for any mechanism in the progressive-collection spec. Separately worth its own look regardless: today's walk pages up to 100 times with no `state` filter passed (`collector.py:4629`, `4826`), a likely larger and unrelated win |
| `github_environment`, `github_ruleset`, `github_runner`, `actions_secret` | `MUTABLE` | No skip; unchanged from today |

None of the above is implemented by this entry — it is the classification `req-tap-cares-progressive-classification` asks every collector to write down, done here as the first worked application, so the general spec is reviewed against a real case rather than in the abstract.
