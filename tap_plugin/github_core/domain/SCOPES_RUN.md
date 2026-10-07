# SCOPES_RUN

## Blurb

A `collection_scope` is the statement about one collection run. Exactly one per run, pointing from the scope to the core `collection_job` it is about.

## Purpose

The run record (`collection_job`) says what happened; the scope says what the run was *allowed* to see. They are different objects with different lifetimes — the job is owned by tap_cares' runtime and written only at terminal state, the scope is a github_core fact established before the walk and patched as tiers complete — and the join between them has to be an edge, because a field on either side would put a plugin's fact on a core type or a core id on a plugin type without a traversable relationship.

What the edge buys is the two questions the falsifier and the operator both ask: *for this run, what could it see?* (job → scope, by reversing the edge) and *for this scope statement, which run made it, and did that run finish?* (scope → job, then the job's `status`). A scope whose job never reached terminal state is a scope whose tier verdicts stop early — and the edge is how a reader finds that out rather than trusting the verdicts that are there.

## Goals

1. Attach every scope statement to exactly one run, by the run's own entity id.
2. Let the tombstone pass find a run's scope in one hop before it weighs an absence.
3. Keep scope facts off `collection_job` and run facts off `collection_scope`.

## Identity

Derived: `uuid5(ns, "edge:SCOPES_RUN__github_core:<scope_uuid>:<job_uuid>")` via `identity.edge_id`. Both ends are deterministic — the scope id is minted from the job id — so the edge is too.

## Boundaries

- **Not the batch link.** `collection_job --PRODUCED_BATCH--> batch` is tap_cares' correlation between a run and what it imported; the scope's own batch is one of those. This edge is about the statement, not the import.
- **Not a claim about completeness.** That the scope exists says the run established its reach; whether the run then read everything is `tiers`, written later.
- **Not a plugin edge onto a plugin type.** The target is a CORE type, addressed by its `ENTITY_TYPE` string (`collection_job`); github_core declares it in `targets` and never imports the model. `collection_job` is `INTERNAL_ONLY` for node writes; an inbound edge from a plugin node is permitted by the edge's own declared targets (permission union), and the job already exists when the scope batch lands because `run_collection` creates it before the collector starts.

## Neutrality

Neutral in concept — any collector against any source could state its reach per run and point at the run — and neutral in target: `collection_job` is core. Only the source is GitHub-shaped. When a substrate scope type is extracted this edge moves with it unchanged.

## Observability

Emitted with the scope node, in the scope's own batch, before the walk — one edge per run, always, because the job id is handed to the collector in `CollectorConfig` and needs no read. Executed 2026-09-15 on the `gc-scope-node` stack: one edge from scope `e046db5f-…` to `collection_job` `01a0a2ce-…`, in the scope's own batch, resolving against the on-grid job under strict dangling-edge mode (the job existed 3 s before the scope batch landed).

**Absence shape:** absent only when the scope node is absent, i.e. the run aborted before establishing its scope (secret resolution or App authentication failed). Never absent for a run that walked anything.

## Authoritative Source

- **Source:** TAP — `tap_cares/specs/spec-tap-cares-collector.md` (`collection_job`, `CollectorConfig.collection_job_entity_id`), the id this edge targets
- **Version:** `req-tap-cares-collector-config-6` (v0: `CollectorConfig` is exactly two ids)
- **Retrieved:** 2026-09-15

## Prior Art

- unified-systems-com/github-core-tap#145 (2026-09-14) — the build issue; George's ruling that the scope is a node on the operation side, joined to the run rather than written on it.
- [`collection_scope`](collection_scope.md) — the source node, and why it is a node.
- `PRODUCED_BATCH` (tap_cares) — the run's OTHER outbound join, to what it imported; kept distinct on purpose.

## Endpoints

- **Source:** `github_core__collection_scope`.
- **Target:** `collection_job` — tap_cares' core run record, named by its `ENTITY_TYPE` string.
- **Dimensions:** `git.host`, `github.observation: execution`. No `github.surface`: the edge is about a run, not a GitHub API surface.
- **Properties:** none. Everything about the reach lives on the scope node, where it is one statement rather than a copy per edge.
