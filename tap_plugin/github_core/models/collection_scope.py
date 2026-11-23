"""Collection scope — what THIS run's credential was allowed to weigh in on.

One node per collection run, on the operation side (`github.observation: execution`), carrying
the fact every downstream absence decision reads before it trusts a missing item: which
repositories the credential could reach, which credential kinds it held, which installation the
App token was minted for, and the account's plan. George ruled it a node rather than a field on
the run (2026-09-14): an App's grants can be narrowed in a settings page and nothing tells the
collector, so the reach is perceived-true-at-a-time like a runner execution. Putting it on the
operation side makes it immutable history and answers "when did we stop being able to see X"
for free.

The node is emitted at the top of the run, before anything is weighed in on, and is later
PATCHED through the service layer — once per tier by reliability 1b's Confirm, and by the
visibility assessment (github-core#15). Both write into seams declared and described here but
left EMPTY by the collector: `tiers` and `visibility`. A run that dies mid-way legitimately
leaves the earlier tiers' verdicts on it.

This node is not the run. Scope facts never go on `collection_job`.
"""

from typing import Any, ClassVar

from django.db import models

from tap_grid.event_time import NO_EVENT_TIME
from tap_grid.models import BaseModel

#: The closed vocabulary a tier verdict's `reason` takes, verbatim, so that
#: `WHERE s.tiers.T2.reason = "count_mismatch"` is a stable Gryphon question. Agreed with
#: reliability 1b (github-core#136), which writes into `tiers` unchanged.
TIER_REASONS: tuple[str, ...] = (
    "complete",
    "truncated",
    "forbidden",
    "errored",
    "filter_unverified",
    "count_mismatch",
    "prerequisite_incomplete",
    "not_attempted",
)

#: The four states the visibility assessment (github-core#15) assigns an entity type.
VISIBILITY_STATES: tuple[str, ...] = ("reachable", "degraded", "unreachable", "unknown")

_SELECTION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "description": (
        "The INSTALLATION_SELECTION run record verbatim — which repositories this run's credential "
        "may reach. Built once and placed both on the run record and here (derive a fact once)."
    ),
    "properties": {
        "credential": {
            "type": "string",
            "description": "Which credential the selection describes: `app` or `pat`.",
        },
        "token_kind": {
            "type": "string",
            "description": (
                "PAT only: `fine_grained` or `classic`, from the token's prefix. The value itself is "
                "never recorded."
            ),
        },
        "kind": {
            "type": "string",
            "description": (
                "`all` (the installation follows the account into new repositories), `selected` "
                "(an explicit list), or `unknown` (a PAT's reach, or an installation whose listing was "
                "refused). A falsifier treats `unknown` as cannot-weigh-in."
            ),
        },
        "repository_ids": {
            "type": ["array", "null"],
            "items": {"type": "integer"},
            "description": (
                "GitHub's numeric ids of the repositories the installation token listed about "
                "itself. Null when unobserved (PAT, or a refused listing) — never an empty list "
                "standing in for could-not-look."
            ),
        },
        "count": {
            "type": ["integer", "null"],
            "description": "How many ids the walk returned. Null when unobserved.",
        },
        "total_count": {
            "type": ["integer", "null"],
            "description": "GitHub's own `total_count` for the listing. Null when unobserved or absent.",
        },
        "complete": {
            "type": "boolean",
            "description": (
                "True only when the walk ran to the end AND `total_count` equals the walked count. "
                "An unreconciled selection is not one absence may be weighed against (fail closed)."
            ),
        },
        "status": {
            "type": "integer",
            "description": "The HTTP status that refused the listing, when one did.",
        },
    },
    "required": ["credential", "kind", "repository_ids", "count", "total_count", "complete"],
    "additionalProperties": False,
    # Fail closed at the schema, not only in the collector (Codex on PR# 146): a selection that
    # claims `complete` must carry the ids and the two counts it was reconciled from, and they
    # must agree — a bare `{"complete": true}` is not a statement absence may be weighed against.
    "if": {"properties": {"complete": {"const": True}}},
    "then": {
        "properties": {
            "kind": {"enum": ["all", "selected"]},
            "repository_ids": {"type": "array"},
            "count": {"type": "integer"},
            "total_count": {"type": "integer"},
        },
    },
}

_VISIBILITY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "description": (
        "Per entity type, whether this run's credential could observe it — the visibility "
        "assessment (github-core#15), derived from the collection manifest's permission triples "
        "crossed with the installation's granted permissions. Keyed by the entity type slug "
        "(`github_core__actions_secret`). EMPTY as emitted by the collector; #15 fills it. An "
        "absent key means the type was not assessed, never that it was reachable."
    ),
    "additionalProperties": {
        "type": "object",
        "description": "One entity type's assessment.",
        "properties": {
            "state": {
                "type": "string",
                "enum": list(VISIBILITY_STATES),
                "description": (
                    "`reachable` (every permission the type needs is granted), `degraded` (some "
                    "sources refused — a partial population), `unreachable` (the credential cannot "
                    "look at all), `unknown` (not assessable — a PAT's grant is not introspectable)."
                ),
            },
            "failing_permission": {
                "type": ["string", "null"],
                "description": (
                    "The canonical permission triple (`<surface>:<key>:<level>`) the credential "
                    "lacks, when the state is `degraded` or `unreachable`; null otherwise."
                ),
            },
        },
        "required": ["state", "failing_permission"],
        "additionalProperties": False,
    },
}

_TIER_SURFACE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "description": "One surface's completeness within a tier, per scope.",
    "properties": {
        "complete": {"type": "boolean", "description": "Whether this surface was read in full."},
        "reason": {
            "type": "string",
            "enum": list(TIER_REASONS),
            "description": "The tier reason vocabulary, verbatim, for this surface.",
        },
        "incomplete_scopes": {
            "type": "array",
            "items": {"type": "string"},
            "description": "The `owner/repo` scopes where this surface was NOT read in full.",
        },
    },
    "required": ["complete", "reason", "incomplete_scopes"],
    "additionalProperties": False,
}

_TIERS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "description": (
        "Per collection tier (T0 … T5, also T3a / T3b), reliability 1b's completeness verdict "
        "(github-core#136), written by Confirm at the tier's end through the service layer. EMPTY "
        "as emitted by the collector; a run that dies mid-T3 legitimately leaves T0–T2 verdicts "
        "here. `reason` is the closed vocabulary verbatim so that "
        "`WHERE s.tiers.T2.reason = \"count_mismatch\"` is a stable Gryphon question."
    ),
    # Only the named tiers may appear (T0 … T5, T3a / T3b): a verdict under a key nobody
    # defined would be a verdict nobody reads.
    "propertyNames": {"pattern": "^T[0-5][ab]?$"},
    "additionalProperties": {
        "type": "object",
        "description": "One tier's verdict.",
        "required": ["complete", "reason", "prerequisite", "decided_at"],
        "additionalProperties": False,
        "properties": {
            "complete": {
                "type": "boolean",
                "description": "Whether the tier read everything it set out to read.",
            },
            "reason": {
                "type": "string",
                "enum": list(TIER_REASONS),
                "description": (
                    "Exactly one of: complete · truncated · forbidden · errored · "
                    "filter_unverified · count_mismatch · prerequisite_incomplete · not_attempted."
                ),
            },
            "prerequisite": {
                "type": ["string", "null"],
                "description": "The parent tier this one depends on, or null for a root tier.",
            },
            "decided_at": {
                "type": "string",
                "format": "date-time",
                "description": "When Confirm wrote the verdict — ISO-8601, at the tier's end.",
            },
            "count_check": {
                "type": ["object", "null"],
                "description": "T2 only: GitHub's reported count against the walked count; null elsewhere.",
                "properties": {
                    "reported": {"type": "integer", "description": "What GitHub said the total was."},
                    "listed": {"type": "integer", "description": "How many the walk actually returned."},
                },
            },
            "surfaces": {
                "type": "object",
                "description": (
                    "T3a / T3b / T4: per surface, per scope — which surfaces were read in full and "
                    "where they were not."
                ),
                "additionalProperties": _TIER_SURFACE_SCHEMA,
            },
        },
    },
}

_CONFIGURATION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "description": (
        "The versions of the three inputs the scope was derived from, so a verdict that changes "
        "between runs is attributable to \"we asked for more\" (the manifest moved) versus \"they "
        "granted less\" (the installation moved) versus \"the plan changed\"."
    ),
    "properties": {
        "manifest": {
            "type": "object",
            "description": "The collection manifest this run read — what TAP asked for.",
            "properties": {
                "version": {"type": "string", "description": "The manifest's declared `manifest_version`."},
                "sha256": {"type": "string", "description": "SHA-256 of the manifest file as shipped."},
                "sources": {"type": "integer", "description": "How many sources the manifest declares."},
            },
        },
        "installation": {
            "type": ["object", "null"],
            "description": (
                "The installation grant as GitHub reported it when the App token was minted — what "
                "the account allowed. Null when the run held no App (PAT only): unobserved, not empty."
            ),
            "properties": {
                "app_id": {"type": ["integer", "null"], "description": "The App's numeric id."},
                "permissions": {
                    "type": "object",
                    "description": "The granted permission map (`contents: read`, …), verbatim.",
                },
                "repository_selection": {
                    "type": "string",
                    "description": "`all` or `selected`, as declared on the installation.",
                },
                "events": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "The webhook events the installation subscribes to, verbatim.",
                },
                "suspended": {"type": "boolean", "description": "Whether GitHub reports the installation suspended."},
            },
        },
        "plan_source": {
            "type": "string",
            "description": (
                "Where `plan` came from — the organization-detail observability state the run "
                "recorded, verbatim: `observed` (the policy block, plan included, was read from "
                "`/orgs/{login}`), `public_only` (the org answered without its policy keys — not an "
                "administrator, so no plan), `unobservable` (refused), `not_applicable` (a user "
                "account), or `no_owner` (a repos-only envelope names no account)."
            ),
            "enum": ["observed", "public_only", "unobservable", "not_applicable", "no_owner"],
        },
    },
    "required": ["manifest", "installation", "plan_source"],
}


class CollectionScope(BaseModel):
    """What one collection run's credential was allowed to weigh in on.

    Spec: specs/spec-github-core-v0.md (req-github-core-collection-scope)
    """

    ENTITY_TYPE: ClassVar[str] = "github_core__collection_scope"
    # The `collection_job` entity id. One scope per run by construction: a re-run is a new job.
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("run_id",)
    ENTITY_NAME: ClassVar[str] = "Collection Scope"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "One per collection run: which repositories, credentials, installation and plan this run "
        "could see — the fact every absence decision reads before it trusts a missing item."
    )
    ENTITY_ICON: ClassVar[str] = "collection-scope"
    # A run of this plugin's own collector: observed_at is collection time, never an event time.
    EVENT_TIME: ClassVar[Any] = NO_EVENT_TIME
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {
        "github.observation": "execution",
        "git.host": "github.com",
    }
    DEFAULT_DISPLAY: ClassVar[dict[str, Any]] = {
        "tap_viz": {
            "shape": "round-diamond",
            "colors": {"fill": "#EAF5FF", "border": "#0969DA", "label": "#1F2328"},
        }
    }

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "run_id": {"type": "string", "minLength": 1},
        "observed_at": {"type": ["string", "null"], "format": "date-time"},
        "credential_kinds": {
            "type": "array",
            "items": {"type": "string", "enum": ["app", "pat"]},
            "description": "Which credential kinds the envelope held this run: `app`, `pat`, or both.",
        },
        "installation_id": {"type": ["integer", "null"]},
        "selection": _SELECTION_SCHEMA,
        "plan": {"type": "string"},
        "visibility": _VISIBILITY_SCHEMA,
        "tiers": _TIERS_SCHEMA,
        "configuration": _CONFIGURATION_SCHEMA,
        "tags": {"type": "object", "description": "TAP's tag map."},
    }

    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        "run_id": {"validation": "jsonschema", "schema": {"type": "string", "minLength": 1}},
        "credential_kinds": {
            "validation": "jsonschema",
            "schema": {"type": "array", "items": {"type": "string", "enum": ["app", "pat"]}},
        },
        "installation_id": {"validation": "jsonschema", "schema": {"type": ["integer", "null"]}},
        "selection": {"validation": "jsonschema", "schema": _SELECTION_SCHEMA},
        "plan": {"validation": "jsonschema", "schema": {"type": "string"}},
        "visibility": {"validation": "jsonschema", "schema": _VISIBILITY_SCHEMA},
        "tiers": {"validation": "jsonschema", "schema": _TIERS_SCHEMA},
        "configuration": {"validation": "jsonschema", "schema": _CONFIGURATION_SCHEMA},
        "tags": {"validation": "jsonschema", "schema": {"type": "object"}},
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["run_id"]

    #: The `collection_job` entity id this statement is about. A string because the job is a core
    #: (tap_cares) entity this plugin must not import a model for; the join is `SCOPES_RUN`.
    run_id = models.CharField(max_length=36, blank=True, default="", db_index=True)
    #: When the scope was established — the start of the run, before anything was weighed in on.
    observed_at = models.DateTimeField(null=True, blank=True)
    credential_kinds = models.JSONField(default=list, blank=True)
    #: Which installation the App token was minted for; null in a PAT-only run.
    installation_id = models.BigIntegerField(null=True, blank=True, db_index=True)
    selection = models.JSONField(default=dict, blank=True)
    #: `enterprise` / `team` / `free` / `unknown`, lower-cased from the account's `plan.name` when
    #: the credential could read it. A scope INPUT — the audit log is Enterprise-only. GitHub's own
    #: name is kept verbatim when it is none of the three (a user account reports `pro`).
    plan = models.CharField(max_length=32, blank=True, default="unknown")
    visibility = models.JSONField(default=dict, blank=True)
    tiers = models.JSONField(default=dict, blank=True)
    configuration = models.JSONField(default=dict, blank=True)
    tags = models.JSONField(default=dict, blank=True)

    class Meta(BaseModel.Meta):
        db_table = "github_core__collection_scope"

    def get_name(self) -> str:
        if self.observed_at is not None:
            return f"collection scope @ {self.observed_at:%Y-%m-%dT%H:%M:%SZ}"
        return f"collection scope of run {self.run_id}" if self.run_id else "collection scope"

    def __str__(self) -> str:
        return self.get_name()
