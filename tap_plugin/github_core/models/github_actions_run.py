"""GitHub Actions Run — one workflow run (latest-attempt snapshot)."""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel
from tap_plugin.github_core.models.schema_types import timestamps


class GithubActionsRun(BaseModel):
    """A GitHub Actions workflow run.

    v0 models a single observation per run_id (latest attempt). Multi-attempt
    tracking is deferred to req-github-core-backlog-run-attempts.

    Reconciliation (github-core#14 shape C, github-core#151): an IMMUTABLE EVENT. The run
    happened and does not stop having happened; absence from a listing means the retention
    window expired, never that anything was deleted. Deliberately NOT a containment target
    (no model declares an edge INTO it in ``CONTAINMENT_EDGES``) and it declares no falsifier —
    so it is never a retirement candidate and never retired on absence. ``RUNS_JOB`` (run ->
    job) is likewise not containment: the jobs are events of the same shape.

    Spec: plugins/github_core/specs/spec-github-core-v0.md (req-github-core-models)
    """

    ENTITY_TYPE: ClassVar[str] = "github_core__github_actions_run"
    # Repository + GitHub's run id. `run_attempt` is deferred — req-github-core-backlog-run-attempts.
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("full_name", "run_id")
    ENTITY_NAME: ClassVar[str] = "GitHub Actions Run"
    ENTITY_DESCRIPTION: ClassVar[str] = "An execution of a GitHub Actions workflow."
    ENTITY_ICON: ClassVar[str] = "github-actions-run"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {
        "git.host": "github.com",
        "github.surface": "actions",
        "github.observation": "execution",
    }

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "full_name": {"type": "string", "minLength": 1},
        "run_id": {"type": ["integer", "null"]},
        "run_number": {"type": ["integer", "null"]},
        "event": {"type": "string"},
        "status": {"type": "string"},
        "conclusion": {"type": "string"},
        "head_sha": {"type": "string"},
        "head_branch": {"type": "string"},
        **timestamps("created_at", "run_started_at", "completed_at"),
        "run_attempt": {"type": ["integer", "null"]},
        "actor_login": {"type": "string"},
        "triggering_actor_login": {"type": "string"},
        "html_url": {"type": "string"},
        "configuration": {"type": "object"},
        "tags": {"type": "object"},
    }

    # FIELD_VALIDATION_SCHEMA runs on save with the post-parse Python value.
    # Datetime fields are typed Django DateTimeFields — their own validation
    # is the right layer. Including a JSON-Schema entry for them would assert
    # against a `datetime` object that the API-input shape "string | null"
    # describes only the inbound JSON shape, not the at-rest Python value.
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        "full_name": {
            "validation": "jsonschema",
            "schema": {"type": "string", "minLength": 1},
        },
        "run_id": {"validation": "jsonschema", "schema": {"type": ["integer", "null"]}},
        "run_number": {
            "validation": "jsonschema",
            "schema": {"type": ["integer", "null"]},
        },
        "event": {"validation": "jsonschema", "schema": {"type": "string"}},
        "status": {"validation": "jsonschema", "schema": {"type": "string"}},
        "conclusion": {"validation": "jsonschema", "schema": {"type": "string"}},
        "head_sha": {"validation": "jsonschema", "schema": {"type": "string"}},
        "head_branch": {"validation": "jsonschema", "schema": {"type": "string"}},
        "run_attempt": {
            "validation": "jsonschema",
            "schema": {"type": ["integer", "null"]},
        },
        "actor_login": {"validation": "jsonschema", "schema": {"type": "string"}},
        "triggering_actor_login": {
            "validation": "jsonschema",
            "schema": {"type": "string"},
        },
        "html_url": {"validation": "jsonschema", "schema": {"type": "string"}},
        "configuration": {"validation": "jsonschema", "schema": {"type": "object"}},
        "tags": {"validation": "jsonschema", "schema": {"type": "object"}},
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["full_name", "run_id"]

    full_name = models.CharField(max_length=255, blank=True, default="", db_index=True)
    run_id = models.BigIntegerField(null=True, blank=True, db_index=True)
    run_number = models.IntegerField(null=True, blank=True)
    event = models.CharField(max_length=64, blank=True, default="")
    status = models.CharField(max_length=32, blank=True, default="")
    conclusion = models.CharField(max_length=32, blank=True, default="")
    head_sha = models.CharField(max_length=64, blank=True, default="", db_index=True)
    head_branch = models.CharField(max_length=255, blank=True, default="")
    created_at = models.DateTimeField(null=True, blank=True, db_index=True)
    run_started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    run_attempt = models.IntegerField(null=True, blank=True)
    actor_login = models.CharField(max_length=255, blank=True, default="")
    triggering_actor_login = models.CharField(max_length=255, blank=True, default="")
    html_url = models.URLField(max_length=512, blank=True, default="")
    configuration = models.JSONField(default=dict, blank=True)
    tags = models.JSONField(default=dict, blank=True)

    class Meta(BaseModel.Meta):
        db_table = "github_core__github_actions_run"

    def get_name(self) -> str:
        if self.run_number:
            return f"Run #{self.run_number}"
        if self.run_id:
            return f"Run {self.run_id}"
        return self.full_name

    def __str__(self) -> str:
        return self.get_name()
