"""GitHub Runner — durable registered self-hosted runner."""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel


class GithubRunner(BaseModel):
    """A durable registered self-hosted GitHub Actions runner.

    v0 creates runner nodes only for durable registered runners visible via
    the runner API (req-github-core-runner-1). GitHub-hosted ephemeral
    runners are NOT modeled as nodes; observed runner fields live in
    `github_actions_job.configuration` instead.

    Reconciliation (github-core#14, github-core#197): no falsifier, no containment — deferred, not
    ruled out. Unlike releases, packages and custom properties, no edge in this plugin reaches a
    runner from its repository at all today: the collector mints `github_runner` nodes standalone
    (`collector.py`'s `_collect_app_installations`-adjacent runner walk) and joins them to
    executing jobs only via `EXECUTED_ON_RUNNER` (job -> runner), never repository -> runner. A
    `CONTAINMENT_EDGES` entry needs a new edge type first (e.g. `HOSTS_RUNNER__github_core`,
    repository -> runner) plus collector wiring to emit it and to author a
    `tap_grid.completeness` surface for the runners listing — real scope, not a docstring update,
    so it is not built in the same pass that added `AppInstallationFalsifier`. Flagged as the
    strongest candidate for a dedicated follow-up: the listing already degrades safely
    (`permission_failure: degrade_with_warning`, Observability above) and the security stakes are
    named directly in this article's own Purpose section ("a self-hosted runner attached to a
    public repository is one of the highest-evidence conditions in the whole set").

    Spec: plugins/github_core/specs/spec-github-core-v0.md (req-github-core-models, req-github-core-runner)
    """

    ENTITY_TYPE: ClassVar[str] = "github_core__github_runner"
    # Repository + GitHub's runner id.
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("full_name", "runner_id")
    ENTITY_NAME: ClassVar[str] = "GitHub Runner"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "A durable registered self-hosted GitHub Actions runner."
    )
    ENTITY_ICON: ClassVar[str] = "github-runner"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {
        "git.host": "github.com",
        "github.surface": "actions",
        "github.observation": "declaration",
    }

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "full_name": {"type": "string", "minLength": 1},
        "runner_id": {"type": ["integer", "null"]},
        "name": {"type": "string"},
        "os": {"type": "string"},
        "status": {"type": "string"},
        "busy": {"type": "boolean"},
        "labels": {"type": "array"},
        "configuration": {"type": "object"},
        "tags": {"type": "object"},
    }

    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        "full_name": {
            "validation": "jsonschema",
            "schema": {"type": "string", "minLength": 1},
        },
        "runner_id": {
            "validation": "jsonschema",
            "schema": {"type": ["integer", "null"]},
        },
        "name": {"validation": "jsonschema", "schema": {"type": "string"}},
        "os": {"validation": "jsonschema", "schema": {"type": "string"}},
        "status": {"validation": "jsonschema", "schema": {"type": "string"}},
        "busy": {"validation": "jsonschema", "schema": {"type": "boolean"}},
        "labels": {"validation": "jsonschema", "schema": {"type": "array"}},
        "configuration": {"validation": "jsonschema", "schema": {"type": "object"}},
        "tags": {"validation": "jsonschema", "schema": {"type": "object"}},
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["full_name", "runner_id"]

    full_name = models.CharField(max_length=255, blank=True, default="", db_index=True)
    runner_id = models.BigIntegerField(null=True, blank=True, db_index=True)
    name = models.CharField(max_length=255, blank=True, default="")
    os = models.CharField(max_length=64, blank=True, default="")
    status = models.CharField(max_length=32, blank=True, default="")
    busy = models.BooleanField(default=False)
    labels = models.JSONField(default=list, blank=True)
    configuration = models.JSONField(default=dict, blank=True)
    tags = models.JSONField(default=dict, blank=True)

    class Meta(BaseModel.Meta):
        db_table = "github_core__github_runner"

    def get_name(self) -> str:
        return self.name or (
            f"Runner {self.runner_id}" if self.runner_id else self.full_name
        )

    def __str__(self) -> str:
        return self.get_name()
