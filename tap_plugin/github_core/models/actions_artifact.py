"""Actions artifact — a file set a workflow run uploaded, with the retention GitHub gives it.

The output side of a pipeline, as an observed event: a run happened and left this behind.
Eleven surveyed sources model an *artifact*; the machinery view's output column renders
"not yet collected" without it (github-core#31, #55). The load-bearing fields are
`digest` — the content hash that lets a downloaded artifact be matched to the one that
was uploaded — and `expired`, which GitHub reports as a state rather than by removing the
row.
"""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel
from tap_plugin.github_core.models.schema_types import timestamp_validations, timestamps


class ActionsArtifact(BaseModel):
    """One artifact as the repository-level listing reports it.

    An **immutable event with a retention window** (github-core#14, shape C): the upload
    happened once, at a timestamp, and does not stop having happened when retention ends.
    GitHub keeps the row listed with `expired: true`, so expiry is observed, never inferred
    from absence — and absence from a listing is never grounds for a tombstone here.

    The declared side — a job's `actions/upload-artifact` and `actions/download-artifact`
    steps — lives on `workflow_job.configuration.artifact_steps`. GitHub records who
    uploaded (the run on `UPLOADS_ARTIFACT`) and nothing about who downloaded, so the
    corpus's `DOWNLOADS_ARTIFACT` has no observable target and is not built; the
    declaration carries `cross_workflow` instead (`req-github-core-artifacts`).

    Spec: plugins/github_core/specs/spec-github-core-v0.md (req-github-core-artifacts)
    """

    ENTITY_TYPE: ClassVar[str] = "github_core__actions_artifact"
    # Repository + GitHub's artifact id (platform-global; the repository prefix is belt-and-braces).
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("full_name", "artifact_id")
    ENTITY_NAME: ClassVar[str] = "Actions Artifact"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "A file set a workflow run uploaded — its name, size, content digest and retention state. "
        "The output of a run, as GitHub recorded it."
    )
    ENTITY_ICON: ClassVar[str] = "actions-artifact"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {
        # Something that HAPPENED: an execution-side object, like the run that produced it.
        "github.observation": "execution",
        "git.host": "github.com",
        "github.surface": "actions",
    }
    DEFAULT_DISPLAY: ClassVar[dict[str, Any]] = {
        "tap_viz": {
            "shape": "round-tag",
            "colors": {"fill": "#DAFBE1", "border": "#1A7F37", "label": "#1F2328"},
        }
    }

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "full_name": {"type": "string", "minLength": 1},
        "artifact_id": {"type": ["integer", "null"]},
        "name": {"type": "string"},
        "size_in_bytes": {"type": ["integer", "null"]},
        "digest": {"type": "string"},
        "expired": {"type": "boolean"},
        **timestamps("expires_at", "created_at", "updated_at"),
        "run_id": {"type": ["integer", "null"]},
        "head_sha": {"type": "string"},
        "head_branch": {"type": "string"},
        "configuration": {"type": "object"},
        "tags": {"type": "object"},
    }

    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        "full_name": {
            "validation": "jsonschema",
            "schema": {"type": "string", "minLength": 1},
        },
        "artifact_id": {
            "validation": "jsonschema",
            "schema": {"type": ["integer", "null"]},
        },
        "name": {"validation": "jsonschema", "schema": {"type": "string"}},
        "size_in_bytes": {
            "validation": "jsonschema",
            "schema": {"type": ["integer", "null"]},
        },
        "digest": {"validation": "jsonschema", "schema": {"type": "string"}},
        "expired": {"validation": "jsonschema", "schema": {"type": "boolean"}},
        **timestamp_validations("expires_at", "created_at", "updated_at"),
        "run_id": {"validation": "jsonschema", "schema": {"type": ["integer", "null"]}},
        "head_sha": {"validation": "jsonschema", "schema": {"type": "string"}},
        "head_branch": {"validation": "jsonschema", "schema": {"type": "string"}},
        "configuration": {"validation": "jsonschema", "schema": {"type": "object"}},
        "tags": {"validation": "jsonschema", "schema": {"type": "object"}},
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["full_name", "artifact_id"]

    full_name = models.CharField(max_length=255, blank=True, default="", db_index=True)
    artifact_id = models.BigIntegerField(null=True, blank=True, db_index=True)
    name = models.CharField(max_length=512, blank=True, default="", db_index=True)
    size_in_bytes = models.BigIntegerField(null=True, blank=True)
    # `sha256:<64 hex>` of the archive content as GitHub computed it at upload. Empty when GitHub
    # did not report one (older artifacts predate the field), which is different from unknown.
    digest = models.CharField(max_length=80, blank=True, default="", db_index=True)
    # Retention state as GitHub REPORTS it. An expired artifact stays listed; this flag is the
    # observed lifecycle, and absence from a listing is never read as expiry.
    expired = models.BooleanField(default=False)
    expires_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(null=True, blank=True)
    # The producing run, as the listing's `workflow_run` names it. Kept as a column so the join
    # to `github_actions_run` is exact whether or not that run was in the collected window.
    run_id = models.BigIntegerField(null=True, blank=True, db_index=True)
    head_sha = models.CharField(max_length=64, blank=True, default="", db_index=True)
    head_branch = models.CharField(max_length=512, blank=True, default="")
    configuration = models.JSONField(default=dict, blank=True)
    tags = models.JSONField(default=dict, blank=True)

    class Meta(BaseModel.Meta):
        db_table = "github_core__actions_artifact"

    def get_name(self) -> str:
        return self.name or (
            str(self.artifact_id) if self.artifact_id is not None else ""
        )

    def __str__(self) -> str:
        return self.get_name()
