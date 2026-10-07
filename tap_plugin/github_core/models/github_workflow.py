"""GitHub Workflow — a workflow definition under a repository's Actions surface."""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel


class GithubWorkflow(BaseModel):
    """A GitHub Actions workflow definition.

    The `configuration` JSONField carries parsed workflow YAML — triggers,
    permissions, the raw YAML body (`configuration.raw_yaml`), and other
    extracted fields per req-github-core-workflow-parse.

    Reconciliation (github-core#14 shape A, github-core#151): git-provable. The workflow is a
    file under ``.github/workflows/`` at HEAD, so its removal is a commit — positive evidence,
    not an inference from a listing. The falsifier reads the file at HEAD and resolves the
    Actions workflow id behind it (``tap_plugin.github_core.falsifiers.WorkflowFalsifier``).

    A workflow CONTAINS the jobs declared inside it (``DEFINES_JOB``): they are falsifiable at
    the granularity of the file that declares them. Its runs are NOT contained — ``EXECUTES_WORKFLOW``
    is run -> workflow, and a run is a shape-C immutable event that never retires on absence.

    Spec: plugins/github_core/specs/spec-github-core-v0.md (req-github-core-models)
    """

    ENTITY_TYPE: ClassVar[str] = "github_core__github_workflow"
    # GitHub's workflow id alone (github-core#209): platform-global, never the path (a renamed
    # file keeps the same workflow) and never `full_name` (a renamed repository must not mint a
    # duplicate). `full_name` stays a plain, refreshed-on-observation attribute below.
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("workflow_id",)
    ENTITY_NAME: ClassVar[str] = "GitHub Workflow"
    ENTITY_DESCRIPTION: ClassVar[str] = "A GitHub Actions workflow definition."
    ENTITY_ICON: ClassVar[str] = "github-workflow"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {
        "git.host": "github.com",
        "github.surface": "actions",
        "github.observation": "declaration",
    }
    # Topographic scheme (spec-github-core-machinery-projection, Topography):
    # the account/repo beds are water-blue; a workflow is a green field laid on
    # the repo bed, and its jobs sit on that field as paler mint cards. The
    # machinery module reads these at render — it restates no colour of its own.
    DEFAULT_DISPLAY: ClassVar[dict[str, Any]] = {
        "tap_viz": {
            "shape": "round-rectangle",
            "colors": {"fill": "#DAFBE1", "border": "#1A7F37", "label": "#0A3622"},
        }
    }

    # Edge permission (union with the edge definitions' own sources/targets): declared so the
    # containment declaration below can name it (req-grid-service-delete-cascade-12). CALLS_WORKFLOW,
    # TRIGGERS_WORKFLOW, REFERENCES_SECRET and the rest stay permitted by their `.edge.json` sources.
    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "github_core__workflow_job"}], "edges": [{"type": "DEFINES_JOB__github_core"}]},
    ]
    #: The declared jobs retire with the file that declares them; `workflow.jobs` is the listing
    #: surface the collector records completeness for under a workflow.
    CONTAINMENT_EDGES: ClassVar[tuple[str, ...]] = ("DEFINES_JOB__github_core",)

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "full_name": {"type": "string", "minLength": 1},
        "workflow_id": {"type": ["integer", "null"]},
        "path": {"type": "string"},
        "name": {"type": "string"},
        "state": {"type": "string"},
        "html_url": {"type": "string"},
        "configuration": {"type": "object"},
        "tags": {"type": "object"},
    }

    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        "full_name": {
            "validation": "jsonschema",
            "schema": {"type": "string", "minLength": 1},
        },
        "workflow_id": {
            "validation": "jsonschema",
            "schema": {"type": ["integer", "null"]},
        },
        "path": {"validation": "jsonschema", "schema": {"type": "string"}},
        "name": {"validation": "jsonschema", "schema": {"type": "string"}},
        "state": {"validation": "jsonschema", "schema": {"type": "string"}},
        "html_url": {"validation": "jsonschema", "schema": {"type": "string"}},
        "configuration": {"validation": "jsonschema", "schema": {"type": "object"}},
        "tags": {"validation": "jsonschema", "schema": {"type": "object"}},
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["full_name"]

    full_name = models.CharField(max_length=255, blank=True, default="", db_index=True)
    workflow_id = models.BigIntegerField(null=True, blank=True, db_index=True)
    path = models.CharField(max_length=512, blank=True, default="", db_index=True)
    name = models.CharField(max_length=255, blank=True, default="")
    state = models.CharField(max_length=32, blank=True, default="")
    html_url = models.URLField(max_length=512, blank=True, default="")
    configuration = models.JSONField(default=dict, blank=True)
    tags = models.JSONField(default=dict, blank=True)

    class Meta(BaseModel.Meta):
        db_table = "github_core__github_workflow"

    def get_name(self) -> str:
        return self.name or self.path or self.full_name

    def __str__(self) -> str:
        return self.get_name()
