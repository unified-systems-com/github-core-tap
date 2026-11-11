"""Workflow job — the job as WRITTEN in a workflow file, not as run.

The distinction this type exists to hold is in
`specs/spec-github-core-vocabulary.md`: `github_actions_job` is an *execution*
(it keys on GitHub's job id and carries status/conclusion), while a
`workflow_job` is a *declaration* (it keys on the YAML job key and carries
`permissions`, `runs-on`, `if`, the environment it deploys to, and the ref it
checks out). Every privilege decision in CI is made at the declared level, and
the two are joined by an edge rather than merged.
"""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel


class WorkflowJob(BaseModel):
    """A job declared in a workflow file.

    Neutral concept (`spec-github-core-vocabulary.md`): a structurally
    different forge declares jobs too, so this type moves to the neutral
    substrate when one is extracted. It lives in `github_core` until then.

    Reconciliation (github-core#14 shape A, github-core#151): git-provable at the granularity
    of the file that declares it — contained by its workflow through ``DEFINES_JOB`` (declared on
    ``GithubWorkflow.CONTAINMENT_EDGES``). The falsifier reads the workflow file at HEAD and
    looks for the job key (``tap_plugin.github_core.falsifiers.WorkflowJobFalsifier``). The
    executions that instantiate it (``github_actions_job``, shape C) are not contained here.

    Spec: plugins/github_core/specs/spec-github-core-v0.md
    (req-github-core-declared-jobs)
    """

    ENTITY_TYPE: ClassVar[str] = "github_core__workflow_job"
    # A DECLARED job: the workflow it is written in (GitHub's platform-global workflow id,
    # github-core#209 — never `full_name`), plus its YAML key — not `name:`, which is free text
    # an author changes without changing what the job is.
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("workflow_id", "job_key")
    ENTITY_NAME: ClassVar[str] = "Workflow Job"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "A job as declared in a workflow file — its permissions, runner, condition, environment "
        "and checkout ref. The declaration, not the execution."
    )
    ENTITY_ICON: ClassVar[str] = "workflow-job"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {
        "git.host": "github.com",
        "github.surface": "actions",
        "github.observation": "declaration",
    }
    # A job is a card on its workflow's green field (see github_workflow): a
    # paler mint than the field so it reads as raised ground, square-ish corners
    # to sit visibly apart from the round execution nodes.
    DEFAULT_DISPLAY: ClassVar[dict[str, Any]] = {
        "tap_viz": {
            "shape": "rectangle",
            "colors": {"fill": "#F0FBF3", "border": "#2DA44E", "label": "#1F2328"},
        }
    }

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "full_name": {"type": "string", "minLength": 1},
        "workflow_id": {"type": ["integer", "null"]},
        "workflow_path": {"type": "string"},
        "job_key": {"type": "string", "minLength": 1},
        "name": {"type": "string"},
        "runs_on": {"type": ["array", "null"]},
        "permissions": {"type": ["object", "string", "null"]},
        "if_condition": {"type": "string"},
        "environment": {"type": "string"},
        "uses": {"type": "string"},
        "needs": {"type": "array"},
        "checkout_ref": {"type": "string"},
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
        "workflow_path": {"validation": "jsonschema", "schema": {"type": "string"}},
        "job_key": {
            "validation": "jsonschema",
            "schema": {"type": "string", "minLength": 1},
        },
        "name": {"validation": "jsonschema", "schema": {"type": "string"}},
        "runs_on": {"validation": "jsonschema", "schema": {"type": ["array", "null"]}},
        # null vs {} is load-bearing and NOT interchangeable: a job with no `permissions:` block
        # INHERITS (null — unobserved at this level), while `permissions: {}` grants the job token
        # nothing at all. Collapsing them would turn the most locked-down job in a repository into
        # the most permissive one. See the grid's null-is-unobserved convention.
        "permissions": {
            "validation": "jsonschema",
            "schema": {"type": ["object", "string", "null"]},
        },
        "if_condition": {"validation": "jsonschema", "schema": {"type": "string"}},
        "environment": {"validation": "jsonschema", "schema": {"type": "string"}},
        "uses": {"validation": "jsonschema", "schema": {"type": "string"}},
        "needs": {"validation": "jsonschema", "schema": {"type": "array"}},
        "checkout_ref": {"validation": "jsonschema", "schema": {"type": "string"}},
        "configuration": {"validation": "jsonschema", "schema": {"type": "object"}},
        "tags": {"validation": "jsonschema", "schema": {"type": "object"}},
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["full_name", "job_key"]

    full_name = models.CharField(max_length=255, blank=True, default="", db_index=True)
    workflow_id = models.BigIntegerField(null=True, blank=True, db_index=True)
    workflow_path = models.CharField(max_length=512, blank=True, default="")
    job_key = models.CharField(max_length=255, blank=True, default="", db_index=True)
    name = models.CharField(max_length=512, blank=True, default="")
    # `runs-on` is a string, a list, or a matrix expression; the list form is canonical here and a
    # bare string is wrapped. null means the job declares none (a reusable-workflow call).
    runs_on = models.JSONField(null=True, blank=True)
    permissions = models.JSONField(null=True, blank=True)
    if_condition = models.TextField(blank=True, default="")
    environment = models.CharField(max_length=255, blank=True, default="")
    uses = models.CharField(max_length=512, blank=True, default="")
    needs = models.JSONField(default=list, blank=True)
    # The ref `actions/checkout` is told to check out. A job triggered by `pull_request_target`
    # that checks out `github.event.pull_request.head.sha` is running a contributor's code with
    # the base repository's secrets — the single most-cited shape in the incident corpus.
    checkout_ref = models.CharField(max_length=512, blank=True, default="")
    configuration = models.JSONField(default=dict, blank=True)
    tags = models.JSONField(default=dict, blank=True)

    class Meta(BaseModel.Meta):
        db_table = "github_core__workflow_job"

    def get_name(self) -> str:
        return self.name or self.job_key

    def __str__(self) -> str:
        return self.get_name()
