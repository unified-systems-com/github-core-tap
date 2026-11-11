"""GitHub environment — a named deployment target with its own protection rules.

Ten sources model it and seven standards have a name for it. Its value here is
mostly in what its *absence* says: a job that deploys with no environment
beside it is a deployment with no gate.
"""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel


class GithubEnvironment(BaseModel):
    """A repository environment: reviewers, wait timer, and branch policy.

    Reconciliation (github-core#14 shape B, github-core#151): contained by its repository
    through ``DECLARES_ENVIRONMENT`` (declared on ``GithubRepository.CONTAINMENT_EDGES``) and
    reconcilable only under a complete walk of ``repository.environments``. The falsifier
    probes ``GET /repos/{owner}/{repo}/environments/{name}`` and compares the numeric id
    (``tap_plugin.github_core.falsifiers.EnvironmentFalsifier``). Declares no containment of
    its own: the secrets scoped to it are references.

    Spec: plugins/github_core/specs/spec-github-core-v0.md (req-github-core-environments)
    """

    ENTITY_TYPE: ClassVar[str] = "github_core__github_environment"
    # GitHub's environment id alone (github-core#209): confirmed platform-global against this
    # estate's real data (no two distinct repositories ever share one), 100% populated, so no
    # "documented but unreliable" gap the way the issue worried about. `full_name` and `name`
    # stay plain, refreshed-on-observation attributes below.
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("environment_id",)
    ENTITY_NAME: ClassVar[str] = "GitHub Environment"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "A named deployment environment and the protection rules standing in front of it."
    )
    ENTITY_ICON: ClassVar[str] = "github-environment"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {
        "github.observation": "declaration",
        "git.host": "github.com",
        "github.surface": "deployments",
    }
    DEFAULT_DISPLAY: ClassVar[dict[str, Any]] = {
        "tap_viz": {
            "shape": "round-rectangle",
            "colors": {"fill": "#DAFBE1", "border": "#1A7F37", "label": "#0A3622"},
        }
    }

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "full_name": {"type": "string", "minLength": 1},
        "environment_id": {"type": ["integer", "null"]},
        "name": {"type": "string", "minLength": 1},
        "protection_rules": {"type": "array"},
        "deployment_branch_policy": {"type": ["object", "null"]},
        "can_admins_bypass": {"type": ["boolean", "null"]},
        "html_url": {"type": "string"},
        "configuration": {"type": "object"},
        "tags": {"type": "object"},
    }

    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        "full_name": {
            "validation": "jsonschema",
            "schema": {"type": "string", "minLength": 1},
        },
        "environment_id": {
            "validation": "jsonschema",
            "schema": {"type": ["integer", "null"]},
        },
        "name": {
            "validation": "jsonschema",
            "schema": {"type": "string", "minLength": 1},
        },
        "protection_rules": {"validation": "jsonschema", "schema": {"type": "array"}},
        # null = no policy declared (every branch may deploy); an object = a restriction exists.
        "deployment_branch_policy": {
            "validation": "jsonschema",
            "schema": {"type": ["object", "null"]},
        },
        "can_admins_bypass": {
            "validation": "jsonschema",
            "schema": {"type": ["boolean", "null"]},
        },
        "html_url": {"validation": "jsonschema", "schema": {"type": "string"}},
        "configuration": {"validation": "jsonschema", "schema": {"type": "object"}},
        "tags": {"validation": "jsonschema", "schema": {"type": "object"}},
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["full_name", "name"]

    full_name = models.CharField(max_length=255, blank=True, default="", db_index=True)
    environment_id = models.BigIntegerField(null=True, blank=True, db_index=True)
    name = models.CharField(max_length=255, blank=True, default="", db_index=True)
    protection_rules = models.JSONField(default=list, blank=True)
    deployment_branch_policy = models.JSONField(null=True, blank=True)
    can_admins_bypass = models.BooleanField(null=True, blank=True)
    html_url = models.URLField(max_length=512, blank=True, default="")
    configuration = models.JSONField(default=dict, blank=True)
    tags = models.JSONField(default=dict, blank=True)

    class Meta(BaseModel.Meta):
        db_table = "github_core__github_environment"

    def get_name(self) -> str:
        return self.name

    def __str__(self) -> str:
        return self.get_name()
