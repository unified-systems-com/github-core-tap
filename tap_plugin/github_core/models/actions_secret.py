"""GitHub Actions secret — the NAME of a credential, never its value.

GitHub's secrets API returns names and timestamps and nothing else: the value is write-only
by design and no credential can read it back. That constraint is the whole reason this node is
safe to hold, and it is stated here rather than in a comment somewhere downstream, because the
first question anyone asks of a node called "secret" is whether TAP is storing one. It is not.

What the name alone buys is the join nothing else can make. A workflow's YAML says which secrets
it *references*; this says which secrets *exist* and at what scope. Crossing the two answers three
questions no single source can:

* a reference that resolves to nothing — the workflow receives an empty string at runtime rather
  than an error, which is the failure mode that never announces itself;
* a secret nothing references — a live credential with no consumer;
* a name defined once at org scope and consumed by many repositories — the blast radius when any
  one of those workflows is compromised.

`scope` carries org vs repository rather than being inferred from `full_name` being empty: an
absent scope and an organisation scope must never read the same.
"""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel
from tap_plugin.github_core.models.schema_types import timestamp_validations, timestamps


class ActionsSecret(BaseModel):
    """An Actions secret's name, scope and timestamps. Never its value.

    Spec: specs/spec-github-core-v0.md (req-github-core-actions-secrets)
    """

    ENTITY_TYPE: ClassVar[str] = "github_core__actions_secret"
    # Scope is in the key because an org secret and a repository secret can share a name and are
    # different credentials; `full_name` / `environment_name` are "" at the scopes that have none.
    # `name` is the CANONICAL spelling — upper-cased — and that is what the key uses. GitHub
    # secret names are not case-sensitive: a workflow writing `${{ secrets.harness_pat }}` and
    # one writing `${{ secrets.HARNESS_PAT }}` read the same credential, so two nodes would say
    # they are two. Ruled by George 2026-09-20 (Issue# 165): fold at write time and store the
    # fold, rather than folding only inside the id recipe where the declared search could not
    # follow. `name_reported` keeps what GitHub actually returned, so nothing is lost by
    # canonicalising — a column is cheap and this one buys precision the key needs.
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("scope", "owner_login", "full_name", "environment_name", "name")
    ENTITY_NAME: ClassVar[str] = "GitHub Actions Secret"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "The name and scope of an Actions secret. GitHub's API returns names only — the value is "
        "write-only and is never read, stored or displayed."
    )
    ENTITY_ICON: ClassVar[str] = "github-secret"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {
        "github.observation": "declaration",
        "git.host": "github.com",
        "github.surface": "secrets",
    }
    DEFAULT_DISPLAY: ClassVar[dict[str, Any]] = {
        "tap_viz": {
            "shape": "round-tag",
            "colors": {"fill": "#FFF1E5", "border": "#A15C00", "label": "#4A2B00"},
        }
    }

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "scope": {
            "type": "string",
            "enum": ["organization", "repository", "environment"],
        },
        "owner_login": {"type": "string", "minLength": 1},
        "full_name": {"type": "string"},
        "environment_name": {"type": "string"},
        "name": {"type": "string", "minLength": 1},
        "name_reported": {"type": "string"},
        "visibility": {"type": "string"},
        **timestamps("created_at", "updated_at"),
        "configuration": {"type": "object"},
        "tags": {"type": "object"},
    }

    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        "scope": {
            "validation": "jsonschema",
            "schema": {
                "type": "string",
                "enum": ["organization", "repository", "environment"],
            },
        },
        "owner_login": {
            "validation": "jsonschema",
            "schema": {"type": "string", "minLength": 1},
        },
        # Empty for an organisation secret — it belongs to no single repository. Distinct from
        # unobserved: an org secret HAS no full_name, it is not that we failed to read one.
        "full_name": {"validation": "jsonschema", "schema": {"type": "string"}},
        "environment_name": {"validation": "jsonschema", "schema": {"type": "string"}},
        "name": {
            "validation": "jsonschema",
            "schema": {"type": "string", "minLength": 1},
        },
        # GitHub's own word for which repositories an org secret reaches: all / private / selected.
        "visibility": {"validation": "jsonschema", "schema": {"type": "string"}},
        **timestamp_validations("created_at", "updated_at"),
        "configuration": {"validation": "jsonschema", "schema": {"type": "object"}},
        "tags": {"validation": "jsonschema", "schema": {"type": "object"}},
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["scope", "owner_login", "name"]

    scope = models.CharField(max_length=32, blank=True, default="", db_index=True)
    owner_login = models.CharField(max_length=255, blank=True, default="", db_index=True)
    full_name = models.CharField(max_length=255, blank=True, default="", db_index=True)
    environment_name = models.CharField(max_length=255, blank=True, default="")
    #: The canonical spelling, upper-cased: GitHub secret names are not case-sensitive, so this
    #: is the identity. Folded at write time so the declared search and the id agree.
    name = models.CharField(max_length=255, blank=True, default="", db_index=True)
    #: The spelling GitHub actually returned, kept verbatim. Never a constituting property —
    #: it is what was reported, not what the secret IS (Issue# 165).
    name_reported = models.CharField(max_length=255, blank=True, default="")
    visibility = models.CharField(max_length=32, blank=True, default="")
    created_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(null=True, blank=True)
    configuration = models.JSONField(default=dict, blank=True)
    tags = models.JSONField(default=dict, blank=True)

    class Meta(BaseModel.Meta):
        db_table = "github_core__actions_secret"

    def get_name(self) -> str:
        return self.name

    def __str__(self) -> str:
        where = self.full_name or self.owner_login
        return f"{self.name} ({where})"
