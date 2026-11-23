"""GitHub custom property — a property an organization declares for its repositories.

The definition is the node; the values live on the repositories. Many repositories
point at one definition (the node test, `spec-github-core-vocabulary.md`), and the
definition is what makes a repository's *unset* value a fact rather than a blank:
a property that exists and is not set on a repository is a different observation
from a property that does not exist.
"""

from typing import Any, ClassVar

from django.db import models

from tap_grid.event_time import NO_EVENT_TIME
from tap_grid.models import BaseModel


class GithubCustomProperty(BaseModel):
    """An organization-level custom property definition: name, type, allowed values, default.

    GitHub's custom properties are the organization's own metadata over its repositories —
    a durable owner, a criticality, a lifecycle — and the mechanism rulesets use to target
    repositories by property. The definition is collected so that every repository's value
    can be read against it: **unset** (the definition exists, the repository carries no
    value), **observed** (a value), or **unobservable** (the credential could not read the
    values at all). The values themselves are `github_repository.custom_properties`, keyed
    by this node's `property_name`.

    Spec: plugins/github_core/specs/spec-github-core-v0.md (req-github-core-custom-properties)
    """

    ENTITY_TYPE: ClassVar[str] = "github_core__github_custom_property"
    # A DEFINITION, keyed on owner + the property name exactly as reported (hyphens, case):
    # that string is also the key of every repository's `custom_properties` map.
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("owner_login", "property_name")
    ENTITY_NAME: ClassVar[str] = "GitHub Custom Property"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "A custom property an organization declares for its repositories — its name, value type, "
        "allowed values and default — against which each repository's value is read."
    )
    ENTITY_ICON: ClassVar[str] = "github-custom-property"
    # An organization's property definition; GitHub states no time for it and the model stores none.
    EVENT_TIME: ClassVar[Any] = NO_EVENT_TIME
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {
        "github.observation": "declaration",
        "git.host": "github.com",
        "github.surface": "custom-properties",
    }
    DEFAULT_DISPLAY: ClassVar[dict[str, Any]] = {
        "tap_viz": {
            "shape": "tag",
            "colors": {"fill": "#FBEFFF", "border": "#8250DF", "label": "#3E1F7A"},
        }
    }

    #: GitHub's own value types for a custom property.
    VALUE_TYPES: ClassVar[list[str]] = [
        "string",
        "single_select",
        "multi_select",
        "true_false",
    ]

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "owner_login": {"type": "string", "minLength": 1},
        "property_name": {"type": "string", "minLength": 1},
        "value_type": {"type": "string"},
        "required": {"type": "boolean"},
        "default_value": {"type": ["string", "array", "null"]},
        "description": {"type": "string"},
        "allowed_values": {"type": "array"},
        "values_editable_by": {"type": "string"},
        "source_type": {"type": "string"},
        "url": {"type": "string"},
        "configuration": {"type": "object"},
        "tags": {"type": "object"},
    }

    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        "owner_login": {
            "validation": "jsonschema",
            "schema": {"type": "string", "minLength": 1},
        },
        "property_name": {
            "validation": "jsonschema",
            "schema": {"type": "string", "minLength": 1},
        },
        # Empty string is "not reported" (GitHub always reports it; the blank is an authoring gap).
        "value_type": {
            "validation": "jsonschema",
            "schema": {"type": "string", "enum": ["", *VALUE_TYPES]},
        },
        "required": {"validation": "jsonschema", "schema": {"type": "boolean"}},
        # A string for string/single_select, an array for multi_select, null when no default is declared.
        "default_value": {
            "validation": "jsonschema",
            "schema": {"type": ["string", "array", "null"]},
        },
        "description": {"validation": "jsonschema", "schema": {"type": "string"}},
        "allowed_values": {
            "validation": "jsonschema",
            "schema": {"type": "array", "items": {"type": "string"}},
        },
        "values_editable_by": {
            "validation": "jsonschema",
            "schema": {"type": "string"},
        },
        "source_type": {"validation": "jsonschema", "schema": {"type": "string"}},
        "url": {"validation": "jsonschema", "schema": {"type": "string"}},
        "configuration": {"validation": "jsonschema", "schema": {"type": "object"}},
        "tags": {"validation": "jsonschema", "schema": {"type": "object"}},
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["owner_login", "property_name"]

    #: The organization that declares the property; half the natural key.
    owner_login = models.CharField(max_length=255, blank=True, default="", db_index=True)
    #: The name exactly as GitHub reports it (hyphens and case preserved) — the key every
    #: repository's `custom_properties` map uses, so it is never normalized.
    property_name = models.CharField(max_length=255, blank=True, default="", db_index=True)
    value_type = models.CharField(max_length=32, blank=True, default="")
    #: Whether GitHub requires every repository to carry a value. A required property has a
    #: `default_value`, which is exactly the silent assertion a populate-first policy avoids.
    required = models.BooleanField(default=False)
    default_value = models.JSONField(null=True, blank=True)
    description = models.TextField(blank=True, default="")
    #: The closed vocabulary for `single_select` / `multi_select`; empty for the other types.
    allowed_values = models.JSONField(default=list, blank=True)
    #: `org_actors` or `org_and_repo_actors` — who may set a value on a repository.
    values_editable_by = models.CharField(max_length=32, blank=True, default="")
    #: `organization` or `enterprise` — where the definition was authored.
    source_type = models.CharField(max_length=32, blank=True, default="")
    url = models.URLField(max_length=512, blank=True, default="")
    configuration = models.JSONField(default=dict, blank=True)
    tags = models.JSONField(default=dict, blank=True)

    class Meta(BaseModel.Meta):
        db_table = "github_core__github_custom_property"

    def get_name(self) -> str:
        return self.property_name or ""

    def __str__(self) -> str:
        return self.get_name()
