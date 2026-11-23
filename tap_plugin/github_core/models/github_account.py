"""GitHub Account — owner/user/org account on GitHub."""

from typing import Any, ClassVar

from django.db import models

from tap_grid.event_time import NO_EVENT_TIME
from tap_grid.models import BaseModel


class GithubAccount(BaseModel):
    """A GitHub account (user or organization).

    Reconciliation (github-core#14 shape D, github-core#151): an account is never retired on
    absence — it stops mattering when its last repository does. It CONTAINS its repositories:
    ``OWNS_REPO`` is the one edge the cascade, the collector's descent and the falsifier's
    fan-out all read (``CONTAINMENT_EDGES``, req-grid-service-delete-cascade). Everything else
    leaving an account (secrets, packages, custom properties) is a reference, not containment,
    and stays live when the account goes.

    Spec: plugins/github_core/specs/spec-github-core-v0.md (req-github-core-models)
    """

    ENTITY_TYPE: ClassVar[str] = "github_core__github_account"
    # The login. GitHub's numeric id is carried as a field for continuity across a rename;
    # the login is what every URL, every `uses:` path and every API response names.
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("login",)
    ENTITY_NAME: ClassVar[str] = "GitHub Account"
    ENTITY_DESCRIPTION: ClassVar[str] = "A GitHub user or organization account."
    ENTITY_ICON: ClassVar[str] = "github-account"
    # No source time is stored: GitHub's account created_at is not kept, and `configuration` holds org policy keys only.
    EVENT_TIME: ClassVar[Any] = NO_EVENT_TIME
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {
        "git.host": "github.com",
        "github.observation": "declaration",
    }
    # Mid level of the GitHub nesting palette — light accent blue. See
    # github_platform.GithubPlatform.DEFAULT_DISPLAY for the family scheme.
    DEFAULT_DISPLAY: ClassVar[dict[str, Any]] = {
        "tap_viz": {
            "shape": "round-rectangle",
            "colors": {"fill": "#DDF4FF", "border": "#54AEFF", "label": "#0A3069"},
            "label": {"valign": "top", "halign": "center", "position": "outside"},
        }
    }

    # Edge permission (union with the edge definitions' own sources/targets): declared so the
    # containment declaration below can name it — containment is a subset of permission
    # (req-grid-service-delete-cascade-12). Every other outbound edge type is still permitted by
    # its `.edge.json` sources; this list constrains nothing it does not name.
    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "github_core__github_repository"}], "edges": [{"type": "OWNS_REPO__github_core"}]},
    ]
    #: What retires with this account, and what the account's repository listing is a surface OF
    #: (completeness `edge_type`, candidates fan-out). Shape B children: a repository is
    #: reconcilable only under a proven-complete, unfiltered walk of `account.repositories`.
    CONTAINMENT_EDGES: ClassVar[tuple[str, ...]] = ("OWNS_REPO__github_core",)

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "login": {"type": "string", "minLength": 1},
        "github_id": {"type": ["integer", "null"]},
        "account_type": {"type": "string"},
        "html_url": {"type": "string"},
        "configuration": {"type": "object"},
        "tags": {"type": "object"},
    }

    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        "login": {
            "validation": "jsonschema",
            "schema": {"type": "string", "minLength": 1},
        },
        "github_id": {
            "validation": "jsonschema",
            "schema": {"type": ["integer", "null"]},
        },
        "account_type": {"validation": "jsonschema", "schema": {"type": "string"}},
        "html_url": {"validation": "jsonschema", "schema": {"type": "string"}},
        "configuration": {"validation": "jsonschema", "schema": {"type": "object"}},
        "tags": {"validation": "jsonschema", "schema": {"type": "object"}},
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["login"]

    login = models.CharField(max_length=255, blank=True, default="", db_index=True)
    github_id = models.BigIntegerField(null=True, blank=True, db_index=True)
    account_type = models.CharField(max_length=32, blank=True, default="")
    html_url = models.URLField(max_length=512, blank=True, default="")
    configuration = models.JSONField(default=dict, blank=True)
    tags = models.JSONField(default=dict, blank=True)

    class Meta(BaseModel.Meta):
        db_table = "github_core__github_account"

    def get_name(self) -> str:
        return self.login or (str(self.github_id) if self.github_id else "")

    def __str__(self) -> str:
        return self.get_name()
