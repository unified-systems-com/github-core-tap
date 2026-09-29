"""GitHub package — a named package in GitHub Packages, the container of its versions.

**The collection seam, not the identity home.** The vocabulary corpus (decision 4) places
`package` / `package_version` in a future `supply_chain_core` plugin, keyed on a purl. That
ruling stands for IDENTITY. GitHub Packages is nevertheless a GitHub surface — its API, its
permission and its visibility rules are GitHub's — so the COLLECTION belongs here. These nodes
are github_core-owned, carry a `purl` so `supply_chain_core` can later claim or alias them by the
identity the corpus chose, and never pretend to be the neutral type.
"""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel


class GithubPackage(BaseModel):
    """One package as GitHub Packages reports it: type, name, owner, visibility, version count.

    Reconciliation (github-core#14, github-core#197): no falsifier, no containment — already the
    ruling on record. `github_account.py`'s own docstring lists packages under "Everything else
    leaving an account (secrets, packages, custom properties) is a reference, not containment, and
    stays live when the account goes." The observability section above reinforces why: the
    packages listing is frequently `unobservable` under the product's own App credential (measured
    400 on the container type), so `enumeration_complete` would rarely if ever be honestly
    assertable for it — the same credential-shaped ambiguity as `github_custom_property`'s
    (Shape E), without that type's mitigating direct-probe endpoint being wired to anything a
    containment declaration could fan out from yet.

    Spec: plugins/github_core/specs/spec-github-core-v0.md (req-github-core-packages)
    """

    ENTITY_TYPE: ClassVar[str] = "github_core__github_package"
    # Owner + type + name — GitHub's own REST path to the package, not its numeric id.
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("owner_login", "package_type", "name")
    ENTITY_NAME: ClassVar[str] = "GitHub Package"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "A package published to GitHub Packages — a container image on ghcr.io, an npm or Maven "
        "package — with its purl, so the supply-chain substrate can claim it by identity."
    )
    ENTITY_ICON: ClassVar[str] = "github-package"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {
        "git.host": "github.com",
        "github.surface": "packages",
        # A package exists because something was PUBLISHED to it; nobody declares one.
        "github.observation": "execution",
    }
    DEFAULT_DISPLAY: ClassVar[dict[str, Any]] = {
        "tap_viz": {
            "shape": "hexagon",
            "colors": {"fill": "#FFF8C5", "border": "#9A6700", "label": "#4D2D00"},
        }
    }

    #: GitHub's closed set of package types, as the REST `package_type` parameter spells them.
    PACKAGE_TYPES: ClassVar[tuple[str, ...]] = (
        "container",
        "npm",
        "maven",
        "rubygems",
        "docker",
        "nuget",
    )

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "package_id": {"type": ["integer", "null"]},
        "owner_login": {"type": "string", "minLength": 1},
        "package_type": {"type": "string", "enum": [*PACKAGE_TYPES, ""]},
        "name": {"type": "string", "minLength": 1},
        "purl": {"type": "string"},
        "visibility": {"type": "string"},
        "version_count": {"type": ["integer", "null"]},
        "repository_full_name": {"type": "string"},
        "html_url": {"type": "string"},
        "created_at": {"type": ["string", "null"]},
        "updated_at": {"type": ["string", "null"]},
        "configuration": {"type": "object"},
        "tags": {"type": "object"},
    }

    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        "package_id": {
            "validation": "jsonschema",
            "schema": {"type": ["integer", "null"]},
        },
        "owner_login": {
            "validation": "jsonschema",
            "schema": {"type": "string", "minLength": 1},
        },
        # "" permitted so a partially-read package lands — the grid's unobserved convention.
        "package_type": {
            "validation": "jsonschema",
            "schema": {"type": "string", "enum": [*PACKAGE_TYPES, ""]},
        },
        "name": {
            "validation": "jsonschema",
            "schema": {"type": "string", "minLength": 1},
        },
        "purl": {"validation": "jsonschema", "schema": {"type": "string"}},
        "visibility": {"validation": "jsonschema", "schema": {"type": "string"}},
        "version_count": {
            "validation": "jsonschema",
            "schema": {"type": ["integer", "null"]},
        },
        "repository_full_name": {
            "validation": "jsonschema",
            "schema": {"type": "string"},
        },
        "html_url": {"validation": "jsonschema", "schema": {"type": "string"}},
        "created_at": {
            "validation": "jsonschema",
            "schema": {"type": ["string", "null"]},
        },
        "updated_at": {
            "validation": "jsonschema",
            "schema": {"type": ["string", "null"]},
        },
        "configuration": {"validation": "jsonschema", "schema": {"type": "object"}},
        "tags": {"validation": "jsonschema", "schema": {"type": "object"}},
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["owner_login", "package_type", "name"]

    package_id = models.BigIntegerField(null=True, blank=True, db_index=True)
    owner_login = models.CharField(
        max_length=255, blank=True, default="", db_index=True
    )
    package_type = models.CharField(
        max_length=32, blank=True, default="", db_index=True
    )
    name = models.CharField(max_length=512, blank=True, default="", db_index=True)
    #: Package-URL WITHOUT a version (`pkg:docker/ghcr.io/owner/name`) — the identity the
    #: supply-chain substrate keys on. Derived once, in `identity.package_purl`.
    purl = models.CharField(max_length=1024, blank=True, default="", db_index=True)
    visibility = models.CharField(max_length=32, blank=True, default="")
    #: GitHub's own count — the number that says how much a capped version walk left behind.
    version_count = models.IntegerField(null=True, blank=True)
    #: `owner/repo` GitHub links the package to, when it does; "" when it is unlinked.
    repository_full_name = models.CharField(
        max_length=255, blank=True, default="", db_index=True
    )
    html_url = models.URLField(max_length=512, blank=True, default="")
    created_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(null=True, blank=True)
    configuration = models.JSONField(default=dict, blank=True)
    tags = models.JSONField(default=dict, blank=True)

    class Meta(BaseModel.Meta):
        db_table = "github_core__github_package"

    def get_name(self) -> str:
        return f"{self.owner_login}/{self.name}" if self.name else ""

    def __str__(self) -> str:
        return self.get_name()
