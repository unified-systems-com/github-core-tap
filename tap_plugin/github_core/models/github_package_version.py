"""GitHub package version — one published version of a package: an image digest, an npm version.

The registry side of `BUILDS_PACKAGE_VERSION`, whose ABSENCE is the finding the vocabulary corpus
built the edge for: a version in the registry with no run behind it is how five incidents read.
Identity here is GitHub's; the `purl` is the corpus's, carried so `supply_chain_core` can claim it.
"""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel


class GithubPackageVersion(BaseModel):
    """One version as GitHub Packages reports it, with the tags that point at it.

    Reconciliation (github-core#14, github-core#197): no falsifier, no containment, for the same
    reason as its own package (`GithubPackage`'s docstring) one level up — the versions listing
    inherits the package listing's App-credential limits (`GET
    /orgs/{owner}/packages/{type}/{name}/versions`, same `enabledForGitHubApps: false` surface)
    and is "reached only through the listing" (Observability, above): when the package's own
    completeness cannot be trusted, nothing about its versions can be walked to exhaustion either.

    Spec: plugins/github_core/specs/spec-github-core-v0.md (req-github-core-packages)
    """

    ENTITY_TYPE: ClassVar[str] = "github_core__github_package_version"
    # The package's coordinates plus GitHub's version id, not the version string: an npm/maven
    # version can be unpublished and re-published as different bytes.
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("owner_login", "package_type", "package_name", "version_id")
    ENTITY_NAME: ClassVar[str] = "GitHub Package Version"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "One published version of a package — a container image digest with the tags pointing at it, "
        "or a registry version — and its purl."
    )
    ENTITY_ICON: ClassVar[str] = "github-package-version"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {
        "git.host": "github.com",
        "github.surface": "packages",
        "github.observation": "execution",
    }
    DEFAULT_DISPLAY: ClassVar[dict[str, Any]] = {
        "tap_viz": {
            "shape": "hexagon",
            "colors": {"fill": "#FFFFFF", "border": "#9A6700", "label": "#1F2328"},
        }
    }

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "version_id": {"type": ["integer", "null"]},
        "owner_login": {"type": "string", "minLength": 1},
        "package_type": {"type": "string"},
        "package_name": {"type": "string", "minLength": 1},
        "version": {"type": "string"},
        "purl": {"type": "string"},
        "container_tags": {"type": "array"},
        "html_url": {"type": "string"},
        "created_at": {"type": ["string", "null"]},
        "updated_at": {"type": ["string", "null"]},
        "configuration": {"type": "object"},
        "tags": {"type": "object"},
    }

    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        "version_id": {
            "validation": "jsonschema",
            "schema": {"type": ["integer", "null"]},
        },
        "owner_login": {
            "validation": "jsonschema",
            "schema": {"type": "string", "minLength": 1},
        },
        "package_type": {"validation": "jsonschema", "schema": {"type": "string"}},
        "package_name": {
            "validation": "jsonschema",
            "schema": {"type": "string", "minLength": 1},
        },
        "version": {"validation": "jsonschema", "schema": {"type": "string"}},
        "purl": {"validation": "jsonschema", "schema": {"type": "string"}},
        "container_tags": {"validation": "jsonschema", "schema": {"type": "array"}},
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
    CREATE_REQUIRED: ClassVar[list[str]] = ["owner_login", "package_name", "version_id"]

    version_id = models.BigIntegerField(null=True, blank=True, db_index=True)
    owner_login = models.CharField(
        max_length=255, blank=True, default="", db_index=True
    )
    package_type = models.CharField(max_length=32, blank=True, default="")
    package_name = models.CharField(
        max_length=512, blank=True, default="", db_index=True
    )
    #: GitHub's version `name`: for a container this is the manifest digest (`sha256:...`),
    #: for a registry package the version string.
    version = models.CharField(max_length=512, blank=True, default="", db_index=True)
    #: Package-URL WITH the version (`pkg:docker/ghcr.io/owner/name@sha256:...`).
    purl = models.CharField(max_length=1024, blank=True, default="", db_index=True)
    #: The tags pointing at this digest when observed (`latest`, `sha-2e39bdf`). Containers only;
    #: a moving tag is recorded by the grid's field history, not diffed here.
    container_tags = models.JSONField(default=list, blank=True)
    html_url = models.URLField(max_length=512, blank=True, default="")
    created_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(null=True, blank=True)
    configuration = models.JSONField(default=dict, blank=True)
    tags = models.JSONField(default=dict, blank=True)

    class Meta(BaseModel.Meta):
        db_table = "github_core__github_package_version"

    def get_name(self) -> str:
        if not self.package_name:
            return ""
        short = (
            self.version[:19] if self.version.startswith("sha256:") else self.version
        )
        return f"{self.package_name}@{short}" if short else self.package_name

    def __str__(self) -> str:
        return self.get_name()
