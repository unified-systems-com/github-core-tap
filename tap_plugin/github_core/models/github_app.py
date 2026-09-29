"""GitHub App — a GitHub App or first-party platform app (e.g. Dependabot)."""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel


class GithubApp(BaseModel):
    """A GitHub App or first-party platform app enabled on a repository.

    Generic across GitHub's app surface: GitHub's own managed apps (Dependabot,
    code scanning) and third-party / OIDC token-issuing apps all model as a
    ``github_app``, linked to the repositories they are enabled on via the
    ``ENABLED_ON`` edge. Identity is the app ``slug`` (e.g. ``dependabot``), so
    one app node is shared across every repo that enables it.

    **This type is the registered APPLICATION only.** The grant — one account's
    installation of it, with the permissions that account approved and the
    repositories it reaches — is ``app_installation``, reached by
    ``HAS_INSTALLATION``. They were one type until the vocabulary corpus split
    them (seven sources); merged, an account's granted permissions would hang
    off a node shared by every account that installed the same App.

    Reconciliation (github-core#14, github-core#197): the APPLICATION itself is never retired on
    absence — like ``github_account``, it "stops mattering" rather than disappears, and GitHub
    gives no listing to walk it against anyway (an app node is minted from a mention as readily as
    from an installation). What DOES retire is the grant: ``app_installation``, reached by
    ``REGISTERS_INSTALLATION`` (the edge's current name; the paragraph above predates the
    github-core#79 rename), is this node's one containment child. An uninstalled App is the
    security-relevant absence: "an application is inert, an installation is a standing capability"
    (above). ``REGISTERS_INSTALLATION`` is declared here even though this node's own absence is
    never observed, exactly as ``github_account`` declares ``OWNS_REPO`` while never retiring
    itself. See ``AppInstallation``'s own docstring for the falsifier
    (``tap_plugin.github_core.falsifiers.AppInstallationFalsifier``), which probes
    ``GET /app/installations/{id}`` under the App's own JWT — a question this node answers about
    itself, with no repository-reach ambiguity to gate.

    Spec: plugins/github_core/specs/spec-github-core-v0.md (req-github-core-app)
    """

    ENTITY_TYPE: ClassVar[str] = "github_core__github_app"
    # The app slug. One app node is shared across every repo that enables it.
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("slug",)
    ENTITY_NAME: ClassVar[str] = "GitHub App"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "A GitHub App or first-party platform app (e.g. Dependabot) enabled on a repository."
    )
    ENTITY_ICON: ClassVar[str] = "github-app"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {
        "git.host": "github.com",
        "github.surface": "apps",
        "github.observation": "declaration",
    }
    # Same family scheme as the other github_core nodes — white fill so it reads
    # as a card; GitHub-purple border to distinguish apps from the blue Actions
    # surface.
    DEFAULT_DISPLAY: ClassVar[dict[str, Any]] = {
        "tap_viz": {
            "shape": "round-rectangle",
            "colors": {"fill": "#FFFFFF", "border": "#8250DF", "label": "#1F2328"},
        }
    }

    # Edge permission (union with the edge definitions' own sources/targets): declared so the
    # containment declaration below can name it — containment is a subset of permission
    # (req-grid-service-delete-cascade-12). Every other outbound edge type this node already
    # emits (ENABLED_ON_REPOSITORY, EXEMPTS_ACTOR, OPENS_PULL_REQUEST) is still permitted by its
    # own `.edge.json` sources; this list constrains nothing it does not name.
    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {
            "nodes": [{"type": "github_core__app_installation"}],
            "edges": [{"type": "REGISTERS_INSTALLATION__github_core"}],
        },
    ]
    #: What retires with this App node — never itself, only the grant (github-core#197).
    CONTAINMENT_EDGES: ClassVar[tuple[str, ...]] = ("REGISTERS_INSTALLATION__github_core",)

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "slug": {"type": "string", "minLength": 1},
        "name": {"type": "string"},
        "app_id": {"type": ["integer", "null"]},
        "client_id": {"type": "string"},
        "html_url": {"type": "string"},
        "description": {"type": "string"},
        "configuration": {"type": "object"},
        "tags": {"type": "object"},
    }

    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        "slug": {
            "validation": "jsonschema",
            "schema": {"type": "string", "minLength": 1},
        },
        "name": {"validation": "jsonschema", "schema": {"type": "string"}},
        "app_id": {"validation": "jsonschema", "schema": {"type": ["integer", "null"]}},
        "client_id": {"validation": "jsonschema", "schema": {"type": "string"}},
        "html_url": {"validation": "jsonschema", "schema": {"type": "string"}},
        "description": {"validation": "jsonschema", "schema": {"type": "string"}},
        "configuration": {"validation": "jsonschema", "schema": {"type": "object"}},
        "tags": {"validation": "jsonschema", "schema": {"type": "object"}},
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["slug"]

    slug = models.CharField(max_length=255, blank=True, default="", db_index=True)
    name = models.CharField(max_length=255, blank=True, default="")
    app_id = models.BigIntegerField(null=True, blank=True, db_index=True)
    #: The App's public client id — the identifier its installations report back.
    client_id = models.CharField(max_length=128, blank=True, default="")
    html_url = models.URLField(max_length=512, blank=True, default="")
    description = models.TextField(blank=True, default="")
    configuration = models.JSONField(default=dict, blank=True)
    tags = models.JSONField(default=dict, blank=True)

    class Meta(BaseModel.Meta):
        db_table = "github_core__github_app"

    def get_name(self) -> str:
        return self.name or self.slug

    def __str__(self) -> str:
        return self.get_name()
