"""GitHub Repository — a repository under a GitHub account."""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel


class GithubRepository(BaseModel):
    """A GitHub repository.

    Reconciliation (github-core#14 shape B, github-core#151): an enumerable platform object.
    Absence from the account's repository listing is evidence only under a proven-complete,
    unfiltered walk, and even then it has four causes (deleted, made private, transferred,
    access narrowed) — so the repository falsifier probes ``GET /repos/{owner}/{repo}`` and
    compares the stable numeric id and the owner login before anything is concluded
    (``tap_plugin.github_core.falsifiers.RepositoryFalsifier``).

    A repository CONTAINS its workflow files (``DEFINES_WORKFLOW``, shape A: the file at HEAD),
    its deployment environments (``DECLARES_ENVIRONMENT``, shape B), and the Actions secrets
    declared directly on IT (``DEFINES_SECRET``, shape B with no stable id —
    ``tap_plugin.github_core.falsifiers.ActionsSecretFalsifier``, github-core#866). Only
    REPOSITORY-scoped secrets are named here: an organisation secret and an environment secret
    are ``DEFINES_SECRET`` edges sourced from the account and the environment respectively, not
    from this repository, and ``GithubAccount`` / ``GithubEnvironment`` both document those as
    references rather than containment — a repository going away does not end an organisation's
    secret, and this model does not speak for what an environment declares. Two relations #14
    lists under the repository are deliberately NOT declared here:

    - rulesets: ``PROTECTS_REPOSITORY`` points ruleset -> repository, and one organization
      ruleset protects many repositories; it is not contained by any one of them.
    - refs: a ref hangs off the neutral ``git_core__git_repository`` through git_core's own
      ``DECLARES_REF`` — that containment is git_core's declaration, not this hosting record's.

    Runs (``EXECUTES_WORKFLOW`` is run -> workflow, shape C), releases, artifacts, caches,
    alerts and pull requests are references or immutable events: none retires with the
    repository through the cascade, and none is a candidate surface.

    Spec: plugins/github_core/specs/spec-github-core-v0.md (req-github-core-models)
    """

    ENTITY_TYPE: ClassVar[str] = "github_core__github_repository"
    # `owner/repo` — the spec's natural key and what every GitHub surface names a repository by.
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("full_name",)
    ENTITY_NAME: ClassVar[str] = "GitHub Repository"
    ENTITY_DESCRIPTION: ClassVar[str] = "A repository hosted on GitHub."
    ENTITY_ICON: ClassVar[str] = "github-repository"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {
        "git.host": "github.com",
        "github.observation": "declaration",
    }
    # Inner level of the GitHub nesting palette — deeper accent blue; the white
    # workflow leaf cards sit on this bed. See github_platform for the scheme.
    DEFAULT_DISPLAY: ClassVar[dict[str, Any]] = {
        "tap_viz": {
            "shape": "round-rectangle",
            "colors": {"fill": "#B6E3FF", "border": "#0969DA", "label": "#0A3069"},
            "label": {"valign": "top", "halign": "center", "position": "outside"},
        }
    }

    #: The custom-property values were returned by the organization's values endpoint.
    CUSTOM_PROPERTIES_OBSERVED = "observed"
    #: The credential could not read them; `custom_properties` must not be rendered as "none set".
    CUSTOM_PROPERTIES_UNOBSERVABLE = "unobservable"

    # Edge permission (union with the edge definitions' own sources/targets): declared so the
    # containment declaration below can name them (req-grid-service-delete-cascade-12). Every
    # other outbound edge type (HOSTS_REPOSITORY, DEFINES_SECRET, PUBLISHES_RELEASE, ...) is
    # still permitted by its `.edge.json` sources; this list constrains nothing it does not name.
    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "github_core__github_workflow"}], "edges": [{"type": "DEFINES_WORKFLOW__github_core"}]},
        {
            "nodes": [{"type": "github_core__github_environment"}],
            "edges": [{"type": "DECLARES_ENVIRONMENT__github_core"}],
        },
        {"nodes": [{"type": "github_core__actions_secret"}], "edges": [{"type": "DEFINES_SECRET__github_core"}]},
    ]
    #: What retires with this repository, and the three listing surfaces the collector records
    #: completeness for under it: `repository.workflows`, `repository.environments` and
    #: `repository.secrets`. The last is the REPOSITORY-scope secret listing only — the
    #: `DEFINES_SECRET` edges an environment or the account itself sources are that entity's
    #: business, not this one's (github-core#866).
    CONTAINMENT_EDGES: ClassVar[tuple[str, ...]] = (
        "DEFINES_WORKFLOW__github_core",
        "DECLARES_ENVIRONMENT__github_core",
        "DEFINES_SECRET__github_core",
    )

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "full_name": {"type": "string", "minLength": 1},
        "owner_login": {"type": "string"},
        "name": {"type": "string"},
        "github_id": {"type": ["integer", "null"]},
        "default_branch": {"type": "string"},
        "visibility": {"type": "string"},
        "html_url": {"type": "string"},
        "outputs_observability": {"type": "object"},
        "custom_properties": {"type": "object"},
        "custom_properties_observability": {
            "type": "string",
            "enum": ["", CUSTOM_PROPERTIES_OBSERVED, CUSTOM_PROPERTIES_UNOBSERVABLE],
        },
        "pull_requests_observability": {"type": "string", "enum": ["", "observed", "unobservable"]},
        "pull_requests_total": {"type": ["integer", "null"]},
        "code_scanning_observability": {
            "type": "string",
            "enum": ["", "observed", "unobservable", "not_enabled"],
        },
        "configuration": {"type": "object"},
        "tags": {"type": "object"},
    }

    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        "full_name": {
            "validation": "jsonschema",
            "schema": {"type": "string", "minLength": 1},
        },
        "owner_login": {"validation": "jsonschema", "schema": {"type": "string"}},
        "name": {"validation": "jsonschema", "schema": {"type": "string"}},
        "github_id": {
            "validation": "jsonschema",
            "schema": {"type": ["integer", "null"]},
        },
        "default_branch": {"validation": "jsonschema", "schema": {"type": "string"}},
        "visibility": {"validation": "jsonschema", "schema": {"type": "string"}},
        "html_url": {"validation": "jsonschema", "schema": {"type": "string"}},
        "outputs_observability": {
            "validation": "jsonschema",
            "schema": {"type": "object"},
        },
        # Keys are property names exactly as GitHub reports them; a value is a string, an array
        # (multi_select) or null. A null value is OBSERVED-UNSET: the definition exists and the
        # repository carries no value. A key that is absent was never read against a definition.
        "custom_properties": {
            "validation": "jsonschema",
            "schema": {"type": "object", "additionalProperties": {"type": ["string", "array", "null"]}},
        },
        "custom_properties_observability": {
            "validation": "jsonschema",
            "schema": {"type": "string", "enum": ["", CUSTOM_PROPERTIES_OBSERVED, CUSTOM_PROPERTIES_UNOBSERVABLE]},
        },
        # Same three states for the pull-request surface: `observed` (the config layer answered
        # `pullRequests` — zero is then a fact), `unobservable` (the field degraded), `""` (a
        # repos-only scope runs no config-layer query).
        "pull_requests_observability": {
            "validation": "jsonschema",
            "schema": {"type": "string", "enum": ["", "observed", "unobservable"]},
        },
        # GitHub's totalCount, so the cap on the collected window is visible beside the rows.
        "pull_requests_total": {"validation": "jsonschema", "schema": {"type": ["integer", "null"]}},
        # FOUR states for the code scanning surface (github-core#89): `observed` (GitHub answered
        # 200 — zero alerts is then a fact), `unobservable` (403: the credential or its permissions
        # could not look), `not_enabled` (GitHub itself says code scanning / Advanced Security is
        # off for this repository — the 404 "no analysis found" or the 403 whose body names
        # Advanced Security), `""` (never asked). `not_enabled` is a finding about the repository;
        # `unobservable` is a finding about us. They must never share a value.
        "code_scanning_observability": {
            "validation": "jsonschema",
            "schema": {"type": "string", "enum": ["", "observed", "unobservable", "not_enabled"]},
        },
        "configuration": {"validation": "jsonschema", "schema": {"type": "object"}},
        "tags": {"validation": "jsonschema", "schema": {"type": "object"}},
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["full_name"]

    full_name = models.CharField(max_length=255, blank=True, default="", db_index=True)
    owner_login = models.CharField(
        max_length=255, blank=True, default="", db_index=True
    )
    name = models.CharField(max_length=255, blank=True, default="")
    github_id = models.BigIntegerField(null=True, blank=True, db_index=True)
    default_branch = models.CharField(max_length=255, blank=True, default="")
    visibility = models.CharField(max_length=32, blank=True, default="")
    html_url = models.URLField(max_length=512, blank=True, default="")
    #: Three states per OUTPUT surface — `{"releases": "observed"|"unobservable", "artifacts": ...,
    #: "packages": ...}` plus a `notes` map saying why. Lives on the repository because a property
    #: that qualifies an absence belongs on the node the absence is about, never on the nodes that
    #: failed to appear (github-core#31; the same ruling as `github_ruleset.bypass_observability`).
    #: Empty `{}` means the collector never ran the output surfaces, which is itself not "none".
    outputs_observability = models.JSONField(default=dict, blank=True)
    #: `{"criticality": "critical", "lifecycle": null, ...}` — one key per custom property the
    #: owning organization DECLARES (`github_custom_property`), the value as GitHub reports it or
    #: null when the repository has not set it. Read against the definitions, so an unset value
    #: is a fact and not a blank. Empty `{}` with observability `observed` means the organization
    #: declares no properties.
    custom_properties = models.JSONField(default=dict, blank=True)
    #: Three states, the ruling of `github_ruleset.bypass_observability` applied here: `observed`
    #: (the values endpoint answered — an empty map is then a fact), `unobservable` (the credential
    #: could not read them — the map means nothing), `""` (the collector never ran the surface,
    #: e.g. a user-owned repository, where custom properties do not exist).
    custom_properties_observability = models.CharField(max_length=16, blank=True, default="")
    #: Whether this repository's pull requests were read (`observed` | `unobservable` | `""` never
    #: asked) and how many GitHub reports in total, so a collected window of thirty is never
    #: mistaken for all of them (req-github-core-pull-requests).
    pull_requests_observability = models.CharField(max_length=16, blank=True, default="")
    pull_requests_total = models.IntegerField(null=True, blank=True)
    #: Whether this repository's code scanning alerts were read: `observed` | `unobservable` |
    #: `not_enabled` (GitHub says the surface is off here) | `""` never asked (req-github-core-code-scanning).
    code_scanning_observability = models.CharField(max_length=16, blank=True, default="")
    configuration = models.JSONField(default=dict, blank=True)
    tags = models.JSONField(default=dict, blank=True)

    class Meta(BaseModel.Meta):
        db_table = "github_core__github_repository"

    def get_name(self) -> str:
        return self.full_name or self.name

    def __str__(self) -> str:
        return self.get_name()
