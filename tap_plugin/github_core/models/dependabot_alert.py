"""Dependabot alert — one vulnerable dependency GitHub found in one manifest, as its alert surface reports it.

The source-specific DETAIL behind a generic finding, never the finding itself. The finding that
rules, panels and cross-plugin queries traverse is compliance_core's
`compliance_core__compliance_finding` (github-core#68, on the shape github-core#89 set for code
scanning); this node hangs off it via `DETAILS_FINDING` and carries what a human reads when they
open one — the package and manifest, the advisory, the vulnerable range and the patched version,
and how (if at all) the alert was dismissed or fixed.
"""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel
from tap_plugin.github_core.models.schema_types import timestamp_validations, timestamps


class DependabotAlert(BaseModel):
    """A Dependabot alert: an advisory that affects a package a repository's manifest names.

    **Every lifecycle state is kept.** `state` is GitHub's own word (`open` / `fixed` /
    `dismissed` / `auto_dismissed`). A fixed alert is history, not noise: "no open alerts" is
    only meaningful beside "N fixed". `fixed_at`, `dismissed_at` and `auto_dismissed_at` are null
    until they happen — null is "unobserved", never "now". `dismissed_reason` / `dismissed_comment`
    / `dismissed_by_login` explain a dismissal and are empty otherwise.

    **Severity is GitHub's grading of the advisory**, not ours (`low` / `medium` / `high` /
    `critical`); `cvss_score` and `cvss_vector` are the CVSS v3 pair when the advisory carries
    one, null otherwise. The ecosystem is whatever GitHub said (`pip`, `npm`, ...): the REST
    documentation's enum has no GitHub Actions value and none has been observed, so nothing is
    filtered on it and the value is recorded as given.

    Reconciliation (github-core#14 shape C): an IMMUTABLE EVENT, like a code scanning alert.
    GitHub never removes a Dependabot alert from the API on fix or dismissal —
    `GET /repos/{owner}/{repo}/dependabot/alerts/{alert_number}` answers a fixed alert forever;
    only `state` and the `*_at` fields change, which the collector re-observes on the alert's own
    record. This type is also the SOURCE of `DETAILS_FINDING`, never a target of any edge in this
    plugin, so no model could declare it a containment child: it is structurally an orphan for the
    retirement-candidate mechanism, and declares no falsifier for that reason.

    Spec: plugins/github_core/specs/spec-github-core-v0.md (req-github-core-dependabot-alerts)
    """

    ENTITY_TYPE: ClassVar[str] = "github_core__dependabot_alert"
    # Repository + GitHub's alert number: stable across re-scans, and numbers restart per repo.
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("full_name", "number")
    ENTITY_NAME: ClassVar[str] = "Dependabot Alert"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "A vulnerable dependency GitHub found in a repository's manifest: the package and manifest, the "
        "advisory and its severity, the vulnerable range and the first patched version, and whether the "
        "alert is open, fixed or dismissed (and why)."
    )
    ENTITY_ICON: ClassVar[str] = "dependabot-alert"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {
        # An alert is the OUTPUT of GitHub's scanner — something that happened, like a run.
        "github.observation": "execution",
        "git.host": "github.com",
        "github.surface": "security",
    }
    DEFAULT_DISPLAY: ClassVar[dict[str, Any]] = {
        "tap_viz": {
            "shape": "octagon",
            "colors": {"fill": "#FFF1E5", "border": "#BC4C00", "label": "#702C00"},
        }
    }

    #: GitHub's own alert states; `""` means the state was not observed.
    STATES: ClassVar[list[str]] = ["", "open", "fixed", "dismissed", "auto_dismissed"]
    #: GitHub's advisory severity; `""` when the advisory carried none.
    SEVERITIES: ClassVar[list[str]] = ["", "low", "medium", "high", "critical"]

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "full_name": {"type": "string", "minLength": 1},
        "number": {"type": "integer"},
        "state": {"type": "string"},
        **timestamps("created_at", "updated_at", "fixed_at", "dismissed_at", "auto_dismissed_at"),
        "dismissed_reason": {"type": "string"},
        "dismissed_comment": {"type": "string"},
        "dismissed_by_login": {"type": "string"},
        "html_url": {"type": "string"},
        "ecosystem": {"type": "string"},
        "package_name": {"type": "string"},
        "manifest_path": {"type": "string"},
        "dependency_scope": {"type": "string"},
        "relationship": {"type": "string"},
        "ghsa_id": {"type": "string"},
        "cve_id": {"type": "string"},
        "advisory_summary": {"type": "string"},
        "advisory_description": {"type": "string"},
        "severity": {"type": "string"},
        "cvss_score": {"type": ["number", "null"]},
        "cvss_vector": {"type": "string"},
        "cwes": {"type": "array"},
        "vulnerable_version_range": {"type": "string"},
        "first_patched_version": {"type": "string"},
        "configuration": {"type": "object"},
        "tags": {"type": "object"},
    }

    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        "full_name": {"validation": "jsonschema", "schema": {"type": "string", "minLength": 1}},
        "number": {"validation": "jsonschema", "schema": {"type": "integer", "minimum": 1}},
        "state": {"validation": "jsonschema", "schema": {"type": "string", "enum": STATES}},
        # null is "we did not observe a timestamp", never "now".
        **timestamp_validations("created_at", "updated_at", "fixed_at", "dismissed_at", "auto_dismissed_at"),
        # GitHub's vocabulary verbatim ("tolerable_risk", "no_bandwidth", ...); "" = not dismissed.
        "dismissed_reason": {"validation": "jsonschema", "schema": {"type": "string"}},
        "dismissed_comment": {"validation": "jsonschema", "schema": {"type": "string"}},
        "dismissed_by_login": {"validation": "jsonschema", "schema": {"type": "string"}},
        "html_url": {"validation": "jsonschema", "schema": {"type": "string"}},
        "ecosystem": {"validation": "jsonschema", "schema": {"type": "string"}},
        "package_name": {"validation": "jsonschema", "schema": {"type": "string"}},
        "manifest_path": {"validation": "jsonschema", "schema": {"type": "string"}},
        "dependency_scope": {"validation": "jsonschema", "schema": {"type": "string"}},
        "relationship": {"validation": "jsonschema", "schema": {"type": "string"}},
        "ghsa_id": {"validation": "jsonschema", "schema": {"type": "string"}},
        "cve_id": {"validation": "jsonschema", "schema": {"type": "string"}},
        "advisory_summary": {"validation": "jsonschema", "schema": {"type": "string"}},
        "advisory_description": {"validation": "jsonschema", "schema": {"type": "string"}},
        "severity": {"validation": "jsonschema", "schema": {"type": "string", "enum": SEVERITIES}},
        # null is "the advisory carried no CVSS v3 score", never 0.
        "cvss_score": {"validation": "jsonschema", "schema": {"type": ["number", "null"]}},
        "cvss_vector": {"validation": "jsonschema", "schema": {"type": "string"}},
        "cwes": {"validation": "jsonschema", "schema": {"type": "array", "items": {"type": "string"}}},
        "vulnerable_version_range": {"validation": "jsonschema", "schema": {"type": "string"}},
        "first_patched_version": {"validation": "jsonschema", "schema": {"type": "string"}},
        "configuration": {"validation": "jsonschema", "schema": {"type": "object"}},
        "tags": {"validation": "jsonschema", "schema": {"type": "object"}},
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["full_name", "number"]

    #: `owner/repo` the alert was raised in; half the natural key.
    full_name = models.CharField(max_length=255, blank=True, default="", db_index=True)
    #: The alert number within that repository; the other half.
    number = models.IntegerField(null=True, blank=True, db_index=True)
    state = models.CharField(max_length=16, blank=True, default="", db_index=True)
    created_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(null=True, blank=True)
    fixed_at = models.DateTimeField(null=True, blank=True)
    dismissed_at = models.DateTimeField(null=True, blank=True)
    auto_dismissed_at = models.DateTimeField(null=True, blank=True)
    #: `""` when not dismissed; otherwise GitHub's reason string verbatim.
    dismissed_reason = models.CharField(max_length=32, blank=True, default="")
    dismissed_comment = models.TextField(blank=True, default="")
    dismissed_by_login = models.CharField(max_length=255, blank=True, default="")
    html_url = models.URLField(max_length=512, blank=True, default="")
    #: GitHub's ecosystem word (`pip`, `npm`, ...), recorded as given — never filtered on.
    ecosystem = models.CharField(max_length=32, blank=True, default="", db_index=True)
    #: The package the manifest names; the join to a `github_action` when it is an action path.
    #: Text, not a bounded column: these four strings come from the repository's own tree and the
    #: advisory, not from us, so a deep path or a long module name must not be able to reject the
    #: alert (and with it a batch) at the database.
    package_name = models.TextField(blank=True, default="")
    #: The manifest file the dependency was found in (`uv.lock`); the join to a workflow when it is one.
    manifest_path = models.TextField(blank=True, default="")
    #: `runtime` / `development`, or `""` when GitHub gave none (the API's `dependency.scope`).
    dependency_scope = models.CharField(max_length=32, blank=True, default="")
    #: `direct` / `transitive` / `unknown`, or `""` (the API's `dependency.relationship`).
    relationship = models.CharField(max_length=32, blank=True, default="")
    ghsa_id = models.CharField(max_length=32, blank=True, default="", db_index=True)
    cve_id = models.CharField(max_length=32, blank=True, default="", db_index=True)
    advisory_summary = models.TextField(blank=True, default="")
    advisory_description = models.TextField(blank=True, default="")
    severity = models.CharField(max_length=16, blank=True, default="", db_index=True)
    cvss_score = models.FloatField(null=True, blank=True)
    cvss_vector = models.CharField(max_length=255, blank=True, default="")
    #: `["CWE-208"]` — the advisory's CWE identifiers.
    cwes = models.JSONField(default=list, blank=True)
    vulnerable_version_range = models.TextField(blank=True, default="")
    #: The first version that fixes it; `""` when no patched version exists.
    first_patched_version = models.TextField(blank=True, default="")
    #: The raw alert as returned, so nothing the model does not name is lost.
    configuration = models.JSONField(default=dict, blank=True)
    tags = models.JSONField(default=dict, blank=True)

    class Meta(BaseModel.Meta):
        db_table = "github_core__dependabot_alert"

    def get_name(self) -> str:
        if self.number is None:
            return ""
        head = " ".join(part for part in (self.package_name, self.ghsa_id) if part)
        # The entity's display name is a bounded column; the package name is not ours to bound.
        return (f"{head} #{self.number}" if head else f"{self.full_name}#{self.number}")[:255]

    def __str__(self) -> str:
        return self.get_name()
