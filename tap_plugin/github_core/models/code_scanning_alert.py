"""Code scanning alert — one rule firing at one location, as GitHub's code scanning surface reports it.

The source-specific DETAIL behind a generic finding, never the finding itself. The finding
that rules, panels and cross-plugin queries traverse is compliance_core's
`compliance_core__compliance_finding` (github-core#89); this node hangs off it via
`DETAILS_FINDING` and carries what a human reads when they open one — the rule, its
severities, where it fired, what the scanner said, and how (if at all) it was dismissed.
Dependabot and secret-scanning alerts will be sibling detail nodes on the same finding shape.
"""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel


class CodeScanningAlert(BaseModel):
    """A code scanning alert: a scanner's rule that fired on a repository, and its lifecycle.

    **Two severities, deliberately both.** `rule_severity` is the tool's own grading of the rule
    (`note` / `warning` / `error`); `security_severity_level` is GitHub's CVSS-shaped grade
    (`low` … `critical`) and is present only for security queries. A quality rule has the first
    and an empty second; that blank is a fact, not a gap.

    **Dismissal is a fact about the alert, not a state machine.** `state` is GitHub's own word
    (`open` / `dismissed` / `fixed`); `dismissed_reason` / `dismissed_comment` / `dismissed_by_login`
    explain a dismissal and are empty otherwise. `fixed_at` and `dismissed_at` are null until they
    happen — null is "unobserved", never "now".

    Reconciliation (github-core#14 shape C, github-core#194): an IMMUTABLE EVENT, and doubly so.
    Like a pull request, GitHub never removes a code scanning alert from the API on dismiss or
    fix — `GET /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}` answers a dismissed or
    fixed alert forever; only `state` and the `dismissed_*`/`fixed_at` fields change, which the
    collector already re-observes on the alert's own record. But this type also has no PATH a
    containment declaration could ever use: it is the SOURCE of `DETAILS_FINDING`
    (alert -> `compliance_core__compliance_finding`), never a target of any edge in this plugin,
    so no model could declare it a containment child even if one wanted to — it is structurally
    an orphan for the retirement-candidate mechanism (`tap_grid.candidates`), the same way
    `github_actions_run` is. It declares no falsifier for that reason and this one together.

    The generic finding this alert backs (`compliance_core__compliance_finding`, minted by
    `identity.py`'s `code_scanning_finding_id()`) is a DIFFERENT type this plugin does not own —
    compliance_core declares its own `CONTAINMENT_EDGES`, if any, and its falsifier question is
    compliance_core's to answer, not this docstring's (github-core#194 surveyed it: no model
    anywhere currently declares `CARRIES_COMPLIANCE_FINDING` as containment either, so today the
    finding is in the same unreached position — but that is an observation, not a decision this
    repo is positioned to make).

    Spec: plugins/github_core/specs/spec-github-core-v0.md (req-github-core-code-scanning)
    """

    ENTITY_TYPE: ClassVar[str] = "github_core__code_scanning_alert"
    # Repository + GitHub's alert number: stable across re-analysis, and numbers restart per repo.
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("full_name", "number")
    ENTITY_NAME: ClassVar[str] = "Code Scanning Alert"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "A code scanning rule that fired on a repository: the rule and its severities, the location and "
        "message, the analysis that produced it, and whether it is open, fixed or dismissed (and why)."
    )
    ENTITY_ICON: ClassVar[str] = "code-scanning-alert"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {
        # An alert is the OUTPUT of a scanner run — something that happened, like a run.
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
    STATES: ClassVar[list[str]] = ["", "open", "dismissed", "fixed"]
    #: The tool's grading of the rule (SARIF `level`).
    RULE_SEVERITIES: ClassVar[list[str]] = ["", "note", "warning", "error"]
    #: GitHub's security severity, present only for security queries.
    SECURITY_SEVERITY_LEVELS: ClassVar[list[str]] = ["", "low", "medium", "high", "critical"]

    #: The location shape C emits — exactly these keys, nothing else.
    _LOCATION_SCHEMA: ClassVar[dict[str, Any]] = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "path": {"type": "string"},
            "start_line": {"type": "integer"},
            "end_line": {"type": "integer"},
            "start_column": {"type": "integer"},
            "end_column": {"type": "integer"},
        },
    }

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "full_name": {"type": "string", "minLength": 1},
        "number": {"type": "integer"},
        "state": {"type": "string"},
        "created_at": {"type": ["string", "null"]},
        "updated_at": {"type": ["string", "null"]},
        "fixed_at": {"type": ["string", "null"]},
        "dismissed_at": {"type": ["string", "null"]},
        "dismissed_reason": {"type": "string"},
        "dismissed_comment": {"type": "string"},
        "dismissed_by_login": {"type": "string"},
        "html_url": {"type": "string"},
        "rule_id": {"type": "string"},
        "rule_name": {"type": "string"},
        "rule_severity": {"type": "string"},
        "security_severity_level": {"type": "string"},
        "rule_description": {"type": "string"},
        "rule_tags": {"type": "array"},
        "tool_name": {"type": "string"},
        "tool_version": {"type": "string"},
        "tool_guid": {"type": "string"},
        "analysis_key": {"type": "string"},
        "category": {"type": "string"},
        "environment": {"type": "string"},
        "ref": {"type": "string"},
        "commit_sha": {"type": "string"},
        "location": {"type": "object"},
        "message": {"type": "string"},
        "classifications": {"type": "array"},
        "instances_url": {"type": "string"},
        "configuration": {"type": "object"},
        "tags": {"type": "object"},
    }

    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        "full_name": {"validation": "jsonschema", "schema": {"type": "string", "minLength": 1}},
        "number": {"validation": "jsonschema", "schema": {"type": "integer", "minimum": 1}},
        "state": {"validation": "jsonschema", "schema": {"type": "string", "enum": STATES}},
        # null is "we did not observe a timestamp", never "now".
        "created_at": {"validation": "jsonschema", "schema": {"type": ["string", "null"]}},
        "updated_at": {"validation": "jsonschema", "schema": {"type": ["string", "null"]}},
        "fixed_at": {"validation": "jsonschema", "schema": {"type": ["string", "null"]}},
        "dismissed_at": {"validation": "jsonschema", "schema": {"type": ["string", "null"]}},
        # GitHub's vocabulary verbatim: "false positive", "won't fix", "used in tests"; "" = not dismissed.
        "dismissed_reason": {"validation": "jsonschema", "schema": {"type": "string"}},
        "dismissed_comment": {"validation": "jsonschema", "schema": {"type": "string"}},
        "dismissed_by_login": {"validation": "jsonschema", "schema": {"type": "string"}},
        "html_url": {"validation": "jsonschema", "schema": {"type": "string"}},
        "rule_id": {"validation": "jsonschema", "schema": {"type": "string"}},
        "rule_name": {"validation": "jsonschema", "schema": {"type": "string"}},
        "rule_severity": {"validation": "jsonschema", "schema": {"type": "string", "enum": RULE_SEVERITIES}},
        "security_severity_level": {
            "validation": "jsonschema",
            "schema": {"type": "string", "enum": SECURITY_SEVERITY_LEVELS},
        },
        "rule_description": {"validation": "jsonschema", "schema": {"type": "string"}},
        "rule_tags": {"validation": "jsonschema", "schema": {"type": "array", "items": {"type": "string"}}},
        "tool_name": {"validation": "jsonschema", "schema": {"type": "string"}},
        "tool_version": {"validation": "jsonschema", "schema": {"type": "string"}},
        "tool_guid": {"validation": "jsonschema", "schema": {"type": "string"}},
        "analysis_key": {"validation": "jsonschema", "schema": {"type": "string"}},
        "category": {"validation": "jsonschema", "schema": {"type": "string"}},
        "environment": {"validation": "jsonschema", "schema": {"type": "string"}},
        "ref": {"validation": "jsonschema", "schema": {"type": "string"}},
        "commit_sha": {"validation": "jsonschema", "schema": {"type": "string"}},
        "location": {"validation": "jsonschema", "schema": _LOCATION_SCHEMA},
        "message": {"validation": "jsonschema", "schema": {"type": "string"}},
        "classifications": {"validation": "jsonschema", "schema": {"type": "array", "items": {"type": "string"}}},
        "instances_url": {"validation": "jsonschema", "schema": {"type": "string"}},
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
    #: `""` when not dismissed; otherwise GitHub's reason string verbatim.
    dismissed_reason = models.CharField(max_length=32, blank=True, default="")
    dismissed_comment = models.TextField(blank=True, default="")
    dismissed_by_login = models.CharField(max_length=255, blank=True, default="")
    html_url = models.URLField(max_length=512, blank=True, default="")
    #: The scanner's rule identifier (`py/sql-injection`, `B105`); the join across alerts.
    rule_id = models.CharField(max_length=255, blank=True, default="", db_index=True)
    rule_name = models.CharField(max_length=255, blank=True, default="")
    rule_severity = models.CharField(max_length=16, blank=True, default="")
    security_severity_level = models.CharField(max_length=16, blank=True, default="", db_index=True)
    rule_description = models.TextField(blank=True, default="")
    #: `["security", "external/cwe/cwe-089"]` — the rule's tags, CWE references included.
    rule_tags = models.JSONField(default=list, blank=True)
    #: The scanner (`CodeQL`, `Bandit`, `Trivy`); many tools upload to the one surface.
    tool_name = models.CharField(max_length=255, blank=True, default="", db_index=True)
    tool_version = models.CharField(max_length=64, blank=True, default="")
    tool_guid = models.CharField(max_length=64, blank=True, default="")
    #: `<workflow path>:<job>` — which workflow job produced the most recent instance.
    analysis_key = models.CharField(max_length=512, blank=True, default="")
    category = models.CharField(max_length=255, blank=True, default="")
    #: The matrix environment of the most recent instance, as a JSON string GitHub returns.
    environment = models.CharField(max_length=512, blank=True, default="")
    #: The ref and commit of the most recent instance (`refs/heads/main`; a 40-hex sha).
    ref = models.CharField(max_length=512, blank=True, default="")
    commit_sha = models.CharField(max_length=64, blank=True, default="", db_index=True)
    #: `{"path", "start_line", "end_line", "start_column", "end_column"}` — where the rule fired.
    location = models.JSONField(default=dict, blank=True)
    #: The scanner's message for this instance, verbatim.
    message = models.TextField(blank=True, default="")
    #: GitHub's classifications of the location (`source`, `generated`, `test`, `library`).
    classifications = models.JSONField(default=list, blank=True)
    instances_url = models.URLField(max_length=512, blank=True, default="")
    #: The raw alert as returned, so nothing the model does not name is lost.
    configuration = models.JSONField(default=dict, blank=True)
    tags = models.JSONField(default=dict, blank=True)

    class Meta(BaseModel.Meta):
        db_table = "github_core__code_scanning_alert"

    def get_name(self) -> str:
        if self.number is None:
            return ""
        head = " ".join(part for part in (self.tool_name, self.rule_id) if part)
        return f"{head} #{self.number}" if head else f"{self.full_name}#{self.number}"

    def __str__(self) -> str:
        return self.get_name()
