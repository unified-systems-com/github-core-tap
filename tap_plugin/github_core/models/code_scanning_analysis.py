"""Code scanning analysis — one SARIF upload: a scanner ran against one commit and reported.

The execution record behind the alerts. An alert says a rule fired; an analysis says a tool ran
at all — which is the fact a "zero alerts" answer depends on. A repository with no analyses has
not been scanned; a repository with analyses and no alerts has been scanned clean. The two
are different, and only this node tells them apart (github-core#89).
"""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel
from tap_plugin.github_core.models.schema_types import DATE_TIME, DATE_TIME_VALIDATION


class CodeScanningAnalysis(BaseModel):
    """A code scanning analysis: which tool ran, on which commit and ref, and what it counted.

    `results_count` / `rules_count` are GitHub's own tallies for the upload; `warning` and
    `error` are the scanner's own words when an upload was partial or failed — an analysis
    with an `error` produced no trustworthy alerts, and a query that counts alerts without
    reading it is counting the wrong thing.

    Spec: plugins/github_core/specs/spec-github-core-v0.md (req-github-core-code-scanning)
    """

    ENTITY_TYPE: ClassVar[str] = "github_core__code_scanning_analysis"
    # Repository + GitHub's analysis id (one SARIF upload).
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("full_name", "analysis_id")
    ENTITY_NAME: ClassVar[str] = "Code Scanning Analysis"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "One code scanning upload: the tool and version, the commit and ref it analysed, "
        "its result and rule counts, and any warning or error the upload carried."
    )
    ENTITY_ICON: ClassVar[str] = "code-scanning-analysis"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {
        # A scanner RAN: an execution in the same category as a workflow run.
        "github.observation": "execution",
        "git.host": "github.com",
        "github.surface": "security",
    }
    DEFAULT_DISPLAY: ClassVar[dict[str, Any]] = {
        "tap_viz": {
            "shape": "round-hexagon",
            "colors": {"fill": "#FFF1E5", "border": "#DB6D28", "label": "#702C00"},
        }
    }

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "full_name": {"type": "string", "minLength": 1},
        "analysis_id": {"type": "integer"},
        "ref": {"type": "string"},
        "commit_sha": {"type": "string"},
        "analysis_key": {"type": "string"},
        "category": {"type": "string"},
        "environment": {"type": "string"},
        "tool_name": {"type": "string"},
        "tool_version": {"type": "string"},
        "tool_guid": {"type": "string"},
        "created_at": DATE_TIME,
        "results_count": {"type": "integer"},
        "rules_count": {"type": "integer"},
        "sarif_id": {"type": "string"},
        "deletable": {"type": "boolean"},
        "warning": {"type": "string"},
        "error": {"type": "string"},
        "url": {"type": "string"},
        "configuration": {"type": "object"},
        "tags": {"type": "object"},
    }

    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        "full_name": {"validation": "jsonschema", "schema": {"type": "string", "minLength": 1}},
        "analysis_id": {"validation": "jsonschema", "schema": {"type": "integer", "minimum": 1}},
        "ref": {"validation": "jsonschema", "schema": {"type": "string"}},
        "commit_sha": {"validation": "jsonschema", "schema": {"type": "string"}},
        "analysis_key": {"validation": "jsonschema", "schema": {"type": "string"}},
        "category": {"validation": "jsonschema", "schema": {"type": "string"}},
        "environment": {"validation": "jsonschema", "schema": {"type": "string"}},
        "tool_name": {"validation": "jsonschema", "schema": {"type": "string"}},
        "tool_version": {"validation": "jsonschema", "schema": {"type": "string"}},
        "tool_guid": {"validation": "jsonschema", "schema": {"type": "string"}},
        # null is "we did not observe a timestamp", never "now".
        "created_at": DATE_TIME_VALIDATION,
        "results_count": {"validation": "jsonschema", "schema": {"type": "integer", "minimum": 0}},
        "rules_count": {"validation": "jsonschema", "schema": {"type": "integer", "minimum": 0}},
        "sarif_id": {"validation": "jsonschema", "schema": {"type": "string"}},
        "deletable": {"validation": "jsonschema", "schema": {"type": "boolean"}},
        "warning": {"validation": "jsonschema", "schema": {"type": "string"}},
        "error": {"validation": "jsonschema", "schema": {"type": "string"}},
        "url": {"validation": "jsonschema", "schema": {"type": "string"}},
        "configuration": {"validation": "jsonschema", "schema": {"type": "object"}},
        "tags": {"validation": "jsonschema", "schema": {"type": "object"}},
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["full_name", "analysis_id"]

    #: `owner/repo` the analysis was uploaded to; half the natural key.
    full_name = models.CharField(max_length=255, blank=True, default="", db_index=True)
    #: GitHub's numeric analysis id; the other half.
    analysis_id = models.BigIntegerField(null=True, blank=True, db_index=True)
    #: The full ref path as GitHub returns it (`refs/heads/main`, `refs/pull/12/merge`).
    ref = models.CharField(max_length=512, blank=True, default="")
    #: The commit analysed. Kept on the node regardless of whether ANALYZES_COMMIT could be drawn.
    commit_sha = models.CharField(max_length=64, blank=True, default="", db_index=True)
    #: `<workflow path>:<job>` — the workflow job that uploaded the SARIF.
    analysis_key = models.CharField(max_length=512, blank=True, default="")
    category = models.CharField(max_length=255, blank=True, default="")
    environment = models.CharField(max_length=512, blank=True, default="")
    tool_name = models.CharField(max_length=255, blank=True, default="", db_index=True)
    tool_version = models.CharField(max_length=64, blank=True, default="")
    tool_guid = models.CharField(max_length=64, blank=True, default="")
    created_at = models.DateTimeField(null=True, blank=True)
    #: GitHub's tallies for the upload: results reported and distinct rules in the run.
    results_count = models.IntegerField(default=0)
    rules_count = models.IntegerField(default=0)
    sarif_id = models.CharField(max_length=255, blank=True, default="")
    #: Whether GitHub would let this analysis be deleted (the newest of a set is; older ones are not).
    deletable = models.BooleanField(default=False)
    #: The scanner's own warning / error text for the upload, verbatim; `""` when clean.
    warning = models.TextField(blank=True, default="")
    error = models.TextField(blank=True, default="")
    url = models.URLField(max_length=512, blank=True, default="")
    #: The raw analysis as returned, so nothing the model does not name is lost.
    configuration = models.JSONField(default=dict, blank=True)
    tags = models.JSONField(default=dict, blank=True)

    class Meta(BaseModel.Meta):
        db_table = "github_core__code_scanning_analysis"

    def get_name(self) -> str:
        if self.analysis_id is None:
            return ""
        tool = self.tool_name or "analysis"
        where = self.commit_sha[:7] if self.commit_sha else (self.ref.rsplit("/", 1)[-1] if self.ref else "")
        return f"{tool} {where} #{self.analysis_id}" if where else f"{tool} #{self.analysis_id}"

    def __str__(self) -> str:
        return self.get_name()
