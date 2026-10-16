"""Actions cache — a stored cache entry, scoped to the ref that created it.

Five incidents turn on this object, including the two most recent: a cache is
written by a job an outsider can reach and restored by a job that holds
publish rights, so it is a convergence node between two trust levels rather
than a performance detail. The `ref` is the load-bearing field — it is what
says which side of the trust boundary the entry came from.
"""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel
from tap_plugin.github_core.models.schema_types import timestamps


class ActionsCache(BaseModel):
    """One cache entry as GitHub reports it: key, version, ref scope and size.

    This is the *observed* entry, not the declared `actions/cache` step. The
    declared side lives on `workflow_job.configuration.cache_steps`, because a
    key written as `${{ runner.os }}-node-${{ hashFiles(...) }}` cannot be
    matched to a concrete key without evaluating an expression language —
    named as a gap rather than guessed at (`req-github-core-caches`).

    Spec: plugins/github_core/specs/spec-github-core-v0.md (req-github-core-caches)
    """

    ENTITY_TYPE: ClassVar[str] = "github_core__actions_cache"
    # Repository + GitHub's cache id.
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("full_name", "cache_id")
    ENTITY_NAME: ClassVar[str] = "Actions Cache"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "A stored Actions cache entry — its key, the ref whose run created it, and when it was "
        "last restored."
    )
    ENTITY_ICON: ClassVar[str] = "actions-cache"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {
        "git.host": "github.com",
        "github.surface": "actions",
        "github.observation": "execution",
    }
    DEFAULT_DISPLAY: ClassVar[dict[str, Any]] = {
        "tap_viz": {
            "shape": "barrel",
            "colors": {"fill": "#FFFFFF", "border": "#BF3989", "label": "#1F2328"},
        }
    }

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "full_name": {"type": "string", "minLength": 1},
        "cache_id": {"type": ["integer", "null"]},
        "key": {"type": "string"},
        "version": {"type": "string"},
        "ref": {"type": "string"},
        "size_in_bytes": {"type": ["integer", "null"]},
        **timestamps("created_at", "last_accessed_at"),
        "configuration": {"type": "object"},
        "tags": {"type": "object"},
    }

    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        "full_name": {
            "validation": "jsonschema",
            "schema": {"type": "string", "minLength": 1},
        },
        "cache_id": {
            "validation": "jsonschema",
            "schema": {"type": ["integer", "null"]},
        },
        "key": {"validation": "jsonschema", "schema": {"type": "string"}},
        "version": {"validation": "jsonschema", "schema": {"type": "string"}},
        "ref": {"validation": "jsonschema", "schema": {"type": "string"}},
        "size_in_bytes": {
            "validation": "jsonschema",
            "schema": {"type": ["integer", "null"]},
        },
        "configuration": {"validation": "jsonschema", "schema": {"type": "object"}},
        "tags": {"validation": "jsonschema", "schema": {"type": "object"}},
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["full_name", "cache_id"]

    full_name = models.CharField(max_length=255, blank=True, default="", db_index=True)
    cache_id = models.BigIntegerField(null=True, blank=True, db_index=True)
    #: The concrete key the entry was stored under — often carrying a commit SHA and a run id.
    key = models.TextField(blank=True, default="")
    #: GitHub's content hash. Two entries sharing a key but differing here are different content.
    version = models.CharField(max_length=128, blank=True, default="")
    #: `refs/heads/main`, `refs/pull/42/merge` — the ref scope the entry belongs to, and the join
    #: onto `git_ref` that says whether a low-trust ref produced something a privileged run reads.
    ref = models.CharField(max_length=512, blank=True, default="", db_index=True)
    size_in_bytes = models.BigIntegerField(null=True, blank=True)
    created_at = models.DateTimeField(null=True, blank=True)
    last_accessed_at = models.DateTimeField(null=True, blank=True)
    configuration = models.JSONField(default=dict, blank=True)
    tags = models.JSONField(default=dict, blank=True)

    class Meta(BaseModel.Meta):
        db_table = "github_core__actions_cache"

    def get_name(self) -> str:
        return self.key or (str(self.cache_id) if self.cache_id else "")

    def __str__(self) -> str:
        return self.get_name()
