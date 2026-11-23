"""GitHub ruleset — the gate a commit must pass to land on a ref.

A ruleset is what many repositories point at, which is why it is a node where
an org policy object is a field (`spec-github-core-vocabulary.md`, the node
test). One ruleset defined at the organization applies to every repository it
matches, so identity is the ruleset id under its owner and the application is
an edge.
"""

from typing import Any, ClassVar

from django.db import models

from tap_grid.event_time import NO_EVENT_TIME
from tap_grid.models import BaseModel


class GithubRuleset(BaseModel):
    """A repository or organization ruleset: enforcement, conditions and rules.

    **Bypass observability is a field, not an inference.** GitHub returns a
    ruleset's bypass-actor list only to a caller with write access to the
    ruleset, so a read-only credential sees an empty list that is
    indistinguishable from "nobody may bypass" — the most reassuring possible
    reading of a blank. `bypass_observability` carries the third state, and it
    lives here rather than on the `EXEMPTS_ACTOR` edge because when the answer is
    *none* or *unknown* there are no edges to carry it.

    Reconciliation (github-core#14 shape B, github-core#151): enumerable per repository, but
    NOT contained by any one of them — one organization ruleset protects many repositories and
    ``PROTECTS_REPOSITORY`` points ruleset -> repository. No containment edge reaches it, so it
    is not a retirement candidate under this vocabulary; declaring one would need an account- or
    repository-owned edge INTO the ruleset (tracked under github-core#151's follow-ups).

    Spec: plugins/github_core/specs/spec-github-core-v0.md (req-github-core-rulesets)
    """

    ENTITY_TYPE: ClassVar[str] = "github_core__github_ruleset"
    # Owner + GitHub's ruleset id. Owner-scoped, not repo-scoped: one organization ruleset is ONE
    # node many repositories point at. See identity.py for why the owner prefix is belt-and-braces.
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("owner_login", "ruleset_id")
    ENTITY_NAME: ClassVar[str] = "GitHub Ruleset"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "A ruleset gating what may land on a ref — its enforcement level, the refs it matches, "
        "the rules it imposes, and whether its bypass list could be read at all."
    )
    ENTITY_ICON: ClassVar[str] = "github-ruleset"
    # No source time is stored: the ruleset's created_at is not kept; its JSON fields are conditions and rules.
    EVENT_TIME: ClassVar[Any] = NO_EVENT_TIME
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {
        "github.observation": "declaration",
        "git.host": "github.com",
        "github.surface": "rules",
    }
    DEFAULT_DISPLAY: ClassVar[dict[str, Any]] = {
        "tap_viz": {
            "shape": "hexagon",
            "colors": {"fill": "#FFF8C5", "border": "#9A6700", "label": "#4D2D00"},
        }
    }

    #: The bypass list was returned by a credential able to read it. An empty list is then a fact.
    BYPASS_OBSERVED = "observed"
    #: The credential could not read the list. An empty list means nothing and must not be rendered
    #: as "nobody can bypass".
    BYPASS_UNOBSERVABLE = "unobservable"

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "owner_login": {"type": "string"},
        "ruleset_id": {"type": ["integer", "null"]},
        "name": {"type": "string"},
        "target": {"type": "string"},
        "enforcement": {"type": "string"},
        "source": {"type": "string"},
        "source_type": {"type": "string"},
        "conditions": {"type": "object"},
        "rules": {"type": "array"},
        "bypass_observability": {
            "type": "string",
            "enum": [BYPASS_OBSERVED, BYPASS_UNOBSERVABLE],
        },
        "bypass_actor_count": {"type": ["integer", "null"]},
        "html_url": {"type": "string"},
        "configuration": {"type": "object"},
        "tags": {"type": "object"},
    }

    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        "owner_login": {"validation": "jsonschema", "schema": {"type": "string"}},
        "ruleset_id": {
            "validation": "jsonschema",
            "schema": {"type": ["integer", "null"]},
        },
        "name": {"validation": "jsonschema", "schema": {"type": "string"}},
        "target": {"validation": "jsonschema", "schema": {"type": "string"}},
        "enforcement": {"validation": "jsonschema", "schema": {"type": "string"}},
        "source": {"validation": "jsonschema", "schema": {"type": "string"}},
        "source_type": {"validation": "jsonschema", "schema": {"type": "string"}},
        "conditions": {"validation": "jsonschema", "schema": {"type": "object"}},
        "rules": {"validation": "jsonschema", "schema": {"type": "array"}},
        "bypass_observability": {
            "validation": "jsonschema",
            "schema": {
                "type": "string",
                "enum": [BYPASS_OBSERVED, BYPASS_UNOBSERVABLE],
            },
        },
        # null is the honest value while `bypass_observability` is `unobservable`: not zero.
        "bypass_actor_count": {
            "validation": "jsonschema",
            "schema": {"type": ["integer", "null"]},
        },
        "html_url": {"validation": "jsonschema", "schema": {"type": "string"}},
        "configuration": {"validation": "jsonschema", "schema": {"type": "object"}},
        "tags": {"validation": "jsonschema", "schema": {"type": "object"}},
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["ruleset_id"]

    owner_login = models.CharField(
        max_length=255, blank=True, default="", db_index=True
    )
    ruleset_id = models.BigIntegerField(null=True, blank=True, db_index=True)
    name = models.CharField(max_length=255, blank=True, default="")
    #: `branch`, `tag` or `push` — GitHub's own enum, and the reason `git_ref` is one type.
    target = models.CharField(max_length=32, blank=True, default="")
    #: `active`, `evaluate` (dry-run) or `disabled`. An `evaluate` ruleset gates nothing.
    enforcement = models.CharField(max_length=32, blank=True, default="")
    source = models.CharField(max_length=255, blank=True, default="")
    #: `Organization` or `Repository` — where the ruleset is defined, which is not where it applies.
    source_type = models.CharField(max_length=32, blank=True, default="")
    #: `{"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}}` — GitHub's tokens
    #: (`~DEFAULT_BRANCH`, `~ALL`) are preserved verbatim rather than resolved at collection time.
    conditions = models.JSONField(default=dict, blank=True)
    #: `[{"type": "required_status_checks", "parameters": {...}}, ...]` as returned.
    rules = models.JSONField(default=list, blank=True)
    bypass_observability = models.CharField(max_length=16, blank=True, default="")
    bypass_actor_count = models.IntegerField(null=True, blank=True)
    html_url = models.URLField(max_length=512, blank=True, default="")
    configuration = models.JSONField(default=dict, blank=True)
    tags = models.JSONField(default=dict, blank=True)

    class Meta(BaseModel.Meta):
        db_table = "github_core__github_ruleset"

    def get_name(self) -> str:
        return self.name or (str(self.ruleset_id) if self.ruleset_id else "")

    def __str__(self) -> str:
        return self.get_name()
