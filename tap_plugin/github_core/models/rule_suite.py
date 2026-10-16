"""Rule suite — one push evaluated against a repository's rulesets.

The counterpart to `github_ruleset`, and the answer to a question that node cannot reach.
A ruleset records **who may bypass** it, which GitHub returns only to a caller with write
access to the ruleset. A rule suite records **who did** — and that surface answers a
read-only App installation token with names.

An occurrence, not a change. The vocabulary corpus rejects "change / snapshot /
audit-event types" because the grid already carries field-level history, and that ruling
governs changes to objects we collect ("this ruleset moved to `evaluate`"). A rule suite
is an event in the world we observed, in the same category as `github_actions_run`: it
has GitHub-assigned identity, a timestamp, and facts that point at it.

Spec: plugins/github_core/specs/spec-github-core-v0.md (req-github-core-rule-suites)
"""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel
from tap_plugin.github_core.models.schema_types import DATE_TIME, DATE_TIME_VALIDATION


class RuleSuite(BaseModel):
    """A push evaluated against the rulesets that matched its ref.

    **Only bypasses are collected** (`req-github-core-rule-suites-4`). A passing suite is a
    routine push — roughly 47 a day on one active repository — and landing every one would
    swamp the grid for no finding. `result` is kept as a field so the model can widen to
    `fail` or `pass` without a migration.

    **The actor is an account, and that is all we know.** GitHub gives a login and a numeric
    id. Whether it is a person, a bot or a machine account is not stated, and this model does
    not guess — `TRIGGERED_EVALUATION` points at a `github_account`, the user-or-organization primitive.
    """

    ENTITY_TYPE: ClassVar[str] = "github_core__rule_suite"
    # GitHub's own suite id, unique across the platform; the suite carries its own repository.
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("suite_id",)
    ENTITY_NAME: ClassVar[str] = "Rule Suite"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "One push evaluated against the rulesets matching its ref — who pushed, onto which ref, "
        "and which controls were bypassed rather than satisfied."
    )
    ENTITY_ICON: ClassVar[str] = "github-rule-suite"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {
        # An execution, not a declaration: this is something that HAPPENED, like a run.
        "github.observation": "execution",
        "git.host": "github.com",
        "github.surface": "rules",
    }
    DEFAULT_DISPLAY: ClassVar[dict[str, Any]] = {
        "tap_viz": {
            "shape": "diamond",
            "colors": {"fill": "#FFEBE9", "border": "#CF222E", "label": "#5A1E1E"},
        }
    }

    #: The push went around at least one rule it should have satisfied.
    RESULT_BYPASS = "bypass"
    #: A rule failed and the push was refused. Collected only if the subset ever widens.
    RESULT_FAIL = "fail"
    #: Every rule was satisfied. Routine; not collected today.
    #: nosec B105 — GitHub's rule-suite result vocabulary ("pass"), not a credential.
    RESULT_PASS = "pass"  # nosec B105

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "suite_id": {"type": ["integer", "null"]},
        "full_name": {"type": "string"},
        "result": {
            "type": "string",
            "enum": [RESULT_BYPASS, RESULT_FAIL, RESULT_PASS, ""],
        },
        "ref": {"type": "string"},
        "actor_login": {"type": "string"},
        "actor_id": {"type": ["integer", "null"]},
        "before_sha": {"type": "string"},
        "after_sha": {"type": "string"},
        "pushed_at": DATE_TIME,
        "bypassed_rules": {"type": "array"},
        "configuration": {"type": "object"},
        "tags": {"type": "object"},
    }

    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        "suite_id": {
            "validation": "jsonschema",
            "schema": {"type": ["integer", "null"]},
        },
        "full_name": {"validation": "jsonschema", "schema": {"type": "string"}},
        "result": {
            "validation": "jsonschema",
            # "" is permitted so a partially-read suite lands rather than being dropped —
            # the grid's unobserved convention, matching every other enum in this plugin.
            "schema": {
                "type": "string",
                "enum": [RESULT_BYPASS, RESULT_FAIL, RESULT_PASS, ""],
            },
        },
        "ref": {"validation": "jsonschema", "schema": {"type": "string"}},
        "actor_login": {"validation": "jsonschema", "schema": {"type": "string"}},
        "actor_id": {
            "validation": "jsonschema",
            "schema": {"type": ["integer", "null"]},
        },
        "before_sha": {"validation": "jsonschema", "schema": {"type": "string"}},
        "after_sha": {"validation": "jsonschema", "schema": {"type": "string"}},
        # null is "we did not observe a timestamp", never "now".
        "pushed_at": DATE_TIME_VALIDATION,
        "bypassed_rules": {"validation": "jsonschema", "schema": {"type": "array"}},
        "configuration": {"validation": "jsonschema", "schema": {"type": "object"}},
        "tags": {"validation": "jsonschema", "schema": {"type": "object"}},
    }
    #: The suite id is the identity and the only thing required — everything else is a fact
    #: about it that a degraded read may be missing.
    CREATE_REQUIRED: ClassVar[list[str]] = ["suite_id"]

    suite_id = models.BigIntegerField(null=True, blank=True, db_index=True)
    #: `owner/repo`, carried so a suite is attributable without walking edges.
    full_name = models.CharField(max_length=512, blank=True, default="", db_index=True)
    result = models.CharField(max_length=16, blank=True, default="", db_index=True)
    #: The full ref path as GitHub returns it (`refs/heads/main`), matching `git_ref`.
    ref = models.CharField(max_length=512, blank=True, default="")
    #: The account login that pushed. Person, bot or machine account — the API does not say.
    actor_login = models.CharField(
        max_length=255, blank=True, default="", db_index=True
    )
    #: Numeric account id, so a login rename is detectable (see `github_account`).
    actor_id = models.BigIntegerField(null=True, blank=True)
    before_sha = models.CharField(max_length=64, blank=True, default="")
    after_sha = models.CharField(max_length=64, blank=True, default="")
    pushed_at = models.DateTimeField(null=True, blank=True)
    #: `[{"rule_type": "required_status_checks", "ruleset_id": 20613528, "ruleset_name": "...",
    #: "details": "Required status check \"gate\" is expected."}, ...]` — the rules that were NOT
    #: satisfied. Kept as data because the BYPASSED_RULE edge carries only the ruleset join, and the
    #: rule type and GitHub's own explanation are what make the event readable.
    bypassed_rules = models.JSONField(default=list, blank=True)
    configuration = models.JSONField(default=dict, blank=True)
    tags = models.JSONField(default=dict, blank=True)

    class Meta(BaseModel.Meta):
        db_table = "github_core__rule_suite"

    def get_name(self) -> str:
        who = self.actor_login or "unknown actor"
        where = self.ref.rsplit("/", 1)[-1] if self.ref else "unknown ref"
        return f"{who} {self.result or 'evaluated'} on {where}" if self.suite_id else ""
