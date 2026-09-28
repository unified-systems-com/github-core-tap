"""Status check — a check context a ruleset requires, and that a workflow's job may produce.

The convergence node between the gate and the machinery (`specs/spec-github-core-vocabulary.md`:
6 sources; "required by rulesets, produced by workflows/apps"). A ruleset says a context must
pass before a ref can move; a workflow's job, named the same, is what makes it pass. Until this
node the two lived in different payloads — `github_ruleset.rules[].parameters` and
`workflow_job.name` — and the question "which workflow satisfies this gate, and which gate has
no producer in this repository" was a string comparison nobody ran (github-core#61).
"""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel


class StatusCheck(BaseModel):
    """A required check context, keyed on the owner and the context string.

    **A check nobody requires has no node.** Every job produces a check run; minting one node
    per job across an estate would drown the convergence in leaves. This node exists because
    some rule references the context, and `PRODUCES_CHECK` is derived only toward such nodes.
    Owner-scoped like `github_ruleset`, because an organization ruleset requires the same
    context across every repository it protects, and one node with fan-in is the point. Which
    integration must produce it is a property of the REQUIREMENT (`REQUIRES_CHECK`), not of
    the check.

    **Not the same thing its name suggests.** This is not GitHub's per-commit status resource
    (`GET /repos/{owner}/{repo}/commits/{ref}/statuses`) and there is no GitHub endpoint that
    answers "does this named check context still exist" — a status check context is not a
    resource GitHub hands back an id for, it is a string two different declarations happen to
    agree on. This node is DERIVED, minted from that convergence: a ruleset's
    `required_status_checks` names a context (`REQUIRES_CHECK`, ruleset -> this node) and a
    workflow job's display name may satisfy one (`PRODUCES_CHECK`, workflow -> this node). A
    falsifier would have nothing on GitHub's side to probe.

    Reconciliation (github-core#14 shape C, github-core#194): neither `GithubRuleset` nor
    `GithubWorkflow` declares `REQUIRES_CHECK` or `PRODUCES_CHECK` in `CONTAINMENT_EDGES` — and
    `GithubRuleset`'s own docstring already says a ruleset is "NOT contained by any one of
    [the repositories it protects]" and is not itself a candidate, so there is no live parent
    this node could ever be missing from. Its freshness is carried entirely by those two edges,
    which the collector already re-derives every run: a ruleset that drops the requirement, or
    a workflow that stops declaring the job, simply does not re-emit its edge into this node —
    ordinary edge reconciliation, not node retirement. No falsifier is declared.

    Spec: plugins/github_core/specs/spec-github-core-v0.md (req-github-core-status-checks)
    """

    ENTITY_TYPE: ClassVar[str] = "github_core__status_check"
    # Owner + the context string, kept exactly as written — check names are case-sensitive.
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("owner_login", "context")
    ENTITY_NAME: ClassVar[str] = "Status Check"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "A check context a ruleset requires — the name a gate waits for, and the name a workflow "
        "job produces. Where the gate and the machinery meet."
    )
    ENTITY_ICON: ClassVar[str] = "status-check"
    # Owner-scoped, no repo: an organization requirement spans repositories.
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {
        "github.observation": "declaration",
        "git.host": "github.com",
        "github.surface": "rules",
    }
    DEFAULT_DISPLAY: ClassVar[dict[str, Any]] = {
        "tap_viz": {
            "shape": "round-diamond",
            "colors": {"fill": "#FFFFFF", "border": "#CF222E", "label": "#1F2328"},
        }
    }

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "owner_login": {"type": "string", "minLength": 1},
        "context": {"type": "string", "minLength": 1},
        "name": {"type": "string"},
        "configuration": {"type": "object"},
        "tags": {"type": "object"},
    }

    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        "owner_login": {
            "validation": "jsonschema",
            "schema": {"type": "string", "minLength": 1},
        },
        "context": {
            "validation": "jsonschema",
            "schema": {"type": "string", "minLength": 1},
        },
        "name": {"validation": "jsonschema", "schema": {"type": "string"}},
        "configuration": {"validation": "jsonschema", "schema": {"type": "object"}},
        "tags": {"validation": "jsonschema", "schema": {"type": "object"}},
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["owner_login", "context"]

    owner_login = models.CharField(
        max_length=255, blank=True, default="", db_index=True
    )
    # The context string exactly as the rule wrote it — the name a check run must carry.
    context = models.CharField(max_length=512, blank=True, default="", db_index=True)
    name = models.CharField(max_length=512, blank=True, default="")
    configuration = models.JSONField(default=dict, blank=True)
    tags = models.JSONField(default=dict, blank=True)

    class Meta(BaseModel.Meta):
        db_table = "github_core__status_check"

    def get_name(self) -> str:
        return self.name or self.context

    def __str__(self) -> str:
        return self.get_name()
