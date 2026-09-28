"""GitHub pull request — the forge's proposal to merge one ref into another, and its gate state.

A forge object, not a Git object: Git has branches and commits, and the pull request is
GitHub's conversation and admission gate wrapped around them (github-core#82; git_core's
v0 non-goals exclude it). It points at git_core's neutral ref and commit nodes rather than
carrying copies of them.
"""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel


class PullRequest(BaseModel):
    """A pull request: what it proposes, where it targets, and what stands between it and merge.

    The head commit's **check rollup** rides the node as data — GitHub's combined verdict over
    every check run and commit status on that commit, including the ones Apps post (SonarCloud,
    Codacy) that no workflow in scope produces. `checks_rollup_state` is the one-word answer;
    `checks` is the itemised evidence. A PR whose head carries no rollup has `""` there — nothing
    ran — which is not `SUCCESS` and must not render as green.

    Reconciliation (github-core#14 shape C, github-core#194): an IMMUTABLE EVENT, not an
    enumerable resource. GitHub never removes a pull request from the API on close or merge —
    `GET /repos/{owner}/{repo}/pulls/{number}` answers a closed or merged PR indefinitely; only
    `state` (and `merged_at`/`closed_at`) change, and the collector's pull-request layer already
    re-reads every state via a `pullRequests` connection with no `states:` filter
    (`graphql_client.py`'s `_PULL_REQUEST_QUERY_TEMPLATE`). So closing or merging is a field
    update this plugin already observes, never an absence to falsify. The one true disappearance
    — the containing repository deleted or transferred — is `github_core__github_repository`'s
    own candidate surface, not this node's; `GithubRepository`'s docstring already carries pull
    requests under "references or immutable events: none retires with the repository through the
    cascade, and none is a candidate surface." No model declares a `CONTAINMENT_EDGES` entry
    that targets this type (`OPENS_PULL_REQUEST` runs account/app -> PR, not repository -> PR),
    so it is never a retirement candidate and declares no falsifier
    (`tap_plugin.github_core.falsifiers`).

    Spec: plugins/github_core/specs/spec-github-core-v0.md (req-github-core-pull-requests)
    """

    ENTITY_TYPE: ClassVar[str] = "github_core__pull_request"
    # The BASE repository plus the PR number — GitHub's own identity within a repository.
    # `github_id` is carried as a field for continuity across a transfer, not as the key.
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("full_name", "number")
    ENTITY_NAME: ClassVar[str] = "Pull Request"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "A proposal to merge one ref into another: its state, author, head and base, review decision, "
        "mergeability, and the combined check verdict on its head commit."
    )
    ENTITY_ICON: ClassVar[str] = "pull-request"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {
        "github.observation": "execution",
        "git.host": "github.com",
        "github.surface": "pulls",
    }
    DEFAULT_DISPLAY: ClassVar[dict[str, Any]] = {
        "tap_viz": {
            "shape": "round-rectangle",
            "colors": {"fill": "#DDF4FF", "border": "#0969DA", "label": "#0A3069"},
        }
    }

    #: GitHub's own states.
    STATES: ClassVar[list[str]] = ["OPEN", "CLOSED", "MERGED"]
    #: GitHub's `StatusState` for the rollup; `""` means no rollup exists on the head commit.
    ROLLUP_STATES: ClassVar[list[str]] = ["", "EXPECTED", "ERROR", "FAILURE", "PENDING", "SUCCESS"]

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "full_name": {"type": "string", "minLength": 1},
        "number": {"type": "integer"},
        "github_id": {"type": ["integer", "null"]},
        "title": {"type": "string"},
        "state": {"type": "string"},
        "is_draft": {"type": "boolean"},
        "author_login": {"type": "string"},
        "author_type": {"type": "string"},
        "author_association": {"type": "string"},
        "head_ref": {"type": "string"},
        "head_sha": {"type": "string"},
        "head_repository": {"type": "string"},
        "base_ref": {"type": "string"},
        "base_sha": {"type": "string"},
        "review_decision": {"type": "string"},
        "mergeable": {"type": "string"},
        "merge_commit_sha": {"type": "string"},
        "created_at": {"type": ["string", "null"]},
        "updated_at": {"type": ["string", "null"]},
        "closed_at": {"type": ["string", "null"]},
        "merged_at": {"type": ["string", "null"]},
        "commit_count": {"type": ["integer", "null"]},
        "additions": {"type": ["integer", "null"]},
        "deletions": {"type": ["integer", "null"]},
        "changed_files": {"type": ["integer", "null"]},
        "labels": {"type": "array"},
        "review_requests": {"type": "array"},
        "latest_reviews": {"type": "array"},
        "checks_rollup_state": {"type": "string"},
        "checks": {"type": "array"},
        "checks_observability": {"type": "string", "enum": ["", "observed", "unobservable"]},
        "html_url": {"type": "string"},
        "configuration": {"type": "object"},
        "tags": {"type": "object"},
    }

    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        "full_name": {"validation": "jsonschema", "schema": {"type": "string", "minLength": 1}},
        "number": {"validation": "jsonschema", "schema": {"type": "integer", "minimum": 1}},
        "github_id": {"validation": "jsonschema", "schema": {"type": ["integer", "null"]}},
        "title": {"validation": "jsonschema", "schema": {"type": "string"}},
        "state": {"validation": "jsonschema", "schema": {"type": "string", "enum": ["", *STATES]}},
        "is_draft": {"validation": "jsonschema", "schema": {"type": "boolean"}},
        "author_login": {"validation": "jsonschema", "schema": {"type": "string"}},
        # `User`, `Bot`, `Organization`, `Mannequin`, `EnterpriseUserAccount` — GitHub's actor kinds.
        "author_type": {"validation": "jsonschema", "schema": {"type": "string"}},
        "author_association": {"validation": "jsonschema", "schema": {"type": "string"}},
        "head_ref": {"validation": "jsonschema", "schema": {"type": "string"}},
        "head_sha": {"validation": "jsonschema", "schema": {"type": "string"}},
        "head_repository": {"validation": "jsonschema", "schema": {"type": "string"}},
        "base_ref": {"validation": "jsonschema", "schema": {"type": "string"}},
        "base_sha": {"validation": "jsonschema", "schema": {"type": "string"}},
        "review_decision": {"validation": "jsonschema", "schema": {"type": "string"}},
        # GitHub's `MergeableState` verbatim — `MERGEABLE`, `CONFLICTING` or `UNKNOWN` (computed
        # lazily; a first read often says UNKNOWN). Never coerced to a boolean.
        "mergeable": {"validation": "jsonschema", "schema": {"type": "string"}},
        "merge_commit_sha": {"validation": "jsonschema", "schema": {"type": "string"}},
        "created_at": {"validation": "jsonschema", "schema": {"type": ["string", "null"]}},
        "updated_at": {"validation": "jsonschema", "schema": {"type": ["string", "null"]}},
        "closed_at": {"validation": "jsonschema", "schema": {"type": ["string", "null"]}},
        "merged_at": {"validation": "jsonschema", "schema": {"type": ["string", "null"]}},
        "commit_count": {"validation": "jsonschema", "schema": {"type": ["integer", "null"]}},
        "additions": {"validation": "jsonschema", "schema": {"type": ["integer", "null"]}},
        "deletions": {"validation": "jsonschema", "schema": {"type": ["integer", "null"]}},
        "changed_files": {"validation": "jsonschema", "schema": {"type": ["integer", "null"]}},
        "labels": {"validation": "jsonschema", "schema": {"type": "array", "items": {"type": "string"}}},
        "review_requests": {"validation": "jsonschema", "schema": {"type": "array", "items": {"type": "object"}}},
        "latest_reviews": {"validation": "jsonschema", "schema": {"type": "array", "items": {"type": "object"}}},
        "checks_rollup_state": {"validation": "jsonschema", "schema": {"type": "string", "enum": ROLLUP_STATES}},
        "checks": {"validation": "jsonschema", "schema": {"type": "array", "items": {"type": "object"}}},
        # Whether the head commit's rollup was READ: `observed` (GitHub answered, possibly with no
        # rollup — then `checks_rollup_state` is "" and that blank is a fact), `unobservable` (the
        # rollup or its contexts were refused and pruned — the blank means nothing), "" (never asked).
        "checks_observability": {
            "validation": "jsonschema",
            "schema": {"type": "string", "enum": ["", "observed", "unobservable"]},
        },
        "html_url": {"validation": "jsonschema", "schema": {"type": "string"}},
        "configuration": {"validation": "jsonschema", "schema": {"type": "object"}},
        "tags": {"validation": "jsonschema", "schema": {"type": "object"}},
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["full_name", "number"]

    #: `owner/repo` of the repository the pull request is opened AGAINST; half the natural key.
    full_name = models.CharField(max_length=255, blank=True, default="", db_index=True)
    #: The pull request number within that repository; the other half.
    number = models.IntegerField(null=True, blank=True, db_index=True)
    github_id = models.BigIntegerField(null=True, blank=True, db_index=True)
    title = models.CharField(max_length=512, blank=True, default="")
    state = models.CharField(max_length=16, blank=True, default="", db_index=True)
    is_draft = models.BooleanField(default=False)
    author_login = models.CharField(max_length=255, blank=True, default="", db_index=True)
    author_type = models.CharField(max_length=32, blank=True, default="")
    author_association = models.CharField(max_length=32, blank=True, default="")
    #: The proposed branch name (no `refs/heads/` prefix) and the commit it pointed at when observed.
    head_ref = models.CharField(max_length=255, blank=True, default="")
    head_sha = models.CharField(max_length=64, blank=True, default="", db_index=True)
    #: `owner/repo` the head lives in; differs from `full_name` for a fork, where no ref edge is drawn.
    head_repository = models.CharField(max_length=255, blank=True, default="")
    base_ref = models.CharField(max_length=255, blank=True, default="")
    base_sha = models.CharField(max_length=64, blank=True, default="")
    #: `APPROVED`, `CHANGES_REQUESTED`, `REVIEW_REQUIRED` or `""` (no review required / not reported).
    review_decision = models.CharField(max_length=32, blank=True, default="")
    mergeable = models.CharField(max_length=16, blank=True, default="")
    merge_commit_sha = models.CharField(max_length=64, blank=True, default="")
    created_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(null=True, blank=True)
    closed_at = models.DateTimeField(null=True, blank=True)
    merged_at = models.DateTimeField(null=True, blank=True)
    commit_count = models.IntegerField(null=True, blank=True)
    additions = models.IntegerField(null=True, blank=True)
    deletions = models.IntegerField(null=True, blank=True)
    changed_files = models.IntegerField(null=True, blank=True)
    labels = models.JSONField(default=list, blank=True)
    #: `[{"kind": "user"|"team", "login": ..}]` — who is asked and has not answered (waiting-on-me).
    review_requests = models.JSONField(default=list, blank=True)
    #: `[{"login": .., "state": .., "submitted_at": ..}]` — the latest review per reviewer.
    latest_reviews = models.JSONField(default=list, blank=True)
    checks_rollup_state = models.CharField(max_length=16, blank=True, default="", db_index=True)
    #: `[{"kind": "check_run"|"status", "name": .., "status": .., "conclusion": .., "app": .., "url": ..}]`
    checks = models.JSONField(default=list, blank=True)
    #: The `bypass_observability` ruling on the rollup: a refused rollup is `unobservable`, never a
    #: blank that reads as "nothing ran".
    checks_observability = models.CharField(max_length=16, blank=True, default="")
    html_url = models.URLField(max_length=512, blank=True, default="")
    configuration = models.JSONField(default=dict, blank=True)
    tags = models.JSONField(default=dict, blank=True)

    class Meta(BaseModel.Meta):
        db_table = "github_core__pull_request"

    def get_name(self) -> str:
        if not self.full_name or self.number is None:
            return self.title or ""
        return f"{self.full_name}#{self.number}"

    def __str__(self) -> str:
        return self.get_name()
