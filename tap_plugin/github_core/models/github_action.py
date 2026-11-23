"""GitHub Action — a reusable step a declared job pulls in with `uses:`.

The one node in a repository's CI that its owner does not write. A `uses:` line hands a
job's token, its checkout and its secrets-in-scope to code that lives in someone else's
repository at whatever commit a name resolves to on the day the run happens. Every
tag-repoint compromise in the incident corpus is that sentence, so what a job pins and
HOW it pins is the fact this node and its edge exist to hold.

Vocabulary corpus (`specs/spec-github-core-vocabulary.md`): `github_action`, self tier,
four sources, one of which carries `is_pinned` independently of us. No Octicon exists —
GitHub retired `github-action` — so the glyph is TAP-drawn (see `static/.../NOTICE`).
"""

from typing import Any, ClassVar

from django.db import models

from tap_grid.event_time import NO_EVENT_TIME
from tap_grid.models import BaseModel


class GithubAction(BaseModel):
    """An action, keyed on the path a `uses:` line names.

    One node per action PATH, shared across every repository and job that uses it — the
    same fan-in shape as `github_app`. `actions/cache` and `actions/cache/restore` are
    different nodes because they are different `action.yml` files with different
    behaviour. The ref a job pins it at is not part of the node: it is a property of the
    job's `USES_ACTION` edge, because the same action is pinned differently by different
    jobs and the pin is the security-relevant fact about the RELATIONSHIP.

    Spec: plugins/github_core/specs/spec-github-core-v0.md (req-github-core-actions-used)
    """

    ENTITY_TYPE: ClassVar[str] = "github_core__github_action"
    # The `uses:` path with the ref stripped. Platform-global: `actions/checkout` is ONE node.
    # The ref is deliberately not here — the pin belongs to the edge.
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("action_path",)
    ENTITY_NAME: ClassVar[str] = "GitHub Action"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "A reusable action a declared job calls with `uses:` — third-party code that runs with "
        "the job's token. How each job pins it lives on the USES_ACTION edge."
    )
    ENTITY_ICON: ClassVar[str] = "github-action"
    # A reusable action named by `uses:`; nothing in it is a time the source states.
    EVENT_TIME: ClassVar[Any] = NO_EVENT_TIME
    # No owner/repo dimension: a shared node belongs to no one repository. Declaration-side,
    # because a `uses:` line is something WRITTEN, and stamping it `execution` would claim the
    # action ran, which the workflow file cannot say.
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {
        "github.observation": "declaration",
        "git.host": "github.com",
        "github.surface": "actions",
    }
    # Third-party code, drawn apart from the repository's own declaration cards: a hexagon in
    # the declaration family's white-on-blue so it reads as "outside, but declared".
    DEFAULT_DISPLAY: ClassVar[dict[str, Any]] = {
        "tap_viz": {
            "shape": "hexagon",
            "colors": {"fill": "#FFFFFF", "border": "#0969DA", "label": "#1F2328"},
        }
    }

    #: Lives in a GitHub repository (`owner/repo[/subdir]`).
    KIND_REPOSITORY = "repository"
    #: A container image run as a step (`docker://image[:tag|@digest]`).
    KIND_DOCKER = "docker"

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "action_path": {"type": "string", "minLength": 1},
        "kind": {"type": "string", "enum": [KIND_REPOSITORY, KIND_DOCKER]},
        "owner": {"type": "string"},
        "repository_full_name": {"type": "string"},
        "subpath": {"type": "string"},
        "name": {"type": "string"},
        "configuration": {"type": "object"},
        "tags": {"type": "object"},
    }

    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        "action_path": {
            "validation": "jsonschema",
            "schema": {"type": "string", "minLength": 1},
        },
        "kind": {
            "validation": "jsonschema",
            "schema": {"type": "string", "enum": [KIND_REPOSITORY, KIND_DOCKER]},
        },
        "owner": {"validation": "jsonschema", "schema": {"type": "string"}},
        "repository_full_name": {
            "validation": "jsonschema",
            "schema": {"type": "string"},
        },
        "subpath": {"validation": "jsonschema", "schema": {"type": "string"}},
        "name": {"validation": "jsonschema", "schema": {"type": "string"}},
        "configuration": {"validation": "jsonschema", "schema": {"type": "object"}},
        "tags": {"validation": "jsonschema", "schema": {"type": "object"}},
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["action_path"]

    # The `uses:` path with the ref stripped — the identity input. `actions/checkout`,
    # `actions/cache/restore`, `docker://alpine`.
    action_path = models.CharField(
        max_length=512, blank=True, default="", db_index=True
    )
    # Defaults to the common case so a node minted from a bare path validates; the enum still
    # refuses anything that is neither.
    kind = models.CharField(
        max_length=16, blank=True, default=KIND_REPOSITORY, db_index=True
    )
    # Who publishes it. Empty for a docker image, whose registry namespace is not a GitHub owner.
    owner = models.CharField(max_length=255, blank=True, default="", db_index=True)
    # The repository the action lives in (`owner/repo`), which is what DEFINED_IN would point at
    # once that edge is built and what the collector resolves pins against when it is in scope.
    repository_full_name = models.CharField(
        max_length=255, blank=True, default="", db_index=True
    )
    # Path inside that repository for a subdirectory action; "" for the repository root.
    subpath = models.CharField(max_length=512, blank=True, default="")
    name = models.CharField(max_length=512, blank=True, default="")
    configuration = models.JSONField(default=dict, blank=True)
    tags = models.JSONField(default=dict, blank=True)

    class Meta(BaseModel.Meta):
        db_table = "github_core__github_action"

    def get_name(self) -> str:
        return self.name or self.action_path

    def __str__(self) -> str:
        return self.get_name()
