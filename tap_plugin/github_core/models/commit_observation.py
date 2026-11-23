"""CommitObservation — what GitHub observed about a commit in one repository: resolved logins, signature verdict."""

from typing import Any, ClassVar

from django.core.exceptions import ValidationError
from django.db import models

from tap_grid.event_time import NO_EVENT_TIME
from tap_grid.models import BaseModel


class CommitObservation(BaseModel):
    """GitHub's observation of a commit, per repository: who it resolved the author and committer to,
    and whether it verified the signature.

    The commit itself — object id, dates, author/committer name and email — is the neutral
    `git_core__git_commit` node, one per oid however many hosts store it (github-core#76). This
    node is the forge's half: a login is GitHub's resolution of an email, and a signature verdict
    is GitHub's, persisted per repository network, so it can differ for the same commit in two
    unrelated networks. Keyed on the host, the repository's stable id and the commit identity
    (ruling 0.2); a stable record updated in place, with TAP field history carrying change.
    `OBSERVES_COMMIT` links to the commit, `OBSERVED_IN_REPOSITORY` to the hosting record.

    Spec: specs/spec-github-core-v0.md (req-github-core-commits)
    """

    ENTITY_TYPE: ClassVar[str] = "github_core__commit_observation"
    # The repository's STABLE numeric id (never `owner/repo`, which renames) plus the commit
    # identity. The platform HOST is part of the key and is a field on this model: GitHub's
    # repository ids are unique per HOST, not globally, so a GHES tenant sharing this grid could
    # collide with github.com on repository id alone. Ruled by George 2026-09-20 (Issue# 164):
    # the host joins the key as a field rather than being read off the node's dimensions,
    # because the generated search deliberately ignores dimensions — dimension values vary by
    # collection path, so a dimension filter would fail to find a row's own previous write
    # (req-grid-entity-natural-key-10). Today every row carries `github.com`; the field earns
    # its keep the day a second host does not.
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("host", "repository_github_id", "hash_algorithm", "sha")
    ENTITY_NAME: ClassVar[str] = "Commit Observation"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "GitHub's view of a commit in one repository — the accounts it resolved the author and committer "
        "to, and its signature verification verdict. The object a required-signatures rule checks."
    )
    ENTITY_ICON: ClassVar[str] = "git-commit"
    # GitHub's verdict on a commit; the commit's own times live on git_core's commit, and this model stores none.
    EVENT_TIME: ClassVar[Any] = NO_EVENT_TIME
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {
        "github.observation": "declaration",
        "git.host": "github.com",
    }
    DEFAULT_DISPLAY: ClassVar[dict[str, Any]] = {
        "tap_viz": {
            "shape": "ellipse",
            "colors": {"fill": "#FFFFFF", "border": "#57606A", "label": "#1F2328"},
        }
    }

    #: The signature field was not answered by the API (pruned at an errored path).
    SIGNATURE_UNOBSERVABLE = "unobservable"
    #: GitHub returned `signature: null` — observed, not signed.
    SIGNATURE_UNSIGNED = "unsigned"

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "host": {"type": "string", "minLength": 1},
        "full_name": {"type": "string", "minLength": 1},
        "repository_github_id": {"type": ["integer", "null"]},
        "hash_algorithm": {"type": "string", "enum": ["sha1", "sha256"]},
        "sha": {"type": "string", "minLength": 40, "maxLength": 64},
        "author_login": {"type": "string"},
        "committer_login": {"type": "string"},
        "signature_kind": {"type": "string", "enum": ["", "gpg", "smime", "ssh"]},
        "signature_state": {"type": "string"},
        "signature_valid": {"type": ["boolean", "null"]},
        "signer_login": {"type": "string"},
        "signed_by_github": {"type": "boolean"},
        "configuration": {"type": "object"},
        "tags": {"type": "object"},
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        "host": {
            "validation": "jsonschema",
            "schema": {"type": "string", "minLength": 1},
        },
        "full_name": {
            "validation": "jsonschema",
            "schema": {"type": "string", "minLength": 1},
        },
        "hash_algorithm": {
            "validation": "jsonschema",
            "schema": {"type": "string", "enum": ["sha1", "sha256"]},
        },
        "sha": {
            "validation": "jsonschema",
            "schema": {"type": "string", "minLength": 40, "maxLength": 64},
        },
        "author_login": {"validation": "jsonschema", "schema": {"type": "string"}},
        "committer_login": {"validation": "jsonschema", "schema": {"type": "string"}},
        "signature_kind": {
            "validation": "jsonschema",
            "schema": {"type": "string", "enum": ["", "gpg", "smime", "ssh"]},
        },
        "signature_state": {"validation": "jsonschema", "schema": {"type": "string"}},
        # null on an unsigned commit: "not valid" would be a claim about a signature that does not exist.
        "signature_valid": {
            "validation": "jsonschema",
            "schema": {"type": ["boolean", "null"]},
        },
        "signer_login": {"validation": "jsonschema", "schema": {"type": "string"}},
        "signed_by_github": {"validation": "jsonschema", "schema": {"type": "boolean"}},
        "configuration": {"validation": "jsonschema", "schema": {"type": "object"}},
        "tags": {"validation": "jsonschema", "schema": {"type": "object"}},
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["full_name", "sha"]

    # The repository this observation was made in — the network the verdict is persisted for —
    # by name for the reader and by GitHub's stable id for the identity.
    #: The forge host this observation was read from ("github.com", or a GHES tenant's host).
    #: A constituting property: repository ids are unique per host, never across hosts.
    host = models.CharField(max_length=255, blank=True, default="", db_index=True)
    full_name = models.CharField(max_length=255, blank=True, default="", db_index=True)
    repository_github_id = models.BigIntegerField(null=True, blank=True, db_index=True)
    hash_algorithm = models.CharField(max_length=16, blank=True, default="sha1")
    sha = models.CharField(max_length=64, blank=True, default="", db_index=True)
    # Identity as observed: a login only when GitHub resolved the email; "" is observed-absent.
    author_login = models.CharField(
        max_length=255, blank=True, default="", db_index=True
    )
    committer_login = models.CharField(
        max_length=255, blank=True, default="", db_index=True
    )
    # Signature in three states: GitHub's verification state (lower-cased), `unsigned`, or
    # `unobservable` when the field was not answered.
    signature_kind = models.CharField(max_length=16, blank=True, default="")
    signature_state = models.CharField(
        max_length=32, blank=True, default="", db_index=True
    )
    signature_valid = models.BooleanField(null=True, blank=True)
    signer_login = models.CharField(max_length=255, blank=True, default="")
    signed_by_github = models.BooleanField(default=False)
    configuration = models.JSONField(default=dict, blank=True)
    tags = models.JSONField(default=dict, blank=True)

    class Meta(BaseModel.Meta):
        db_table = "github_core_commit_observation"

    def validate(self) -> None:
        if self.sha != self.sha.lower():
            raise ValidationError({"sha": ["sha must be lower-case hex"]})

    def get_name(self) -> str:
        return f"{self.full_name}@{self.sha[:12]}" if self.sha else self.full_name

    def __str__(self) -> str:
        return self.get_name()
