"""The collector's declarative config and the default-deny trust list it names (req-github-core-sbom-attestations-1, -2).

Both are validated before anything else happens. A file that cannot be read, does not validate, or names no
subject and no signer is a ``ConfigError``: there is no "trust nothing and continue" state.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import jsonschema

from .errors import ConfigError

CONFIG_FORMAT: Final[str] = "github-core-sbom-attestations/1"
#: The verifier choices the config may name (verifier.py): in-process sigstore_core, or the gh CLI.
VERIFIERS: Final[tuple[str, ...]] = ("sigstore_core", "gh")
TRUST_LIST_FORMAT: Final[str] = "tap-sbom-trusted-signers/1"
SCHEMA_PATH: Final[Path] = Path(__file__).with_name("sbom_attestation_config.schema.json")
#: The collector config file, beside the credential under TAP_SECRETS_ROOT/<scope>/.
CONFIG_FILENAME: Final[str] = "sbom_attestations.config.json"

_OWNER_REPO = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")
_WORKFLOW = re.compile(r"^\.github/workflows/[A-Za-z0-9._-]+\.ya?ml$")
_REF = re.compile(r"^(refs/(heads|tags)/[A-Za-z0-9._/-]+|[0-9a-f]{40})$")
_SIGNER_DIGEST = re.compile(r"^[0-9a-f]{40}$")
_SIGNER_ID = re.compile(r"^[a-z0-9][a-z0-9-]*$")


@dataclass(frozen=True)
class TrustedSigner:
    """One identity whose SBOM attestations are accepted: the signing workflow, matched exactly."""

    id: str
    repository: str
    workflow_path: str
    ref: str
    signer_digest: str | None
    transitional: bool = False

    @property
    def identity(self) -> str:
        """The certificate's subject alternative name this entry demands, matched exactly."""
        return f"https://github.com/{self.repository}/{self.workflow_path}@{self.ref}"


@dataclass(frozen=True)
class Subject:
    image: str
    digest: str

    @property
    def owner(self) -> str:
        return self.image.split("/")[1]

    @property
    def oci(self) -> str:
        return f"oci://{self.image}@{self.digest}"


@dataclass(frozen=True)
class SbomAttestationConfig:
    trusted_signers_path: str
    subjects: tuple[Subject, ...]
    on_unverified_attestation: str = "warn"
    verifier: str = "sigstore_core"
    batch_name: str = "SBOM vulnerabilities (verified attestations)"


def _read_json(path: str | Path, what: str) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ConfigError(f"cannot read {what} at {path}: {type(exc).__name__}: {exc}") from exc


def parse_config(document: Any) -> SbomAttestationConfig:
    """Validate a config document against the shipped schema and return it typed."""
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    try:
        jsonschema.validate(document, schema)
    except jsonschema.ValidationError as exc:
        raise ConfigError(f"the collector config does not validate: {exc.message} at {list(exc.absolute_path)}") from exc
    subjects = tuple(Subject(image=s["image"], digest=s["digest"]) for s in document["subjects"])
    if len({s.digest for s in subjects}) != len(subjects):
        raise ConfigError("the collector config names the same digest twice")
    return SbomAttestationConfig(
        trusted_signers_path=document["trusted_signers_path"],
        subjects=subjects,
        on_unverified_attestation=document.get("on_unverified_attestation", "warn"),
        verifier=document.get("verifier", "sigstore_core"),
        batch_name=document.get("batch_name", SbomAttestationConfig.batch_name),
    )


def load_config(path: str | Path) -> SbomAttestationConfig:
    return parse_config(_read_json(path, "the collector config"))


def parse_trusted_signers(document: Any) -> tuple[TrustedSigner, ...]:
    """The trust list, checked to the same rules as tap's ``trusted-signers.schema.json``.

    The rules are restated rather than imported because the list belongs to tap (``scripts/sbom``) and this
    plugin must not import tap's scripts. A list that is empty, has an unknown field, or leaves a signer
    unpinned without the transitional marker is refused.
    """
    if not isinstance(document, Mapping) or document.get("format") != TRUST_LIST_FORMAT:
        raise ConfigError(f"the trust list is not format {TRUST_LIST_FORMAT!r}")
    raw = document.get("signers")
    if not isinstance(raw, list) or not raw:
        raise ConfigError("the trust list names no signer: an empty list refuses everything, it does not trust nothing")
    allowed = {"_description", "id", "repository", "workflow_path", "ref", "signer_digest", "transitional", "reason", "added_by"}
    required = {"_description", "id", "repository", "workflow_path", "ref", "signer_digest", "reason", "added_by"}
    signers: list[TrustedSigner] = []
    for index, entry in enumerate(raw):
        where = f"signers[{index}]"
        if not isinstance(entry, Mapping):
            raise ConfigError(f"{where} is not an object")
        if set(entry) - allowed or required - set(entry):
            raise ConfigError(f"{where} has unknown {sorted(set(entry) - allowed)} or missing {sorted(required - set(entry))} fields")
        text = {k: entry[k] for k in ("id", "repository", "workflow_path", "ref")}
        if not all(isinstance(v, str) for v in text.values()):
            raise ConfigError(f"{where}: id, repository, workflow_path and ref are strings")
        checks = (
            (_SIGNER_ID, "id"),
            (_OWNER_REPO, "repository"),
            (_WORKFLOW, "workflow_path"),
            (_REF, "ref"),
        )
        for pattern, key in checks:
            if not pattern.fullmatch(text[key]):
                raise ConfigError(f"{where}: {key} {text[key]!r} does not match its pattern")
        digest = entry["signer_digest"]
        if digest is not None and (not isinstance(digest, str) or not _SIGNER_DIGEST.fullmatch(digest)):
            raise ConfigError(f"{where}: signer_digest is null or 40 hex characters")
        transitional = entry.get("transitional", False)
        if not isinstance(transitional, bool):
            raise ConfigError(f"{where}: transitional is a boolean")
        if digest is None and not transitional:
            raise ConfigError(f"{where}: an unpinned signer must be marked transitional")
        signers.append(TrustedSigner(text["id"], text["repository"], text["workflow_path"], text["ref"], digest, transitional))
    if len({s.id for s in signers}) != len(signers) or len({s.identity for s in signers}) != len(signers):
        raise ConfigError("the trust list repeats a signer id or identity")
    return tuple(signers)


def load_trusted_signers(path: str | Path) -> tuple[TrustedSigner, ...]:
    return parse_trusted_signers(_read_json(path, "the trust list"))
