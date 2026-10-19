"""One verified attestation, checked again against the trust list, and the choice of the current revision.

``gh attestation verify`` (or any verifier behind the seam) has already checked the signature chain. This
module does not repeat that; it refuses what the verifier handed back if it is not what the trust list
allows and not what it claims to be (req-github-core-sbom-attestations-3), and reads the content digest the
way tap does: sha256 over the exact bytes of ``predicate`` inside the signed DSSE payload, never over a
re-serialization (req-github-core-sbom-attestations-5).
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from .config import TrustedSigner
from .errors import AttestationRefused

PREDICATE_TYPE: Final[str] = "https://cyclonedx.org/bom"
OIDC_ISSUER: Final[str] = "https://token.actions.githubusercontent.com"
_STATEMENT_TYPE: Final[str] = "https://in-toto.io/Statement/v1"


@dataclass(frozen=True)
class Revision:
    """One verified revision of an SBOM: which signer, which version, and the signed bytes."""

    subject_digest: str
    signer: TrustedSigner
    version: int
    serial: str
    integrated_time: int
    content_digest: str
    predicate: bytes


@dataclass(frozen=True)
class Selection:
    current: Revision
    superseded: tuple[Revision, ...]


def signed_predicate_bytes(payload: str) -> bytes:
    """The bytes of the top-level ``predicate`` value, cut out of the signed statement text in place.

    The statement is walked key by key at its top level, so a nested key or a string value spelled
    ``"predicate"`` cannot be mistaken for it, and a second top-level ``predicate`` is refused.
    """
    decoder = json.JSONDecoder()

    def skip(i: int) -> int:
        while i < len(payload) and payload[i] in " \t\r\n":
            i += 1
        return i

    try:
        i = skip(0)
        if payload[i] != "{":
            raise ValueError("the statement is not an object")
        i = skip(i + 1)
        found: tuple[int, int] | None = None
        while payload[i] != "}":
            key, i = decoder.raw_decode(payload, i)
            i = skip(i)
            if payload[i] != ":":
                raise ValueError("expected ':' after a key")
            i = skip(i + 1)
            _, end = decoder.raw_decode(payload, i)
            if key == "predicate":
                if found is not None:
                    raise ValueError("the statement has two predicate keys")
                found = (i, end)
            i = skip(end)
            if payload[i] == ",":
                i = skip(i + 1)
        if found is None:
            raise ValueError("the statement has no predicate")
        return payload[found[0] : found[1]].encode("utf-8")
    except (IndexError, ValueError) as exc:
        raise AttestationRefused(f"cannot cut the signed predicate out of the attestation payload: {exc}") from exc


def _integrated_time(item: Mapping[str, Any]) -> int:
    try:
        return int(item["attestation"]["bundle"]["verificationMaterial"]["tlogEntries"][0]["integratedTime"])
    except (KeyError, IndexError, TypeError, ValueError):
        return 0


def check_item(item: Any, *, subject_digest: str, signer: TrustedSigner) -> Revision:
    """Accept one ``gh attestation verify --format json`` entry only if it is exactly the signer asked for.

    Refuses (``AttestationRefused``) when the certificate identity is not the trust-list entry's, the issuer
    is not GitHub Actions, a pinned signer digest differs, the statement is not an in-toto statement of the
    CycloneDX predicate type for this subject digest, or the predicate the verifier parsed is not the one
    in the signed payload.
    """
    who = f"signer {signer.id} for {subject_digest}"
    if not isinstance(item, Mapping):
        raise AttestationRefused(f"{who}: a verification result is not an object")
    result = item.get("verificationResult")
    if not isinstance(result, Mapping):
        raise AttestationRefused(f"{who}: the entry carries no verification result")
    certificate = (result.get("signature") or {}).get("certificate")
    if not isinstance(certificate, Mapping):
        raise AttestationRefused(f"{who}: the result carries no certificate to check against the trust list")
    if certificate.get("subjectAlternativeName") != signer.identity:
        raise AttestationRefused(
            f"{who}: certificate identity {certificate.get('subjectAlternativeName')!r} is not the trusted {signer.identity!r}"
        )
    if certificate.get("issuer") != OIDC_ISSUER:
        raise AttestationRefused(f"{who}: certificate issuer {certificate.get('issuer')!r} is not GitHub Actions")
    if signer.signer_digest is not None and certificate.get("buildSignerDigest") != signer.signer_digest:
        raise AttestationRefused(
            f"{who}: build signer digest {certificate.get('buildSignerDigest')!r} is not the pinned {signer.signer_digest}"
        )
    try:
        payload_text = base64.b64decode(item["attestation"]["bundle"]["dsseEnvelope"]["payload"], validate=True).decode("utf-8")
        statement = json.loads(payload_text)
    except (KeyError, TypeError, ValueError) as exc:
        raise AttestationRefused(f"{who}: the signed payload cannot be read: {type(exc).__name__}: {exc}") from exc
    if statement.get("_type") != _STATEMENT_TYPE or statement.get("predicateType") != PREDICATE_TYPE:
        raise AttestationRefused(f"{who}: the signed statement is not a CycloneDX in-toto statement")
    subjects = [(s.get("digest") or {}).get("sha256") for s in statement.get("subject") or [] if isinstance(s, Mapping)]
    if subject_digest.removeprefix("sha256:") not in subjects:
        raise AttestationRefused(f"{who}: the signed statement is about a different subject digest")
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict) or isinstance(predicate.get("version"), bool) or not isinstance(predicate.get("version"), int):
        raise AttestationRefused(f"{who}: the signed predicate is not a CycloneDX document with a version")
    serial = predicate.get("serialNumber")
    if not isinstance(serial, str) or not serial:
        raise AttestationRefused(f"{who}: the signed predicate has no serialNumber")
    if (result.get("statement") or {}).get("predicate") != predicate:
        raise AttestationRefused(f"{who}: the predicate the verifier returned is not the one in the signed payload")
    raw = signed_predicate_bytes(payload_text)
    if json.loads(raw) != predicate:  # the cut bytes must be the document, not something that merely parses
        raise AttestationRefused(f"{who}: the bytes cut from the payload are not the predicate")
    return Revision(
        subject_digest=subject_digest,
        signer=signer,
        version=predicate["version"],
        serial=serial,
        integrated_time=_integrated_time(item),
        content_digest=hashlib.sha256(raw).hexdigest(),
        predicate=raw,
    )


def select(revisions: Sequence[Revision]) -> Selection:
    """The highest version is current; every other revision of the same serial is superseded.

    Ties on version go to the later signature time, then to the content digest, so the choice is
    deterministic. Revisions of one subject that disagree on ``serialNumber`` are refused: they are not one
    lineage, and choosing between them would be a guess. A byte-identical revision seen twice counts once.
    """
    if not revisions:
        raise AttestationRefused("no attestation verified against the trust list")
    serials = sorted({r.serial for r in revisions})
    if len(serials) != 1:
        raise AttestationRefused(f"verified revisions of {revisions[0].subject_digest} disagree on serialNumber: {serials}")
    unique = {r.content_digest: r for r in revisions}.values()
    ordered = sorted(unique, key=lambda r: (r.version, r.integrated_time, r.content_digest), reverse=True)
    return Selection(current=ordered[0], superseded=tuple(ordered[1:]))
