"""Verify, choose the current revision, parse and map: the whole collector minus Django and the grid.

``run_pipeline`` is what the collector runs and what the offline tests run: the verifier and the lister are
arguments, so a recorded ``gh attestation verify`` result stands in for the network
(req-github-core-sbom-attestations-8). It returns the GRIFT document and a per-subject account of what was
read; it submits nothing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from tap_plugin.computing_core.sbom import Verification, VulnerabilityBatch, parse_cyclonedx_vulnerabilities
from tap_plugin.github_core.sbom_vulnerabilities import SbomVulnerabilityResult, sbom_vulnerability_grift

from .attestations import Revision, check_item, select
from .config import SbomAttestationConfig, Subject, TrustedSigner
from .errors import AttestationRefused, SbomAttestationError
from .lister import AttestationLister
from .verifier import AttestationVerifier

STATED = "stated"
UNSCANNED = "unscanned"


@dataclass(frozen=True)
class SubjectOutcome:
    image: str
    digest: str
    status: str
    """``stated``: the current revision carries ``vulnerabilities[]`` and was mapped. ``unscanned``: it does not
    (revision 1 only), so there is nothing to state and nothing to resolve."""
    current_version: int
    current_signer: str
    superseded_versions: tuple[int, ...]
    superseded_unscanned: int
    """Earlier revisions that carry no ``vulnerabilities[]`` (revision 1): lineage, never findings."""
    verified: int
    listed: int | None
    """Attestations GitHub listed, ``None`` when it could not be asked."""
    unverified: int | None
    """Listed minus verified (a floor of 0); ``None`` when ``listed`` is. These were never read."""
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class PipelineResult:
    grift: SbomVulnerabilityResult | None
    subjects: tuple[SubjectOutcome, ...]


def _scanned(revision: Revision) -> bool:
    document = json.loads(revision.predicate)
    return isinstance(document, dict) and document.get("vulnerabilities") is not None


def _parse(revision: Revision) -> VulnerabilityBatch:
    return parse_cyclonedx_vulnerabilities(
        revision.predicate, verification=Verification("verified", signer=revision.signer.identity)
    )


def _verified_revisions(
    subject: Subject, signers: tuple[TrustedSigner, ...], verifier: AttestationVerifier
) -> tuple[list[Revision], list[str]]:
    revisions: list[Revision] = []
    why_empty: list[str] = []
    for signer in signers:
        result = verifier.verify(subject, signer)
        if not result.items:
            why_empty.append(f"{signer.id}: {result.note or 'nothing verified'}")
        for item in result.items:
            revisions.append(check_item(item, subject_digest=subject.digest, signer=signer))
    return revisions, why_empty


def run_pipeline(
    config: SbomAttestationConfig,
    signers: tuple[TrustedSigner, ...],
    verifier: AttestationVerifier,
    lister: AttestationLister | None = None,
) -> PipelineResult:
    """Read every configured subject; raise ``SbomAttestationError`` before returning anything if any is refused.

    All subjects are examined first and every refusal is reported together, so one bad subject does not hide
    another. Nothing is returned for a partly refused set: a half-trusted batch is not submitted.
    """
    if not signers:
        raise AttestationRefused("no trusted signer: refusing every attestation")
    refusals: list[str] = []
    outcomes: list[SubjectOutcome] = []
    current: list[VulnerabilityBatch] = []
    superseded: list[VulnerabilityBatch] = []

    for subject in config.subjects:
        try:
            revisions, why_empty = _verified_revisions(subject, signers, verifier)
            if not revisions:
                raise AttestationRefused(
                    f"{subject.image}@{subject.digest}: no attestation verified against the trust list ({'; '.join(why_empty)})"
                )
            chosen = select(revisions)
        except AttestationRefused as exc:
            refusals.append(str(exc))
            continue

        distinct = 1 + len(chosen.superseded)
        listed = lister.count(subject) if lister is not None else None
        count = None if listed is None else listed.total
        unverified = None if count is None else max(0, count - distinct)
        notes: list[str] = []
        if listed is not None and listed.note:
            notes.append(listed.note)
        if listed is not None and count is not None and not listed.complete:
            notes.append("the attestation listing was cut short, so the unverified count is a floor")
        if unverified and config.on_unverified_attestation == "abort":
            refusals.append(
                f"{subject.image}@{subject.digest}: GitHub lists {count} CycloneDX attestation(s), {distinct} verified "
                f"against the trust list; the other {unverified} were not read (on_unverified_attestation is abort)"
            )
            continue

        scanned_old = [r for r in chosen.superseded if _scanned(r)]
        unscanned_old = len(chosen.superseded) - len(scanned_old)
        status = STATED if _scanned(chosen.current) else UNSCANNED
        if status == STATED:
            try:
                parsed_current = _parse(chosen.current)
                parsed_old = [_parse(r) for r in scanned_old]
            except ValueError as exc:  # SbomParseError: a signed document that cannot be read is refused, not skipped
                refusals.append(f"{subject.image}@{subject.digest}: a verified document cannot be read: {exc}")
                continue
            current.append(parsed_current)
            superseded.extend(parsed_old)
        else:
            notes.append(
                f"revision {chosen.current.version} carries no vulnerabilities[]: it was never scanned, so it states and "
                f"resolves nothing"
            )
        outcomes.append(
            SubjectOutcome(
                image=subject.image,
                digest=subject.digest,
                status=status,
                current_version=chosen.current.version,
                current_signer=chosen.current.signer.id,
                superseded_versions=tuple(r.version for r in chosen.superseded),
                superseded_unscanned=unscanned_old,
                verified=distinct,
                listed=count,
                unverified=unverified,
                notes=tuple(notes),
            )
        )

    if refusals:
        raise AttestationRefused("; ".join(refusals))
    grift = None
    if current:
        try:
            grift = sbom_vulnerability_grift(current, superseded, batch_name=config.batch_name)
        except ValueError as exc:
            raise SbomAttestationError(f"the verified documents cannot be mapped: {exc}") from exc
    return PipelineResult(grift=grift, subjects=tuple(outcomes))
