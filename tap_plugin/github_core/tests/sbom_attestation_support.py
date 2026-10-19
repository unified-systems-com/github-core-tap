"""Shared builders for the SBOM attestation collector tests: recorded verification and synthetic attestations."""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
from pathlib import Path
from typing import Any

from tap_plugin.github_core.collectors.sbom_attestation_collector.attestations import OIDC_ISSUER, PREDICATE_TYPE
from tap_plugin.github_core.collectors.sbom_attestation_collector.config import Subject, TrustedSigner
from tap_plugin.github_core.collectors.sbom_attestation_collector.lister import Listing
from tap_plugin.github_core.collectors.sbom_attestation_collector.verifier import VerifyResult

FIXTURES = Path(__file__).parent / "fixtures"
TRUST_LIST = FIXTURES / "sbom-trusted-signers.json"
RECORDED = FIXTURES / "sbom-attestations-verify-tap-web-a9149a88.json.gz"
REV2_PREDICATE = FIXTURES / "sbom-tap-web-rev2-a9149a88.cdx.json"
IMAGE = "ghcr.io/unified-systems-com/tap-web"
DIGEST = "sha256:a9149a88a6239fc7a5351d9854fbff42448d2ed28cc71951a4c2aa2f4aca7750"


def recorded_results() -> list[dict[str, Any]]:
    """Both entries `gh attestation verify --format json` returned for the digest on 2026-10-16."""
    return json.loads(gzip.decompress(RECORDED.read_bytes()))


def _san(item: dict[str, Any]) -> str:
    return item["verificationResult"]["signature"]["certificate"]["subjectAlternativeName"]


def _cert_digest(item: dict[str, Any]) -> str:
    return item["verificationResult"]["signature"]["certificate"]["buildSignerDigest"]


class RecordedVerifier:
    """Replays results somebody else verified, filtered the way `gh --cert-identity/--signer-digest` filters.

    It checks no signature: it is the offline stand-in for the verifier seam and nothing else.
    """

    def __init__(self, results_by_digest: dict[str, list[dict[str, Any]]], notes: dict[str, str] | None = None) -> None:
        self.results = results_by_digest
        self.notes = notes or {}
        self.calls: list[tuple[str, str]] = []

    def verify(self, subject: Subject, signer: TrustedSigner) -> VerifyResult:
        self.calls.append((subject.digest, signer.id))
        kept = [
            item
            for item in self.results.get(subject.digest, [])
            if _san(item) == signer.identity and (signer.signer_digest is None or _cert_digest(item) == signer.signer_digest)
        ]
        return VerifyResult(kept, "" if kept else self.notes.get(signer.id, "no attestation found"))


class CountingLister:
    def __init__(self, counts: dict[str, int | None], complete: bool = True) -> None:
        self.counts = counts
        self.complete = complete

    def count(self, subject: Subject) -> Listing:
        count = self.counts.get(subject.digest)
        return Listing(count, "" if count is not None else "GitHub answered 403", self.complete)


def make_item(
    predicate: dict[str, Any],
    signer: TrustedSigner,
    digest: str = DIGEST,
    *,
    integrated_time: int = 1,
    statement: dict[str, Any] | None = None,
    payload_text: str | None = None,
    result_predicate: Any = None,
    cert: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """A `gh attestation verify` entry for a synthetic predicate, signed (in the record) by `signer`."""
    body = statement or {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": IMAGE, "digest": {"sha256": digest.removeprefix("sha256:")}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate,
    }
    text = payload_text if payload_text is not None else json.dumps(body, separators=(",", ":"))
    certificate = {
        "subjectAlternativeName": signer.identity,
        "issuer": OIDC_ISSUER,
        "buildSignerDigest": signer.signer_digest or hashlib.sha256(signer.id.encode()).hexdigest()[:40],
        **(cert or {}),
    }
    return {
        "attestation": {
            "bundle": {
                "dsseEnvelope": {"payload": base64.b64encode(text.encode()).decode(), "payloadType": "application/vnd.in-toto+json"},
                "verificationMaterial": {"tlogEntries": [{"integratedTime": str(integrated_time)}]},
            }
        },
        "verificationResult": {
            "signature": {"certificate": certificate},
            "statement": {"predicateType": PREDICATE_TYPE, "predicate": predicate if result_predicate is None else result_predicate},
        },
    }


def cdx(version: int, vulns: list[tuple[str, str]] | None, serial: str = "urn:uuid:11111111-1111-4111-8111-111111111111") -> dict[str, Any]:
    """A small CycloneDX document: `vulns` (id, component) pairs, or None for an unscanned revision."""
    names = sorted({c for _, c in vulns or []} | {"zlib"})
    doc: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": serial,
        "version": version,
        "metadata": {
            "timestamp": f"2026-10-{10 + version:02d}T00:00:00Z",
            "component": {"type": "container", "name": IMAGE, "version": DIGEST, "bom-ref": "image"},
        },
        "components": [
            {"type": "library", "name": n, "version": "1.0", "purl": f"pkg:pypi/{n}@1.0", "bom-ref": f"pkg:pypi/{n}@1.0"}
            for n in names
        ],
    }
    if vulns is not None:
        doc["vulnerabilities"] = [
            {
                "id": vid,
                "source": {"name": "nvd"},
                "description": f"{vid} in {comp}",
                "affects": [{"ref": f"pkg:pypi/{comp}@1.0"}],
                "tools": {"components": [{"type": "application", "name": "grype", "version": "0.1"}]},
            }
            for vid, comp in vulns
        ]
    return doc


def grift_content(document: dict[str, Any]) -> dict[str, Any]:
    """A GRIFT document without the per-run identity of its batch (time-ordered ids, collection timestamp)."""
    out = json.loads(json.dumps(document))
    out.pop("metadata", None)
    for batch in out.get("batches", []):
        batch.pop("batch_entity", None)
        (batch.get("batch_node", {}).get("description_json") or {}).pop("collected_at", None)
    return out
