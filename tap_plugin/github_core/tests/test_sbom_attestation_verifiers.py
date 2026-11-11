"""The two verifiers behind the seam, and the fetcher (req-github-core-sbom-attestations-12, -13, -14).

Offline: `sigstore_core` is not imported. `SigstoreCoreVerifier` takes its three entry points as arguments, and the
fakes below apply the policy the way the real verifier does (SAN equality, Build Signer Digest equality) to the
recorded `gh` bundles of 2026-10-16, so what is under test is the mapping from a trust-list entry to a policy, the
per-signer filtering, the failure accounting, and that what comes back passes `check_item` and the pipeline. The
real cryptography is exercised in `test_sbom_attestation_sigstore_core.py` when `sigstore_core` is installed.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

import pytest
from tap_plugin.github_core.collectors.sbom_attestation_collector import attestations as att
from tap_plugin.github_core.collectors.sbom_attestation_collector import config as cfg
from tap_plugin.github_core.collectors.sbom_attestation_collector.errors import ConfigError, VerifierUnavailable
from tap_plugin.github_core.collectors.sbom_attestation_collector.pipeline import run_pipeline
from tap_plugin.github_core.collectors.sbom_attestation_collector.verifier import (
    BundleListing,
    GithubAttestationFetcher,
    SigstoreCoreVerifier,
    load_sigstore_core,
)
from tap_plugin.github_core.sbom_vulnerabilities import SbomVulnerabilityResult

from .sbom_attestation_support import DIGEST, IMAGE, TRUST_LIST, CountingLister, RecordedVerifier, recorded_results
from .sbom_attestation_support import grift_content as _content

SIGNERS = cfg.load_trusted_signers(TRUST_LIST)
PUBLISH, EVIDENCE = SIGNERS
SUBJECT = cfg.Subject(image=IMAGE, digest=DIGEST)
ISSUER = "https://token.actions.githubusercontent.com"


@dataclass(frozen=True)
class FakePolicy:
    """Stands in for sigstore_core's GitHubWorkflowPolicy: the same field names, nothing else."""

    oidc_issuer: str
    github_repository: str
    workflow_identity_uri: str | None = None
    workflow_ref: str | None = None
    workflow_sha: str | None = None
    build_signer_digest: str | None = None


def _bundles() -> list[dict[str, Any]]:
    return [item["attestation"]["bundle"] for item in recorded_results()]


def _cert_of(bundle: dict[str, Any]) -> dict[str, Any]:
    for item in recorded_results():
        if item["attestation"]["bundle"] == bundle:
            return item["verificationResult"]["signature"]["certificate"]
    raise AssertionError("not a recorded bundle")


class FakeSigstoreCore:
    """verify_dsse / extract_predicate stand-ins that apply the policy to the recorded certificate."""

    def __init__(self, override: dict[str, Any] | None = None) -> None:
        self.policies: list[FakePolicy] = []
        self.override = override or {}

    def verify_dsse(self, bundle_bytes: bytes, *, policy: FakePolicy) -> Any:
        self.policies.append(policy)
        bundle = json.loads(bundle_bytes)
        cert = _cert_of(bundle)
        payload = base64.b64decode(bundle["dsseEnvelope"]["payload"])
        base = {
            "signed_by": cert["subjectAlternativeName"],
            "signing_issuer": cert["issuer"],
            "build_signer_digest": cert["buildSignerDigest"],
            "payload": b"",
            "failure_code": "",
            "failure_detail": "",
        }
        wrong = (
            policy.oidc_issuer != cert["issuer"]
            or policy.workflow_identity_uri != cert["subjectAlternativeName"]
            or (policy.build_signer_digest is not None and policy.build_signer_digest != cert["buildSignerDigest"])
        )
        if wrong:
            return SimpleNamespace(signature_verified=False, **{**base, "failure_code": "policy_mismatch"})
        return SimpleNamespace(signature_verified=True, **{**base, "payload": payload, **self.override})

    @staticmethod
    def extract_predicate(payload: bytes, *, expected_subject_sha256: str, expected_predicate_type: str) -> Any:
        statement = json.loads(payload)
        subjects = [s["digest"]["sha256"] for s in statement["subject"]]
        if expected_subject_sha256.removeprefix("sha256:") not in subjects:
            return SimpleNamespace(ok=False, failure_code="subject_mismatch", predicate=b"")
        if statement["predicateType"] != expected_predicate_type:
            return SimpleNamespace(ok=False, failure_code="predicate_type_mismatch", predicate=b"")
        return SimpleNamespace(ok=True, failure_code="", predicate=att.signed_predicate_bytes(payload.decode()))


class StaticFetcher:
    def __init__(self, bundles: list[dict[str, Any]], note: str = "") -> None:
        self.listing = BundleListing(bundles, note)
        self.calls = 0

    def bundles(self, subject: cfg.Subject) -> BundleListing:
        self.calls += 1
        return self.listing


def _verifier(fetcher: Any = None, core: FakeSigstoreCore | None = None) -> tuple[SigstoreCoreVerifier, FakeSigstoreCore]:
    core = core or FakeSigstoreCore()
    fetcher = fetcher or StaticFetcher(_bundles())
    return SigstoreCoreVerifier(
        fetcher, verify_dsse=core.verify_dsse, extract_predicate=core.extract_predicate, policy_factory=FakePolicy
    ), core


class TestConfigVerifierKey:
    """req-github-core-sbom-attestations-12"""

    def _config(self, **over: Any) -> cfg.SbomAttestationConfig:
        base = {
            "_description": "test",
            "format": cfg.CONFIG_FORMAT,
            "trusted_signers_path": str(TRUST_LIST),
            "subjects": [{"_description": "tap-web", "image": IMAGE, "digest": DIGEST}],
        }
        return cfg.parse_config({**base, **over})

    def test_the_default_is_sigstore_core(self):
        assert self._config().verifier == "sigstore_core"

    def test_gh_can_be_selected(self):
        assert self._config(verifier="gh").verifier == "gh"

    @pytest.mark.parametrize("value", ["cosign", "", None, 1])
    def test_anything_else_is_refused(self, value):
        with pytest.raises(ConfigError):
            self._config(verifier=value)

    def test_the_schema_and_the_code_name_the_same_choices(self):
        schema = json.loads(cfg.SCHEMA_PATH.read_text())
        assert tuple(schema["properties"]["verifier"]["enum"]) == cfg.VERIFIERS
        assert schema["properties"]["verifier"]["description"]


class TestSigstoreCoreVerifier:
    """req-github-core-sbom-attestations-13: the policy is the trust-list entry; the rest is dropped, not trusted."""

    def test_a_pinned_entry_maps_to_issuer_repository_identity_and_the_build_signer_digest(self):
        verifier, _ = _verifier()
        policy = verifier.policy_for(EVIDENCE)
        assert policy == FakePolicy(
            oidc_issuer=ISSUER,
            github_repository="unified-systems-com/tap",
            workflow_identity_uri=EVIDENCE.identity,
            build_signer_digest="5736329dff506c952b5567260dd82c51adab5d74",
        )
        # The trigger commit is never what a pin means: it stays unset.
        assert policy.workflow_sha is None and policy.workflow_ref is None

    def test_a_transitional_entry_has_no_digest_to_pin(self):
        verifier, _ = _verifier()
        policy = verifier.policy_for(PUBLISH)
        assert policy.build_signer_digest is None
        assert policy.workflow_identity_uri == "https://github.com/unified-systems-com/tap/.github/workflows/publish-images.yml@refs/heads/main"

    def test_each_signer_keeps_only_the_bundles_its_policy_admits(self):
        verifier, core = _verifier()
        evidence = verifier.verify(SUBJECT, EVIDENCE)
        publish = verifier.verify(SUBJECT, PUBLISH)
        assert [att.check_item(i, subject_digest=DIGEST, signer=EVIDENCE).version for i in evidence.items] == [2]
        assert [att.check_item(i, subject_digest=DIGEST, signer=PUBLISH).version for i in publish.items] == [1]
        assert len(core.policies) == 4  # every bundle is offered to every signer's policy

    def test_what_comes_back_has_the_shape_check_item_reads_and_carries_the_verified_certificate(self):
        verifier, _ = _verifier()
        (item,) = verifier.verify(SUBJECT, EVIDENCE).items
        certificate = item["verificationResult"]["signature"]["certificate"]
        assert certificate == {
            "subjectAlternativeName": EVIDENCE.identity,
            "issuer": ISSUER,
            "buildSignerDigest": EVIDENCE.signer_digest,
        }
        assert item["attestation"]["bundle"] in _bundles()

    def test_nothing_verified_says_how_many_were_listed_and_why_each_was_dropped(self):
        verifier, _ = _verifier(StaticFetcher(_bundles(), note="the attestation listing was cut short"))
        other = cfg.TrustedSigner("other", "unified-systems-com/tap", ".github/workflows/other.yml", "refs/heads/main", None, True)
        result = verifier.verify(SUBJECT, other)
        assert result.items == []
        assert result.note == "2 bundle(s) listed, none verified for this signer (2 policy_mismatch); the attestation listing was cut short"

    def test_a_bundle_that_matches_the_identity_but_fails_a_check_is_dropped_and_counted(self):
        core = FakeSigstoreCore()
        original = core.verify_dsse

        def failing(bundle_bytes, *, policy):
            result = original(bundle_bytes, policy=policy)
            if result.signature_verified:
                return SimpleNamespace(**{**vars(result), "signature_verified": False, "failure_code": "signature", "payload": b""})
            return result

        core.verify_dsse = failing
        verifier, _ = _verifier(core=core)
        result = verifier.verify(SUBJECT, EVIDENCE)
        assert result.items == [] and "1 policy_mismatch" in result.note and "1 signature" in result.note

    def test_a_statement_about_another_subject_is_dropped(self):
        other = cfg.Subject(image=IMAGE, digest="sha256:" + "b" * 64)
        verifier, _ = _verifier()
        result = verifier.verify(other, EVIDENCE)
        assert result.items == [] and "subject_mismatch" in result.note

    def test_a_verifier_that_could_not_run_is_unavailable_not_empty(self):
        core = FakeSigstoreCore()
        core.verify_dsse = lambda b, *, policy: SimpleNamespace(
            signature_verified=False, failure_code="unexpected", failure_detail="TUF refresh failed: network unreachable"
        )
        verifier, _ = _verifier(core=core)
        with pytest.raises(VerifierUnavailable, match="TUF refresh failed"):
            verifier.verify(SUBJECT, EVIDENCE)

    def test_an_unparseable_bundle_is_a_drop(self):
        core = FakeSigstoreCore()
        core.verify_dsse = lambda b, *, policy: SimpleNamespace(signature_verified=None, failure_code="bundle_parse", failure_detail="x")
        verifier, _ = _verifier(core=core)
        result = verifier.verify(SUBJECT, EVIDENCE)
        assert result.items == [] and "bundle_parse" in result.note

    def test_the_pipeline_reads_the_same_revisions_as_it_does_from_the_recorded_gh_output(self):
        config = cfg.parse_config(
            {
                "_description": "t",
                "format": cfg.CONFIG_FORMAT,
                "trusted_signers_path": str(TRUST_LIST),
                "subjects": [{"_description": "tap-web", "image": IMAGE, "digest": DIGEST}],
            }
        )
        verifier, _ = _verifier()
        lister = CountingLister({DIGEST: 2})
        mine = run_pipeline(config, SIGNERS, verifier, lister)
        theirs = run_pipeline(config, SIGNERS, RecordedVerifier({DIGEST: recorded_results()}), lister)
        assert mine.subjects == theirs.subjects
        assert isinstance(mine.grift, SbomVulnerabilityResult)
        assert _content(mine.grift.document) == _content(theirs.grift.document)
        (outcome,) = mine.subjects
        assert (outcome.current_version, outcome.superseded_versions, outcome.verified) == (2, (1,), 2)

    def test_the_entry_points_are_loaded_from_sigstore_core_or_the_absence_is_named(self):
        try:
            verify_dsse, extract, policy = load_sigstore_core()
        except VerifierUnavailable as exc:
            assert "sigstore_core" in str(exc) and "'gh'" in str(exc)
        else:  # installed: the three entry points are the real callables
            assert callable(verify_dsse) and callable(extract) and policy.__name__ == "GitHubWorkflowPolicy"


class TestGithubAttestationFetcher:
    """req-github-core-sbom-attestations-14: the documented endpoint, inline bundles, cached per digest."""

    class _Client:
        def __init__(self, answers: dict[str, Any], complete: bool = True) -> None:
            self.answers, self.complete, self.paths = answers, complete, []
            self.last_walk_complete = True

        def get_paginated(self, path, *, params=None, item_path=None, max_pages=100):
            self.paths.append((path, params, item_path))
            answer = self.answers[path.split("/")[1]]
            if isinstance(answer, Exception):
                raise answer
            self.last_walk_complete = self.complete
            return answer

    def _rows(self) -> list[dict[str, Any]]:
        return [{"repository_id": 1, "bundle_url": "u", "bundle": b} for b in _bundles()]

    def test_the_organisation_endpoint_is_asked_and_the_inline_bundles_returned(self):
        client = self._Client({"orgs": self._rows()})
        listing = GithubAttestationFetcher(client).bundles(SUBJECT)
        assert listing.bundles == _bundles() and listing.note == ""
        assert client.paths == [
            (
                f"/orgs/unified-systems-com/attestations/{DIGEST}",
                {"predicate_type": "https://cyclonedx.org/bom", "per_page": "100"},
                "attestations",
            )
        ]

    def test_a_404_falls_back_to_the_user_endpoint(self):
        from tap_plugin.github_core.collectors.github_collector.api_client import GithubAPIError

        client = self._Client({"orgs": GithubAPIError(404, "u", "{}"), "users": self._rows()})
        assert len(GithubAttestationFetcher(client).bundles(SUBJECT).bundles) == 2

    def test_rows_without_an_inline_bundle_are_noted_and_not_read(self):
        rows = self._rows() + [{"repository_id": 1, "bundle_url": "u"}]
        listing = GithubAttestationFetcher(self._Client({"orgs": rows})).bundles(SUBJECT)
        assert len(listing.bundles) == 2 and "no inline bundle" in listing.note

    def test_a_cut_short_walk_is_noted(self):
        listing = GithubAttestationFetcher(self._Client({"orgs": self._rows()}, complete=False)).bundles(SUBJECT)
        assert "cut short" in listing.note

    def test_a_refusal_is_an_empty_unobserved_listing_that_is_not_cached(self):
        from tap_plugin.github_core.collectors.github_collector.api_client import GithubAPIError

        client = self._Client({"orgs": GithubAPIError(403, "u", "{}")})
        fetcher = GithubAttestationFetcher(client)
        first = fetcher.bundles(SUBJECT)
        assert first.bundles == [] and "403" in first.note
        client.answers["orgs"] = self._rows()
        assert len(fetcher.bundles(SUBJECT).bundles) == 2

    def test_the_listing_is_fetched_once_per_digest(self):
        client = self._Client({"orgs": self._rows()})
        fetcher = GithubAttestationFetcher(client)
        fetcher.bundles(SUBJECT)
        fetcher.bundles(SUBJECT)
        assert len(client.paths) == 1
