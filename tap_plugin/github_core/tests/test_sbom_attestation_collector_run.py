"""The collector class around the pipeline (req-github-core-sbom-attestations-4, -8, -10, -11, -12).

No database and no network: `submit_grift` is replaced by a recorder, the verifier and the lister are injected
(or, for the credential path, replaced where the collector builds them), and the config is a temporary file.
"""

from __future__ import annotations

import json
import uuid
from types import SimpleNamespace
from typing import Any

import pytest
from tap_plugin.github_core.collectors.sbom_attestation_collector import collector as module
from tap_plugin.github_core.collectors.sbom_attestation_collector.collector import SbomAttestationCollector
from tap_plugin.github_core.collectors.sbom_attestation_collector.errors import (
    SbomAttestationError,
    VerifierUnavailable,
)

from tap_cares.collectors.config import CollectorConfig

from .sbom_attestation_support import (
    DIGEST,
    IMAGE,
    TRUST_LIST,
    CountingLister,
    RecordedVerifier,
    cdx,
    make_item,
    recorded_results,
)
from .test_sbom_attestation_collector import EVIDENCE, PUBLISH


@pytest.fixture
def config_file(tmp_path):
    path = tmp_path / "sbom_attestations.config.json"
    path.write_text(
        json.dumps(
            {
                "_description": "test",
                "format": "github-core-sbom-attestations/1",
                "trusted_signers_path": str(TRUST_LIST),
                "verifier": "gh",
                "subjects": [{"_description": "tap-web", "image": IMAGE, "digest": DIGEST}],
            }
        )
    )
    return path


@pytest.fixture
def config_file_default_verifier(config_file):
    """The same config without a `verifier` key: the default, sigstore_core (req-github-core-sbom-attestations-12)."""
    document = json.loads(config_file.read_text())
    del document["verifier"]
    config_file.write_text(json.dumps(document))
    return config_file


def _build(config_file, verifier=None, lister=None):
    class Collector(SbomAttestationCollector):
        pass

    Collector.config_path = config_file
    Collector.verifier = verifier
    Collector.lister = lister
    collector = Collector(CollectorConfig(uuid.uuid4(), uuid.uuid4()))
    collector.submitted = []  # type: ignore[attr-defined]
    collector.submit_grift = lambda document, **kw: collector.submitted.append((document, kw))  # type: ignore[attr-defined,method-assign]
    return collector


def _codes(collector, level):
    return [e["message_code"] for e in collector.results[level]]


def test_a_run_submits_one_batch_through_submit_grift_with_the_default_abort(config_file):
    collector = _build(config_file, RecordedVerifier({DIGEST: recorded_results()}), CountingLister({DIGEST: 2}))
    collector.run()
    (document, kwargs), = collector.submitted
    assert kwargs == {}  # on_rejection stays at its default, "abort"
    assert document["batches"][0]["batch_node"]["name"] == "SBOM vulnerabilities (verified attestations)"
    assert "SUBJECT_VERIFIED" in _codes(collector, "info") and "SBOM_BATCH_SUBMITTED" in _codes(collector, "info")
    assert _codes(collector, "warn") == [] and _codes(collector, "error") == []
    assert collector.summary.startswith("1 subject(s): 94 open, 0 resolved")


def test_an_attestation_outside_the_trust_list_is_a_warning_and_is_not_read(config_file):
    collector = _build(config_file, RecordedVerifier({DIGEST: recorded_results()}), CountingLister({DIGEST: 3}))
    collector.run()
    assert _codes(collector, "warn") == ["ATTESTATIONS_NOT_ON_TRUST_LIST"]
    assert collector.results["warn"][0]["message_data"]["listed"] == 3


def test_an_unobserved_listing_is_a_warning_not_a_zero(config_file):
    collector = _build(config_file, RecordedVerifier({DIGEST: recorded_results()}), CountingLister({DIGEST: None}))
    collector.run()
    assert _codes(collector, "warn") == ["ATTESTATION_LISTING_UNOBSERVED"]


def test_a_refusal_aborts_loudly_and_submits_nothing(config_file):
    bad = make_item(cdx(2, []), EVIDENCE, cert={"issuer": "https://example.com"})
    collector = _build(config_file, RecordedVerifier({DIGEST: [bad]}), CountingLister({DIGEST: 1}))
    with pytest.raises(SbomAttestationError, match="Nothing was submitted"):
        collector.run()
    assert collector.submitted == []
    assert _codes(collector, "error") == ["ATTESTATION_REFUSED"]


def test_a_revision_never_scanned_submits_nothing_and_says_so(config_file):
    items = [make_item(cdx(1, None), PUBLISH)]
    collector = _build(config_file, RecordedVerifier({DIGEST: items}), CountingLister({DIGEST: 1}))
    collector.run()
    assert collector.submitted == []
    assert set(_codes(collector, "warn")) == {"CURRENT_REVISION_UNSCANNED", "NOTHING_TO_SUBMIT"}


@pytest.mark.parametrize("body", [None, "{not json", "[]"])
def test_a_missing_or_invalid_config_aborts_before_anything_is_verified(tmp_path, body):
    path = tmp_path / "config.json"
    if body is not None:
        path.write_text(body)
    verifier = RecordedVerifier({})
    collector = _build(path, verifier, CountingLister({}))
    with pytest.raises(SbomAttestationError):
        collector.run()
    assert verifier.calls == [] and _codes(collector, "error") == ["CONFIG_UNUSABLE"]


def test_a_trust_list_that_names_no_signer_aborts(config_file, tmp_path):
    empty = tmp_path / "signers.json"
    empty.write_text(json.dumps({"format": "tap-sbom-trusted-signers/1", "signers": []}))
    doc = json.loads(config_file.read_text()) | {"trusted_signers_path": str(empty)}
    config_file.write_text(json.dumps(doc))
    collector = _build(config_file, RecordedVerifier({}), CountingLister({}))
    with pytest.raises(SbomAttestationError):
        collector.run()
    assert _codes(collector, "error") == ["CONFIG_UNUSABLE"]


class _Built:
    """Stands in for the pieces `run` builds from the credential, recording what each was given."""

    verifiers: list = []
    clients: list = []

    class Verifier(RecordedVerifier):
        def __init__(self, *, token):
            super().__init__({DIGEST: recorded_results()})
            _Built.verifiers.append(token)
            self.closed = False

        def close(self):
            self.closed = True


def _patch_credential(monkeypatch, token="stand-in-value-one"):
    _Built.verifiers, _Built.clients = [], []
    secret = SimpleNamespace(kind="github", data={"x": 1})
    monkeypatch.setattr(module, "resolve_github_secret", lambda ref: secret)
    monkeypatch.setattr(module, "api_base_url", lambda data: "https://api.github.com")
    monkeypatch.setattr(module, "GithubAuth", lambda **kw: SimpleNamespace(token=lambda: token))
    monkeypatch.setattr(module, "GhCliVerifier", _Built.Verifier)
    monkeypatch.setattr(module, "GithubClient", lambda **kw: _Built.clients.append(kw) or object())
    monkeypatch.setattr(module, "GithubAttestationLister", lambda client: CountingLister({DIGEST: 2}))


def test_without_injected_seams_the_collector_builds_them_from_the_collector_credential(config_file, monkeypatch):
    _patch_credential(monkeypatch)
    collector = _build(config_file)
    collector.run()
    assert _Built.verifiers == ["stand-in-value-one"]
    assert _Built.clients and _Built.clients[0]["token"] == "stand-in-value-one"
    assert len(collector.submitted) == 1
    blob = json.dumps(collector.results)
    assert "stand-in-value-one" not in blob and "stand-in-value-one" not in collector.summary


def test_a_credential_failure_aborts_without_echoing_secret_material(config_file, monkeypatch):
    _patch_credential(monkeypatch)

    def refuse(ref):
        raise module.SecretError("no envelope")

    monkeypatch.setattr(module, "resolve_github_secret", refuse)
    collector = _build(config_file)
    with pytest.raises(SbomAttestationError):
        collector.run()
    assert _codes(collector, "error") == ["SECRET_UNUSABLE"] and collector.submitted == []


def test_a_missing_gh_aborts_with_verifier_unavailable_as_the_reason(config_file, monkeypatch):
    _patch_credential(monkeypatch)

    def no_gh(*, token):
        raise VerifierUnavailable("the gh CLI is not on PATH, so no attestation can be verified")

    monkeypatch.setattr(module, "GhCliVerifier", no_gh)
    collector = _build(config_file)
    with pytest.raises(SbomAttestationError, match="gh CLI"):
        collector.run()
    assert _codes(collector, "error") == ["VERIFIER_UNAVAILABLE"]


def test_the_verifier_the_collector_built_is_closed_even_when_the_run_is_refused(config_file, monkeypatch):
    _patch_credential(monkeypatch)
    built: list[Any] = []

    class Refusing(_Built.Verifier):
        def __init__(self, *, token):
            super().__init__(token=token)
            self.results = {}
            built.append(self)

    monkeypatch.setattr(module, "GhCliVerifier", Refusing)
    collector = _build(config_file)
    with pytest.raises(SbomAttestationError):
        collector.run()
    assert built[0].closed


def _patch_sigstore_core_path(monkeypatch):
    """Replace what `run` builds on the default path; record what each piece was given."""
    built: dict[str, Any] = {}
    _patch_credential(monkeypatch)

    class Fetcher:
        def __init__(self, client):
            built["fetcher_client"] = client

    class Verifier(RecordedVerifier):
        def __init__(self, fetcher):
            super().__init__({DIGEST: recorded_results()})
            built["verifier_fetcher"] = fetcher

    def no_gh(*, token):
        raise AssertionError("the default path must not build the gh verifier")

    monkeypatch.setattr(module, "GithubAttestationFetcher", Fetcher)
    monkeypatch.setattr(module, "SigstoreCoreVerifier", Verifier)
    monkeypatch.setattr(module, "GhCliVerifier", no_gh)
    return built


def test_the_default_verifier_is_sigstore_core_built_from_the_collector_credential(config_file_default_verifier, monkeypatch):
    built = _patch_sigstore_core_path(monkeypatch)
    collector = _build(config_file_default_verifier)
    collector.run()
    assert len(collector.submitted) == 1
    assert built["verifier_fetcher"] is not None and built["fetcher_client"] is not None
    assert _Built.clients[0]["token"] == "stand-in-value-one"  # the one client the fetcher and the lister share
    assert "stand-in-value-one" not in json.dumps(collector.results)


def test_sigstore_core_not_installed_aborts_with_verifier_unavailable_as_the_reason(config_file_default_verifier, monkeypatch):
    _patch_sigstore_core_path(monkeypatch)

    def missing(fetcher):
        raise VerifierUnavailable("sigstore_core with DSSE verification is not installed")

    monkeypatch.setattr(module, "SigstoreCoreVerifier", missing)
    collector = _build(config_file_default_verifier)
    with pytest.raises(SbomAttestationError, match="not installed"):
        collector.run()
    assert _codes(collector, "error") == ["VERIFIER_UNAVAILABLE"] and collector.submitted == []


class TestSelfTest:
    def _run(self, config_file, monkeypatch, gh="/usr/bin/gh", verifier=None):
        class Collector(SbomAttestationCollector):
            pass

        Collector.config_path = config_file
        Collector.verifier = verifier
        monkeypatch.setattr(module, "resolve_github_secret", lambda ref: SimpleNamespace(kind="github", data={}))
        import shutil

        monkeypatch.setattr(shutil, "which", lambda name: gh)
        return Collector.self_test()

    def test_ready_when_config_trust_list_credential_and_gh_are_present(self, config_file, monkeypatch):
        result = self._run(config_file, monkeypatch)
        assert result.status.value == "ready"

    def test_a_missing_gh_is_misconfigured_unless_a_verifier_is_injected(self, config_file, monkeypatch):
        assert self._run(config_file, monkeypatch, gh=None).status.value == "misconfigured"
        assert self._run(config_file, monkeypatch, gh=None, verifier=RecordedVerifier({})).status.value == "ready"

    def test_the_default_verifier_needs_sigstore_core_not_gh(self, config_file_default_verifier, monkeypatch):
        monkeypatch.setattr(module, "load_sigstore_core", lambda: None)
        result = self._run(config_file_default_verifier, monkeypatch, gh=None)  # no gh on PATH, and none needed
        assert result.status.value == "ready"

    def test_a_missing_sigstore_core_is_misconfigured_on_the_default_path(self, config_file_default_verifier, monkeypatch):
        def missing():
            raise VerifierUnavailable("sigstore_core with DSSE verification is not installed")

        monkeypatch.setattr(module, "load_sigstore_core", missing)
        assert self._run(config_file_default_verifier, monkeypatch).status.value == "misconfigured"

    def test_an_absent_config_is_unconfigured(self, tmp_path, monkeypatch):
        assert self._run(tmp_path / "absent.json", monkeypatch).status.value == "unconfigured"
