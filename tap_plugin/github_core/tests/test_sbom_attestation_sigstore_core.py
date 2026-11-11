"""The real verifier on the real bundles (req-github-core-sbom-attestations-15).

Runs only where `sigstore` and a `sigstore_core` that carries `verify_dsse_bundle` are installed; skipped otherwise,
so this plugin's tests do not require them. No network: the Sigstore public-good `trusted_root.json` is a fixture
(SOURCE: `sigstore.models.ClientTrustConfig.production().trusted_root`, serialised 2026-10-19; a test fixture only,
production verification always uses the TUF-delivered root) and is handed to `sigstore_core`'s cached verifier
slot. The bundles are the two entries `gh attestation verify --format json` returned for tap-web
`sha256:a9149a88...` on 2026-10-16, so their Rekor integrated time, not the clock, decides certificate validity.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("sigstore")
sigstore_verify = pytest.importorskip("tap_plugin.sigstore_core.verify")
if not hasattr(sigstore_verify, "verify_dsse_bundle"):  # an older sigstore_core release
    pytest.skip("the installed sigstore_core has no verify_dsse_bundle", allow_module_level=True)

from sigstore.models import TrustedRoot  # noqa: E402
from sigstore.verify import Verifier  # noqa: E402
from tap_plugin.github_core.collectors.sbom_attestation_collector import config as cfg  # noqa: E402
from tap_plugin.github_core.collectors.sbom_attestation_collector.pipeline import run_pipeline  # noqa: E402
from tap_plugin.github_core.collectors.sbom_attestation_collector.verifier import (  # noqa: E402
    BundleListing,
    SigstoreCoreVerifier,
)

from .sbom_attestation_support import DIGEST, IMAGE, TRUST_LIST, RecordedVerifier, recorded_results  # noqa: E402
from .sbom_attestation_support import grift_content as _content  # noqa: E402

ROOT = Path(__file__).parent / "fixtures" / "sigstore-public-good-trusted-root.json"
SIGNERS = cfg.load_trusted_signers(TRUST_LIST)
PUBLISH, EVIDENCE = SIGNERS
SUBJECT = cfg.Subject(image=IMAGE, digest=DIGEST)


class _Fetcher:
    def __init__(self, bundles):
        self._bundles = bundles

    def bundles(self, subject):
        return BundleListing(self._bundles)


@pytest.fixture(autouse=True)
def offline_trust_root(monkeypatch):
    verifier = Verifier(trusted_root=TrustedRoot.from_file(str(ROOT)))
    monkeypatch.setattr(sigstore_verify, "_get_verifier", lambda: verifier)


def _bundles():
    return [json.loads(json.dumps(item["attestation"]["bundle"])) for item in recorded_results()]


def _config():
    return cfg.parse_config(
        {
            "_description": "t",
            "format": cfg.CONFIG_FORMAT,
            "trusted_signers_path": str(TRUST_LIST),
            "subjects": [{"_description": "tap-web", "image": IMAGE, "digest": DIGEST}],
        }
    )


def test_each_trust_list_entry_verifies_exactly_its_own_recorded_bundle():
    verifier = SigstoreCoreVerifier(_Fetcher(_bundles()))
    assert len(verifier.verify(SUBJECT, EVIDENCE).items) == 1  # revision 2, signer digest pinned
    assert len(verifier.verify(SUBJECT, PUBLISH).items) == 1  # revision 1, transitional (no pin)


def test_the_pipeline_on_really_verified_bundles_equals_the_pipeline_on_the_recorded_gh_output():
    real = run_pipeline(_config(), SIGNERS, SigstoreCoreVerifier(_Fetcher(_bundles())))
    recorded = run_pipeline(_config(), SIGNERS, RecordedVerifier({DIGEST: recorded_results()}))
    assert real.subjects == recorded.subjects
    assert _content(real.grift.document) == _content(recorded.grift.document)
    (outcome,) = real.subjects
    assert (outcome.current_version, outcome.superseded_versions) == (2, (1,))


def test_a_wrong_pin_in_the_trust_list_verifies_nothing():
    wrong = cfg.TrustedSigner(EVIDENCE.id, EVIDENCE.repository, EVIDENCE.workflow_path, EVIDENCE.ref, "0" * 40, False)
    result = SigstoreCoreVerifier(_Fetcher(_bundles())).verify(SUBJECT, wrong)
    assert result.items == [] and "policy_mismatch" in result.note


def test_a_tampered_payload_verifies_nothing_even_for_the_right_signer():
    bundles = _bundles()
    for bundle in bundles:
        payload = bundle["dsseEnvelope"]["payload"]
        bundle["dsseEnvelope"]["payload"] = payload[:-8] + ("A" if payload[-8] != "A" else "B") + payload[-7:]
    result = SigstoreCoreVerifier(_Fetcher(bundles)).verify(SUBJECT, EVIDENCE)
    assert result.items == [] and "signature" in result.note
