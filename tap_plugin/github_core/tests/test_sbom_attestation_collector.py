"""The SBOM attestation collector (req-github-core-sbom-attestations).

Everything runs offline. The verifier seam is filled by `RecordedVerifier`, which replays the two entries that
`gh attestation verify --format json` returned for tap-web `sha256:a9149a88...` on 2026-10-16 (revision 2 signed
by `sbom-vulnerability-evidence.yml`, revision 1 by `publish-images.yml`), or by synthetic attestations built in
`sbom_attestation_support`. No live fetch or verification is made here.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

import pytest
from tap_plugin.computing_core.sbom import Verification, parse_cyclonedx_vulnerabilities
from tap_plugin.github_core.collectors.sbom_attestation_collector import attestations as att
from tap_plugin.github_core.collectors.sbom_attestation_collector import config as cfg
from tap_plugin.github_core.collectors.sbom_attestation_collector.errors import (
    AttestationRefused,
    ConfigError,
    VerifierUnavailable,
)
from tap_plugin.github_core.collectors.sbom_attestation_collector.pipeline import STATED, UNSCANNED, run_pipeline
from tap_plugin.github_core.collectors.sbom_attestation_collector.verifier import GhCliVerifier
from tap_plugin.github_core.sbom_vulnerabilities import sbom_vulnerability_grift

from .sbom_attestation_support import (
    DIGEST,
    IMAGE,
    REV2_PREDICATE,
    TRUST_LIST,
    CountingLister,
    RecordedVerifier,
    cdx,
    make_item,
    recorded_results,
)

SIGNERS = cfg.load_trusted_signers(TRUST_LIST)
PUBLISH, EVIDENCE = SIGNERS
SUBJECT = cfg.Subject(image=IMAGE, digest=DIGEST)


def _config(**over) -> cfg.SbomAttestationConfig:
    base = {
        "_description": "test",
        "format": cfg.CONFIG_FORMAT,
        "trusted_signers_path": str(TRUST_LIST),
        "subjects": [{"_description": "tap-web arm64", "image": IMAGE, "digest": DIGEST}],
    }
    return cfg.parse_config({**base, **over})


def _items(*pairs) -> list[dict]:
    """Synthetic entries: (version, vulns or None, signer) in the given order."""
    return [make_item(cdx(v, vulns), signer, integrated_time=v) for v, vulns, signer in pairs]


class TestConfig:
    """req-github-core-sbom-attestations-1"""

    def test_a_valid_config_loads_with_its_defaults(self):
        c = _config()
        assert c.subjects == (SUBJECT,) and c.on_unverified_attestation == "warn"
        assert SUBJECT.owner == "unified-systems-com" and SUBJECT.oci == f"oci://{IMAGE}@{DIGEST}"

    @pytest.mark.parametrize(
        "over",
        [
            {"subjects": []},
            {"unknown": 1},
            {"trusted_signers_path": "relative/path.json"},
            {"on_unverified_attestation": "ignore"},
            {"format": "other/1"},
            {"subjects": [{"_description": "x", "image": "docker.io/a/b", "digest": DIGEST}]},
            {"subjects": [{"_description": "x", "image": IMAGE, "digest": "sha256:abc"}]},
            {"subjects": [{"image": IMAGE, "digest": DIGEST}]},
        ],
    )
    def test_an_invalid_config_is_refused(self, over):
        with pytest.raises(ConfigError):
            _config(**over)

    def test_the_same_digest_twice_is_refused(self):
        s = {"_description": "x", "image": IMAGE, "digest": DIGEST}
        with pytest.raises(ConfigError, match="twice"):
            _config(subjects=[s, dict(s)])

    def test_no_image_name_is_built_in_and_every_schema_entry_is_described(self):
        schema = json.loads(cfg.SCHEMA_PATH.read_text())
        assert "tap-web" not in json.dumps(schema)

        def walk(node, path="schema"):
            if isinstance(node, dict) and "properties" in node:
                for name, sub in node["properties"].items():
                    assert sub.get("description") or name == "_description" or "const" in sub, f"{path}.{name} has no description"
                    walk(sub, f"{path}.{name}")
            if isinstance(node, dict) and "items" in node:
                walk(node["items"], f"{path}[]")

        assert schema["description"]
        walk(schema)

    def test_a_missing_file_is_a_config_error(self, tmp_path):
        with pytest.raises(ConfigError, match="cannot read"):
            cfg.load_config(tmp_path / "absent.json")


class TestTrustList:
    """req-github-core-sbom-attestations-2"""

    def test_the_real_list_loads_with_both_signers_and_their_identities(self):
        assert [s.id for s in SIGNERS] == ["tap-publish-images-transitional", "tap-sbom-evidence-5736329d"]
        assert PUBLISH.identity == "https://github.com/unified-systems-com/tap/.github/workflows/publish-images.yml@refs/heads/main"
        assert EVIDENCE.signer_digest == "5736329dff506c952b5567260dd82c51adab5d74"

    def _doc(self):
        return json.loads(TRUST_LIST.read_text())

    def test_an_empty_list_refuses_everything(self):
        doc = self._doc() | {"signers": []}
        with pytest.raises(ConfigError, match="empty list"):
            cfg.parse_trusted_signers(doc)

    def test_an_unpinned_signer_must_be_transitional(self):
        doc = self._doc()
        doc["signers"][0]["transitional"] = False
        with pytest.raises(ConfigError, match="transitional"):
            cfg.parse_trusted_signers(doc)

    def test_an_unknown_field_a_bad_pattern_and_a_repeat_are_refused(self):
        doc = self._doc()
        doc["signers"][1]["extra"] = 1
        with pytest.raises(ConfigError, match="unknown"):
            cfg.parse_trusted_signers(doc)
        doc = self._doc()
        doc["signers"][1]["workflow_path"] = "scripts/x.sh"
        with pytest.raises(ConfigError, match="pattern"):
            cfg.parse_trusted_signers(doc)
        doc = self._doc()
        doc["signers"].append(copy.deepcopy(doc["signers"][1]))
        with pytest.raises(ConfigError, match="repeats"):
            cfg.parse_trusted_signers(doc)

    def test_a_wrong_format_or_a_non_object_is_refused(self):
        with pytest.raises(ConfigError):
            cfg.parse_trusted_signers({"format": "x", "signers": [1]})
        with pytest.raises(ConfigError):
            cfg.parse_trusted_signers([])


class TestTrustCheckOnEveryEntry:
    """req-github-core-sbom-attestations-3"""

    def _rev2(self) -> dict:
        return next(i for i in recorded_results() if i["verificationResult"]["statement"]["predicate"]["version"] == 2)

    def test_the_recorded_revision_two_passes_under_the_evidence_signer_only(self):
        revision = att.check_item(self._rev2(), subject_digest=DIGEST, signer=EVIDENCE)
        assert (revision.version, revision.signer.id) == (2, "tap-sbom-evidence-5736329d")
        with pytest.raises(AttestationRefused, match="is not the trusted"):
            att.check_item(self._rev2(), subject_digest=DIGEST, signer=PUBLISH)

    def test_a_different_pinned_signer_digest_is_refused(self):
        item = self._rev2()
        item["verificationResult"]["signature"]["certificate"]["buildSignerDigest"] = "0" * 40
        with pytest.raises(AttestationRefused, match="pinned"):
            att.check_item(item, subject_digest=DIGEST, signer=EVIDENCE)

    def test_a_foreign_issuer_is_refused(self):
        item = make_item(cdx(2, []), EVIDENCE, cert={"issuer": "https://example.com"})
        with pytest.raises(AttestationRefused, match="issuer"):
            att.check_item(item, subject_digest=DIGEST, signer=EVIDENCE)

    def test_a_statement_about_another_subject_is_refused(self):
        item = make_item(cdx(2, []), EVIDENCE, digest="sha256:" + "1" * 64)
        with pytest.raises(AttestationRefused, match="different subject"):
            att.check_item(item, subject_digest=DIGEST, signer=EVIDENCE)

    def test_a_statement_of_another_predicate_type_is_refused(self):
        body = {"_type": "https://in-toto.io/Statement/v1", "subject": [{"digest": {"sha256": DIGEST[7:]}}], "predicateType": "https://slsa.dev/provenance/v1", "predicate": {"version": 1, "serialNumber": "urn:uuid:x"}}
        item = make_item({}, EVIDENCE, statement=body)
        with pytest.raises(AttestationRefused, match="not a CycloneDX"):
            att.check_item(item, subject_digest=DIGEST, signer=EVIDENCE)

    def test_a_predicate_the_verifier_returned_but_the_payload_does_not_hold_is_refused(self):
        item = make_item(cdx(2, []), EVIDENCE, result_predicate=cdx(3, []))
        with pytest.raises(AttestationRefused, match="not the one in the signed payload"):
            att.check_item(item, subject_digest=DIGEST, signer=EVIDENCE)

    @pytest.mark.parametrize("breakage", ["no-result", "no-cert", "no-payload", "bad-base64", "no-version", "no-serial", "not-object"])
    def test_a_malformed_entry_is_refused_not_crashed_on(self, breakage):
        item = make_item(cdx(2, []), EVIDENCE)
        if breakage == "no-result":
            del item["verificationResult"]
        elif breakage == "no-cert":
            item["verificationResult"]["signature"] = {}
        elif breakage == "no-payload":
            del item["attestation"]["bundle"]["dsseEnvelope"]
        elif breakage == "bad-base64":
            item["attestation"]["bundle"]["dsseEnvelope"]["payload"] = "!!!"
        elif breakage == "no-version":
            item = make_item({"serialNumber": "urn:uuid:x"}, EVIDENCE)
        elif breakage == "no-serial":
            item = make_item({"version": 2}, EVIDENCE)
        elif breakage == "not-object":
            item = []
        with pytest.raises(AttestationRefused):
            att.check_item(item, subject_digest=DIGEST, signer=EVIDENCE)


class TestContentDigestOverSignedBytes:
    """req-github-core-sbom-attestations-5"""

    def test_the_recorded_revision_two_digest_is_the_sha256_of_the_published_fixture_bytes(self):
        item = next(i for i in recorded_results() if i["verificationResult"]["statement"]["predicate"]["version"] == 2)
        revision = att.check_item(item, subject_digest=DIGEST, signer=EVIDENCE)
        fixture = REV2_PREDICATE.read_bytes()
        assert revision.predicate == fixture
        assert revision.content_digest == hashlib.sha256(fixture).hexdigest()

    def test_whitespace_key_order_and_escapes_are_kept_byte_for_byte(self):
        odd = '{ "version" : 2,\n  "serialNumber":"urn:uuid:a", "note":"\\u00e9 \\"predicate\\" ", "bomFormat":"CycloneDX" }'
        text = (
            '{"predicate" : ' + odd + ', "subject":[{"name":"predicate","digest":{"sha256":"' + DIGEST[7:] + '"}}], '
            '"predicateType":"https://cyclonedx.org/bom","_type":"https://in-toto.io/Statement/v1"}'
        )
        assert att.signed_predicate_bytes(text) == odd.encode()
        item = make_item(json.loads(odd), EVIDENCE, payload_text=text)
        assert att.check_item(item, subject_digest=DIGEST, signer=EVIDENCE).content_digest == hashlib.sha256(odd.encode()).hexdigest()

    def test_a_nested_or_valued_predicate_is_not_the_predicate(self):
        text = '{"subject":[{"name":"predicate","predicate":{"x":1}}],"predicate":{"y":2}}'
        assert att.signed_predicate_bytes(text) == b'{"y":2}'

    @pytest.mark.parametrize("text", ['{"predicate":1,"predicate":2}', '{"a":1}', "[]", '{"predicate"', ""])
    def test_a_statement_without_exactly_one_predicate_is_refused(self, text):
        with pytest.raises(AttestationRefused):
            att.signed_predicate_bytes(text)


class TestRevisionChoice:
    """req-github-core-sbom-attestations-6"""

    def _rev(self, version, signer=EVIDENCE, serial="urn:uuid:a", time=1, tag=""):
        doc = cdx(version, [], serial=serial) | {"note": tag}
        return att.check_item(make_item(doc, signer, integrated_time=time), subject_digest=DIGEST, signer=signer)

    def test_the_highest_version_is_current_and_the_rest_are_superseded(self):
        chosen = att.select([self._rev(1, PUBLISH), self._rev(3), self._rev(2)])
        assert chosen.current.version == 3 and [r.version for r in chosen.superseded] == [2, 1]

    def test_a_tie_goes_to_the_later_signature_then_the_digest(self):
        early, late = self._rev(2, time=1, tag="a"), self._rev(2, time=9, tag="b")
        assert att.select([early, late]).current is late
        assert att.select([late, early]).current is late

    def test_byte_identical_revisions_count_once(self):
        r = self._rev(2)
        chosen = att.select([r, r])
        assert chosen.superseded == ()

    def test_revisions_that_disagree_on_serial_are_refused(self):
        with pytest.raises(AttestationRefused, match="disagree on serialNumber"):
            att.select([self._rev(1, serial="urn:uuid:a"), self._rev(2, serial="urn:uuid:b")])

    def test_nothing_verified_is_refused(self):
        with pytest.raises(AttestationRefused, match="no attestation verified"):
            att.select([])


class TestPipelineOnTheRecordedAttestations:
    """req-github-core-sbom-attestations-4, -6, -7 and -9 against the real revisions 1 and 2."""

    @pytest.fixture(scope="class")
    def outcome(self):
        verifier = RecordedVerifier({DIGEST: recorded_results()})
        return run_pipeline(_config(), SIGNERS, verifier), verifier

    def test_revision_two_is_current_and_revision_one_is_lineage_only(self, outcome):
        result, verifier = outcome
        (s,) = result.subjects
        assert (s.status, s.current_version, s.current_signer, s.superseded_versions, s.superseded_unscanned) == (
            STATED, 2, "tap-sbom-evidence-5736329d", (1,), 1,
        )
        assert sorted(verifier.calls) == sorted([(DIGEST, PUBLISH.id), (DIGEST, EVIDENCE.id)])

    def test_the_mapping_is_the_one_pr_225_pins(self, outcome):
        result, _ = outcome
        g = result.grift
        assert (g.findings_open, g.findings_resolved, g.vulnerabilities, g.scanners) == (94, 0, 27, 1)
        direct = sbom_vulnerability_grift(
            [parse_cyclonedx_vulnerabilities(REV2_PREDICATE.read_bytes(), verification=Verification("verified", signer=EVIDENCE.identity))]
        )
        batch, expected = g.document["batches"][0], direct.document["batches"][0]
        assert len(batch["nodes"]) == len(expected["nodes"]) and len(batch["edges"]) == len(expected["edges"])

    def test_a_signer_not_on_the_list_leaves_nothing_to_read(self):
        only_publish = RecordedVerifier({DIGEST: recorded_results()})
        result = run_pipeline(_config(), (PUBLISH,), only_publish)
        (s,) = result.subjects
        assert (s.status, s.current_version) == (UNSCANNED, 1) and result.grift is None

    def test_no_signers_refuses_everything(self):
        with pytest.raises(AttestationRefused, match="no trusted signer"):
            run_pipeline(_config(), (), RecordedVerifier({DIGEST: recorded_results()}))


class TestPipelineLifecycle:
    """req-github-core-sbom-attestations-4, -6, -7 on synthetic lineages."""

    def _run(self, items, cfg_over=None, lister=None, signers=SIGNERS):
        return run_pipeline(_config(**(cfg_over or {})), signers, RecordedVerifier({DIGEST: items}), lister)

    def test_a_finding_the_newest_revision_no_longer_states_resolves(self):
        items = _items((1, None, PUBLISH), (2, [("CVE-1", "a"), ("CVE-2", "b")], EVIDENCE), (3, [("CVE-1", "a")], EVIDENCE))
        result = self._run(items)
        (s,) = result.subjects
        assert (s.current_version, s.superseded_versions, s.superseded_unscanned) == (3, (2, 1), 1)
        assert (result.grift.findings_open, result.grift.findings_resolved) == (1, 1)

    def test_a_revision_that_was_never_scanned_states_and_resolves_nothing(self):
        result = self._run(_items((1, None, PUBLISH)))
        (s,) = result.subjects
        assert (s.status, s.superseded_unscanned) == (UNSCANNED, 0) and result.grift is None
        assert any("never scanned" in n for n in s.notes)

    def test_a_clean_scan_is_a_document_with_an_empty_array_and_resolves_the_earlier_findings(self):
        result = self._run(_items((2, [("CVE-1", "a")], EVIDENCE), (3, [], EVIDENCE)))
        assert (result.grift.findings_open, result.grift.findings_resolved) == (0, 1)

    def test_nothing_verified_for_a_configured_subject_is_refused_with_the_verifier_notes(self):
        verifier = RecordedVerifier({}, notes={EVIDENCE.id: "exit 1: no attestations found"})
        with pytest.raises(AttestationRefused, match="no attestation verified.*no attestations found"):
            run_pipeline(_config(), SIGNERS, verifier)

    def test_one_refused_subject_stops_the_whole_set_and_every_refusal_is_reported(self):
        other = "sha256:" + "2" * 64
        config = _config(
            subjects=[
                {"_description": "a", "image": IMAGE, "digest": DIGEST},
                {"_description": "b", "image": IMAGE, "digest": other},
            ]
        )
        good = _items((2, [("CVE-1", "a")], EVIDENCE))
        bad = [make_item(cdx(2, []), EVIDENCE, digest=other, cert={"issuer": "https://example.com"})]
        with pytest.raises(AttestationRefused) as caught:
            run_pipeline(config, SIGNERS, RecordedVerifier({DIGEST: good, other: bad}))
        assert "issuer" in str(caught.value) and "different" not in str(caught.value)

    def test_unverified_attestations_are_counted_and_never_read(self):
        items = _items((2, [("CVE-1", "a")], EVIDENCE))
        result = self._run(items, lister=CountingLister({DIGEST: 3}))
        (s,) = result.subjects
        assert (s.listed, s.verified, s.unverified) == (3, 1, 2)

    def test_abort_policy_refuses_when_listed_exceeds_verified(self):
        items = _items((2, [("CVE-1", "a")], EVIDENCE))
        with pytest.raises(AttestationRefused, match="on_unverified_attestation is abort"):
            self._run(items, {"on_unverified_attestation": "abort"}, CountingLister({DIGEST: 2}))
        assert self._run(items, {"on_unverified_attestation": "abort"}, CountingLister({DIGEST: 1})).grift is not None

    def test_a_listing_that_could_not_be_read_is_unobserved_not_zero(self):
        result = self._run(_items((2, [], EVIDENCE)), lister=CountingLister({DIGEST: None}))
        (s,) = result.subjects
        assert s.listed is None and s.unverified is None and any("403" in n for n in s.notes)

    def test_a_cut_short_listing_says_its_count_is_a_floor(self):
        result = self._run(_items((2, [], EVIDENCE)), lister=CountingLister({DIGEST: 5}, complete=False))
        assert any("floor" in n for n in result.subjects[0].notes)

    def test_a_corrupt_scanned_document_is_not_swallowed(self):
        bad = cdx(2, [])
        bad["vulnerabilities"] = "not-a-list"
        with pytest.raises(AttestationRefused, match="cannot be read"):
            run_pipeline(_config(), SIGNERS, RecordedVerifier({DIGEST: [make_item(bad, EVIDENCE)]}))


class TestGhCliVerifier:
    """req-github-core-sbom-attestations-10: the command is tap's own, the token travels in the environment only."""

    def _script(self, tmp_path: Path, body: str) -> str:
        path = tmp_path / "gh"
        path.write_text(f"#!/bin/sh\n{body}\n")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return str(path)

    def test_the_argv_is_the_one_tap_runs_for_each_signer(self, tmp_path):
        v = GhCliVerifier(token="tk-9f3", executable="/usr/bin/gh")
        assert v.argv(SUBJECT, EVIDENCE) == [
            "/usr/bin/gh", "attestation", "verify", f"oci://{IMAGE}@{DIGEST}", "--owner", "unified-systems-com",
            "--predicate-type", "https://cyclonedx.org/bom", "--cert-identity", EVIDENCE.identity,
            "--cert-oidc-issuer", "https://token.actions.githubusercontent.com", "--format", "json",
            "--signer-digest", EVIDENCE.signer_digest,
        ]  # fmt: skip
        assert "--signer-digest" not in v.argv(SUBJECT, PUBLISH)
        assert "tk-9f3" not in " ".join(v.argv(SUBJECT, EVIDENCE))
        v.close()

    def test_json_on_stdout_is_returned_and_the_token_is_in_the_child_environment_only(self, tmp_path):
        script = self._script(tmp_path, 'test "$GH_TOKEN" = stand-in-value-two || exit 9\nprintf "[{\\"ok\\": true}]"')
        v = GhCliVerifier(token="stand-in-value-two", executable=script)
        assert v.verify(SUBJECT, EVIDENCE).items == [{"ok": True}]
        v.close()

    def test_a_failure_is_an_empty_result_with_a_scrubbed_note(self, tmp_path):
        script = self._script(tmp_path, 'echo "verification failed for $GH_TOKEN" >&2\nexit 1')
        v = GhCliVerifier(token="stand-in-value-three", executable=script)
        result = v.verify(SUBJECT, EVIDENCE)
        assert result.items == [] and "stand-in-value-three" not in result.note and "***" in result.note and result.note.startswith("exit 1")
        v.close()

    @pytest.mark.parametrize("stdout", ["not json", '{"a": 1}'])
    def test_output_that_is_not_a_list_of_results_is_unavailable_not_empty(self, tmp_path, stdout):
        script = self._script(tmp_path, f"printf '{stdout}'")
        v = GhCliVerifier(token="t", executable=script)
        with pytest.raises(VerifierUnavailable):
            v.verify(SUBJECT, EVIDENCE)
        v.close()

    def test_no_gh_and_no_token_are_unavailable(self, monkeypatch):
        monkeypatch.setenv("PATH", "/nonexistent")
        with pytest.raises(VerifierUnavailable, match="not on PATH"):
            GhCliVerifier(token="t")
        with pytest.raises(VerifierUnavailable, match="no GitHub token"):
            GhCliVerifier(token="", executable=sys.executable)

    def test_the_child_does_not_inherit_the_parents_environment(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "leak-me")
        script = self._script(tmp_path, 'test -z "$AWS_SECRET_ACCESS_KEY" || exit 7\nprintf "[]"')
        v = GhCliVerifier(token="t", executable=script)
        assert v.verify(SUBJECT, EVIDENCE) == ([], "")
        v.close()
        assert os.environ["AWS_SECRET_ACCESS_KEY"] == "leak-me"


def test_the_base64_helper_round_trips_what_check_item_reads():
    item = make_item(cdx(2, []), EVIDENCE)
    text = base64.b64decode(item["attestation"]["bundle"]["dsseEnvelope"]["payload"]).decode()
    assert json.loads(att.signed_predicate_bytes(text)) == cdx(2, [])


class TestGithubAttestationLister:
    """req-github-core-sbom-attestations-8: the count comes from the documented REST endpoint through the plugin's client."""

    class _Client:
        def __init__(self, answers: dict, complete: bool = True) -> None:
            self.answers, self.complete, self.paths = answers, complete, []
            self.last_walk_complete = True

        def get_paginated(self, path, *, params=None, item_path=None, max_pages=100):
            self.paths.append((path, params, item_path))
            answer = self.answers[path.split("/")[1]]
            if isinstance(answer, Exception):
                raise answer
            self.last_walk_complete = self.complete
            return answer

    def _lister(self, client):
        from tap_plugin.github_core.collectors.sbom_attestation_collector.lister import GithubAttestationLister

        return GithubAttestationLister(client)

    def test_an_organisation_is_asked_with_the_predicate_type_and_counted(self):
        client = self._Client({"orgs": [{}, {}, {}]})
        listing = self._lister(client).count(SUBJECT)
        assert (listing.total, listing.complete) == (3, True)
        assert client.paths == [
            (f"/orgs/unified-systems-com/attestations/{DIGEST}", {"predicate_type": "https://cyclonedx.org/bom", "per_page": "100"}, "attestations")
        ]

    def test_a_404_falls_back_to_the_user_endpoint(self):
        from tap_plugin.github_core.collectors.sbom_attestation_collector.lister import GithubAPIError

        client = self._Client({"orgs": GithubAPIError(404, "u", "{}"), "users": [{}]})
        assert self._lister(client).count(SUBJECT).total == 1

    def test_a_refusal_is_unobserved_not_zero(self):
        from tap_plugin.github_core.collectors.sbom_attestation_collector.lister import GithubAPIError

        listing = self._lister(self._Client({"orgs": GithubAPIError(403, "u", "{}")})).count(SUBJECT)
        assert listing.total is None and "403" in listing.note

    def test_a_walk_cut_short_is_marked_incomplete(self):
        assert self._lister(self._Client({"orgs": [{}]}, complete=False)).count(SUBJECT).complete is False
