"""SBOM vulnerabilities land as compliance nodes (req-github-core-sbom-vulnerabilities).

`fixtures/sbom-tap-web-rev3-a9149a88.cdx.json` is revision 3 of the attested tap-web SBOM, byte for byte the
predicate `gh attestation verify` returned for image `sha256:a9149a88...` (signed by
`sbom-vulnerability-evidence.yml@e9841198`): 192 components, 94 vulnerability entries naming 27 ids, now with
title, publication time and advisory links. `fixtures/sbom-tap-web-rev2-a9149a88.cdx.json` is the earlier
revision 2 (none of those three), kept to show an absent fact stays absent. Every number
asserted here can be re-read from it. Cases the real document cannot show (a resolved finding, a VEX state)
are synthetic and labelled so.

The first half needs no database: the entry point is pure. The second half imports the document through the
GRIFT importer, after the inventory it names, and shows the edges resolve against the grid's natural keys.
"""

from __future__ import annotations

import json
import multiprocessing
import uuid
from collections import Counter
from pathlib import Path

import pytest
from tap_plugin.computing_core.sbom import (
    Verification,
    VulnerabilityBatch,
    parse_cyclonedx,
    parse_cyclonedx_vulnerabilities,
)
from tap_plugin.github_core.collectors.github_collector import identity
from tap_plugin.github_core.sbom_vulnerabilities import SbomVulnerabilityResult, sbom_vulnerability_grift

SIGNER = (
    "https://github.com/unified-systems-com/tap/.github/workflows/sbom-vulnerability-evidence.yml"
    "@5736329dff506c952b5567260dd82c51adab5d74"
)
VERIFIED = Verification("verified", signer=SIGNER)
FIXTURE = Path(__file__).parent / "fixtures" / "sbom-tap-web-rev3-a9149a88.cdx.json"
REV2 = Path(__file__).parent / "fixtures" / "sbom-tap-web-rev2-a9149a88.cdx.json"
IMAGE = "ghcr.io/unified-systems-com/tap-web"
FINDING = "compliance_core__compliance_finding"
VULNERABILITY = "compliance_core__compliance_vulnerability"
SCANNER = "compliance_core__compliance_scanner"
CONCERNS = "CONCERNS_COMPLIANCE_VULNERABILITY__compliance_core"
CARRIES = "CARRIES_COMPLIANCE_FINDING__compliance_core"
DETECTS = "DETECTS_COMPLIANCE_FINDING__compliance_core"
HOST = str(uuid.UUID("01a13c38-4f5e-735c-9cf2-1f159f4282b6"))


@pytest.fixture(scope="module")
def raw() -> bytes:
    return FIXTURE.read_bytes()


@pytest.fixture(scope="module")
def parsed(raw: bytes) -> VulnerabilityBatch:
    return parse_cyclonedx_vulnerabilities(raw, verification=VERIFIED)


@pytest.fixture(scope="module")
def result(parsed: VulnerabilityBatch) -> SbomVulnerabilityResult:
    return sbom_vulnerability_grift([parsed])


def _batch(document: dict) -> VulnerabilityBatch:
    return parse_cyclonedx_vulnerabilities(json.dumps(document).encode(), verification=VERIFIED)


def _nodes(result: SbomVulnerabilityResult, entity_type: str) -> list[dict]:
    return [n for n in result.document["batches"][0]["nodes"] if n["entity"]["entity_type"] == entity_type]


def _edges(result: SbomVulnerabilityResult, edge_type: str) -> list[dict]:
    return [e for e in result.document["batches"][0]["edges"] if e["edge"]["edge_type"] == edge_type]


def _findings(result: SbomVulnerabilityResult) -> dict[str, dict]:
    return {n["node"]["source_key"]: n["node"] for n in _nodes(result, FINDING)}


def _synthetic(vulns: list[tuple[str, str]], **meta) -> dict:
    """A small scanned document: (vulnerability id, component name) pairs, each component at version 1."""
    names = sorted({c for _, c in vulns})
    components = [
        {
            "bom-ref": f"pkg:apk/wolfi/{n}@1",
            "type": "library",
            "name": n,
            "version": "1",
            "purl": f"pkg:apk/wolfi/{n}@1",
        }
        for n in names
    ] or [{"bom-ref": "x", "type": "library", "name": "x", "version": "1", "purl": "pkg:apk/wolfi/x@1"}]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": meta.get("revision", 2),
        "serialNumber": meta.get("serial", "urn:uuid:90f083a0-a7b6-4183-a41d-ad1bb111feeb"),
        "metadata": {
            "timestamp": meta.get("produced", "2026-10-16T19:30:31Z"),
            "component": {"type": "container", "name": meta.get("image", IMAGE), "version": "sha256:" + "a" * 64},
        },
        "components": components,
        "vulnerabilities": [
            {
                "id": vuln_id,
                "description": f"{vuln_id} in {name}",
                "affects": [{"ref": f"pkg:apk/wolfi/{name}@1", "versions": [{"version": "1", "status": "affected"}]}],
                "tools": {"components": [{"type": "application", "name": "grype", "version": "0.120.1"}]},
                **meta.get("extra", {}),
            }
            for vuln_id, name in vulns
        ],
    }


def _spawned(function, *args):
    with multiprocessing.get_context("spawn").Pool(1) as pool:
        return pool.apply(function, args)


def _probe_django_free(path: str) -> tuple[int, list[str]]:
    """Run in a fresh interpreter: import and call the entry point with Django blocked."""
    import sys

    class _Block:
        def find_spec(self, name, path=None, target=None):
            if name == "django" or name.startswith("django."):
                raise ImportError(f"Django is blocked: {name}")

    sys.meta_path.insert(0, _Block())
    from pathlib import Path as _Path

    from tap_plugin.computing_core.sbom import Verification as _V
    from tap_plugin.computing_core.sbom import parse_cyclonedx_vulnerabilities as _parse
    from tap_plugin.github_core.sbom_vulnerabilities import sbom_vulnerability_grift as _grift

    out = _grift([_parse(_Path(path).read_bytes(), verification=_V("verified", signer="x/y/z.yml@abc"))])
    return len(out.document["batches"][0]["nodes"]), [
        m for m in sys.modules if m == "django" or m.startswith("django.")
    ]


class TestPureAndDjangoFree:
    """req-github-core-sbom-vulnerabilities-1."""

    @pytest.mark.spec("req-github-core-sbom-vulnerabilities-1")
    def test_the_entry_point_imports_and_runs_with_django_blocked(self):
        nodes, django_modules = _spawned(_probe_django_free, str(FIXTURE))
        assert nodes == 27 + 94 + 1  # vulnerabilities, findings, the one scanner
        assert django_modules == []

    @pytest.mark.spec("req-github-core-sbom-vulnerabilities-1")
    def test_the_same_documents_give_the_same_graph(self, parsed):
        first = sbom_vulnerability_grift([parsed])
        second = sbom_vulnerability_grift([parsed])
        strip = lambda r: {  # noqa: E731 - the batch entity id and collection time are fresh per call
            "nodes": r.document["batches"][0]["nodes"],
            "edges": r.document["batches"][0]["edges"],
        }
        assert strip(first) == strip(second)


class TestTheRealDocument:
    """req-github-core-sbom-vulnerabilities-2 to -7, over the real revision 2."""

    @pytest.mark.spec("req-github-core-sbom-vulnerabilities-2")
    def test_the_counts(self, result):
        assert (result.findings_open, result.findings_resolved) == (94, 0)
        assert (result.vulnerabilities, result.scanners) == (27, 1)
        assert Counter(n["entity"]["entity_type"] for n in result.document["batches"][0]["nodes"]) == {
            FINDING: 94,
            VULNERABILITY: 27,
            SCANNER: 1,
        }
        assert Counter(e["edge"]["edge_type"] for e in result.document["batches"][0]["edges"]) == {
            CONCERNS: 94,
            CARRIES: 94,
            DETECTS: 94,
        }

    @pytest.mark.spec("req-github-core-sbom-vulnerabilities-2")
    def test_a_vulnerability_node_is_keyed_by_its_id_alone_and_carries_what_the_sbom_observed(self, result):  # noqa: E501
        node = next(n for n in _nodes(result, VULNERABILITY) if n["node"]["vuln_id"] == "CVE-2025-15367")
        assert node["entity"]["name"] == "CVE-2025-15367"
        assert node["entity"]["dimensions"] == {"compliance": "vulnerability"}
        assert node["node"] == {
            "vuln_id": "CVE-2025-15367",
            "aliases": [],
            "title": "POP3 command injection in user-controlled commands",
            "description": (
                "The poplib module, when passed a user-controlled command, can have\n"
                "additional commands injected using newlines. Mitigation rejects commands\n"
                "containing control characters."
            ),
            "published_at": "2026-01-20T21:47:09.885Z",
            "record_url": "https://www.cve.org/CVERecord?id=CVE-2025-15367",
            "cvss_score": 5.9,
            "cvss_version": "4.0",
            "cvss_source": "PSF",
            "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N",
            "cwes": ["CWE-77"],
            "ssvc_exploitation": "none",
            "ssvc_automatable": "no",
            "ssvc_technical_impact": "total",
            "ssvc_assessed_at": "2026-01-22T04:55:33.480214Z",
            "kev": False,
            "kev_catalog_version": "2026.10.16",
            "epss_score": 0.00377,
            "epss_percentile": 0.30112,
            "epss_date": "2026-10-18",
            "record_updated_at": "2026-02-26T14:44:41.341Z",
        }

    @pytest.mark.spec("req-github-core-sbom-vulnerabilities-2")
    def test_nothing_the_sbom_does_not_carry_is_written_as_a_blank(self, result):
        for node in _nodes(result, VULNERABILITY):
            assert all(value is not None for value in node["node"].values())
        ghsa = [n for n in _nodes(result, VULNERABILITY) if n["node"]["vuln_id"].startswith("GHSA-")]
        assert len(ghsa) == 5
        for node in ghsa:
            assert not {k for k in node["node"] if k.startswith(("ssvc_", "epss_"))}

    @pytest.mark.spec("req-github-core-sbom-vulnerabilities-2")
    def test_every_vulnerability_has_a_title_a_publication_time_and_a_record_link(self, result):
        nodes = _nodes(result, VULNERABILITY)
        assert len(nodes) == 27
        for field in ("title", "published_at", "record_url", "description", "record_updated_at"):
            assert sum(field in n["node"] for n in nodes) == 27, field
        ghsa = next(n for n in nodes if n["node"]["vuln_id"] == "GHSA-fmf4-pr35-46c2")
        assert ghsa["node"]["record_url"] == "https://github.com/advisories/GHSA-fmf4-pr35-46c2"
        assert ghsa["node"]["published_at"] == "2026-09-22T18:33:29Z"

    @pytest.mark.spec("req-github-core-sbom-vulnerabilities-2")
    def test_revision_two_has_none_of_the_three_so_the_node_has_none(self):
        out = sbom_vulnerability_grift([parse_cyclonedx_vulnerabilities(REV2.read_bytes(), verification=VERIFIED)])
        for node in _nodes(out, VULNERABILITY):
            assert not set(node["node"]) & {"title", "published_at", "record_url"}

    @pytest.mark.spec("req-github-core-sbom-vulnerabilities-3")
    def test_a_finding_is_keyed_by_source_and_an_sbom_scoped_key(self, result):
        findings = _findings(result)
        assert len(findings) == 94
        for key, fields in findings.items():
            assert fields["source"] == "github_core"
            assert key.startswith(f"{IMAGE}#sbom#")
            assert fields["status"] == "open"
            assert fields["name"]
        sample = "ghcr.io/unified-systems-com/tap-web#sbom#CVE-2025-15367#apk/python-3.14@3.14.8_git20261001-r0"
        assert sample in findings
        assert findings[sample]["name"] == "CVE-2025-15367 python-3.14 3.14.8_git20261001-r0"

    @pytest.mark.spec("req-github-core-sbom-vulnerabilities-3")
    def test_an_sbom_key_can_never_equal_an_alert_key(self, result):
        alert_keys = {
            identity.dependabot_finding_source_key("unified-systems-com/tap", 7),
            identity.code_scanning_finding_source_key("unified-systems-com/tap", 7),
        }
        assert not alert_keys & set(_findings(result))
        assert all(identity.SBOM_SURFACE in key.split("#")[1:2] for key in _findings(result))

    @pytest.mark.spec("req-github-core-sbom-vulnerabilities-3")
    def test_every_finding_concerns_one_vulnerability_and_is_carried_and_detected(self, result):
        refs = {n["entity"]["ref"]: n for n in _nodes(result, FINDING)}
        for edge_type, end in ((CONCERNS, "from_ref"), (CARRIES, "to_ref"), (DETECTS, "to_ref")):
            per_finding = Counter(e["edge"][end] for e in _edges(result, edge_type))
            assert set(per_finding) == set(refs)
            assert set(per_finding.values()) == {1}
        vulnerabilities = {n["entity"]["ref"] for n in _nodes(result, VULNERABILITY)}
        assert {e["edge"]["to_ref"] for e in _edges(result, CONCERNS)} <= vulnerabilities

    @pytest.mark.spec("req-github-core-sbom-vulnerabilities-4")
    def test_the_component_is_named_by_natural_key_and_never_created(self, result):
        assert not [
            n for n in result.document["batches"][0]["nodes"] if n["entity"]["entity_type"].startswith("computing_core")
        ]
        ends = {json.dumps(e["edge"]["from_key"], sort_keys=True) for e in _edges(result, CARRIES)}
        assert len(ends) == len(result.components) == 13  # 12 packages and the openssl-fips-provider library
        for edge in _edges(result, CARRIES):
            end = edge["edge"]["from_key"]
            assert set(end) == {"entity_type", "key"}
            assert end["entity_type"] in ("computing_core__package", "computing_core__library")
            assert set(end["key"]) == {"ecosystem", "name", "version"}
        libraries = [e for e in _edges(result, CARRIES) if e["edge"]["from_key"]["entity_type"].endswith("library")]
        assert len(libraries) == 13

    @pytest.mark.spec("req-github-core-sbom-vulnerabilities-5")
    def test_the_scanner_is_an_install_not_a_version(self, result):
        (scanner,) = _nodes(result, SCANNER)
        assert scanner["node"] == {
            "source": "github_core",
            "scanner_key": "grype#unified-systems-com/tap/.github/workflows/sbom-vulnerability-evidence.yml",
            "name": "Grype",
            "locator": "unified-systems-com/tap/.github/workflows/sbom-vulnerability-evidence.yml",
        }
        assert "0.120.1" not in json.dumps(scanner)
        for edge in _edges(result, DETECTS):
            assert edge["edge"]["properties"] == {"category": IMAGE, "tool_version": "0.120.1"}

    @pytest.mark.spec("req-github-core-sbom-vulnerabilities-6")
    def test_fixed_versions_ride_the_edge_and_an_unknown_fix_is_absent(self, result):
        by_state = Counter("fixed_versions" in e["edge"]["properties"] for e in _edges(result, CONCERNS))
        assert by_state == {True: 67, False: 27}
        fixed = next(e for e in _edges(result, CONCERNS) if e["edge"]["properties"].get("fixed_versions"))
        assert all(isinstance(v, str) for v in fixed["edge"]["properties"]["fixed_versions"])


class TestTheLifecycle:
    """req-github-core-sbom-vulnerabilities-7. Synthetic: the real document is one revision."""

    @pytest.mark.spec("req-github-core-sbom-vulnerabilities-7")
    def test_a_finding_that_leaves_a_newer_revision_is_resolved_and_kept(self):
        older = _batch(_synthetic([("CVE-2026-0001", "a"), ("CVE-2026-0002", "b")], revision=2))
        newer = _batch(_synthetic([("CVE-2026-0001", "a")], revision=3, produced="2026-10-17T00:00:00Z"))
        out = sbom_vulnerability_grift([newer], [older])
        statuses = {k.split("#sbom#")[1]: f["status"] for k, f in _findings(out).items()}
        assert statuses == {"CVE-2026-0001#apk/a@1": "open", "CVE-2026-0002#apk/b@1": "resolved"}
        assert (out.findings_open, out.findings_resolved) == (1, 1)
        resolved = next(f for f in _findings(out).values() if f["status"] == "resolved")
        assert "CVE-2026-0002 in b" in resolved["description"]  # the fields it had, not a stub

    @pytest.mark.spec("req-github-core-sbom-vulnerabilities-7")
    def test_two_revisions_of_one_serial_in_current_count_as_one_the_highest(self):
        older = _batch(_synthetic([("CVE-2026-0001", "a"), ("CVE-2026-0002", "b")], revision=2))
        newer = _batch(_synthetic([("CVE-2026-0001", "a")], revision=3))
        out = sbom_vulnerability_grift([older, newer])
        assert (out.findings_open, out.findings_resolved) == (1, 1)

    @pytest.mark.spec("req-github-core-sbom-vulnerabilities-7")
    def test_a_finding_still_stated_is_not_resolved_by_an_older_document(self):
        older = _batch(_synthetic([("CVE-2026-0001", "a")], revision=2))
        newer = _batch(_synthetic([("CVE-2026-0001", "a")], revision=3))
        out = sbom_vulnerability_grift([newer], [older])
        assert (out.findings_open, out.findings_resolved) == (1, 0)
        assert len(_findings(out)) == 1

    @pytest.mark.spec("req-github-core-sbom-vulnerabilities-7")
    def test_a_clean_scan_resolves_everything_it_replaces(self):
        older = _batch(_synthetic([("CVE-2026-0001", "a")], revision=2))
        clean = _synthetic([], revision=3)
        out = sbom_vulnerability_grift([_batch(clean)], [older])
        assert (out.findings_open, out.findings_resolved) == (0, 1)

    @pytest.mark.spec("req-github-core-sbom-vulnerabilities-7")
    def test_a_vex_statement_that_the_component_is_not_exposed_resolves_the_finding(self):
        document = _synthetic([("CVE-2026-0001", "a")], extra={"analysis": {"state": "not_affected"}})
        out = sbom_vulnerability_grift([_batch(document)])
        assert (out.findings_open, out.findings_resolved) == (0, 1)

    @pytest.mark.spec("req-github-core-sbom-vulnerabilities-7")
    def test_findings_of_another_image_are_untouched(self):
        other = _batch(_synthetic([("CVE-2026-0009", "z")], image="ghcr.io/unified-systems-com/tap-db"))
        mine = _batch(_synthetic([("CVE-2026-0001", "a")]))
        with pytest.raises(ValueError, match="no current document of the same image"):
            sbom_vulnerability_grift([mine], [other])

    @pytest.mark.spec("req-github-core-sbom-vulnerabilities-7")
    def test_the_same_weakness_in_two_images_is_two_findings_and_one_vulnerability(self):
        one = _batch(_synthetic([("CVE-2026-0001", "a")], serial="urn:uuid:11111111-1111-4111-8111-111111111111"))
        two = _batch(
            _synthetic(
                [("CVE-2026-0001", "a")],
                image="ghcr.io/unified-systems-com/tap-db",
                serial="urn:uuid:22222222-2222-4222-8222-222222222222",
            )
        )
        out = sbom_vulnerability_grift([one, two])
        assert len(_findings(out)) == 2
        assert len(_nodes(out, VULNERABILITY)) == 1


class TestRefusals:
    """req-github-core-sbom-vulnerabilities-8."""

    @pytest.mark.spec("req-github-core-sbom-vulnerabilities-8")
    def test_no_current_document_is_refused(self):
        with pytest.raises(ValueError, match="no current document"):
            sbom_vulnerability_grift([])

    @pytest.mark.spec("req-github-core-sbom-vulnerabilities-8")
    def test_a_document_that_names_no_image_is_refused(self):
        document = _synthetic([("CVE-2026-0001", "a")])
        del document["metadata"]["component"]
        with pytest.raises(ValueError, match="names no image"):
            sbom_vulnerability_grift([_batch(document)])

    @pytest.mark.spec("req-github-core-sbom-vulnerabilities-8")
    @pytest.mark.parametrize("not_a_batch", [None, {}, b"{}", "doc"])
    def test_anything_but_a_parsed_batch_is_refused(self, not_a_batch):
        with pytest.raises(ValueError, match="VulnerabilityBatch"):
            sbom_vulnerability_grift([not_a_batch])  # type: ignore[list-item]

    @pytest.mark.spec("req-github-core-sbom-vulnerabilities-8")
    def test_an_unverified_document_never_reaches_this_module(self, raw):
        """The gate is computing_core's: there is no batch to hand over for a document that did not verify."""
        with pytest.raises(ValueError, match="is not parsed"):
            parse_cyclonedx_vulnerabilities(raw, verification=Verification("refused", "signer-identity"))


# --- through the importer -----------------------------------------------------------------------------


def _import(document: dict, mode: str = "strict"):
    from tap_grid.grift import grift_import

    return grift_import(document, dangling_edge_mode=mode)


def _inventory(raw: bytes) -> None:
    from tap_grid.grift import grift_import
    from tap_grid.services import create_node

    host = create_node("computing_core__host", {"realm": "assert", "stable_id": "tap-web-image", "kind": "container"})
    assert host.success, host.errors
    batch = parse_cyclonedx(raw, host_id=str(host.entity_id), verification=VERIFIED)
    result = grift_import(
        {
            "metadata": {"grift_version": "0"},
            "_reserved": {},
            "batches": [batch.as_grift_batch(str(uuid.uuid4()), name="inventory", source="test")],
        }
    )
    assert result.success, [e.message for e in result.errors[:5]]


def _live_edges(edge_type: str) -> int:
    from tap_grid.models import Edge

    return Edge.objects.filter(edge_type=edge_type, entity__deleted_at__isnull=True).count()


@pytest.mark.django_db
class TestThroughTheImporter:
    """req-github-core-sbom-vulnerabilities-9: the document is loadable and idempotent."""

    @pytest.mark.spec("req-github-core-sbom-vulnerabilities-9")
    def test_it_lands_against_the_inventory_it_names(self, raw, result):
        from tap_grid.registry import get_model_class

        _inventory(raw)
        imported = _import(result.document)
        assert imported.success, [e.message for e in imported.errors[:5]]
        assert get_model_class(FINDING).objects.count() == 94
        assert get_model_class(VULNERABILITY).objects.count() == 27
        assert get_model_class(SCANNER).objects.count() == 1
        assert (_live_edges(CONCERNS), _live_edges(CARRIES), _live_edges(DETECTS)) == (94, 94, 94)
        finding = get_model_class(FINDING).objects.get(
            source="github_core",
            source_key="ghcr.io/unified-systems-com/tap-web#sbom#CVE-2025-15367#apk/python-3.14@3.14.8_git20261001-r0",
        )
        assert finding.status == "open"
        vulnerability = get_model_class(VULNERABILITY).objects.get(vuln_id="CVE-2025-15367")
        assert (vulnerability.cvss_score, vulnerability.kev, vulnerability.title) == (
            5.9,
            False,
            "POP3 command injection in user-controlled commands",
        )
        assert vulnerability.record_url == "https://www.cve.org/CVERecord?id=CVE-2025-15367"

    @pytest.mark.spec("req-github-core-sbom-vulnerabilities-9")
    def test_the_page_traversals_find_the_findings(self, raw, result):
        """The shape the playground pages read: component -> finding -> vulnerability, host -> package -> finding."""
        from tap_grid.models import Edge

        _inventory(raw)
        assert _import(result.document).success
        carried = Edge.objects.filter(edge_type=CARRIES, entity__deleted_at__isnull=True)
        finding_ids = {str(e.to_entity_id) for e in carried}
        concerned = Edge.objects.filter(edge_type=CONCERNS, from_entity_id__in=finding_ids)
        assert concerned.count() == 94
        installs = {str(e.to_entity_id) for e in Edge.objects.filter(edge_type="INSTALLS_PACKAGE__computing_core")}
        packages = {str(e.from_entity_id) for e in carried} & installs
        assert len(packages) == 12  # every carrying package is one the host installs

    @pytest.mark.spec("req-github-core-sbom-vulnerabilities-9")
    def test_importing_again_adds_nothing(self, raw, result):
        from tap_grid.models import Edge, Entity

        _inventory(raw)
        assert _import(result.document).success
        entities, edges = Entity.objects.count(), Edge.objects.count()
        assert _import(result.document).success
        assert (Entity.objects.count() - 1, Edge.objects.count()) == (entities, edges)  # +1: the second batch entity

    @pytest.mark.spec("req-github-core-sbom-vulnerabilities-9")
    def test_a_resolution_updates_the_finding_it_does_not_add_one(self, raw):
        from tap_grid.registry import get_model_class

        older = _batch(_synthetic([("CVE-2026-0001", "a"), ("CVE-2026-0002", "b")], revision=2))
        newer = _batch(_synthetic([("CVE-2026-0001", "a")], revision=3))
        _inventory(raw)
        assert _import(sbom_vulnerability_grift([older]).document, "permissive").success
        assert get_model_class(FINDING).objects.filter(status="open").count() == 2
        assert _import(sbom_vulnerability_grift([newer], [older]).document, "permissive").success
        findings = get_model_class(FINDING).objects
        assert findings.count() == 2
        assert findings.filter(status="open").count() == 1
        assert findings.get(status="resolved").source_key.endswith("#CVE-2026-0002#apk/b@1")

    @pytest.mark.spec("req-github-core-sbom-vulnerabilities-4")
    def test_a_component_not_on_the_grid_fails_strict_and_skips_one_edge_when_permissive(self, result):
        from tap_grid.registry import get_model_class

        strict = _import(result.document, "strict")
        assert not strict.success
        assert any(e.code == "dangling_edge" for e in strict.errors)
        assert get_model_class(FINDING).objects.count() == 0  # atomic: nothing landed
        permissive = _import(result.document, "permissive")
        assert permissive.success, [e.message for e in permissive.errors[:5]]
        assert get_model_class(FINDING).objects.count() == 94
        assert _live_edges(CARRIES) == 0
        assert (_live_edges(CONCERNS), _live_edges(DETECTS)) == (94, 94)

    @pytest.mark.spec("req-github-core-sbom-vulnerabilities-2")
    def test_every_field_written_is_a_declared_field_of_the_model(self, result):
        from tap_grid.registry import get_model_class

        for entity_type in (FINDING, VULNERABILITY, SCANNER):
            declared = set(get_model_class(entity_type).FIELD_CRUD_SCHEMA)
            for node in _nodes(result, entity_type):
                assert set(node["node"]) <= declared, (entity_type, set(node["node"]) - declared)
