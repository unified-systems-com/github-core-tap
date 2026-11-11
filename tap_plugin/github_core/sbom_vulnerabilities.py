"""Write the vulnerabilities of verified SBOMs onto the compliance substrate (req-github-core-sbom-vulnerabilities).

``sbom_vulnerability_grift(current, superseded=())`` takes what computing_core's
``parse_cyclonedx_vulnerabilities`` read from CI-signed, CI-scanned CycloneDX documents and returns a
GRIFT document of ``compliance_core`` nodes and edges: one ``compliance_vulnerability`` per public id,
one ``compliance_finding`` per (image, vulnerability, component), one ``compliance_scanner`` per install of
the detecting tool, and the edges that tie them to each other and to the ``computing_core`` package,
library or operating-system node the SBOM names.

It is the entry point a collector calls. It imports no Django, opens no file or socket and obtains no
document: the caller verifies an attestation, reads the bytes and hands over the parsed batches
(computing_core owns that logic; this module owns the compliance vocabulary it lands in).

**Identity.** A finding is ``("github_core", "<image>#sbom#<vuln_id>#<ecosystem>/<name>@<version>")``; the
``#sbom#`` segment keeps it apart from the repository-scoped keys of Dependabot and code-scanning findings
(``identity.sbom_finding_source_key``). A vulnerability is its ``vuln_id`` alone, so it is the same node the
alert-sourced findings point at. The component is named by a GRIFT ``from_key`` endpoint on its natural
key, never by an id: the importer finds the live row or, in permissive mode, skips that one edge and says
so. Nothing here creates a package.

**Lifecycle.** A finding present in a ``current`` document is ``open`` (``resolved`` when the document's own
VEX ``analysis`` says the component is not exposed). A finding present in a ``superseded`` document and in no
``current`` one is ``resolved``, rewritten with the fields it had; nothing is ever deleted. The caller names
which documents are which, because only it knows the deployed set: this module reads no grid.

**Absent is not written.** A fact the SBOM does not carry (SSVC of an id with no CVE record; title, publication
time and record URL in a revision-2 document) is left out of the node, not written as a blank. Revision 3 and
later carry title, publication time and the record link; the record link is the CVE Record, else the advisory.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from tap_plugin.computing_core.sbom import (
    ComponentKey,
    VulnerabilityBatch,
    VulnerabilityMatch,
    VulnerabilityRecord,
)
from tap_plugin.github_core.collectors.github_collector.batch import assemble_batch
from tap_plugin.github_core.collectors.github_collector.identity import (
    COMPLIANCE_FINDING_SOURCE,
    Ref,
    sbom_finding_id,
    sbom_finding_source_key,
    sbom_scanner_id,
    sbom_scanner_key,
    sbom_vulnerability_id,
)

FINDING = "compliance_core__compliance_finding"
VULNERABILITY = "compliance_core__compliance_vulnerability"
SCANNER = "compliance_core__compliance_scanner"
CONCERNS = "CONCERNS_COMPLIANCE_VULNERABILITY__compliance_core"
CARRIES = "CARRIES_COMPLIANCE_FINDING__compliance_core"
DETECTS = "DETECTS_COMPLIANCE_FINDING__compliance_core"

_FINDING_DIMS = {"compliance": "finding"}
_VULNERABILITY_DIMS = {"compliance": "vulnerability"}
_SCANNER_DIMS = {"compliance": "scanner"}

#: compliance_core's column limits, restated because its models are another plugin's (a value over one is
#: shortened, never refused: the model would refuse the whole batch).
_NAME_MAX = 255
_SUMMARY_MAX = 500
_SOURCE_KEY_MAX = 512


@dataclass(frozen=True)
class SbomVulnerabilityResult:
    """The GRIFT document and what is in it, so a caller can report without re-reading it."""

    document: dict[str, Any]
    findings_open: int
    findings_resolved: int
    vulnerabilities: int
    scanners: int
    components: tuple[ComponentKey, ...]
    """The nodes the carrier edges name by key; the importer reports any it cannot find (a component not on the grid)."""
    notes: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class _Finding:
    key: str
    image: str
    match: VulnerabilityMatch
    status: str
    doc_order: tuple[str, str]


def _locator(signer: str) -> str:
    """The verified signer's workflow path without its host and ref: where the scanner is installed."""
    text = signer.removeprefix("https://github.com/").removeprefix("http://github.com/")
    return text.split("@", 1)[0] or "unknown-signer"


def _rank(batch: VulnerabilityBatch) -> tuple[str, str]:
    return (batch.document.produced_at or "", batch.document.content_digest)


def _image(batch: VulnerabilityBatch) -> str:
    name = batch.document.subject_name
    if not name:
        raise ValueError(
            f"document {batch.document.content_digest[:12]} names no image (metadata.component.name), so "
            f"its findings have nothing to be scoped to"
        )
    return name


def _serial(batch: VulnerabilityBatch) -> str:
    return batch.document.serial_number or f"digest:{batch.document.content_digest}"


def _newest_revision_per_serial(
    batches: Sequence[VulnerabilityBatch],
) -> tuple[list[VulnerabilityBatch], list[VulnerabilityBatch]]:
    """Split into the highest revision of each serial number and the older revisions of the same serials."""
    newest: dict[str, VulnerabilityBatch] = {}
    ordered = sorted(batches, key=lambda b: (b.document.revision, _rank(b)))
    for batch in ordered:
        newest[_serial(batch)] = batch
    keep = {id(b) for b in newest.values()}
    return [b for b in ordered if id(b) in keep], [b for b in ordered if id(b) not in keep]


def _findings(batches: Sequence[VulnerabilityBatch]) -> dict[str, _Finding]:
    """Every finding the batches state, the most recently produced document winning where two state one."""
    found: dict[str, _Finding] = {}
    for batch in sorted(batches, key=_rank):
        image = _image(batch)
        for match in batch.matches:
            key = sbom_finding_source_key(image, match.vuln_id, match.component.label)
            if len(key) > _SOURCE_KEY_MAX:
                raise ValueError(
                    f"the finding key for {match.vuln_id} on {match.component.label} is over {_SOURCE_KEY_MAX} characters"
                )
            status = "open" if match.exposed else "resolved"
            found[key] = _Finding(key=key, image=image, match=match, status=status, doc_order=_rank(batch))
    return found


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _finding_fields(finding: _Finding, record: VulnerabilityRecord | None) -> dict[str, Any]:
    match = finding.match
    component = match.component
    description = (record.description if record else None) or ""
    if match.fixed_versions:
        fix = "fixed in " + ", ".join(match.fixed_versions)
    elif match.fixed_versions == ():
        fix = "no fix is available"
    else:
        fix = "no fix is known"
    where = f"{finding.image}: {component.label}; {fix}"
    return {
        "source": COMPLIANCE_FINDING_SOURCE,
        "source_key": finding.key,
        "name": _clip(f"{match.vuln_id} {component.name} {component.version}".strip(), _NAME_MAX),
        "summary": _clip(description.strip().splitlines()[0], _SUMMARY_MAX) if description.strip() else "",
        "description": "\n\n".join(p for p in (description.strip(), where) if p),
        "status": finding.status,
    }


def _vulnerability_fields(record: VulnerabilityRecord) -> dict[str, Any]:
    """The compliance_vulnerability fields the record observed (``req-github-core-sbom-vulnerabilities-2``).

    A fact the record does not carry is absent from the node, not blank. There is one deliberate exception,
    **GROUP NULLS** (``req-github-core-sbom-vulnerabilities-10``, ruled 2026-10-29, github-core-tap#238):

    CVSS, SSVC, KEV and EPSS are each a *group*: a block of facts that arrive together under one anchor (the
    ``cvss`` block, the ``ssvc`` block, a KEV answer with ``listed`` set, the ``epss`` block). When the anchor
    is present, EVERY member of its group is written, and a member the record gives no value for is written
    as an explicit ``None``. When the anchor is absent, no member of the group is written.

    Why: an import of a node that already exists leaves an absent field alone (unified-systems-com/tap#1128).
    So a CVE once listed in CISA's KEV catalog and later delisted, sent as ``kev = False`` with its date, due
    date and required action merely absent, would keep the old dates beside ``kev = False``. ``None`` is how
    this node says "the answer is no, so there is no date". Every field written here is nullable on the model.

    If this ever becomes a problem (a node showing null where a value was expected, or a test about "no
    None values" failing), search for ``GROUP NULLS`` and ``github-core-tap#238``: the spec row, the issue
    thread and the pull request that introduced it all carry that phrase, and so does the test that pins it.
    To go back to "absent, not null", drop the ``None`` members below and accept stale delisting details.
    """
    fields: dict[str, Any] = {"vuln_id": record.vuln_id}
    if record.aliases is not None:
        fields["aliases"] = list(record.aliases)
    if record.title is not None:
        fields["title"] = record.title
    if record.description is not None:
        fields["description"] = record.description
    if record.published_at is not None:
        fields["published_at"] = record.published_at
    if record.record_url is not None:
        fields["record_url"] = record.record_url
    if record.cvss is not None:
        # GROUP NULLS (github-core-tap#238): the vector is a member of the CVSS group.
        fields["cvss_score"] = record.cvss.score
        fields["cvss_version"] = record.cvss.version
        fields["cvss_source"] = record.cvss.source
        fields["cvss_vector"] = record.cvss.vector
    if record.cwes is not None:
        fields["cwes"] = list(record.cwes)
    if record.ssvc is not None:
        # GROUP NULLS (github-core-tap#238): all four SSVC members, None where the block gives none.
        fields["ssvc_exploitation"] = record.ssvc.exploitation
        fields["ssvc_automatable"] = record.ssvc.automatable
        fields["ssvc_technical_impact"] = record.ssvc.technical_impact
        fields["ssvc_assessed_at"] = record.ssvc.assessed_at
    if record.kev is not None and record.kev.listed is not None:
        # GROUP NULLS (github-core-tap#238): a delisted CVE is `kev = False` with its dates cleared, not left
        # at whatever an earlier answer wrote. An unread catalog (`listed is None`) writes no KEV member at all.
        fields["kev"] = record.kev.listed
        fields["kev_added"] = record.kev.date_added
        fields["kev_catalog_version"] = record.kev.catalog_version
        fields["kev_due_date"] = record.kev.due_date
        fields["kev_required_action"] = record.kev.required_action
        fields["kev_ransomware_use"] = record.kev.ransomware_use
    if record.epss is not None:
        # GROUP NULLS (github-core-tap#238): score, percentile and date are written together.
        fields["epss_score"] = record.epss.score
        fields["epss_percentile"] = record.epss.percentile
        fields["epss_date"] = record.epss.date
    if record.record_updated_at is not None:
        fields["record_updated_at"] = record.record_updated_at
    return fields


def _node(
    ref: Ref, entity_type: str, name: str, dimensions: Mapping[str, str], fields: dict[str, Any]
) -> dict[str, Any]:
    return {
        "entity": {"ref": str(ref), "entity_type": entity_type, "name": name, "dimensions": dict(dimensions)},
        "node": fields,
    }


def _edge(
    edge_type: str, label: str, dimensions: Mapping[str, str], endpoints: dict[str, Any], properties: dict[str, Any]
) -> dict[str, Any]:
    return {
        "entity": {"ref": f"edge:{edge_type}:{label}", "entity_type": "edge", "dimensions": dict(dimensions)},
        "edge": {"edge_type": edge_type, **endpoints, "properties": properties},
    }


def sbom_vulnerability_grift(
    current: Sequence[VulnerabilityBatch],
    superseded: Sequence[VulnerabilityBatch] = (),
    *,
    batch_name: str = "SBOM vulnerabilities",
) -> SbomVulnerabilityResult:
    """The compliance nodes and edges that ``current`` states, and the resolutions that ``superseded`` implies.

    ``current`` are the documents that describe what is deployed now (the newest revision of each image's
    SBOM). ``superseded`` are documents already ingested earlier: a finding they state that no ``current``
    document states is written ``resolved``. Several revisions of one ``serialNumber`` may be passed in either
    list; only the highest revision of a serial counts as current, the rest are treated as superseded.

    Raises ``ValueError`` for a document that names no image, for an empty ``current``, and for a superseded
    document whose image has no current document (resolving a finding needs a scan that no longer states it,
    and a clean scan is a document with ``"vulnerabilities": []``, not an absent one).
    """
    for batch in (*current, *superseded):
        if not isinstance(batch, VulnerabilityBatch):
            raise ValueError("documents must be VulnerabilityBatch values from parse_cyclonedx_vulnerabilities")
    if not current:
        raise ValueError("no current document: there is nothing to state or to resolve against")
    # a revision passed as superseded may be newer than the one passed as current: the highest revision of
    # each serial that `current` names wins, whichever list carried it
    serials = {_serial(b) for b in current}
    revisions = [*current, *(b for b in superseded if _serial(b) in serials)]
    live, older = _newest_revision_per_serial(revisions)
    old_ones = [*older, *(b for b in superseded if _serial(b) not in serials)]
    images = {_image(b) for b in live}
    stray = sorted({_image(b) for b in old_ones} - images)
    if stray:
        raise ValueError(f"superseded documents for {stray} have no current document of the same image")

    now = _findings(live)
    before = {k: f for k, f in _findings(old_ones).items() if k not in now}
    findings = {**before, **now}
    notes: list[str] = []
    for key, old in before.items():
        findings[key] = _Finding(key=key, image=old.image, match=old.match, status="resolved", doc_order=old.doc_order)

    records: dict[str, VulnerabilityRecord] = {}
    for batch in sorted(old_ones, key=_rank):
        records.update({r.vuln_id: r for r in batch.vulnerabilities})
    for batch in sorted(live, key=_rank):
        records.update({r.vuln_id: r for r in batch.vulnerabilities})

    # the document that last stated each finding names its scanner install (the live ones win over the old)
    stated_by: dict[str, VulnerabilityBatch] = {}
    for batch in [*sorted(old_ones, key=_rank), *sorted(live, key=_rank)]:
        image = _image(batch)
        for match in batch.matches:
            stated_by[sbom_finding_source_key(image, match.vuln_id, match.component.label)] = batch

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    components: dict[tuple[str, tuple[str, str, str]], ComponentKey] = {}
    scanners: dict[tuple[str, str], Ref] = {}
    named_vulns: set[str] = set()

    for key in sorted(findings):
        finding = findings[key]
        match = finding.match
        named_vulns.add(match.vuln_id)
        finding_ref = sbom_finding_id(finding.image, match.vuln_id, match.component.label)
        fields = _finding_fields(finding, records.get(match.vuln_id))
        nodes.append(_node(finding_ref, FINDING, fields["name"], _FINDING_DIMS, fields))
        vulnerability_ref = sbom_vulnerability_id(match.vuln_id)
        concerns: dict[str, Any] = {}
        if match.fixed_versions is not None:
            concerns["fixed_versions"] = list(match.fixed_versions)
        edges.append(
            _edge(
                CONCERNS,
                f"{finding_ref}>{vulnerability_ref}",
                _VULNERABILITY_DIMS,
                {"from_ref": str(finding_ref), "to_ref": str(vulnerability_ref)},
                concerns,
            )
        )
        component = match.component
        components[(component.entity_type, component.values)] = component
        edges.append(
            _edge(
                CARRIES,
                f"{component.entity_type}:{component.label}>{finding_ref}",
                _FINDING_DIMS,
                {"from_key": {"entity_type": component.entity_type, "key": component.key}, "to_ref": str(finding_ref)},
                {},
            )
        )
        locator = _locator(stated_by[key].document.signer)
        for detector in match.detectors:
            scanner_ref = scanners.setdefault((detector.name, locator), sbom_scanner_id(detector.name, locator))
            detects: dict[str, Any] = {"category": finding.image}
            if detector.version:
                detects["tool_version"] = detector.version
            edges.append(
                _edge(
                    DETECTS,
                    f"{scanner_ref}>{finding_ref}",
                    _FINDING_DIMS,
                    {"from_ref": str(scanner_ref), "to_ref": str(finding_ref)},
                    detects,
                )
            )

    for (tool, locator), ref in sorted(scanners.items()):
        display = tool[:1].upper() + tool[1:]
        fields = {
            "source": COMPLIANCE_FINDING_SOURCE,
            "scanner_key": sbom_scanner_key(tool, locator),
            "name": display,
            "locator": locator,
        }
        nodes.append(_node(ref, SCANNER, display, _SCANNER_DIMS, fields))
    for vuln_id in sorted(named_vulns):
        record = records.get(vuln_id)
        if record is None:
            notes.append(f"{vuln_id}: matched but no record states it; written with its id only")
            fields = {"vuln_id": vuln_id}
        else:
            fields = _vulnerability_fields(record)
        nodes.append(_node(sbom_vulnerability_id(vuln_id), VULNERABILITY, vuln_id, _VULNERABILITY_DIMS, fields))

    nodes.sort(key=lambda n: (n["entity"]["entity_type"], n["entity"]["ref"]))
    edges.sort(key=lambda e: (e["edge"]["edge_type"], e["entity"]["ref"]))
    seen: set[str] = set()
    unique_edges = []
    for edge in edges:
        if edge["entity"]["ref"] not in seen:
            seen.add(edge["entity"]["ref"])
            unique_edges.append(edge)
    document = assemble_batch(
        batch_name=batch_name,
        description=(
            f"Findings, vulnerabilities and scanners stated by {len(live)} CI-signed SBOM document(s) "
            f"of {', '.join(sorted(images))}; {len(before)} earlier finding(s) no longer stated are resolved."
        ),
        nodes=nodes,
        edges=unique_edges,
        batch_dimensions={},
    )
    return SbomVulnerabilityResult(
        document=document,
        findings_open=sum(1 for f in findings.values() if f.status == "open"),
        findings_resolved=sum(1 for f in findings.values() if f.status == "resolved"),
        vulnerabilities=len(named_vulns),
        scanners=len(scanners),
        components=tuple(components[k] for k in sorted(components)),
        notes=tuple(notes),
    )
