"""Code scanning: what the scanners found, minted as findings the compliance substrate already
reads (req-github-core-code-scanning; github-core#89).

Fixtures are **captured from the live REST API**, not hand-authored. `tests/fixtures/
code_scanning_alerts.json` and `code_scanning_analyses.json` hold verbatim responses taken on
2026-09-09 with the `notgeorge` gh CLI OAuth token against `unified-systems-com/tap`: alerts
`state=open` (9, SonarCloud), `state=dismissed` (5, SonarCloud, dismissed by the Sonar bot and
later fixed too), `state=fixed` (3, Trivy CVEs on the image), and `analyses?per_page=10`
(SonarCloud and CodeQL across four commits). The 404 bodies are the verbatim answers from
`unified-systems-com/.github`, a repository that has never uploaded SARIF. Nothing was stripped.

The 403 bodies below are SYNTHETIC and labelled so: no repository this token can reach refuses
it, and GitHub's two documented 403 phrasings — a plain refusal, and one naming Advanced
Security — are the branch the classifier has to take.

What matters most is what an EMPTY answer means. Zero alerts is a fact only when the repository
says `code_scanning_observability = observed`; `not_enabled` and `unobservable` are different
absences, and neither is a clean bill.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

import pytest
import tap_plugin.github_core.models as github  # noqa: F401 — trigger model registration
from tap_plugin.github_core.collectors.github_collector.api_client import GithubAPIError
from tap_plugin.github_core.collectors.github_collector.batch import node_envelope
from tap_plugin.github_core.collectors.github_collector.collector import GithubCollector
from tap_plugin.github_core.collectors.github_collector.identity import (
    GITHUB_CORE_NAMESPACE,
    code_scanning_alert_id,
    code_scanning_analysis_id,
    code_scanning_finding_id,
    repository_id,
)

from tap_grid.grift import grift_import
from tap_grid.registry import get_model_class

from .envelopes import edge_from, edge_to, envelope_key

_FIXTURES = Path(__file__).parent / "fixtures"
_ALERTS = json.loads((_FIXTURES / "code_scanning_alerts.json").read_text())
_ANALYSES = json.loads((_FIXTURES / "code_scanning_analyses.json").read_text())
_COLLECTOR = Path(__file__).resolve().parent.parent / "collectors" / "github_collector"
_MANIFEST = json.loads((_COLLECTOR / "github_collection_manifest.json").read_text())
_LEDGER = json.loads((_COLLECTOR / "github_app_permissions.json").read_text())

_REPO = "unified-systems-com/tap"
_REPO_GITHUB_ID = 123456789
_DIMS = {
    "git.host": "github.com",
    "github.owner": "unified-systems-com",
    "github.repo": "tap",
    "github.surface": "security",
    "github.observation": "execution",
}
_ALL_ALERTS: list[dict[str, Any]] = _ALERTS["open"] + _ALERTS["dismissed"] + _ALERTS["fixed"]
_FINDING_TYPE = "compliance_core__compliance_finding"
_ALERT_TYPE = "github_core__code_scanning_alert"
_ANALYSIS_TYPE = "github_core__code_scanning_analysis"
_HAS_FINDING = "CARRIES_COMPLIANCE_FINDING__compliance_core"

#: SYNTHETIC 403 bodies (see module docstring).
_REFUSED_403 = json.dumps({"message": "Resource not accessible by integration", "status": "403"})
_GHAS_403 = json.dumps(
    {"message": "Advanced Security must be enabled for this repository to use code scanning.", "status": "403"}
)


class _FakeClient:
    """Replays the captured listings; records what was asked for; fakes the walk verdict.

    `calls` is asserted against because HOW we query is itself a requirement: alerts are walked
    without a `state` filter (one walk returns every state) and analyses are ONE page.
    """

    def __init__(
        self,
        *,
        alerts: list[dict[str, Any]] | None = None,
        analyses: list[dict[str, Any]] | None = None,
        fail: dict[str, tuple[int, str]] | None = None,
        incomplete: tuple[str, ...] = (),
    ) -> None:
        self.calls: list[tuple[str, dict[str, str], int]] = []
        self._items = {
            "alerts": list(_ALL_ALERTS) if alerts is None else alerts,
            "analyses": list(_ANALYSES["analyses"]) if analyses is None else analyses,
        }
        self._fail = fail or {}
        self._incomplete = incomplete
        self.last_walk_complete = True

    def get_paginated(
        self, path: str, params: dict[str, str] | None = None, item_path: str | None = None, max_pages: int = 100
    ) -> list[dict[str, Any]]:
        self.calls.append((path, dict(params or {}), max_pages))
        surface = path.rsplit("/", 1)[-1]
        if surface in self._fail:
            status, body = self._fail[surface]
            raise GithubAPIError(status=status, url=path, body=body)
        self.last_walk_complete = surface not in self._incomplete
        return list(self._items[surface])


def _repo_envelope() -> dict[str, Any]:
    return node_envelope(
        entity_id=repository_id(_REPO),
        entity_type="github_core__github_repository",
        name=_REPO,
        dimensions={k: v for k, v in _DIMS.items() if not k.startswith("github.surface")},
        fields={"full_name": _REPO, "github_id": _REPO_GITHUB_ID, "code_scanning_observability": ""},
    )


def _collect(
    client: _FakeClient,
    *,
    workflows: dict[str, Any] | None = None,
    commits: dict[str, Any] | None = None,
):
    """Drive the emitter alone. `__new__` rather than `__init__`: CollectorBase wants a runtime
    config we do not need. Matches test_rule_suites / test_pull_requests."""
    collector = GithubCollector.__new__(GithubCollector)
    # The indexes the joins read, seeded the way the real walk seeds them.
    collector._walk_state()["by_path"].update({(_REPO, path): wf for path, wf in (workflows or {}).items()})
    collector._commits_seen().update(commits or {})
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    warns: list[tuple[Any, ...]] = []
    infos: list[tuple[Any, ...]] = []
    collector.record_warn = lambda *a, **k: warns.append((a, k))  # type: ignore[method-assign]
    collector.record_info = lambda *a, **k: infos.append((a, k))  # type: ignore[method-assign]
    envelope = _repo_envelope()
    collector._collect_code_scanning(client, _REPO, repository_id(_REPO), envelope, _DIMS, nodes, edges)
    return envelope["node"], nodes, edges, warns, infos


def _of_type(nodes: list[dict[str, Any]], entity_type: str) -> list[dict[str, Any]]:
    return [n for n in nodes if n["entity"]["entity_type"] == entity_type]


def _edges_of(edges: list[dict[str, Any]], slug: str) -> list[dict[str, Any]]:
    return [e for e in edges if e["edge"]["edge_type"] == slug]


def _codes(events: list[tuple[Any, ...]]) -> list[str]:
    return [args[1] for args, _ in events]


def _by_number(nodes: list[dict[str, Any]], entity_type: str) -> dict[int, dict[str, Any]]:
    return {n["node"]["number"]: n for n in _of_type(nodes, entity_type)}


# ---------------------------------------------------------------------------------------------
# 1. The alert lands with its captured shape.
# ---------------------------------------------------------------------------------------------


class TestAlertShape:
    @pytest.mark.spec("req-github-core-code-scanning-1")
    def test_one_detail_node_per_alert_keyed_on_repository_and_number(self) -> None:
        _, nodes, _, _, _ = _collect(_FakeClient())
        alerts = _by_number(nodes, _ALERT_TYPE)
        assert set(alerts) == {a["number"] for a in _ALL_ALERTS}
        assert envelope_key(alerts[164]) == str(code_scanning_alert_id(_REPO, 164))
        assert alerts[164]["entity"]["dimensions"] == _DIMS

    @pytest.mark.spec("req-github-core-code-scanning-1")
    def test_the_nested_payload_is_flattened_and_kept_whole(self) -> None:
        """`rule.*`, `tool.*`, `most_recent_instance.*` become columns; the raw alert rides
        `configuration` so nothing GitHub said is lost to the flattening."""
        _, nodes, _, _, _ = _collect(_FakeClient())
        node = _by_number(nodes, _ALERT_TYPE)[164]["node"]
        captured = next(a for a in _ALERTS["open"] if a["number"] == 164)
        assert node["state"] == "open"
        assert node["rule_id"] == captured["rule"]["id"] == "pythonsecurity:S6549"
        assert node["rule_severity"] == captured["rule"]["severity"]
        assert node["rule_description"] == captured["rule"]["description"]
        assert node["rule_tags"] == captured["rule"]["tags"]
        assert node["tool_name"] == "SonarCloud"
        assert node["ref"] == captured["most_recent_instance"]["ref"]
        assert node["commit_sha"] == captured["most_recent_instance"]["commit_sha"]
        assert node["location"] == captured["most_recent_instance"]["location"]
        assert node["message"] == captured["most_recent_instance"]["message"]["text"]
        assert node["html_url"] == captured["html_url"]
        assert node["configuration"] == captured

    @pytest.mark.spec("req-github-core-code-scanning-1")
    def test_null_stays_null_and_absent_strings_are_empty(self) -> None:
        """An open alert has never been fixed or dismissed: those timestamps are null because
        GitHub said null, not because we defaulted them. Nested optional strings become `""`."""
        _, nodes, _, _, _ = _collect(_FakeClient())
        alerts = _by_number(nodes, _ALERT_TYPE)
        open_alert = alerts[164]["node"]
        assert open_alert["fixed_at"] is None and open_alert["dismissed_at"] is None
        assert open_alert["dismissed_reason"] == "" and open_alert["dismissed_by_login"] == ""
        assert open_alert["tool_version"] == "" and open_alert["tool_guid"] == ""
        dismissed = alerts[165]["node"]
        assert dismissed["dismissed_reason"] == "false positive"
        assert dismissed["dismissed_by_login"] == "sonarqubecloud[bot]"
        assert dismissed["dismissed_at"] == "2026-08-31T21:38:49Z"
        # Dismissed AND later fixed — real, and why both timestamps are columns.
        assert dismissed["fixed_at"] is not None

    @pytest.mark.spec("req-github-core-code-scanning-1")
    def test_the_registered_model_accepts_the_captured_shape(self) -> None:
        """The fields the collector emits are ones the model actually declares."""
        model = get_model_class(_ALERT_TYPE)
        declared = set(model.FIELD_CRUD_SCHEMA)
        _, nodes, _, _, _ = _collect(_FakeClient())
        emitted = set(_of_type(nodes, _ALERT_TYPE)[0]["node"])
        assert emitted <= declared, f"emitted fields not on the model: {sorted(emitted - declared)}"

    @pytest.mark.spec("req-github-core-code-scanning-1")
    def test_ids_are_stable_across_two_emits(self) -> None:
        _, first, first_edges, _, _ = _collect(_FakeClient())
        _, second, second_edges, _, _ = _collect(_FakeClient())
        assert [envelope_key(n) for n in first] == [envelope_key(n) for n in second]
        assert [envelope_key(e) for e in first_edges] == [envelope_key(e) for e in second_edges]


# ---------------------------------------------------------------------------------------------
# 2. The analysis lands with its captured shape.
# ---------------------------------------------------------------------------------------------


class TestAnalysisShape:
    @pytest.mark.spec("req-github-core-code-scanning-2")
    def test_one_node_per_analysis_with_the_flattened_shape(self) -> None:
        _, nodes, _, _, _ = _collect(_FakeClient())
        analyses = {n["node"]["analysis_id"]: n for n in _of_type(nodes, _ANALYSIS_TYPE)}
        assert set(analyses) == {a["id"] for a in _ANALYSES["analyses"]}
        captured = _ANALYSES["analyses"][1]  # CodeQL, /language:python
        node = analyses[captured["id"]]
        assert envelope_key(node) == str(code_scanning_analysis_id(_REPO, captured["id"]))
        assert node["node"]["tool_name"] == "CodeQL"
        assert node["node"]["tool_version"] == captured["tool"]["version"]
        assert node["node"]["category"] == "/language:python"
        assert node["node"]["ref"] == captured["ref"]
        assert node["node"]["commit_sha"] == captured["commit_sha"]
        assert node["node"]["results_count"] == captured["results_count"]
        assert node["node"]["rules_count"] == captured["rules_count"]
        assert node["node"]["sarif_id"] == captured["sarif_id"]
        assert node["node"]["deletable"] is True
        # GitHub returns `environment` as a JSON-encoded STRING; it is stored as given.
        assert isinstance(node["node"]["environment"], str)
        assert node["node"]["configuration"] == captured

    @pytest.mark.spec("req-github-core-code-scanning-2")
    def test_the_registered_model_accepts_the_captured_shape(self) -> None:
        model = get_model_class(_ANALYSIS_TYPE)
        declared = set(model.FIELD_CRUD_SCHEMA)
        _, nodes, _, _, _ = _collect(_FakeClient())
        emitted = set(_of_type(nodes, _ANALYSIS_TYPE)[0]["node"])
        assert emitted <= declared, f"emitted fields not on the model: {sorted(emitted - declared)}"


# ---------------------------------------------------------------------------------------------
# 3. Four states on the repository node, because three would lie.
# ---------------------------------------------------------------------------------------------


class TestFourStateObservability:
    @pytest.mark.spec("req-github-core-code-scanning-3")
    def test_never_asked_is_the_empty_string(self) -> None:
        assert _repo_envelope()["node"]["code_scanning_observability"] == ""

    @pytest.mark.spec("req-github-core-code-scanning-3")
    def test_both_listings_answering_is_observed_even_at_zero(self) -> None:
        """Zero alerts from a 200 is a FACT — and the only way zero gets to be one."""
        node, nodes, _, warns, infos = _collect(_FakeClient(alerts=[], analyses=[]))
        assert node["code_scanning_observability"] == "observed"
        assert not nodes and not warns
        assert "CODE_SCANNING_COLLECTED" in _codes(infos)

    @pytest.mark.spec("req-github-core-code-scanning-3")
    def test_a_credential_refusal_is_unobservable_with_a_warning_and_nothing_minted(self) -> None:
        """Landing zero findings on a 403 would say "nothing found" — the most reassuring
        possible reading of a permission failure."""
        node, nodes, edges, warns, _ = _collect(
            _FakeClient(fail={"alerts": (403, _REFUSED_403), "analyses": (403, _REFUSED_403)})
        )
        assert node["code_scanning_observability"] == "unobservable"
        assert not nodes and not edges
        assert _codes(warns) == ["CODE_SCANNING_UNOBSERVABLE"]
        assert "not the same as no findings" in warns[0][0][2]

    @pytest.mark.spec("req-github-core-code-scanning-3")
    def test_githubs_no_analysis_found_is_not_enabled_with_an_info(self) -> None:
        """The verbatim 404 from a repository that never uploaded SARIF: the feature is off,
        which is a fact about the repository and a gap worth knowing — not a refusal."""
        body = json.dumps(_ALERTS["not_enabled_404"])
        node, nodes, _, warns, infos = _collect(
            _FakeClient(fail={"alerts": (404, body), "analyses": (404, json.dumps(_ANALYSES["not_enabled_404"]))})
        )
        assert node["code_scanning_observability"] == "not_enabled"
        assert not nodes and not warns
        assert "CODE_SCANNING_NOT_ENABLED" in _codes(infos)

    @pytest.mark.spec("req-github-core-code-scanning-3")
    def test_a_403_naming_advanced_security_is_not_enabled_not_refused(self) -> None:
        """SYNTHETIC body: a private repository without GHAS answers 403 and SAYS why. That is
        the feature being off, not the credential being short."""
        node, _, _, warns, infos = _collect(_FakeClient(fail={"alerts": (403, _GHAS_403), "analyses": (403, _GHAS_403)}))
        assert node["code_scanning_observability"] == "not_enabled"
        assert not warns and "CODE_SCANNING_NOT_ENABLED" in _codes(infos)

    @pytest.mark.spec("req-github-core-code-scanning-3")
    def test_an_unexplained_404_is_unobservable(self) -> None:
        """A bare `Not Found` is what a credential that cannot see the repository gets."""
        node, _, _, warns, _ = _collect(
            _FakeClient(fail={"alerts": (404, '{"message":"Not Found"}'), "analyses": (404, '{"message":"Not Found"}')})
        )
        assert node["code_scanning_observability"] == "unobservable"
        assert _codes(warns) == ["CODE_SCANNING_UNOBSERVABLE"]

    @pytest.mark.spec("req-github-core-code-scanning-3")
    def test_one_refused_half_makes_the_repository_unobservable_but_keeps_what_answered(self) -> None:
        """Alerts answered, analyses refused: the alerts land (they are real), but the
        repository cannot claim `observed` — refused beats not_enabled beats observed."""
        node, nodes, _, warns, _ = _collect(_FakeClient(fail={"analyses": (403, _REFUSED_403)}))
        assert node["code_scanning_observability"] == "unobservable"
        assert len(_of_type(nodes, _ALERT_TYPE)) == len(_ALL_ALERTS)
        assert not _of_type(nodes, _ANALYSIS_TYPE)
        assert _codes(warns) == ["CODE_SCANNING_UNOBSERVABLE"]
        assert "analyses answered 403" in warns[0][0][2]

    @pytest.mark.spec("req-github-core-code-scanning-3")
    def test_refused_outranks_not_enabled(self) -> None:
        node, _, _, warns, infos = _collect(
            _FakeClient(fail={"alerts": (403, _REFUSED_403), "analyses": (404, json.dumps(_ANALYSES["not_enabled_404"]))})
        )
        assert node["code_scanning_observability"] == "unobservable"
        assert _codes(warns) == ["CODE_SCANNING_UNOBSERVABLE"]
        assert "CODE_SCANNING_NOT_ENABLED" not in _codes(infos)

    @pytest.mark.spec("req-github-core-code-scanning-3")
    @pytest.mark.parametrize("status", [500, 503])
    def test_anything_else_re_raises_like_every_sibling_surface(self, status: int) -> None:
        with pytest.raises(GithubAPIError):
            _collect(_FakeClient(fail={"alerts": (status, "upstream")}))


# ---------------------------------------------------------------------------------------------
# 4. One substrate finding per alert, with the two-state status.
# ---------------------------------------------------------------------------------------------


class TestFindingPerAlert:
    """`compliance_core` is not registered in every container this suite runs in, so the finding
    is asserted as the emitted envelope (keys, values, identity, dimensions) rather than through
    `create_node`. The model's contract — name ≤255 required, summary ≤500, description text,
    status in {open, resolved}, no configuration/tags — is what the assertions encode."""

    @pytest.mark.spec("req-github-core-code-scanning-4")
    def test_one_finding_per_alert_named_by_a_ref_compliance_core_can_resolve(self) -> None:
        """One finding per alert, each naming itself by a ref rather than a minted id.

        The ref string is unchanged from the one the pre-adoption uuid5 hashed (Issue# 8 -
        tap-plugin-compliance-core), which is what keeps every edge id byte-identical; the
        assertion holds it to the letter so a Dependabot finding (`#dependabot#`) can never
        collide with a code-scanning one.
        """
        _, nodes, _, _, _ = _collect(_FakeClient())
        findings = _of_type(nodes, _FINDING_TYPE)
        assert len(findings) == len(_ALL_ALERTS)
        ids = {envelope_key(f) for f in findings}
        assert ids == {str(code_scanning_finding_id(_REPO, a["number"])) for a in _ALL_ALERTS}
        assert all("ref" in f["entity"] for f in findings), "the id is core's to assign"
        assert code_scanning_finding_id(_REPO, 164) == f"{_FINDING_TYPE}:{_REPO}#code_scanning#164"
        # The string the old derivation hashed — pinned so the edge ids it feeds cannot shift.
        assert uuid.uuid5(GITHUB_CORE_NAMESPACE, str(code_scanning_finding_id(_REPO, 164))) == uuid.uuid5(
            GITHUB_CORE_NAMESPACE, f"{_FINDING_TYPE}:{_REPO}#code_scanning#164"
        )

    @pytest.mark.spec("req-github-core-code-scanning-4")
    def test_the_finding_carries_the_two_values_compliance_cores_key_names(self) -> None:
        """The data contract, asserted: compliance_core decides the key, github_core owes values.

        `NATURAL_KEY = ("source", "source_key")` on the model compliance_core owns, so these
        two columns are what the importer's generated search filters. Omitting them would not
        fail — the search would find a hole, answer "not found", and core would assign a fresh
        id: one duplicate finding per alert per run. That silence is why this is a test.
        """
        _, nodes, _, _, _ = _collect(_FakeClient())
        for alert in _ALL_ALERTS:
            number = alert["number"]
            ref = str(code_scanning_finding_id(_REPO, number))
            finding = next(f for f in _of_type(nodes, _FINDING_TYPE) if envelope_key(f) == ref)
            assert finding["node"]["source"] == "github_core"
            assert finding["node"]["source_key"] == f"{_REPO}#code_scanning#{number}"
            # The ref and the written key are the same string, composed once in identity.py:
            # if they ever drifted, the search would miss the row the ref names.
            assert ref.endswith(finding["node"]["source_key"])

    @pytest.mark.spec("req-github-core-code-scanning-4")
    def test_the_finding_carries_only_the_substrates_fields(self) -> None:
        _, nodes, _, _, _ = _collect(_FakeClient())
        finding = next(
            f for f in _of_type(nodes, _FINDING_TYPE) if envelope_key(f) == str(code_scanning_finding_id(_REPO, 164))
        )
        assert set(finding["node"]) == {"source", "source_key", "name", "summary", "description", "status"}
        assert finding["node"]["name"] == "SonarCloud pythonsecurity:S6549"
        assert finding["entity"]["name"] == finding["node"]["name"]
        assert finding["node"]["summary"] == "Accessing files should not lead to filesystem oracle attacks"
        assert finding["node"]["description"].endswith("tap/preboot.py:460")
        assert finding["node"]["status"] == "open"
        assert len(finding["node"]["name"]) <= 255 and len(finding["node"]["summary"]) <= 500

    @pytest.mark.spec("req-github-core-code-scanning-4")
    def test_dismissed_and_fixed_are_both_resolved_and_the_true_state_lives_on_the_detail(self) -> None:
        _, nodes, edges, _, _ = _collect(_FakeClient())
        detail_by_finding = {
            edge_to(e): edge_from(e) for e in _edges_of(edges, "DETAILS_FINDING__github_core")
        }
        alerts = {envelope_key(n): n["node"] for n in _of_type(nodes, _ALERT_TYPE)}
        statuses: dict[str, set[str]] = {}
        for finding in _of_type(nodes, _FINDING_TYPE):
            detail = alerts[detail_by_finding[envelope_key(finding)]]
            statuses.setdefault(detail["state"], set()).add(finding["node"]["status"])
        assert statuses == {"open": {"open"}, "dismissed": {"resolved"}, "fixed": {"resolved"}}

    @pytest.mark.spec("req-github-core-code-scanning-4")
    def test_the_finding_sits_in_the_repositorys_dimensions_plus_the_substrates(self) -> None:
        _, nodes, _, _, _ = _collect(_FakeClient())
        finding = _of_type(nodes, _FINDING_TYPE)[0]
        assert finding["entity"]["dimensions"] == {**_DIMS, "compliance": "finding"}

    @pytest.mark.spec("req-github-core-code-scanning-4")
    def test_a_rule_without_a_description_falls_back_to_its_name(self) -> None:
        alert = json.loads(json.dumps(_ALERTS["open"][0]))
        alert["rule"]["description"] = None
        _, nodes, _, _, _ = _collect(_FakeClient(alerts=[alert], analyses=[]))
        assert _of_type(nodes, _FINDING_TYPE)[0]["node"]["summary"] == alert["rule"]["name"]


# ---------------------------------------------------------------------------------------------
# 5. CARRIES_COMPLIANCE_FINDING from the repository always; from the workflow when the path matches.
# ---------------------------------------------------------------------------------------------


class TestHasComplianceFinding:
    @pytest.mark.spec("req-github-core-code-scanning-5")
    def test_the_repository_has_every_finding(self) -> None:
        _, nodes, edges, _, _ = _collect(_FakeClient())
        from_repo = [e for e in _edges_of(edges, _HAS_FINDING) if edge_from(e) == str(repository_id(_REPO))]
        assert {edge_to(e) for e in from_repo} == {
            envelope_key(f) for f in _of_type(nodes, _FINDING_TYPE)
        }
        assert from_repo[0]["entity"]["dimensions"] == _DIMS

    @pytest.mark.spec("req-github-core-code-scanning-5")
    def test_a_finding_in_a_collected_workflow_file_is_also_the_workflows(self) -> None:
        """Alerts 101 and 99 are SonarCloud `githubactions:*` rules inside two workflow files.
        With those files collected, each gets a second edge from its workflow; nothing else does."""
        wf_product_lines, wf_plugin_ci = uuid.uuid4(), uuid.uuid4()
        _, _, edges, _, _ = _collect(
            _FakeClient(),
            workflows={
                ".github/workflows/product-lines.yml": wf_product_lines,
                ".github/workflows/plugin-ci.yml": wf_plugin_ci,
            },
        )
        from_workflows = {
            edge_from(e): edge_to(e)
            for e in _edges_of(edges, _HAS_FINDING)
            if edge_from(e) != str(repository_id(_REPO))
        }
        assert from_workflows == {
            str(wf_product_lines): str(code_scanning_finding_id(_REPO, 101)),
            str(wf_plugin_ci): str(code_scanning_finding_id(_REPO, 99)),
        }

    @pytest.mark.spec("req-github-core-code-scanning-5")
    def test_without_a_collected_workflow_only_the_repository_edge_exists(self) -> None:
        _, nodes, edges, _, _ = _collect(_FakeClient())
        assert len(_edges_of(edges, _HAS_FINDING)) == len(_of_type(nodes, _FINDING_TYPE))


# ---------------------------------------------------------------------------------------------
# 6. DETAILS_FINDING: the alert is the evidence behind the finding, one each.
# ---------------------------------------------------------------------------------------------


class TestDetailsFinding:
    @pytest.mark.spec("req-github-core-code-scanning-6")
    def test_exactly_one_detail_edge_per_finding_from_the_alert(self) -> None:
        _, nodes, edges, _, _ = _collect(_FakeClient())
        details = _edges_of(edges, "DETAILS_FINDING__github_core")
        assert len(details) == len(_of_type(nodes, _FINDING_TYPE))
        for alert in _ALL_ALERTS:
            number = alert["number"]
            matching = [e for e in details if edge_from(e) == str(code_scanning_alert_id(_REPO, number))]
            assert len(matching) == 1, f"alert #{number} details {len(matching)} findings"
            assert edge_to(matching[0]) == str(code_scanning_finding_id(_REPO, number))


# ---------------------------------------------------------------------------------------------
# 7. Analyses: ANALYZES_REPOSITORY always; ANALYZES_COMMIT only when the commit is in the batch.
# ---------------------------------------------------------------------------------------------


class TestAnalysisEdges:
    @pytest.mark.spec("req-github-core-code-scanning-7")
    def test_every_analysis_analyzes_the_repository(self) -> None:
        _, nodes, edges, _, _ = _collect(_FakeClient())
        analyzes = _edges_of(edges, "ANALYZES_REPOSITORY__github_core")
        assert {edge_from(e) for e in analyzes} == {
            envelope_key(n) for n in _of_type(nodes, _ANALYSIS_TYPE)
        }
        assert {edge_to(e) for e in analyzes} == {str(repository_id(_REPO))}

    @pytest.mark.spec("req-github-core-code-scanning-7")
    def test_the_commit_edge_exists_only_for_a_commit_collected_this_run(self) -> None:
        """No commits collected: no commit edges and no warning — a pull-request head past the
        ref window is normal. One collected: exactly the analyses on that sha join to it."""
        _, _, edges, warns, _ = _collect(_FakeClient())
        assert not _edges_of(edges, "ANALYZES_COMMIT__github_core") and not warns

        sha = "1030aba9fac94d8835c5b1093cba22804c793819"  # four captured analyses ran on it
        commit_uuid = uuid.uuid4()
        _, _, edges, warns, _ = _collect(_FakeClient(), commits={sha: commit_uuid})
        on_commit = _edges_of(edges, "ANALYZES_COMMIT__github_core")
        expected = {str(code_scanning_analysis_id(_REPO, a["id"])) for a in _ANALYSES["analyses"] if a["commit_sha"] == sha}
        assert len(expected) == 4
        assert {edge_from(e) for e in on_commit} == expected
        assert {edge_to(e) for e in on_commit} == {str(commit_uuid)}
        assert not warns

    @pytest.mark.spec("req-github-core-code-scanning-7")
    def test_the_sha_stays_on_the_node_whether_or_not_the_edge_exists(self) -> None:
        _, nodes, _, _, _ = _collect(_FakeClient())
        assert all(len(n["node"]["commit_sha"]) == 40 for n in _of_type(nodes, _ANALYSIS_TYPE))


# ---------------------------------------------------------------------------------------------
# 8. The permission is declared where the App's least-privilege set is derived from.
# ---------------------------------------------------------------------------------------------


class TestPermissionDeclared:
    @pytest.mark.spec("req-github-core-code-scanning-8")
    def test_both_sources_declare_security_events_read_and_degrade(self) -> None:
        sources = {s["name"]: s for s in _MANIFEST["sources"]}
        for name in ("code_scanning_alerts", "code_scanning_analyses"):
            assert sources[name]["permission"] == "repository:security_events:read"
            assert sources[name]["permission_failure"] == "degrade_with_warning"
            assert sources[name]["kind"] == "rest_endpoint"
            assert sources[name]["target_entity_type"], name
            assert "EMPTY MEANS" in sources[name]["description"], f"{name} must say what empty means"

    @pytest.mark.spec("req-github-core-code-scanning-8")
    def test_the_ledger_marks_security_events_requested_by_exactly_these_sources(self) -> None:
        """The recommended -> requested flip, and the audit trail from permission to consumer.
        test_app_permission_ledger holds the whole ledger against the manifest; this pins the one
        entry this feature owns."""
        entry = _LEDGER["permissions"]["security_events"]
        assert entry["state"] == "requested" and entry["level"] == "read"
        assert sorted(entry["sources"]) == ["code_scanning_alerts", "code_scanning_analyses"]
        assert "Sensitive read" in entry["why"], "the sensitivity note must survive the flip"

    @pytest.mark.spec("req-github-core-code-scanning-8")
    def test_the_manifest_inventories_every_edge_this_surface_emits(self) -> None:
        pairs = {(e["slug"], e["source"], e["target"]) for e in _MANIFEST["edges"]}
        assert {
            (_HAS_FINDING, "github_core__github_repository", _FINDING_TYPE),
            (_HAS_FINDING, "github_core__github_workflow", _FINDING_TYPE),
            ("DETAILS_FINDING__github_core", _ALERT_TYPE, _FINDING_TYPE),
            ("ANALYZES_REPOSITORY__github_core", _ANALYSIS_TYPE, "github_core__github_repository"),
            ("ANALYZES_COMMIT__github_core", _ANALYSIS_TYPE, "git_core__git_commit"),
        } <= pairs


# ---------------------------------------------------------------------------------------------
# 9. How we ask, and what an incomplete walk says.
# ---------------------------------------------------------------------------------------------


class TestWalkAndTruncation:
    @pytest.mark.spec("req-github-core-code-scanning-9")
    def test_alerts_are_walked_without_a_state_filter_and_analyses_are_one_page(self) -> None:
        """Measured 2026-09-09: omitting `state` returns every state in one listing, so one walk
        replaces three. Analyses are the most recent hundred, deliberately."""
        client = _FakeClient()
        _collect(client)
        by_surface = {path.rsplit("/", 1)[-1]: (params, max_pages) for path, params, max_pages in client.calls}
        assert set(by_surface) == {"alerts", "analyses"}
        assert "state" not in by_surface["alerts"][0] and by_surface["alerts"][0]["per_page"] == "100"
        assert by_surface["alerts"][1] > 1, "alerts must be walked, not capped at a page"
        assert by_surface["analyses"][1] == 1, "analyses are ONE page"

    @pytest.mark.spec("req-github-core-code-scanning-9")
    def test_an_incomplete_alert_walk_is_warned_and_completeness_is_not_claimed(self) -> None:
        node, nodes, _, warns, infos = _collect(_FakeClient(incomplete=("alerts",)))
        assert node["code_scanning_observability"] == "observed"
        assert len(_of_type(nodes, _ALERT_TYPE)) == len(_ALL_ALERTS), "what was walked still lands"
        assert _codes(warns) == ["CODE_SCANNING_ALERTS_TRUNCATED"]
        assert "INCOMPLETE" in warns[0][0][2]
        summary = next(kw for args, kw in infos if args[1] == "CODE_SCANNING_COLLECTED")
        assert summary["message_data"]["alerts_complete"] is False

    @pytest.mark.spec("req-github-core-code-scanning-9")
    def test_a_pending_analyses_page_is_warned_as_non_evidence(self) -> None:
        _, _, _, warns, _ = _collect(_FakeClient(incomplete=("analyses",)))
        assert _codes(warns) == ["CODE_SCANNING_ANALYSES_TRUNCATED"]
        assert "not evidence it did not run" in warns[0][0][2]

    @pytest.mark.spec("req-github-core-code-scanning-9")
    def test_a_complete_walk_warns_nothing_and_summarises_by_state_and_tool(self) -> None:
        _, _, _, warns, infos = _collect(_FakeClient())
        assert not warns
        summary = next(kw for args, kw in infos if args[1] == "CODE_SCANNING_COLLECTED")["message_data"]
        assert summary["alerts_by_state"] == {"open": 9, "dismissed": 5, "fixed": 3}
        assert summary["alerts_by_tool"] == {"SonarCloud": 14, "Trivy": 3}
        assert summary["analyses_by_tool"] == {"CodeQL": 7, "SonarCloud": 3}


# ---------------------------------------------------------------------------------------------
# 10. The cross-plugin contract, end to end: the finding ref resolves against compliance_core's
#     declaration, and a second collection of the same alert re-observes one node.
# ---------------------------------------------------------------------------------------------


def _import_node(envelope: dict[str, Any]) -> str:
    """Import one collected node envelope as its own GRIFT batch; return the id core resolved.

    Sends the envelope the collector actually built, unedited: a test that re-authored the
    payload would prove its own document resolves, not the collector's.
    """
    doc = {
        "metadata": {"grift_version": "0"},
        "_reserved": {},
        "batches": [
            {
                "batch_entity": {
                    "entity_id": str(uuid.uuid4()),
                    "entity_type": "batch",
                    "name": "code scanning",
                    "dimensions": {},
                },
                "batch_node": {
                    "name": "code scanning",
                    "description": "",
                    "description_json": None,
                    "source": "test",
                    "metadata": {},
                },
                "nodes": [envelope],
                "edges": [],
            }
        ],
    }
    result = grift_import(doc)
    assert result.success, result.errors
    return str(result.imported_batches[0].resolved_refs[envelope["entity"]["ref"]])


@pytest.mark.django_db
class TestTheFindingResolvesAgainstComplianceCore:
    """The half of the adoption this repository cannot prove alone, proved here.

    `compliance_core__compliance_finding` is another plugin's type: the `NATURAL_KEY` the
    importer resolves this ref against lives on ITS model. So these two tests fail — correctly —
    against a pinned compliance_core that has not declared (Issue# 8 -
    tap-plugin-compliance-core), and that red IS the blocker, made visible. Without them the
    flip could merge green under a pin that cannot resolve it and only break on a real grid.
    """

    @pytest.mark.spec("req-github-core-code-scanning-4")
    def test_two_collections_of_one_alert_resolve_to_one_finding(self) -> None:
        _, nodes, _, _, _ = _collect(_FakeClient())
        finding = next(
            f for f in _of_type(nodes, _FINDING_TYPE) if envelope_key(f) == str(code_scanning_finding_id(_REPO, 164))
        )
        first = _import_node(finding)
        second = _import_node(finding)
        assert second == first, "a re-scan re-observed the finding instead of duplicating it"
        assert uuid.UUID(first).version == 7, "the id is core's to assign, not github_core's to derive"
        assert get_model_class(_FINDING_TYPE).objects.live().count() == 1

    @pytest.mark.spec("req-github-core-code-scanning-4")
    def test_the_resolved_row_carries_the_key_the_declaration_names(self) -> None:
        """What the search will filter on the NEXT run, read back off the row it wrote."""
        _, nodes, _, _, _ = _collect(_FakeClient())
        finding = next(
            f for f in _of_type(nodes, _FINDING_TYPE) if envelope_key(f) == str(code_scanning_finding_id(_REPO, 164))
        )
        row = get_model_class(_FINDING_TYPE).objects.live().get(entity_id=uuid.UUID(_import_node(finding)))
        assert row.source == "github_core"
        assert row.source_key == f"{_REPO}#code_scanning#164"
