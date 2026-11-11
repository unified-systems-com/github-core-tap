"""Dependabot alerts: what GitHub found in the manifests, minted as findings the compliance
substrate already reads (req-github-core-dependabot-alerts; github-core#68).

`tests/fixtures/dependabot_alerts.json` holds verbatim responses taken on 2026-10-13 with the
`notgeorge` gh CLI OAuth token against `unified-systems-com/tap`: the 2 open alerts and the first
6 of the 46 fixed ones (the listing was 48 alerts, all `pip`, in one page). Nothing was stripped.
No `dismissed` or `auto_dismissed` alert exists on that repository, so those states are exercised
with SYNTHETIC alerts built in this file and labelled so, never added to the captured fixture.

What matters most is what an EMPTY answer means. Zero alerts is a fact only when the repository
says `dependabot_observability = observed`; `not_enabled` and `unobservable` are different
absences, and neither is a clean bill.
"""

from __future__ import annotations

import copy
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
    dependabot_alert_id,
    dependabot_finding_id,
    github_action_id,
    repository_id,
)

from tap_grid.grift import grift_import
from tap_grid.registry import get_model_class
from tap_grid.services import create_node

from .envelopes import edge_from, edge_to, envelope_key

_FIXTURES = Path(__file__).parent / "fixtures"
_ALERTS = json.loads((_FIXTURES / "dependabot_alerts.json").read_text())
_COLLECTOR = Path(__file__).resolve().parent.parent / "collectors" / "github_collector"
_MANIFEST = json.loads((_COLLECTOR / "github_collection_manifest.json").read_text())
_LEDGER = json.loads((_COLLECTOR / "github_app_permissions.json").read_text())

_REPO = "unified-systems-com/tap"
_DIMS = {
    "git.host": "github.com",
    "github.owner": "unified-systems-com",
    "github.repo": "tap",
    "github.surface": "security",
    "github.observation": "execution",
}
_ALL_ALERTS: list[dict[str, Any]] = _ALERTS["open"] + _ALERTS["fixed"]
_FINDING_TYPE = "compliance_core__compliance_finding"
_ALERT_TYPE = "github_core__dependabot_alert"
_CARRIES = "CARRIES_COMPLIANCE_FINDING__compliance_core"
_OPEN_NUMBER = _ALERTS["open"][0]["number"]
_FIXED_NUMBER = _ALERTS["fixed"][0]["number"]

#: SYNTHETIC 403 bodies (see module docstring): no repository this token reaches refuses it.
_REFUSED_403 = json.dumps({"message": "Resource not accessible by integration", "status": "403"})
_DISABLED_403 = json.dumps({"message": "Dependabot alerts are disabled for this repository.", "status": "403"})


def _synthetic(base: dict[str, Any], number: int, **overrides: Any) -> dict[str, Any]:
    """A SYNTHETIC alert: a captured one re-numbered, then changed. Labelled so in every test."""
    alert = copy.deepcopy(base)
    alert["number"] = number
    alert.update(overrides)
    return alert


class _FakeClient:
    """Replays the captured listing; records what was asked for; fakes the walk verdict."""

    def __init__(
        self,
        *,
        alerts: list[dict[str, Any]] | None = None,
        fail: tuple[int, str] | None = None,
        incomplete: bool = False,
    ) -> None:
        self.calls: list[tuple[str, dict[str, str], int]] = []
        self._alerts = list(_ALL_ALERTS) if alerts is None else alerts
        self._fail = fail
        self._incomplete = incomplete
        self.last_walk_complete = True

    def get_paginated(
        self, path: str, params: dict[str, str] | None = None, item_path: str | None = None, max_pages: int = 100
    ) -> list[dict[str, Any]]:
        self.calls.append((path, dict(params or {}), max_pages))
        if self._fail is not None:
            status, body = self._fail
            raise GithubAPIError(status=status, url=path, body=body)
        self.last_walk_complete = not self._incomplete
        return list(self._alerts)


def _repo_envelope() -> dict[str, Any]:
    return node_envelope(
        entity_id=repository_id(_REPO),
        entity_type="github_core__github_repository",
        name=_REPO,
        dimensions={k: v for k, v in _DIMS.items() if not k.startswith("github.surface")},
        fields={"full_name": _REPO, "dependabot_observability": ""},
    )


def _collect(
    client: _FakeClient,
    *,
    workflows: dict[str, Any] | None = None,
    actions: set[str] | None = None,
):
    """Drive the emitter alone (`__new__`, not `__init__`: CollectorBase wants a runtime config we
    do not need). Matches test_code_scanning."""
    collector = GithubCollector.__new__(GithubCollector)
    collector._walk_state()["by_path"].update({(_REPO, path): wf for path, wf in (workflows or {}).items()})
    collector._usage_tally()["actions"].update(actions or set())
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    warns: list[tuple[Any, ...]] = []
    infos: list[tuple[Any, ...]] = []
    collector.record_warn = lambda *a, **k: warns.append((a, k))  # type: ignore[method-assign]
    collector.record_info = lambda *a, **k: infos.append((a, k))  # type: ignore[method-assign]
    envelope = _repo_envelope()
    collector._collect_dependabot_alerts(client, _REPO, repository_id(_REPO), envelope, _DIMS, nodes, edges)
    return envelope["node"], nodes, edges, warns, infos


def _of_type(nodes: list[dict[str, Any]], entity_type: str) -> list[dict[str, Any]]:
    return [n for n in nodes if n["entity"]["entity_type"] == entity_type]


def _edges_of(edges: list[dict[str, Any]], slug: str) -> list[dict[str, Any]]:
    return [e for e in edges if e["edge"]["edge_type"] == slug]


def _codes(events: list[tuple[Any, ...]]) -> list[str]:
    return [args[1] for args, _ in events]


def _by_number(nodes: list[dict[str, Any]], entity_type: str) -> dict[int, dict[str, Any]]:
    return {n["node"]["number"]: n for n in _of_type(nodes, entity_type)}


def _finding(nodes: list[dict[str, Any]], number: int) -> dict[str, Any]:
    key = str(dependabot_finding_id(_REPO, number))
    return next(f for f in _of_type(nodes, _FINDING_TYPE) if envelope_key(f) == key)


class TestAlertShape:
    @pytest.mark.spec("req-github-core-dependabot-alerts-1")
    def test_one_detail_node_per_alert_keyed_on_repository_and_number(self) -> None:
        _, nodes, _, _, _ = _collect(_FakeClient())
        alerts = _by_number(nodes, _ALERT_TYPE)
        assert set(alerts) == {a["number"] for a in _ALL_ALERTS}
        assert envelope_key(alerts[_OPEN_NUMBER]) == str(dependabot_alert_id(_REPO, _OPEN_NUMBER))
        assert alerts[_OPEN_NUMBER]["entity"]["dimensions"] == _DIMS

    @pytest.mark.spec("req-github-core-dependabot-alerts-1")
    def test_the_nested_payload_is_flattened_and_kept_whole(self) -> None:
        """`dependency.*`, `security_advisory.*`, `security_vulnerability.*` become columns; the raw
        alert rides `configuration` so nothing GitHub said is lost to the flattening."""
        _, nodes, _, _, _ = _collect(_FakeClient())
        node = _by_number(nodes, _ALERT_TYPE)[_OPEN_NUMBER]["node"]
        captured = next(a for a in _ALERTS["open"] if a["number"] == _OPEN_NUMBER)
        assert node["state"] == "open"
        assert node["ecosystem"] == captured["dependency"]["package"]["ecosystem"] == "pip"
        assert node["package_name"] == captured["dependency"]["package"]["name"]
        assert node["manifest_path"] == captured["dependency"]["manifest_path"]
        assert node["dependency_scope"] == captured["dependency"]["scope"]
        assert node["relationship"] == captured["dependency"]["relationship"]
        assert node["ghsa_id"] == captured["security_advisory"]["ghsa_id"]
        assert node["cve_id"] == captured["security_advisory"]["cve_id"]
        assert node["advisory_summary"] == captured["security_advisory"]["summary"]
        assert node["severity"] == captured["security_advisory"]["severity"]
        assert node["cwes"] == [c["cwe_id"] for c in captured["security_advisory"]["cwes"]]
        assert node["vulnerable_version_range"] == captured["security_vulnerability"]["vulnerable_version_range"]
        assert node["first_patched_version"] == captured["security_vulnerability"]["first_patched_version"]["identifier"]
        assert node["created_at"] == captured["created_at"]
        assert node["html_url"] == captured["html_url"]
        assert node["configuration"] == captured

    @pytest.mark.spec("req-github-core-dependabot-alerts-1")
    def test_the_cvss_v3_pair_is_kept_and_a_zero_with_no_vector_is_not_a_score(self) -> None:
        _, nodes, _, _, _ = _collect(_FakeClient())
        node = _by_number(nodes, _ALERT_TYPE)[_OPEN_NUMBER]["node"]
        captured = next(a for a in _ALERTS["open"] if a["number"] == _OPEN_NUMBER)
        v3 = captured["security_advisory"]["cvss_severities"]["cvss_v3"]
        assert node["cvss_score"] == v3["score"] and node["cvss_vector"] == v3["vector_string"]
        # SYNTHETIC: an advisory with neither a v3 vector nor a legacy one reports 0.0 / None.
        bare = _synthetic(
            captured,
            900,
            security_advisory={
                **captured["security_advisory"],
                "cvss": {"vector_string": None, "score": 0.0},
                "cvss_severities": {"cvss_v3": {"vector_string": None, "score": 0.0}},
            },
        )
        _, nodes, _, _, _ = _collect(_FakeClient(alerts=[bare]))
        node = _by_number(nodes, _ALERT_TYPE)[900]["node"]
        assert node["cvss_score"] is None and node["cvss_vector"] == ""

    @pytest.mark.spec("req-github-core-dependabot-alerts-1")
    def test_null_stays_null_and_absent_strings_are_empty(self) -> None:
        """An open alert has never been fixed or dismissed: those timestamps are null because
        GitHub said null, not because we defaulted them. Nested optional strings become `""`."""
        _, nodes, _, _, _ = _collect(_FakeClient())
        alerts = _by_number(nodes, _ALERT_TYPE)
        opened = alerts[_OPEN_NUMBER]["node"]
        assert opened["fixed_at"] is None and opened["dismissed_at"] is None and opened["auto_dismissed_at"] is None
        assert opened["dismissed_reason"] == "" and opened["dismissed_by_login"] == ""
        fixed = alerts[_FIXED_NUMBER]["node"]
        assert fixed["state"] == "fixed" and fixed["fixed_at"]

    @pytest.mark.spec("req-github-core-dependabot-alerts-1")
    def test_dismissal_is_carried_verbatim(self) -> None:
        # SYNTHETIC: no dismissed alert exists on the captured repository.
        base = _ALERTS["open"][0]
        dismissed = _synthetic(
            base,
            901,
            state="dismissed",
            dismissed_at="2026-10-01T10:00:00Z",
            dismissed_by={"login": "someone"},
            dismissed_reason="tolerable_risk",
            dismissed_comment="behind the gateway",
        )
        _, nodes, _, _, _ = _collect(_FakeClient(alerts=[dismissed]))
        node = _by_number(nodes, _ALERT_TYPE)[901]["node"]
        assert node["state"] == "dismissed" and node["dismissed_at"] == "2026-10-01T10:00:00Z"
        assert node["dismissed_reason"] == "tolerable_risk"
        assert node["dismissed_comment"] == "behind the gateway"
        assert node["dismissed_by_login"] == "someone"

    @pytest.mark.spec("req-github-core-dependabot-alerts-1")
    def test_the_registered_model_accepts_the_captured_shape(self) -> None:
        """The fields the collector emits are ones the model actually declares."""
        model = get_model_class(_ALERT_TYPE)
        declared = set(model.FIELD_CRUD_SCHEMA)
        _, nodes, _, _, _ = _collect(_FakeClient())
        emitted = set(_of_type(nodes, _ALERT_TYPE)[0]["node"])
        assert emitted <= declared, f"emitted fields not on the model: {sorted(emitted - declared)}"

    @pytest.mark.spec("req-github-core-dependabot-alerts-1")
    def test_ids_are_stable_across_two_emits(self) -> None:
        _, first, first_edges, _, _ = _collect(_FakeClient())
        _, second, second_edges, _, _ = _collect(_FakeClient())
        assert [envelope_key(n) for n in first] == [envelope_key(n) for n in second]
        assert [envelope_key(e) for e in first_edges] == [envelope_key(e) for e in second_edges]


class TestFourStateObservability:
    @pytest.mark.spec("req-github-core-dependabot-alerts-2")
    def test_never_asked_is_the_empty_string(self) -> None:
        assert _repo_envelope()["node"]["dependabot_observability"] == ""

    @pytest.mark.spec("req-github-core-dependabot-alerts-2")
    def test_a_200_with_zero_alerts_is_observed(self) -> None:
        node, nodes, _, warns, _ = _collect(_FakeClient(alerts=[]))
        assert node["dependabot_observability"] == "observed"
        assert nodes == [] and warns == []

    @pytest.mark.spec("req-github-core-dependabot-alerts-2")
    def test_a_credential_refusal_is_unobservable_with_a_warning_and_nothing_minted(self) -> None:
        node, nodes, edges, warns, _ = _collect(_FakeClient(fail=(403, _REFUSED_403)))
        assert node["dependabot_observability"] == "unobservable"
        assert nodes == [] and edges == []
        assert _codes(warns) == ["DEPENDABOT_UNOBSERVABLE"]

    @pytest.mark.spec("req-github-core-dependabot-alerts-2")
    def test_githubs_disabled_sentence_is_not_enabled_with_an_info(self) -> None:
        node, nodes, _, warns, infos = _collect(_FakeClient(fail=(403, _DISABLED_403)))
        assert node["dependabot_observability"] == "not_enabled"
        assert nodes == [] and warns == []
        assert _codes(infos) == ["DEPENDABOT_NOT_ENABLED"]

    @pytest.mark.spec("req-github-core-dependabot-alerts-2")
    def test_an_unexplained_404_is_unobservable(self) -> None:
        node, _, _, warns, _ = _collect(_FakeClient(fail=(404, json.dumps({"message": "Not Found"}))))
        assert node["dependabot_observability"] == "unobservable"
        assert _codes(warns) == ["DEPENDABOT_UNOBSERVABLE"]

    @pytest.mark.spec("req-github-core-dependabot-alerts-2")
    @pytest.mark.parametrize("status", [400, 429, 500, 502])
    def test_anything_else_re_raises_like_every_sibling_surface(self, status: int) -> None:
        with pytest.raises(GithubAPIError):
            _collect(_FakeClient(fail=(status, "boom")))


class TestFindingPerAlert:
    @pytest.mark.spec("req-github-core-dependabot-alerts-3")
    def test_one_finding_per_alert_named_by_a_ref_compliance_core_can_resolve(self) -> None:
        _, nodes, _, _, _ = _collect(_FakeClient())
        findings = _of_type(nodes, _FINDING_TYPE)
        assert len(findings) == len(_ALL_ALERTS)
        assert {envelope_key(f) for f in findings} == {
            str(dependabot_finding_id(_REPO, a["number"])) for a in _ALL_ALERTS
        }

    @pytest.mark.spec("req-github-core-dependabot-alerts-3")
    def test_the_finding_carries_the_two_values_compliance_cores_key_names(self) -> None:
        _, nodes, _, _, _ = _collect(_FakeClient())
        node = _finding(nodes, _OPEN_NUMBER)["node"]
        assert node["source"] == "github_core"
        assert node["source_key"] == f"{_REPO}#dependabot#{_OPEN_NUMBER}"

    @pytest.mark.spec("req-github-core-dependabot-alerts-3")
    def test_a_dependabot_and_a_code_scanning_alert_of_one_number_are_two_findings(self) -> None:
        from tap_plugin.github_core.collectors.github_collector.identity import code_scanning_finding_id

        assert dependabot_finding_id(_REPO, 7) != code_scanning_finding_id(_REPO, 7)

    @pytest.mark.spec("req-github-core-dependabot-alerts-3")
    def test_the_finding_carries_only_the_substrates_fields(self) -> None:
        _, nodes, _, _, _ = _collect(_FakeClient())
        model = get_model_class(_FINDING_TYPE)
        for finding in _of_type(nodes, _FINDING_TYPE):
            assert set(finding["node"]) <= set(model.FIELD_CRUD_SCHEMA)

    @pytest.mark.spec("req-github-core-dependabot-alerts-3")
    def test_open_is_open_and_everything_else_is_resolved_with_the_true_state_on_the_detail(self) -> None:
        # SYNTHETIC dismissed and auto_dismissed alongside the captured open and fixed.
        base = _ALERTS["open"][0]
        extra = [_synthetic(base, 902, state="dismissed"), _synthetic(base, 903, state="auto_dismissed")]
        _, nodes, _, _, _ = _collect(_FakeClient(alerts=_ALL_ALERTS + extra))
        assert _finding(nodes, _OPEN_NUMBER)["node"]["status"] == "open"
        for number in (_FIXED_NUMBER, 902, 903):
            assert _finding(nodes, number)["node"]["status"] == "resolved"
        details = _by_number(nodes, _ALERT_TYPE)
        assert details[902]["node"]["state"] == "dismissed" and details[903]["node"]["state"] == "auto_dismissed"

    @pytest.mark.spec("req-github-core-dependabot-alerts-3")
    def test_the_finding_is_named_summarised_and_described_from_the_advisory(self) -> None:
        _, nodes, _, _, _ = _collect(_FakeClient())
        detail = _by_number(nodes, _ALERT_TYPE)[_OPEN_NUMBER]["node"]
        finding = _finding(nodes, _OPEN_NUMBER)["node"]
        assert finding["name"] == f"{detail['package_name']} {detail['ghsa_id']}"
        assert finding["summary"] == detail["advisory_summary"]
        assert detail["manifest_path"] in finding["description"]
        assert detail["first_patched_version"] in finding["description"]

    @pytest.mark.spec("req-github-core-dependabot-alerts-3")
    def test_a_finding_with_no_patched_version_says_so(self) -> None:
        # SYNTHETIC: an advisory with no fix yet.
        base = _ALERTS["open"][0]
        unpatched = _synthetic(base, 904, security_vulnerability={**base["security_vulnerability"], "first_patched_version": None})
        _, nodes, _, _, _ = _collect(_FakeClient(alerts=[unpatched]))
        assert _by_number(nodes, _ALERT_TYPE)[904]["node"]["first_patched_version"] == ""
        assert "no patched version" in _finding(nodes, 904)["node"]["description"]


class TestPlacementAndDetail:
    @pytest.mark.spec("req-github-core-dependabot-alerts-4")
    def test_the_repository_carries_every_finding(self) -> None:
        _, nodes, edges, _, _ = _collect(_FakeClient())
        carried = {
            edge_to(e) for e in _edges_of(edges, _CARRIES) if edge_from(e) == str(repository_id(_REPO))
        }
        assert carried == {envelope_key(f) for f in _of_type(nodes, _FINDING_TYPE)}

    @pytest.mark.spec("req-github-core-dependabot-alerts-4")
    def test_a_manifest_that_is_a_collected_workflow_also_carries_the_finding(self) -> None:
        # SYNTHETIC: a Dependabot alert whose manifest is a workflow file.
        wf = uuid.uuid4()
        base = _ALERTS["open"][0]
        flagged = _synthetic(base, 905, dependency={**base["dependency"], "manifest_path": ".github/workflows/ci.yml"})
        _, nodes, edges, _, _ = _collect(
            _FakeClient(alerts=[flagged, base]), workflows={".github/workflows/ci.yml": wf}
        )
        sources = [edge_from(e) for e in _edges_of(edges, _CARRIES) if edge_to(e) == envelope_key(_finding(nodes, 905))]
        assert str(wf) in sources
        other = [edge_from(e) for e in _edges_of(edges, _CARRIES) if edge_to(e) == envelope_key(_finding(nodes, base["number"]))]
        assert str(wf) not in other

    @pytest.mark.spec("req-github-core-dependabot-alerts-4")
    def test_a_package_that_is_a_used_action_also_carries_the_finding_and_a_pip_package_does_not(self) -> None:
        # SYNTHETIC: an Actions-shaped alert. The Actions ecosystem value is not observed (ACID 5),
        # so the join is on the package name being an action this run saw used, never on ecosystem.
        base = _ALERTS["open"][0]
        action = _synthetic(
            base, 906, dependency={"package": {"ecosystem": "actions", "name": "actions/download-artifact"}, "manifest_path": ".github/workflows/ci.yml"}
        )
        _, nodes, edges, _, _ = _collect(
            _FakeClient(alerts=[action, base]), actions={"actions/download-artifact"}
        )
        action_id = str(github_action_id("actions/download-artifact"))
        carriers = {
            edge_to(e) for e in _edges_of(edges, _CARRIES) if edge_from(e) == action_id
        }
        assert carriers == {envelope_key(_finding(nodes, 906))}

    @pytest.mark.spec("req-github-core-dependabot-alerts-4")
    def test_an_action_path_never_used_in_the_run_gets_no_action_edge(self) -> None:
        base = _ALERTS["open"][0]
        action = _synthetic(
            base, 907, dependency={"package": {"ecosystem": "actions", "name": "actions/checkout"}, "manifest_path": "x.yml"}
        )
        _, _, edges, _, _ = _collect(_FakeClient(alerts=[action]), actions=set())
        assert not [e for e in _edges_of(edges, _CARRIES) if edge_from(e) == str(github_action_id("actions/checkout"))]

    @pytest.mark.spec("req-github-core-dependabot-alerts-5")
    def test_exactly_one_detail_edge_per_finding_from_the_alert(self) -> None:
        _, nodes, edges, _, _ = _collect(_FakeClient())
        details = _edges_of(edges, "DETAILS_FINDING__github_core")
        assert len(details) == len(_ALL_ALERTS)
        for number in (_OPEN_NUMBER, _FIXED_NUMBER):
            finding = envelope_key(_finding(nodes, number))
            into = [e for e in details if edge_to(e) == finding]
            assert [edge_from(e) for e in into] == [str(dependabot_alert_id(_REPO, number))]


class TestWalkAndTruncation:
    @pytest.mark.spec("req-github-core-dependabot-alerts-6")
    def test_all_four_states_are_asked_for_by_name_and_the_walk_follows_the_link_chain(self) -> None:
        client = _FakeClient()
        _collect(client)
        ((path, params, max_pages),) = client.calls
        assert path == f"/repos/{_REPO}/dependabot/alerts"
        assert params == {"state": "open,fixed,dismissed,auto_dismissed", "per_page": "100"}
        # The endpoint rejects `page` (400): cursor pagination only, so we never send one.
        assert "page" not in params and max_pages == 100

    @pytest.mark.spec("req-github-core-dependabot-alerts-2")
    def test_an_alert_with_no_number_is_warned_and_the_repository_is_not_observed(self) -> None:
        # SYNTHETIC: a malformed item, which GitHub's schema should never produce.
        broken = {k: v for k, v in _ALERTS["open"][0].items() if k != "number"}
        node, nodes, _, warns, _ = _collect(_FakeClient(alerts=[broken, *_ALL_ALERTS]))
        assert node["dependabot_observability"] == "unobservable"
        assert _codes(warns) == ["DEPENDABOT_UNREADABLE"]
        assert warns[0][1]["message_data"]["unreadable"] == 1
        assert len(_of_type(nodes, _ALERT_TYPE)) == len(_ALL_ALERTS)

    @pytest.mark.spec("req-github-core-dependabot-alerts-2")
    def test_an_entry_that_is_not_an_object_is_counted_not_discarded(self) -> None:
        # SYNTHETIC: a list entry that is not an alert object at all.
        node, nodes, _, warns, _ = _collect(_FakeClient(alerts=["not an alert", None, *_ALL_ALERTS]))  # type: ignore[list-item]
        assert node["dependabot_observability"] == "unobservable"
        assert warns[0][1]["message_data"]["unreadable"] == 2
        assert len(_of_type(nodes, _ALERT_TYPE)) == len(_ALL_ALERTS)

    @pytest.mark.spec("req-github-core-dependabot-alerts-6")
    def test_an_incomplete_walk_is_warned_and_the_repository_is_not_observed(self) -> None:
        """A capped walk landed some alerts but cannot say there are no others: the alerts it read
        still land, the repository is `unobservable`, and nothing is presented as the whole."""
        node, nodes, _, warns, infos = _collect(_FakeClient(incomplete=True))
        assert _codes(warns) == ["DEPENDABOT_TRUNCATED"]
        assert node["dependabot_observability"] == "unobservable"
        assert len(_of_type(nodes, _ALERT_TYPE)) == len(_ALL_ALERTS)
        assert not infos or infos[0][1]["message_data"]["complete"] is False

    @pytest.mark.spec("req-github-core-dependabot-alerts-8")
    def test_a_complete_walk_summarises_by_state_and_records_the_ecosystems_seen(self) -> None:
        _, _, _, warns, infos = _collect(_FakeClient())
        assert warns == []
        assert _codes(infos) == ["DEPENDABOT_COLLECTED"]
        data = infos[0][1]["message_data"]
        assert data["alerts"] == len(_ALL_ALERTS)
        assert data["alerts_by_state"] == {"open": len(_ALERTS["open"]), "fixed": len(_ALERTS["fixed"])}
        assert data["ecosystems"] == {"pip": len(_ALL_ALERTS)}
        assert data["complete"] is True


class TestPermissionDeclared:
    @pytest.mark.spec("req-github-core-dependabot-alerts-7")
    def test_the_source_declares_vulnerability_alerts_read_and_degrades(self) -> None:
        source = next(s for s in _MANIFEST["sources"] if s["name"] == "dependabot_alerts")
        assert source["permission"] == "repository:vulnerability_alerts:read"
        assert source["permission_failure"] == "degrade_with_warning"
        assert source["kind"] == "rest_endpoint"
        assert source["target_entity_type"] == _ALERT_TYPE
        assert "EMPTY MEANS" in source["description"]
        assert source["query"]["state"] == "open,fixed,dismissed,auto_dismissed"

    @pytest.mark.spec("req-github-core-dependabot-alerts-7")
    def test_the_ledger_marks_vulnerability_alerts_requested_by_exactly_this_source(self) -> None:
        entry = _LEDGER["permissions"]["vulnerability_alerts"]
        assert entry["state"] == "requested" and entry["level"] == "read"
        assert entry["sources"] == ["dependabot_alerts"]
        assert "Sensitive read" in entry["why"]

    @pytest.mark.spec("req-github-core-dependabot-alerts-7")
    def test_the_manifest_inventories_every_edge_this_surface_emits(self) -> None:
        pairs = {(e["slug"], e["source"], e["target"]) for e in _MANIFEST["edges"]}
        assert {
            (_CARRIES, "github_core__github_repository", _FINDING_TYPE),
            (_CARRIES, "github_core__github_workflow", _FINDING_TYPE),
            (_CARRIES, "github_core__github_action", _FINDING_TYPE),
            ("DETAILS_FINDING__github_core", _ALERT_TYPE, _FINDING_TYPE),
        } <= pairs

    @pytest.mark.spec("req-github-core-dependabot-alerts-7")
    def test_the_repository_declares_the_same_four_states(self) -> None:
        schema = get_model_class("github_core__github_repository").FIELD_VALIDATION_SCHEMA
        assert schema["dependabot_observability"]["schema"]["enum"] == ["", "observed", "unobservable", "not_enabled"]


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
                    "name": "dependabot",
                    "dimensions": {},
                },
                "batch_node": {
                    "name": "dependabot",
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
    """The half of the adoption this repository cannot prove alone: the finding ref resolves
    against compliance_core's declared key, and a re-collection re-observes one node."""

    @pytest.mark.spec("req-github-core-dependabot-alerts-3")
    def test_two_collections_of_one_alert_resolve_to_one_finding(self) -> None:
        _, nodes, _, _, _ = _collect(_FakeClient())
        finding = _finding(nodes, _OPEN_NUMBER)
        first = _import_node(finding)
        second = _import_node(finding)
        assert second == first, "a re-scan re-observed the finding instead of duplicating it"
        assert uuid.UUID(first).version == 7, "the id is core's to assign, not github_core's to derive"
        assert get_model_class(_FINDING_TYPE).objects.live().count() == 1

    @pytest.mark.spec("req-github-core-dependabot-alerts-3")
    def test_the_resolved_row_carries_the_key_the_declaration_names(self) -> None:
        _, nodes, _, _, _ = _collect(_FakeClient())
        row = get_model_class(_FINDING_TYPE).objects.live().get(
            entity_id=uuid.UUID(_import_node(_finding(nodes, _OPEN_NUMBER)))
        )
        assert row.source == "github_core"
        assert row.source_key == f"{_REPO}#dependabot#{_OPEN_NUMBER}"


@pytest.mark.django_db
class TestModels:
    @pytest.mark.spec("req-github-core-dependabot-alerts-1")
    def test_every_emitted_alert_is_accepted_by_the_model_validation(self) -> None:
        """The captured shape, flattened by the collector, passes the model's own validation —
        including the null CVSS score and the empty-string defaults."""
        _, nodes, _, _, _ = _collect(_FakeClient())
        for envelope in _of_type(nodes, _ALERT_TYPE):
            payload = dict(envelope["node"])
            result = create_node(_ALERT_TYPE, payload)
            assert result.success, (envelope["node"]["number"], result.errors)

    @pytest.mark.spec("req-github-core-dependabot-alerts-1")
    def test_repository_controlled_strings_longer_than_any_old_column_are_stored(self) -> None:
        """A deep manifest path or a long module name comes from the repository's own tree: it must
        not be able to make the database reject the alert (and with it a batch)."""
        base = _ALERTS["open"][0]
        deep = "a/" * 300 + "requirements.txt"
        long = _synthetic(
            base,
            908,
            dependency={"package": {"ecosystem": "go", "name": "example.com/" + "x" * 400}, "manifest_path": deep},
            security_vulnerability={
                "package": {"ecosystem": "go", "name": "n"},
                "severity": "high",
                "vulnerable_version_range": ">= 1.0.0, < 2.0.0, " + "|| >= 3.0.0 " * 40,
                "first_patched_version": {"identifier": "v" + "9" * 200},
            },
        )
        _, nodes, _, _, _ = _collect(_FakeClient(alerts=[long]))
        payload = _by_number(nodes, _ALERT_TYPE)[908]["node"]
        assert len(payload["manifest_path"]) > 512 and len(payload["package_name"]) > 255
        result = create_node(_ALERT_TYPE, dict(payload))
        assert result.success, result.errors
        row = get_model_class(_ALERT_TYPE).objects.get(entity_id=result.entity_id)
        assert row.manifest_path == deep and row.package_name == payload["package_name"]

    @pytest.mark.spec("req-github-core-dependabot-alerts-1")
    def test_a_state_outside_githubs_four_is_refused(self) -> None:
        result = create_node(_ALERT_TYPE, {"full_name": _REPO, "number": 1, "state": "resolved"})
        assert not result.success

    @pytest.mark.spec("req-github-core-dependabot-alerts-2")
    @pytest.mark.parametrize("state", ["", "observed", "unobservable", "not_enabled"])
    def test_the_repository_accepts_all_four_states_and_refuses_a_fifth(self, state: str) -> None:
        repo = get_model_class("github_core__github_repository")
        result = create_node(repo.ENTITY_TYPE, {"full_name": f"{_REPO}-{state or 'unasked'}", "dependabot_observability": state})
        assert result.success, result.errors
        assert repo.objects.get(entity_id=result.entity_id).dependabot_observability == state
        bad = create_node(repo.ENTITY_TYPE, {"full_name": _REPO, "dependabot_observability": "disabled"})
        assert not bad.success
