"""Code scanning models: the alert and analysis shapes the collector lands, and the repository's
four-state observability (github-core#89; req-github-core-code-scanning).

What matters most is what an EMPTY answer means. `state=""` is observed-empty (GitHub answered
and said nothing about the state); `dismissed_at=None` is unobserved (no timestamp, never
"now"); `security_severity_level=""` on a quality rule is a fact. And the repository has FOUR
observability states because "GitHub says code scanning is off here" is a finding about the
repository, while "our credential could not look" is a finding about us.
"""

from __future__ import annotations

from typing import Any

import pytest
import tap_plugin.github_core.models as github  # noqa: F401 — trigger model registration
from tap_plugin.github_core.models.code_scanning_alert import CodeScanningAlert
from tap_plugin.github_core.models.code_scanning_analysis import CodeScanningAnalysis
from tap_plugin.github_core.models.github_repository import GithubRepository

from tap_grid.services import create_node
from tap_plugin.github_core.tests.conftest import dimension_view

_REPO = "unified-systems-com/tap"
_SHA = "0f3b2bac1d4e5f60718293a4b5c6d7e8f9a0b1c2"


def _alert_payload(**overrides: Any) -> dict[str, Any]:
    """A CodeQL security alert as the REST alerts endpoint shapes it, flattened to the node."""
    payload: dict[str, Any] = {
        "full_name": _REPO,
        "number": 42,
        "state": "open",
        "created_at": "2026-09-01T12:00:00Z",
        "updated_at": "2026-09-08T09:30:00Z",
        "fixed_at": None,
        "dismissed_at": None,
        "dismissed_reason": "",
        "dismissed_comment": "",
        "dismissed_by_login": "",
        "html_url": f"https://github.com/{_REPO}/security/code-scanning/42",
        "rule_id": "py/sql-injection",
        "rule_name": "py/sql-injection",
        "rule_severity": "error",
        "security_severity_level": "high",
        "rule_description": "SQL query built from user-controlled sources",
        "rule_tags": ["security", "external/cwe/cwe-089"],
        "tool_name": "CodeQL",
        "tool_version": "2.19.3",
        "tool_guid": "",
        "analysis_key": ".github/workflows/codeql.yml:analyze",
        "category": "/language:python",
        "environment": '{"language":"python"}',
        "ref": "refs/heads/main",
        "commit_sha": _SHA,
        "location": {
            "path": "tap_grid/search.py",
            "start_line": 120,
            "end_line": 120,
            "start_column": 9,
            "end_column": 44,
        },
        "message": "This SQL query depends on a user-provided value.",
        "classifications": ["source"],
        "instances_url": f"https://api.github.com/repos/{_REPO}/code-scanning/alerts/42/instances",
        "configuration": {"raw": True},
        "tags": {},
    }
    payload.update(overrides)
    return payload


def _analysis_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "full_name": _REPO,
        "analysis_id": 201_234_567,
        "ref": "refs/heads/main",
        "commit_sha": _SHA,
        "analysis_key": ".github/workflows/codeql.yml:analyze",
        "category": "/language:python",
        "environment": '{"language":"python"}',
        "tool_name": "CodeQL",
        "tool_version": "2.19.3",
        "tool_guid": "",
        "created_at": "2026-09-08T09:30:00Z",
        "results_count": 3,
        "rules_count": 158,
        "sarif_id": "8981cd8e-b078-4ac3-a3be-1dad7dbd0b58",
        "deletable": True,
        "warning": "",
        "error": "",
        "url": f"https://api.github.com/repos/{_REPO}/code-scanning/analyses/201234567",
        "configuration": {"raw": True},
        "tags": {},
    }
    payload.update(overrides)
    return payload


@pytest.mark.spec("req-github-core-code-scanning-1")
class TestCodeScanningAlertShape:
    @pytest.mark.django_db
    def test_the_registered_model_accepts_the_alert_shape(self) -> None:
        result = create_node(CodeScanningAlert.ENTITY_TYPE, _alert_payload())
        assert result.success, result.errors
        row = CodeScanningAlert.objects.get(entity_id=result.entity_id)
        row.entity.refresh_from_db()
        assert row.entity.name == "CodeQL py/sql-injection #42"
        assert dimension_view(row.entity)["github.observation"] == "execution"
        assert dimension_view(row.entity)["github.surface"] == "security"
        assert row.number == 42
        assert row.security_severity_level == "high"
        assert row.location["start_line"] == 120
        assert row.rule_tags == ["security", "external/cwe/cwe-089"]

    @pytest.mark.django_db
    def test_null_is_unobserved_and_blank_is_observed_empty(self) -> None:
        """`dismissed_at=None` means no timestamp was observed; `state=""` means GitHub said nothing."""
        result = create_node(
            CodeScanningAlert.ENTITY_TYPE,
            _alert_payload(state="", dismissed_at=None, fixed_at=None, security_severity_level=""),
        )
        assert result.success, result.errors
        row = CodeScanningAlert.objects.get(entity_id=result.entity_id)
        assert row.state == ""
        assert row.dismissed_at is None
        assert row.fixed_at is None
        # A quality rule carries no security severity; the blank is a fact, not a gap.
        assert row.security_severity_level == ""

    @pytest.mark.django_db
    def test_a_dismissal_lands_with_its_reason(self) -> None:
        result = create_node(
            CodeScanningAlert.ENTITY_TYPE,
            _alert_payload(
                state="dismissed",
                dismissed_at="2026-09-08T10:00:00Z",
                dismissed_reason="used in tests",
                dismissed_comment="Fixture SQL, never reaches production.",
                dismissed_by_login="criticalsec",
            ),
        )
        assert result.success, result.errors
        row = CodeScanningAlert.objects.get(entity_id=result.entity_id)
        assert row.state == "dismissed"
        assert row.dismissed_at is not None
        assert row.dismissed_reason == "used in tests"

    @pytest.mark.django_db
    def test_an_unknown_state_or_severity_is_refused(self) -> None:
        bad_state = create_node(CodeScanningAlert.ENTITY_TYPE, _alert_payload(state="closed"))
        assert not bad_state.success
        bad_level = create_node(CodeScanningAlert.ENTITY_TYPE, _alert_payload(security_severity_level="severe"))
        assert not bad_level.success

    @pytest.mark.django_db
    def test_the_location_shape_is_closed(self) -> None:
        """C supplies exactly five keys; a sixth is a collector defect, not new data."""
        location = {"path": "x.py", "start_line": 1, "end_line": 1, "start_column": 1, "end_column": 2, "uri": "x"}
        result = create_node(CodeScanningAlert.ENTITY_TYPE, _alert_payload(location=location))
        assert not result.success

    @pytest.mark.django_db
    def test_the_natural_key_is_required(self) -> None:
        payload = _alert_payload()
        del payload["number"]
        assert not create_node(CodeScanningAlert.ENTITY_TYPE, payload).success


@pytest.mark.spec("req-github-core-code-scanning-2")
class TestCodeScanningAnalysisShape:
    @pytest.mark.django_db
    def test_the_registered_model_accepts_the_analysis_shape(self) -> None:
        result = create_node(CodeScanningAnalysis.ENTITY_TYPE, _analysis_payload())
        assert result.success, result.errors
        row = CodeScanningAnalysis.objects.get(entity_id=result.entity_id)
        row.entity.refresh_from_db()
        assert row.entity.name == f"CodeQL {_SHA[:7]} #201234567"
        assert dimension_view(row.entity)["github.observation"] == "execution"
        assert dimension_view(row.entity)["github.surface"] == "security"
        assert row.analysis_id == 201_234_567
        assert row.commit_sha == _SHA
        assert row.results_count == 3 and row.rules_count == 158
        assert row.deletable is True

    @pytest.mark.django_db
    def test_a_failed_upload_keeps_its_error_and_an_unobserved_timestamp(self) -> None:
        result = create_node(
            CodeScanningAnalysis.ENTITY_TYPE,
            _analysis_payload(created_at=None, results_count=0, error="SARIF exceeded the size limit"),
        )
        assert result.success, result.errors
        row = CodeScanningAnalysis.objects.get(entity_id=result.entity_id)
        assert row.created_at is None
        assert row.error == "SARIF exceeded the size limit"
        assert row.results_count == 0

    @pytest.mark.django_db
    def test_the_natural_key_is_required(self) -> None:
        payload = _analysis_payload()
        del payload["analysis_id"]
        assert not create_node(CodeScanningAnalysis.ENTITY_TYPE, payload).success


@pytest.mark.spec("req-github-core-code-scanning-3")
class TestRepositoryCodeScanningObservability:
    @pytest.mark.django_db
    @pytest.mark.parametrize("state", ["", "observed", "unobservable", "not_enabled"])
    def test_all_four_states_are_accepted(self, state: str) -> None:
        result = create_node(
            GithubRepository.ENTITY_TYPE,
            {"full_name": f"{_REPO}-{state or 'unasked'}", "code_scanning_observability": state},
        )
        assert result.success, result.errors
        row = GithubRepository.objects.get(entity_id=result.entity_id)
        assert row.code_scanning_observability == state

    @pytest.mark.django_db
    def test_never_asked_is_the_default(self) -> None:
        result = create_node(GithubRepository.ENTITY_TYPE, {"full_name": _REPO})
        assert result.success, result.errors
        assert GithubRepository.objects.get(entity_id=result.entity_id).code_scanning_observability == ""

    @pytest.mark.django_db
    def test_a_fifth_state_is_refused(self) -> None:
        """`disabled`, `none`, `false` — every synonym that would let a blank read as a verdict."""
        result = create_node(
            GithubRepository.ENTITY_TYPE, {"full_name": _REPO, "code_scanning_observability": "disabled"}
        )
        assert not result.success
