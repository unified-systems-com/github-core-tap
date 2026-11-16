"""Custom properties: the organization's own metadata over its repositories (github-core#77;
req-github-core-custom-properties).

Fixtures are **captured from the live API** (`tests/fixtures/custom_properties.json`, 2026-09-08,
`unified-systems-com`, the afternoon the five properties were declared), not hand-authored. The
row that matters most is a repository created AFTER the declaration: the listing reports every
declared property for it with `value: null`, which is what lets "unset" be a fact on the wire.

The tests that matter most are about what an EMPTY answer means. A refused schema, a refused
values listing, a user account with no such surface: each is a blank that must not render as
"nothing set".
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import tap_plugin.github_core.models as github  # noqa: F401 — trigger model registration
from tap_plugin.github_core.collectors.github_collector.api_client import GithubAPIError
from tap_plugin.github_core.collectors.github_collector.batch import node_envelope
from tap_plugin.github_core.collectors.github_collector.collector import GithubCollector
from tap_plugin.github_core.collectors.github_collector.identity import (
    custom_property_id,
    repository_id,
    status_check_id,
)
from tap_plugin.github_core.models.github_custom_property import GithubCustomProperty
from tap_plugin.github_core.models.github_repository import GithubRepository

from tap_grid.registry import get_model_class
from tap_grid.services import create_node

from .envelopes import envelope_key
from tap_plugin.github_core.tests.conftest import dimension_view

_FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "custom_properties.json").read_text())
_OWNER = "unified-systems-com"
_TYPE = "github_core__github_custom_property"
_ALL_FIVE = {"criticality", "lifecycle", "ownership-name", "ownership-type", "repository-role"}
#: A repository populated the day the properties were declared, one created afterwards (all
#: null on the wire), and one the listing never mentions at all.
_POPULATED = f"{_OWNER}/tap"
_LATER = f"{_OWNER}/git-core-tap"
_UNLISTED = f"{_OWNER}/ghost"


class _FakeClient:
    """Replays the captured responses per path, and records what was asked for."""

    def __init__(self, *, schema_fail: int | None = None, values_fail: int | None = None) -> None:
        self.calls: list[tuple[str, dict[str, str]]] = []
        self._schema_fail = schema_fail
        self._values_fail = values_fail

    def get_paginated(self, path: str, params: dict[str, str] | None = None, **_: Any) -> list[Any]:
        self.calls.append((path, dict(params or {})))
        if path.endswith("/properties/schema"):
            if self._schema_fail is not None:
                raise GithubAPIError(status=self._schema_fail, url=path, body="Resource not accessible")
            return list(json.loads(json.dumps(_FIXTURE["schema"])))
        if path.endswith("/properties/values"):
            if self._values_fail is not None:
                raise GithubAPIError(status=self._values_fail, url=path, body="Resource not accessible")
            return list(json.loads(json.dumps(_FIXTURE["values"])))
        raise AssertionError(f"unexpected GET {path}")


def _repo_envelope(full_name: str) -> dict[str, Any]:
    return node_envelope(
        entity_id=repository_id(full_name),
        entity_type="github_core__github_repository",
        name=full_name,
        dimensions={"git.host": "github.com"},
        fields={"full_name": full_name, "custom_properties": {}, "custom_properties_observability": ""},
    )


def _collector(*, account_type: str = "Organization", repos: tuple[str, ...] = (_POPULATED, _LATER, _UNLISTED)):
    # `__new__` rather than `__init__`: CollectorBase wants a runtime config we do not need to
    # exercise a pure emitter. Matches the pattern in test_outputs.
    collector = GithubCollector.__new__(GithubCollector)
    collector._account_type = account_type
    collector._repo_envelopes = {name: _repo_envelope(name) for name in repos}
    warns: list[tuple[Any, ...]] = []
    infos: list[tuple[Any, ...]] = []
    collector.record_warn = lambda *a, **k: warns.append((a, k))  # type: ignore[method-assign]
    collector.record_info = lambda *a, **k: infos.append((a, k))  # type: ignore[method-assign]
    collector.warns = warns  # type: ignore[attr-defined]
    collector.infos = infos  # type: ignore[attr-defined]
    return collector


def _collect(collector: GithubCollector, client: _FakeClient, owner: str | None = _OWNER):
    nodes: list[dict[str, Any]] = []
    state = collector._collect_custom_properties(client, owner, nodes)  # type: ignore[arg-type]
    return state, nodes


def _definitions(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [n for n in nodes if n["entity"]["entity_type"] == _TYPE]


def _codes(records: list[tuple[Any, ...]]) -> list[str]:
    return [a[1] for a, _ in records]


def _repo_node(collector: GithubCollector, full_name: str) -> dict[str, Any]:
    return dict(collector._repo_envelopes[full_name]["node"])


@pytest.mark.spec("req-github-core-custom-properties-1")
class TestDefinitionsLand:
    def test_one_node_per_declared_property_keyed_on_owner_and_name(self) -> None:
        state, nodes = _collect(_collector(), _FakeClient())
        assert state == "observed"
        by_name = {n["node"]["property_name"]: n for n in _definitions(nodes)}
        assert set(by_name) == _ALL_FIVE
        crit = by_name["criticality"]
        assert envelope_key(crit) == str(custom_property_id(_OWNER, "criticality"))
        assert crit["entity"]["dimensions"]["github.surface"] == "custom-properties"
        assert crit["entity"]["dimensions"]["github.owner"] == _OWNER
        assert crit["node"]["value_type"] == "single_select"
        assert crit["node"]["allowed_values"] == ["critical", "high", "medium", "low"]
        assert crit["node"]["required"] is False
        assert crit["node"]["default_value"] is None
        assert crit["node"]["source_type"] == "organization"
        assert crit["node"]["configuration"]["require_explicit_values"] is False

    def test_the_name_is_kept_exactly_as_reported(self) -> None:
        _, nodes = _collect(_collector(), _FakeClient())
        names = [n["node"]["property_name"] for n in _definitions(nodes)]
        assert "ownership-type" in names  # the hyphen survives; it is the map key too

    @pytest.mark.django_db
    def test_the_registered_model_accepts_the_captured_shape(self) -> None:
        _, nodes = _collect(_collector(), _FakeClient())
        fields = next(n["node"] for n in nodes if n["node"].get("property_name") == "ownership-name")
        result = create_node(_TYPE, fields)
        assert result.success, result.errors
        assert get_model_class(_TYPE) is GithubCustomProperty
        row = GithubCustomProperty.objects.get(entity_id=result.entity_id)
        row.entity.refresh_from_db()
        assert row.entity.name == "ownership-name"
        assert row.value_type == "string"
        assert dimension_view(row.entity).get("github.surface") == "custom-properties"

    def test_identity_is_deterministic_and_distinct_from_other_owner_scoped_types(self) -> None:
        minted = custom_property_id(_OWNER, "criticality")
        # The same natural key, built from a literal rather than the module constant, mints the same id.
        assert custom_property_id("unified-systems-com", "criticality") == minted
        assert custom_property_id("other-org", "criticality") != minted
        assert custom_property_id(_OWNER, "gate") != status_check_id(_OWNER, "gate")


@pytest.mark.spec("req-github-core-custom-properties-2")
class TestValuesStampedOnTheRepository:
    def test_a_populated_repository_carries_every_declared_property(self) -> None:
        collector = _collector()
        _collect(collector, _FakeClient())
        node = _repo_node(collector, _POPULATED)
        assert node["custom_properties_observability"] == "observed"
        assert node["custom_properties"] == {
            "criticality": "critical",
            "lifecycle": "active",
            "ownership-name": "maintainers",
            "ownership-type": "team",
            "repository-role": "platform",
        }

    def test_a_repository_created_after_the_declaration_is_unset_not_absent(self) -> None:
        collector = _collector()
        _collect(collector, _FakeClient())
        node = _repo_node(collector, _LATER)
        assert node["custom_properties_observability"] == "observed"
        assert set(node["custom_properties"]) == _ALL_FIVE
        assert all(value is None for value in node["custom_properties"].values())

    def test_a_repository_the_listing_never_mentions_is_unobservable_not_all_unset(self) -> None:
        # An omitted row is not evidence of five unset values; it is a row we did not get.
        collector = _collector()
        _collect(collector, _FakeClient())
        node = _repo_node(collector, _UNLISTED)
        assert node["custom_properties_observability"] == "unobservable"
        assert node["custom_properties"] == {}
        assert _codes(collector.warns) == ["CUSTOM_PROPERTIES_REPOSITORY_UNLISTED"]
        assert collector.warns[0][1]["message_data"]["repositories"] == [_UNLISTED]
        # The reported repositories are unaffected by their neighbour's omission.
        assert _repo_node(collector, _POPULATED)["custom_properties_observability"] == "observed"

    def test_the_run_summary_counts_what_it_saw(self) -> None:
        collector = _collector()
        _collect(collector, _FakeClient())
        assert _codes(collector.infos) == ["CUSTOM_PROPERTIES_COLLECTED"]
        data = collector.infos[0][1]["message_data"]
        assert data["state"] == "observed"
        assert len(data["definitions"]) == 5
        assert data["repositories_with_values"] == 2  # ghost is not in the listing
        assert data["unset_values"] == 5  # git-core-tap's five nulls

    @pytest.mark.django_db
    def test_the_repository_model_accepts_the_stamped_shape(self) -> None:
        collector = _collector()
        _collect(collector, _FakeClient())
        result = create_node("github_core__github_repository", dict(_repo_node(collector, _LATER)))
        assert result.success, result.errors
        row = GithubRepository.objects.get(entity_id=result.entity_id)
        assert row.custom_properties["criticality"] is None
        assert row.custom_properties_observability == GithubRepository.CUSTOM_PROPERTIES_OBSERVED

    def test_the_values_listing_is_asked_at_the_maximum_page_size(self) -> None:
        client = _FakeClient()
        _collect(_collector(), client)
        assert client.calls == [
            (f"/orgs/{_OWNER}/properties/schema", {}),
            (f"/orgs/{_OWNER}/properties/values", {"per_page": "100"}),
        ]


@pytest.mark.spec("req-github-core-custom-properties-3")
class TestRefusedIsNotEmpty:
    @pytest.mark.parametrize("status", [403, 404])
    def test_a_refused_schema_mints_nothing_and_marks_every_repository_unobservable(self, status: int) -> None:
        collector = _collector()
        state, nodes = _collect(collector, _FakeClient(schema_fail=status))
        assert state == "unobservable"
        assert _definitions(nodes) == []
        for full_name in (_POPULATED, _LATER, _UNLISTED):
            node = _repo_node(collector, full_name)
            assert node["custom_properties_observability"] == "unobservable"
            assert node["custom_properties"] == {}
        assert _codes(collector.warns) == [f"CUSTOM_PROPERTIES_UNOBSERVABLE_{status}"]
        assert collector.infos == []

    def test_refused_values_land_the_definitions_and_mark_the_values_unobservable(self) -> None:
        collector = _collector()
        state, nodes = _collect(collector, _FakeClient(values_fail=403))
        assert state == "unobservable"
        assert len(_definitions(nodes)) == 5
        node = _repo_node(collector, _POPULATED)
        assert node["custom_properties_observability"] == "unobservable"
        assert node["custom_properties"] == {}
        assert _codes(collector.warns) == ["CUSTOM_PROPERTIES_VALUES_UNOBSERVABLE_403"]
        assert collector.infos[0][1]["message_data"]["state"] == "unobservable"


@pytest.mark.spec("req-github-core-custom-properties-4")
class TestNotAskedIsNotRefused:
    def test_a_user_account_is_skipped_with_no_request(self) -> None:
        collector = _collector(account_type="User")
        client = _FakeClient()
        state, nodes = _collect(collector, client, owner="notgeorge")
        assert state == ""
        assert nodes == []
        assert client.calls == []
        node = _repo_node(collector, _POPULATED)
        assert node["custom_properties_observability"] == ""
        assert node["custom_properties"] == {}
        assert _codes(collector.infos) == ["CUSTOM_PROPERTIES_SKIPPED"]
        assert collector.warns == []

    def test_a_repos_only_scope_is_skipped_with_no_request(self) -> None:
        collector = _collector(account_type="")
        client = _FakeClient()
        state, _ = _collect(collector, client, owner=None)
        assert state == ""
        assert client.calls == []
        assert _codes(collector.infos) == ["CUSTOM_PROPERTIES_SKIPPED"]


class TestTheModelSaysWhatTheBlankMeans:
    def test_the_observability_vocabulary_is_the_rulesets_vocabulary(self) -> None:
        assert GithubRepository.CUSTOM_PROPERTIES_OBSERVED == "observed"
        assert GithubRepository.CUSTOM_PROPERTIES_UNOBSERVABLE == "unobservable"
        enum = GithubRepository.FIELD_VALIDATION_SCHEMA["custom_properties_observability"]["schema"]["enum"]
        assert enum == ["", "observed", "unobservable"]

    def test_the_definition_node_declares_githubs_value_types(self) -> None:
        assert GithubCustomProperty.VALUE_TYPES == ["string", "single_select", "multi_select", "true_false"]
