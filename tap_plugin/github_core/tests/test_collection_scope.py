"""Collection scope — one node per run, what THIS run's credential was allowed to weigh in on
(github-core#145; req-github-core-collection-scope).

Three things are under test. The node is EMITTED before the walk, in its own batch, joined to
the core `collection_job` it is about and carrying the INSTALLATION_SELECTION record verbatim.
The `visibility` and `tiers` seams exist EMPTY, with the agreed shape described in the schema,
so the visibility assessment (github-core#15) and reliability 1b (github-core#136) land into a
declared seam rather than inventing the node. And nothing about the credential's VALUE ever
reaches the node — a token is inspected for its prefix and never recorded.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import UUID, uuid4, uuid7

import jsonschema
import pytest
import tap_plugin.github_core.models as github  # noqa: F401 — trigger model registration
from tap_plugin.github_core.collectors.github_collector.collector import (
    GithubCollector,
    plan_from_org_detail,
)
from tap_plugin.github_core.collectors.github_collector.identity import (
    Ref,
    app_installation_id,
    collection_scope_id,
)
from tap_plugin.github_core.models.collection_scope import (
    TIER_REASONS,
    VISIBILITY_STATES,
    CollectionScope,
)

from tap_cares.collectors.config import CollectorConfig
from tap_grid.services import create_node

from .envelopes import edge_from, edge_to, envelope_key
from tap_plugin.github_core.tests.conftest import dimension_view

EDGES_DIR = Path(github.__file__).parent.parent / "edges"

#: The closed vocabulary agreed with reliability 1b, verbatim. A drift here is a Gryphon
#: question that silently stops matching, which is exactly what the enum exists to prevent.
_AGREED_REASONS = [
    "complete",
    "truncated",
    "forbidden",
    "errored",
    "filter_unverified",
    "count_mismatch",
    "prerequisite_incomplete",
    "not_attempted",
]

_SELECTED = {
    "credential": "app",
    "kind": "selected",
    "repository_ids": [101, 102],
    "count": 2,
    "total_count": 2,
    "complete": True,
}


def _scope_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "run_id": str(uuid4()),
        "observed_at": "2026-09-14T12:00:00Z",
        "credential_kinds": ["app"],
        "installation_id": 7,
        "selection": dict(_SELECTED),
        "plan": "team",
        "visibility": {},
        "tiers": {},
        "configuration": {
            "manifest": {"version": "0", "sha256": "ab" * 32, "sources": 41},
            "installation": {
                "app_id": 3,
                "permissions": {"contents": "read"},
                "repository_selection": "selected",
                "events": [],
                "suspended": False,
            },
            "plan_source": "observed",
        },
        "tags": {},
    }
    payload.update(overrides)
    return payload


class _Auth:
    def __init__(self, *, app: bool, pat_token: str = "", installation: dict[str, Any] | None = None):
        self.has_app, self.has_pat = app, bool(pat_token)
        self._pat_token = pat_token
        self.installation = installation if app else None

    @property
    def held(self) -> list[str]:
        return [k for k, present in (("app", self.has_app), ("pat", self.has_pat)) if present]

    def token(self, prefer: str | None = None) -> str:
        return self._pat_token


_INSTALLATION = {
    "id": 7,
    "app_id": 3,
    "repository_selection": "selected",
    "permissions": {"contents": "read", "metadata": "read"},
    "events": ["push"],
    "suspended_at": None,
}


def _collector(auth: _Auth, *, account_type: str = "Organization", org_detail: dict[str, Any] | None = None):
    """A collector with just the state `_emit_collection_scope` reads, and the two account reads
    stubbed — the plan is derived from whatever `/orgs/{login}` answered."""
    c = GithubCollector.__new__(GithubCollector)
    c.results = {"info": [], "warn": [], "error": []}
    c.config = CollectorConfig(collector_entity_id=uuid4(), collection_job_entity_id=uuid4())
    c._auth = auth
    c._account_type = ""
    c._org_detail = None
    c._org_detail_state = ""
    c._scope_observed_at = datetime(2026, 9, 14, 12, 0, 0, tzinfo=UTC)
    c._scope_uuid = None
    c._emitted_installation_ids = set()
    c._fetch_account = lambda client, owner: {"type": account_type}  # type: ignore[method-assign]
    c._fetch_org_detail = lambda client, login: (org_detail, "observed" if org_detail else "unobservable")  # type: ignore[method-assign]
    submitted: list[dict[str, Any]] = []

    def _submit(document: dict[str, Any]) -> SimpleNamespace:
        """Stand in for `submit_grift`, INCLUDING the ref -> id map it answers with.

        The scope node rides its own batch, so its batch-local ref dies at that batch's edge
        and the id core assigned is learned only here (Issue# 162). A stub that returned None
        would have let `_scope_uuid` stay None and every later assertion about the
        installation edge pass vacuously, so the stub assigns an id exactly as the importer
        does — a fresh UUIDv7 per ref — and reports it the way the result reports it.
        """
        submitted.append(document)
        return SimpleNamespace(
            imported_batches=[
                SimpleNamespace(
                    resolved_refs={
                        node["entity"]["ref"]: str(uuid7())
                        for batch in document["batches"]
                        for node in batch["nodes"]
                        if "ref" in node["entity"]
                    }
                )
            ]
        )

    c.submit_grift = _submit  # type: ignore[method-assign]
    return c, submitted


@pytest.mark.spec("req-github-core-collection-scope-1")
class TestEmission:
    def test_one_node_in_its_own_batch_joined_to_the_job(self) -> None:
        c, submitted = _collector(_Auth(app=True, installation=_INSTALLATION), org_detail={"plan": {"name": "Team"}})
        c._emit_collection_scope(None, "acme", dict(_SELECTED))
        (doc,) = submitted
        (batch,) = doc["batches"]
        (node,) = batch["nodes"]
        (edge,) = batch["edges"]
        job = c.config.collection_job_entity_id
        assert node["entity"]["entity_type"] == "github_core__collection_scope"
        assert envelope_key(node) == str(collection_scope_id(job))
        assert node["entity"]["dimensions"] == {"git.host": "github.com", "github.observation": "execution"}
        assert node["node"]["run_id"] == str(job)
        assert node["node"]["observed_at"] == "2026-09-14T12:00:00Z"
        assert node["node"]["credential_kinds"] == ["app"]
        assert node["node"]["installation_id"] == 7
        assert node["node"]["plan"] == "team"
        assert edge["edge"]["edge_type"] == "SCOPES_RUN__github_core"
        assert edge_from(edge) == envelope_key(node)
        assert edge_to(edge) == str(job)
        assert batch["batch_entity"]["dimensions"] == {"git.host": "github.com", "github.owner": "acme"}
        # The id is core's, not the collector's: what the collector keeps is what the import
        # result told it the ref became, and that is a UUIDv7 nothing here can predict.
        assert isinstance(c._scope_uuid, UUID) and c._scope_uuid.version == 7
        assert str(c._scope_uuid) != str(collection_scope_id(job))
        (event,) = c.results["info"]
        assert event["message_code"] == "COLLECTION_SCOPE_ESTABLISHED"
        assert event["message_data"]["plan_source"] == "observed"

    def test_selection_is_the_record_verbatim(self) -> None:
        """Derive a fact once: the dict the run record carries is the dict the node carries."""
        c, submitted = _collector(_Auth(app=True, installation=_INSTALLATION))
        selection = dict(_SELECTED)
        c._emit_collection_scope(None, "acme", selection)
        assert submitted[0]["batches"][0]["nodes"][0]["node"]["selection"] is selection

    def test_the_seams_are_emitted_empty(self) -> None:
        c, submitted = _collector(_Auth(app=True, installation=_INSTALLATION))
        c._emit_collection_scope(None, "acme", dict(_SELECTED))
        fields = submitted[0]["batches"][0]["nodes"][0]["node"]
        assert fields["visibility"] == {} and fields["tiers"] == {}

    def test_the_three_inputs_are_versioned(self) -> None:
        c, submitted = _collector(_Auth(app=True, installation=_INSTALLATION), org_detail={"plan": {"name": "enterprise"}})
        c._emit_collection_scope(None, "acme", dict(_SELECTED))
        configuration = submitted[0]["batches"][0]["nodes"][0]["node"]["configuration"]
        manifest = configuration["manifest"]
        assert manifest["version"] == "0" and len(manifest["sha256"]) == 64 and manifest["sources"] > 0
        assert configuration["installation"] == {
            "app_id": 3,
            "permissions": {"contents": "read", "metadata": "read"},
            "repository_selection": "selected",
            "events": ["push"],
            "suspended": False,
        }
        assert configuration["plan_source"] == "observed"
        assert "observed" in CollectionScope.FIELD_CRUD_SCHEMA["configuration"]["properties"]["plan_source"]["enum"]

    def test_pat_only_has_no_installation_and_never_records_the_token(self) -> None:
        token = "github_pat_" + "A1" * 12  # token-SHAPED, built by concatenation; not a credential
        c, submitted = _collector(_Auth(app=False, pat_token=token))
        c._emit_collection_scope(None, None, {"credential": "pat", "kind": "unknown", "complete": False})
        fields = submitted[0]["batches"][0]["nodes"][0]["node"]
        assert fields["credential_kinds"] == ["pat"]
        assert fields["installation_id"] is None
        assert fields["configuration"]["installation"] is None
        assert fields["plan"] == "unknown" and fields["configuration"]["plan_source"] == "no_owner"
        assert token not in json.dumps(submitted[0])
        assert token not in json.dumps(c.results)

    def test_a_user_account_has_no_plan_to_read(self) -> None:
        c, submitted = _collector(_Auth(app=True, installation=_INSTALLATION), account_type="User")
        calls: list[str] = []
        c._fetch_org_detail = lambda client, login: calls.append(login) or (None, "observed")  # type: ignore[method-assign]
        c._emit_collection_scope(None, "someone", dict(_SELECTED))
        fields = submitted[0]["batches"][0]["nodes"][0]["node"]
        assert fields["plan"] == "unknown" and fields["configuration"]["plan_source"] == "not_applicable"
        assert calls == []

    def test_an_unreadable_org_detail_is_unknown_not_free(self) -> None:
        c, submitted = _collector(_Auth(app=True, installation=_INSTALLATION), org_detail=None)
        c._emit_collection_scope(None, "acme", dict(_SELECTED))
        fields = submitted[0]["batches"][0]["nodes"][0]["node"]
        assert fields["plan"] == "unknown" and fields["configuration"]["plan_source"] == "unobservable"

    def test_the_org_detail_is_read_once_for_the_run(self) -> None:
        """The account node's later mint reuses what the scope read — one call, not two."""
        c, _ = _collector(_Auth(app=True, installation=_INSTALLATION), org_detail={"plan": {"name": "free"}})
        c._emit_collection_scope(None, "acme", dict(_SELECTED))
        assert c._org_detail_state == "observed" and c._org_detail == {"plan": {"name": "free"}}


@pytest.mark.spec("req-github-core-collection-scope-2")
class TestInstallationEdge:
    def test_lands_with_the_main_batch_beside_the_installation_node(self) -> None:
        c, _ = _collector(_Auth(app=True, installation=_INSTALLATION))
        c._emit_collection_scope(None, "acme", dict(_SELECTED))
        edges: list[dict[str, Any]] = []
        c._append_scope_installation_edge(edges)
        assert edges == [], "no installation node this run — no edge, never a guess"
        c._emitted_installation_ids.add(str(app_installation_id(7)))
        c._append_scope_installation_edge(edges)
        (edge,) = edges
        assert edge["edge"]["edge_type"] == "DERIVED_FROM_INSTALLATION__github_core"
        assert edge_from(edge) == str(c._scope_uuid)
        assert edge_to(edge) == str(app_installation_id(7))
        assert edge["entity"]["dimensions"]["github.observation"] == "execution"

    def test_pat_only_has_nothing_to_derive_from(self) -> None:
        c, _ = _collector(_Auth(app=False, pat_token="ghp_" + "b2" * 18))
        c._emit_collection_scope(None, "acme", {"credential": "pat", "kind": "unknown", "complete": False})
        c._emitted_installation_ids.add(str(app_installation_id(7)))
        edges: list[dict[str, Any]] = []
        c._append_scope_installation_edge(edges)
        assert edges == []


class TestSelectionIsReturned:
    """github-core#141's record and github-core#145's node are ONE dict."""

    class _Client:
        def __init__(self, rows: list[dict[str, Any]], status: int | None = None):
            self.rows, self.status, self.last_walk_complete = rows, status, True

        def get(self, path: str, *, params: Any = None) -> dict[str, Any]:
            from tap_plugin.github_core.collectors.github_collector.api_client import GithubAPIError

            if self.status:
                raise GithubAPIError(status=self.status, url=path, body="{}")
            return {"total_count": len(self.rows), "repositories": self.rows}

        def get_paginated(self, path: str, *, params: Any = None, item_path: Any = None, max_pages: int = 100) -> list:
            return list(self.rows)

    def test_app_selection_returned_is_the_recorded_one(self) -> None:
        c, _ = _collector(_Auth(app=True, installation=_INSTALLATION))
        returned = c._collect_installation_selection(self._Client([{"id": 101}, {"id": 102}]))
        assert returned is c.results["info"][0]["message_data"]
        assert returned["repository_ids"] == [101, 102] and returned["complete"] is True

    def test_pat_selection_returned_is_the_recorded_one(self) -> None:
        c, _ = _collector(_Auth(app=False, pat_token="github_pat_" + "c3" * 12))
        returned = c._collect_installation_selection(self._Client([]))
        assert returned is c.results["info"][0]["message_data"]
        assert returned["kind"] == "unknown" and returned["token_kind"] == "fine_grained"

    def test_a_refused_listing_returns_the_full_shape(self) -> None:
        c, _ = _collector(_Auth(app=True, installation=_INSTALLATION))
        returned = c._collect_installation_selection(self._Client([], status=403))
        assert returned is c.results["warn"][0]["message_data"]
        assert returned == {
            "credential": "app", "kind": "selected", "repository_ids": None, "count": None,
            "total_count": None, "complete": False, "status": 403,
        }


@pytest.mark.spec("req-github-core-collection-scope-3")
class TestDeclaredSeams:
    """Done-test 3: `visibility` and `tiers` exist as described, so #15 and 1b land into a
    declared seam."""

    def test_tiers_describes_the_agreed_shape(self) -> None:
        schema = CollectionScope.FIELD_CRUD_SCHEMA["tiers"]
        assert schema["type"] == "object" and schema["description"]
        tier = schema["additionalProperties"]
        assert set(tier["properties"]) == {"complete", "reason", "prerequisite", "decided_at", "count_check", "surfaces"}
        assert tier["properties"]["reason"]["enum"] == _AGREED_REASONS == list(TIER_REASONS)
        assert tier["properties"]["count_check"]["type"] == ["object", "null"]
        assert set(tier["properties"]["count_check"]["properties"]) == {"reported", "listed"}
        surface = tier["properties"]["surfaces"]["additionalProperties"]
        assert set(surface["properties"]) == {"complete", "reason", "incomplete_scopes"}
        assert surface["properties"]["reason"]["enum"] == _AGREED_REASONS

    def test_a_tier_verdict_in_the_agreed_shape_validates_and_a_stray_reason_does_not(self) -> None:
        schema = CollectionScope.FIELD_CRUD_SCHEMA["tiers"]
        verdicts = {
            "T0": {"complete": True, "reason": "complete", "prerequisite": None, "decided_at": "2026-09-14T12:00:01Z", "count_check": None},
            "T2": {"complete": False, "reason": "count_mismatch", "prerequisite": "T1", "decided_at": "2026-09-14T12:00:05Z", "count_check": {"reported": 19, "listed": 18}},
            "T3a": {
                "complete": False, "reason": "forbidden", "prerequisite": "T2", "decided_at": "2026-09-14T12:00:09Z", "count_check": None,
                "surfaces": {"secrets": {"complete": False, "reason": "forbidden", "incomplete_scopes": ["acme/vault"]}},
            },
        }
        jsonschema.validate(instance=verdicts, schema=schema)
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance={"T1": {"complete": False, "reason": "partial"}}, schema=schema)

    def test_a_bare_complete_is_refused_everywhere(self) -> None:
        """Codex on PR# 146: a seam that DESCRIBES a shape but does not REQUIRE it lets a bare
        `{"complete": true}` persist as an apparently complete authority fact. Fail closed."""
        sel = CollectionScope.FIELD_CRUD_SCHEMA["selection"]
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance={"complete": True}, schema=sel)
        with pytest.raises(jsonschema.ValidationError):  # complete without reconciled ids/counts
            jsonschema.validate(instance={**_SELECTED, "repository_ids": None, "count": None}, schema=sel)
        with pytest.raises(jsonschema.ValidationError):  # complete cannot be claimed for an unknown reach
            jsonschema.validate(instance={**_SELECTED, "kind": "unknown"}, schema=sel)
        tiers = CollectionScope.FIELD_CRUD_SCHEMA["tiers"]
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance={"T2": {"complete": True}}, schema=tiers)
        with pytest.raises(jsonschema.ValidationError):  # a tier nobody defined
            jsonschema.validate(
                instance={"T9": {"complete": True, "reason": "complete", "prerequisite": None, "decided_at": "2026-09-14T12:00:00Z"}},
                schema=tiers,
            )
        with pytest.raises(jsonschema.ValidationError):  # a stray key on a verdict
            jsonschema.validate(
                instance={"T0": {"complete": True, "reason": "complete", "prerequisite": None, "decided_at": "2026-09-14T12:00:00Z", "note": "x"}},
                schema=tiers,
            )
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance={"github_core__actions_secret": {"state": "reachable"}}, schema=CollectionScope.FIELD_CRUD_SCHEMA["visibility"])

    def test_every_selection_shape_the_collector_emits_validates(self) -> None:
        sel = CollectionScope.FIELD_CRUD_SCHEMA["selection"]
        c, _ = _collector(_Auth(app=True, installation=_INSTALLATION))
        jsonschema.validate(instance=c._collect_installation_selection(TestSelectionIsReturned._Client([{"id": 1}])), schema=sel)
        c, _ = _collector(_Auth(app=True, installation=_INSTALLATION))
        jsonschema.validate(instance=c._collect_installation_selection(TestSelectionIsReturned._Client([], status=403)), schema=sel)
        c, _ = _collector(_Auth(app=False, pat_token="ghp_" + "d4" * 18))
        jsonschema.validate(instance=c._collect_installation_selection(TestSelectionIsReturned._Client([])), schema=sel)

    def test_visibility_describes_the_four_states_and_the_failing_permission(self) -> None:
        schema = CollectionScope.FIELD_CRUD_SCHEMA["visibility"]
        assert schema["type"] == "object" and schema["description"]
        per_type = schema["additionalProperties"]
        assert set(per_type["properties"]) == {"state", "failing_permission"}
        assert per_type["properties"]["state"]["enum"] == list(VISIBILITY_STATES) == ["reachable", "degraded", "unreachable", "unknown"]
        jsonschema.validate(
            instance={"github_core__actions_secret": {"state": "unreachable", "failing_permission": "repository:secrets:read"}},
            schema=schema,
        )

    def test_every_json_structure_is_described_top_level_and_per_key(self) -> None:
        """json-structures-require-descriptions: the top level AND each entry."""

        def walk(node: dict[str, Any], path: str) -> None:
            assert node.get("description"), f"{path} lacks a description"
            for key, sub in (node.get("properties") or {}).items():
                walk(sub, f"{path}.{key}")
            extra = node.get("additionalProperties")
            if isinstance(extra, dict):
                walk(extra, f"{path}.*")

        for field in ("credential_kinds", "selection", "visibility", "tiers", "configuration", "tags"):
            walk(CollectionScope.FIELD_CRUD_SCHEMA[field], field)


@pytest.mark.spec("req-github-core-collection-scope-1")
class TestModelShape:
    @pytest.mark.django_db
    def test_the_registered_model_accepts_the_shape(self) -> None:
        result = create_node(CollectionScope.ENTITY_TYPE, _scope_payload())
        assert result.success, result.errors
        row = CollectionScope.objects.get(entity_id=result.entity_id)
        row.entity.refresh_from_db()
        assert dimension_view(row.entity)["github.observation"] == "execution"
        assert row.entity.name == "collection scope @ 2026-09-14T12:00:00Z"
        assert row.selection == _SELECTED and row.visibility == {} and row.tiers == {}
        assert row.plan == "team" and row.installation_id == 7

    @pytest.mark.django_db
    def test_a_credential_kind_outside_the_vocabulary_is_refused(self) -> None:
        result = create_node(CollectionScope.ENTITY_TYPE, _scope_payload(credential_kinds=["oauth"]))
        assert not result.success

    def test_identity_is_the_run(self) -> None:
        job = uuid4()
        assert collection_scope_id(job) == collection_scope_id(str(job))
        assert collection_scope_id(job) != collection_scope_id(uuid4())
        # A batch-local ref since Issue# 162, not a minted id: the run is still the whole of
        # the key, and `CollectionScope.NATURAL_KEY` declares the `run_id` field it is read off.
        assert isinstance(collection_scope_id(job), Ref)
        assert str(collection_scope_id(job)) == f"github_core__collection_scope:{job}"
        assert CollectionScope.NATURAL_KEY == ("run_id",)


class TestPlan:
    @pytest.mark.parametrize(
        ("detail", "expected"),
        [
            ({"plan": {"name": "Enterprise"}}, "enterprise"),
            ({"plan": {"name": "team"}}, "team"),
            ({"plan": {"name": "free"}}, "free"),
            ({"plan": "pro"}, "pro"),
            ({"login": "acme"}, "unknown"),
            ({"plan": {}}, "unknown"),
            (None, "unknown"),
        ],
    )
    def test_plan_from_org_detail(self, detail: dict[str, Any] | None, expected: str) -> None:
        assert plan_from_org_detail(detail) == expected


class TestEdgeDeclarations:
    def test_scopes_run_targets_the_core_job_type(self) -> None:
        edge = json.loads((EDGES_DIR / "SCOPES_RUN.edge.json").read_text())
        assert edge["sources"] == ["github_core__collection_scope"] and edge["targets"] == ["collection_job"]
        assert edge["default_dimensions"]["github.observation"] == "execution"

    def test_derived_from_installation_targets_the_installation(self) -> None:
        edge = json.loads((EDGES_DIR / "DERIVED_FROM_INSTALLATION.edge.json").read_text())
        assert edge["sources"] == ["github_core__collection_scope"]
        assert edge["targets"] == ["github_core__app_installation"]
        assert edge["default_dimensions"]["github.observation"] == "execution"
