"""Artifacts: the output of a run, and what GitHub does and does not record about it
(req-github-core-artifacts).

Spec: plugins/github_core/specs/spec-github-core-v0.md (req-github-core-artifacts)
Issue: unified-systems-com/github-core-tap#55

The fixture items are shaped like the executed call on 2026-09-02 (`GET /repos/{o}/{r}/actions/
artifacts` on unified-systems-com/tap: 3,831 artifacts, `digest`, `expired`, `workflow_run`).
"""

from __future__ import annotations

from typing import Any

import pytest
import tap_plugin.github_core.models as github  # noqa: F401 — trigger model registration
from tap_plugin.github_core.collectors.github_collector.api_client import GithubAPIError
from tap_plugin.github_core.collectors.github_collector.collector import GithubCollector
from tap_plugin.github_core.collectors.github_collector.identity import actions_artifact_id, repository_id, run_id
from tap_plugin.github_core.collectors.github_collector.parser import parse_workflow_yaml

from tap_grid.models import Entity
from tap_grid.registry import get_model_class
from tap_grid.services import create_edge, create_node

from .envelopes import edge_from, edge_to


def _create(type_slug: str, payload: dict):
    result = create_node(type_slug, payload)
    assert result.success, f"create_node failed: {result.errors}"
    entity = Entity.objects.get(pk=result.entity_id)
    return get_model_class(type_slug).objects.get(entity=entity)


def _artifact(aid: int, run: int, *, expired: bool = False, digest: str = "sha256:" + "a" * 64) -> dict[str, Any]:
    return {
        "id": aid,
        "node_id": "MDg6QXJ0aWZhY3Q=",
        "name": "sbom",
        "size_in_bytes": 1234,
        "url": f"https://api.github.com/repos/o/r/actions/artifacts/{aid}",
        "archive_download_url": f"https://api.github.com/repos/o/r/actions/artifacts/{aid}/zip",
        "expired": expired,
        "created_at": "2026-09-02T20:00:00Z",
        "updated_at": "2026-09-02T20:00:01Z",
        "expires_at": "2026-12-01T20:00:00Z",
        "digest": digest,
        "workflow_run": {
            "id": run,
            "repository_id": 1,
            "head_repository_id": 1,
            "head_branch": "main",
            "head_sha": "c" * 40,
        },
    }


class _Client:
    def __init__(self, artifacts: list[dict], *, total: int | None = None, fail: int | None = None) -> None:
        self._artifacts = artifacts
        self._total = total
        self._fail = fail
        self.calls: list[tuple[str, dict]] = []

    def get(self, path: str, params: dict | None = None, **_: Any) -> dict:
        self.calls.append((path, dict(params or {})))
        if self._fail is not None:
            raise GithubAPIError(status=self._fail, url=path, body="Resource not accessible")
        return {"total_count": self._total if self._total is not None else len(self._artifacts), "artifacts": self._artifacts}


def _collector() -> GithubCollector:
    c = GithubCollector.__new__(GithubCollector)
    c.events = []  # type: ignore[attr-defined]
    c.record_warn = lambda site, code, message, **kw: c.events.append(("warn", code, kw.get("message_data")))  # type: ignore[method-assign]
    c.record_info = lambda site, code, message, **kw: c.events.append(("info", code, kw.get("message_data")))  # type: ignore[method-assign]
    return c


def _collect(client: _Client, runs_in_batch: set[int]) -> tuple[GithubCollector, list[dict], list[dict]]:
    c = _collector()
    nodes: list[dict] = []
    edges: list[dict] = []
    run_index = [{"run_id": r, "uuid": run_id("o/r", r), "head_sha": "", "head_branch": "", "event": ""} for r in runs_in_batch]
    c._collect_artifacts(client, "o/r", repository_id("o/r"), {"git.host": "github.com"}, run_index, nodes, edges, {})  # type: ignore[arg-type]
    return c, nodes, edges


class TestIdentity:
    def test_pinned_to_a_literal(self) -> None:
        assert str(actions_artifact_id("o/r", 7)) == str(actions_artifact_id("o/r", "7"))
        assert actions_artifact_id("o/r", 7) != actions_artifact_id("o/other", 7)


class TestCollection:
    def test_the_repository_listing_is_used_with_a_cap(self) -> None:
        client = _Client([_artifact(1, 100)])
        _collect(client, {100})
        assert client.calls == [("/repos/o/r/actions/artifacts", {"per_page": "100"})]

    def test_an_artifact_of_a_run_in_the_batch_gets_the_upload_edge(self) -> None:
        _, nodes, all_edges = _collect(_Client([_artifact(1, 100)]), {100})
        edges = [e for e in all_edges if e["edge"]["edge_type"] == "UPLOADS_ARTIFACT__github_core"]
        assert len(nodes) == 1 and len(edges) == 1
        assert edge_from(edges[0]) == str(run_id("o/r", 100))
        assert edge_to(edges[0]) == str(actions_artifact_id("o/r", 1))
        stores = [e for e in all_edges if e["edge"]["edge_type"] == "STORES_ARTIFACT__github_core"]
        assert len(stores) == 1 and edge_from(stores[0]) == str(repository_id("o/r"))
        assert nodes[0]["node"]["configuration"]["run_in_batch"] is True

    def test_an_artifact_of_a_run_outside_the_window_is_counted_not_dropped(self) -> None:
        """Older runs are normal, not an error and not nothing: the node lands with its run_id,
        no edge is emitted (the dangling-edge guard would have dropped it silently), and the
        summary says how many."""
        c, nodes, all_edges = _collect(_Client([_artifact(1, 100), _artifact(2, 99)]), {100})
        edges = [e for e in all_edges if e["edge"]["edge_type"] == "UPLOADS_ARTIFACT__github_core"]
        assert len(nodes) == 2 and len(edges) == 1
        # every artifact hangs off the repository, in or out of the window
        assert sum(e["edge"]["edge_type"] == "STORES_ARTIFACT__github_core" for e in all_edges) == 2
        older = next(n for n in nodes if n["node"]["artifact_id"] == 2)
        assert older["node"]["run_id"] == 99 and older["node"]["configuration"]["run_in_batch"] is False
        summary = next(e for e in c.events if e[1] == "ARTIFACTS_COLLECTED")  # type: ignore[attr-defined]
        assert summary[2] == {"repo": "o/r", "collected": 2, "linked": 1, "unlinked": 1, "expired": 0}

    def test_expiry_is_stored_as_reported_and_an_expired_artifact_still_lands(self) -> None:
        """Shape C: GitHub keeps the row and sets the flag. Expiry is observed, never inferred."""
        c, nodes, _ = _collect(_Client([_artifact(1, 100, expired=True)]), {100})
        assert nodes[0]["node"]["expired"] is True
        assert next(e for e in c.events if e[1] == "ARTIFACTS_COLLECTED")[2]["expired"] == 1  # type: ignore[attr-defined]

    def test_the_digest_and_the_producing_commit_are_columns(self) -> None:
        _, nodes, _ = _collect(_Client([_artifact(1, 100)]), {100})
        assert nodes[0]["node"]["digest"] == "sha256:" + "a" * 64
        assert nodes[0]["node"]["head_sha"] == "c" * 40 and nodes[0]["node"]["head_branch"] == "main"

    def test_truncation_is_reported_as_non_evidence(self) -> None:
        c, nodes, _ = _collect(_Client([_artifact(1, 100)], total=3831), {100})
        warn = next(e for e in c.events if e[1] == "ARTIFACTS_TRUNCATED")  # type: ignore[attr-defined]
        assert warn[2] == {"repo": "o/r", "collected": 1, "total": 3831}

    def test_a_refused_listing_is_unobservable_not_empty(self) -> None:
        c, nodes, edges = _collect(_Client([], fail=403), {100})
        assert nodes == [] and edges == []
        assert any(e[1] == "ARTIFACTS_UNREADABLE_403" for e in c.events)  # type: ignore[attr-defined]
        assert not any(e[1] == "ARTIFACTS_COLLECTED" for e in c.events)  # type: ignore[attr-defined]


_DECLARED = """
on: push
jobs:
  build:
    steps:
      - uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.json
  consume:
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: sbom
      - uses: actions/download-artifact@v4
        with:
          pattern: wheel-*
          run-id: ${{ github.event.workflow_run.id }}
          repository: acme/producer
"""


class TestDeclaredSteps:
    def test_upload_and_download_declarations_are_kept_on_the_job(self) -> None:
        jobs = {j["id"]: j for j in parse_workflow_yaml(_DECLARED)["jobs"]}
        assert jobs["build"]["artifact_steps"] == [{"step_index": 0, "mode": "upload", "name": "sbom"}]
        downloads = jobs["consume"]["artifact_steps"]
        assert downloads[0] == {"step_index": 0, "mode": "download", "name": "sbom", "pattern": "", "cross_workflow": False}

    def test_a_download_reaching_into_another_run_is_cross_workflow(self) -> None:
        """The corpus's `cross_workflow` property, carried where it is derivable: on the
        declaration, not on an edge to an artifact nobody can identify."""
        jobs = {j["id"]: j for j in parse_workflow_yaml(_DECLARED)["jobs"]}
        cross = jobs["consume"]["artifact_steps"][1]
        assert cross["cross_workflow"] is True and cross["pattern"] == "wheel-*"

    def test_no_download_edge_type_exists(self) -> None:
        """GitHub keeps no record of who downloaded an artifact; an edge would be a guess."""
        from tap_grid.constraints import get_edge_type_constraints

        assert get_edge_type_constraints("UPLOADS_ARTIFACT__github_core") is not None
        assert get_edge_type_constraints("DOWNLOADS_ARTIFACT__github_core") is None


@pytest.mark.django_db
class TestModelAndEdge:
    def test_the_node_is_execution_side(self) -> None:
        artifact = _create("github_core__actions_artifact", {"full_name": "o/r", "artifact_id": 1, "name": "sbom"})
        artifact.entity.refresh_from_db()
        assert artifact.entity.dimensions.get("github.observation") == "execution"
        assert artifact.get_name() == "sbom"

    def test_the_upload_edge_is_run_to_artifact_and_property_free(self) -> None:
        run = _create("github_core__github_actions_run", {"full_name": "o/r", "run_id": 100})
        artifact = _create("github_core__actions_artifact", {"full_name": "o/r", "artifact_id": 1})
        edge = create_edge(run.entity, artifact.entity, "UPLOADS_ARTIFACT__github_core")
        assert edge.properties == {}
