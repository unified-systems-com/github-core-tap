"""Workflow chains: reusable-workflow calls and `workflow_run` triggers (req-github-core-workflow-chains).

Spec: plugins/github_core/specs/spec-github-core-v0.md (req-github-core-workflow-chains)
Issues: unified-systems-com/github-core-tap#29 (CALLS_WORKFLOW), #52 (TRIGGERS_WORKFLOW)

The tests that matter are about what happens when the other end is NOT there: a callee in a
repository outside the scope must leave a recorded state on the caller and no invented node.
"""

from __future__ import annotations

from typing import Any

import pytest
import tap_plugin.github_core.models as github  # noqa: F401 — trigger model registration
from tap_plugin.github_core.collectors.github_collector.batch import node_envelope
from tap_plugin.github_core.collectors.github_collector.collector import GithubCollector
from tap_plugin.github_core.collectors.github_collector.identity import workflow_id, workflow_job_id
from tap_plugin.github_core.collectors.github_collector.parser import parse_workflow_yaml, split_workflow_call

from tap_grid.exceptions import EdgePropertyValidationError
from tap_grid.models import Entity
from tap_grid.registry import get_model_class
from tap_grid.services import create_edge, create_node

from .envelopes import edge_from, edge_to


def _create(type_slug: str, payload: dict):
    result = create_node(type_slug, payload)
    assert result.success, f"create_node failed: {result.errors}"
    entity = Entity.objects.get(pk=result.entity_id)
    return get_model_class(type_slug).objects.get(entity=entity)


# --------------------------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------------------------


class TestSplitWorkflowCall:
    def test_a_cross_repository_call_is_split_into_repo_path_and_pin(self) -> None:
        call = split_workflow_call("unified-systems-com/tap/.github/workflows/plugin-ci.yml@main")
        assert call == {
            "same_repository": False,
            "repository_full_name": "unified-systems-com/tap",
            "path": ".github/workflows/plugin-ci.yml",
            "ref": "main",
            "pin_kind": "unresolved",
        }

    def test_a_same_repository_call_is_local_and_pinned_by_construction(self) -> None:
        call = split_workflow_call("./.github/workflows/release.yml")
        assert call["same_repository"] is True and call["pin_kind"] == "local" and call["ref"] == ""
        assert call["path"] == ".github/workflows/release.yml"

    def test_a_sha_pin_is_a_sha(self) -> None:
        assert split_workflow_call("a/b/.github/workflows/x.yml@" + "f" * 40)["pin_kind"] == "sha"

    def test_no_call_is_none(self) -> None:
        assert split_workflow_call("") is None


_CHAIN = """
name: AI review
on:
  workflow_run:
    workflows: ["AI review capture"]
    types: [completed]
jobs:
  review:
    uses: unified-systems-com/unified-ai-review/.github/workflows/review.yml@8d7946c4c85a2814eccf0712e8f142f0f1ee3b22
    secrets:
      OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
  forward:
    uses: ./.github/workflows/x.yml
    secrets: inherit
"""


class TestParse:
    def test_workflow_run_keeps_the_names_and_only_the_written_filters(self) -> None:
        parsed = parse_workflow_yaml(_CHAIN)
        assert parsed["workflow_run"] == {"workflows": ["AI review capture"], "types": ["completed"]}
        assert "branches" not in parsed["workflow_run"]
        assert parsed["triggers"] == ["workflow_run"]

    def test_a_workflow_without_the_trigger_says_none_not_empty(self) -> None:
        assert parse_workflow_yaml("on: push\njobs: {}\n")["workflow_run"] is None

    def test_secrets_inherit_and_named_secrets_are_kept_as_names_only(self) -> None:
        jobs = {j["id"]: j for j in parse_workflow_yaml(_CHAIN)["jobs"]}
        assert jobs["forward"]["secrets_inherit"] is True and jobs["forward"]["secrets_passed"] == []
        assert jobs["review"]["secrets_inherit"] is False
        assert jobs["review"]["secrets_passed"] == ["OPENAI_API_KEY"]
        assert "${{" not in str(jobs["review"]["secrets_passed"])

    def test_a_job_level_uses_is_a_workflow_call(self) -> None:
        jobs = {j["id"]: j for j in parse_workflow_yaml(_CHAIN)["jobs"]}
        assert jobs["review"]["workflow_call"]["pin_kind"] == "sha"
        assert jobs["forward"]["workflow_call"]["same_repository"] is True


# --------------------------------------------------------------------------------------------
# Collector post-pass
# --------------------------------------------------------------------------------------------


def _collector() -> GithubCollector:
    c = GithubCollector.__new__(GithubCollector)
    c._config = {}
    c.events = []  # type: ignore[attr-defined]
    c.record_warn = lambda site, code, message, **kw: c.events.append(("warn", code))  # type: ignore[method-assign]
    c.record_info = lambda site, code, message, **kw: c.events.append(("info", code))  # type: ignore[method-assign]
    return c


def _workflow(c: GithubCollector, repo: str, wf_id: int, path: str, name: str, parsed: dict[str, Any]) -> tuple[Any, dict]:
    uuid = workflow_id(repo, wf_id)
    env = node_envelope(entity_id=uuid, entity_type="github_core__github_workflow", name=name, dimensions={},
                        fields={"configuration": parsed})
    c._walk_state()["collected_repos"].add(repo)
    c._register_workflow(repo, path, name, uuid, env, parsed, {"git.host": "github.com"})
    return uuid, env


def _job_call(c: GithubCollector, repo: str, wf_id: int, key: str, uses: str, *, inherit: bool = False) -> tuple[Any, dict]:
    uuid = workflow_job_id(repo, wf_id, key)
    env = node_envelope(entity_id=uuid, entity_type="github_core__workflow_job", name=key, dimensions={},
                        fields={"configuration": {}})
    c._walk_state()["pending_calls"].append(
        {"envelope": env, "job_uuid": uuid, "caller": repo, "call": split_workflow_call(uses),
         "secrets_inherit": inherit, "dims": {"git.host": "github.com"}}
    )
    return uuid, env


class TestCalls:
    def test_a_call_to_a_workflow_on_the_grid_is_an_edge_from_the_job(self) -> None:
        c = _collector()
        gate, _ = _workflow(c, "acme/tap", 1, ".github/workflows/plugin-ci.yml", "plugin-ci", {})
        job, env = _job_call(c, "acme/plugin", 7, "tap", "acme/tap/.github/workflows/plugin-ci.yml@" + "a" * 40)
        edges: list[dict] = []
        c._emit_workflow_calls(edges)
        assert len(edges) == 1
        assert edge_from(edges[0]) == str(job) and edge_to(edges[0]) == str(gate)
        props = edges[0]["edge"]["properties"]
        assert props["pin_kind"] == "sha" and props["is_pinned"] is True and props["same_repository"] is False
        assert props["secrets_inherit"] is False
        assert env["node"]["configuration"]["call_resolution"] == "resolved"

    def test_thirteen_callers_fan_in_to_one_gate(self) -> None:
        c = _collector()
        gate, _ = _workflow(c, "acme/tap", 1, ".github/workflows/plugin-ci.yml", "plugin-ci", {})
        for i in range(13):
            _job_call(c, f"acme/plugin{i}", i, "tap", "acme/tap/.github/workflows/plugin-ci.yml@main")
        edges: list[dict] = []
        c._emit_workflow_calls(edges)
        assert sum(1 for e in edges if edge_to(e) == str(gate)) == 13

    def test_a_callee_outside_the_scope_is_recorded_on_the_job_and_no_node_is_invented(self) -> None:
        """The state a view must be able to say 'calls a workflow we cannot see' from."""
        c = _collector()
        _, env = _job_call(c, "acme/plugin", 7, "capture", "vendor/review/.github/workflows/capture.yml@" + "b" * 40)
        edges: list[dict] = []
        c._emit_workflow_calls(edges)
        assert edges == []
        assert env["node"]["configuration"]["call_resolution"] == "out_of_scope"
        assert ("warn", "WORKFLOW_CALL_UNRESOLVED") not in c.events  # type: ignore[attr-defined]

    def test_a_callee_in_scope_but_missing_is_a_different_state_and_warns(self) -> None:
        c = _collector()
        _workflow(c, "acme/tap", 1, ".github/workflows/other.yml", "other", {})
        _, env = _job_call(c, "acme/plugin", 7, "tap", "acme/tap/.github/workflows/gone.yml@main")
        edges: list[dict] = []
        c._emit_workflow_calls(edges)
        assert edges == []
        assert env["node"]["configuration"]["call_resolution"] == "unresolved_in_scope"
        assert ("warn", "WORKFLOW_CALL_UNRESOLVED") in c.events  # type: ignore[attr-defined]

    def test_a_same_repository_call_is_local_and_pinned(self) -> None:
        c = _collector()
        _workflow(c, "acme/app", 2, ".github/workflows/x.yml", "x", {})
        _job_call(c, "acme/app", 1, "forward", "./.github/workflows/x.yml", inherit=True)
        edges: list[dict] = []
        c._emit_workflow_calls(edges)
        props = edges[0]["edge"]["properties"]
        assert props["pin_kind"] == "local" and props["is_pinned"] is True and props["same_repository"] is True
        assert props["secrets_inherit"] is True and props["declared_ref"] == ""

    def test_a_main_call_resolves_to_a_branch_when_the_callee_repository_is_in_scope(self) -> None:
        c = _collector()
        c._config = {"acme/tap": {
            "nameWithOwner": "acme/tap",
            "defaultBranchRef": {"name": "main", "target": {"oid": "0" * 40}},
            "branchRefs": {"totalCount": 1, "nodes": [{"name": "main", "target": {"oid": "d" * 40}}]},
            "tagRefs": {"totalCount": 0, "nodes": []},
        }}
        _workflow(c, "acme/tap", 1, ".github/workflows/plugin-ci.yml", "plugin-ci", {})
        _job_call(c, "acme/plugin", 7, "tap", "acme/tap/.github/workflows/plugin-ci.yml@main")
        edges: list[dict] = []
        c._emit_workflow_calls(edges)
        props = edges[0]["edge"]["properties"]
        assert props["pin_kind"] == "branch" and props["resolved_sha"] == "d" * 40 and props["resolution"] == "in_scope"


class TestWalkRegistration:
    def test_the_production_walk_registers_each_workflow_under_its_own_path(self, monkeypatch) -> None:
        """Through `_collect_repo`, not by calling `_register_workflow` directly (PR #54 review):
        the index key must be the workflow's `path` from the listing, or every call resolves to
        `unresolved_in_scope` and the three-state machinery makes a broken index look like a
        scope limit."""
        from tap_plugin.github_core.tests.test_self_tier_vocabulary import _walk_one_repo

        captured: list[tuple] = []
        monkeypatch.setattr(
            GithubCollector, "_register_workflow", lambda self, *args, **kw: captured.append(args)
        )
        _nodes, _edges, client, _warns = _walk_one_repo(monkeypatch)
        listed = client.get_paginated("/repos/acme/widget/actions/workflows", item_path="workflows")
        real = [wf for wf in listed if not str(wf.get("path", "")).startswith("dynamic/")]
        assert real, "the stub lists no real workflow — the assertion below would be vacuous"
        assert [(c[0], c[1]) for c in captured] == [("acme/widget", wf["path"]) for wf in real]
        # And the display name is the stored one, which is what `workflow_run` names resolve against.
        assert [c[2] for c in captured] == [wf.get("name") or wf.get("path") for wf in real]


class TestTriggers:
    def test_the_edge_points_from_the_completing_workflow_to_the_declaring_one(self) -> None:
        c = _collector()
        capture, _ = _workflow(c, "acme/app", 1, ".github/workflows/capture.yml", "AI review capture", {})
        review, env = _workflow(
            c, "acme/app", 2, ".github/workflows/review.yml", "AI review",
            {"workflow_run": {"workflows": ["AI review capture"], "types": ["completed"]}},
        )
        edges: list[dict] = []
        c._emit_workflow_triggers(edges)
        assert len(edges) == 1
        assert edge_from(edges[0]) == str(capture) and edge_to(edges[0]) == str(review)
        assert edges[0]["edge"]["properties"] == {
            "trigger_event": "workflow_run", "declared_name": "AI review capture", "types": ["completed"]
        }
        assert env["node"]["configuration"]["trigger_resolution"] == {"resolved": 1, "unresolved": []}

    def test_a_name_shared_by_two_workflows_fans_out_because_github_fires_both(self) -> None:
        c = _collector()
        _workflow(c, "acme/app", 1, ".github/workflows/a.yml", "Build", {})
        _workflow(c, "acme/app", 2, ".github/workflows/b.yml", "Build", {})
        _workflow(c, "acme/app", 3, ".github/workflows/c.yml", "After", {"workflow_run": {"workflows": ["Build"]}})
        edges: list[dict] = []
        c._emit_workflow_triggers(edges)
        assert len(edges) == 2
        assert "types" not in edges[0]["edge"]["properties"]  # GitHub's default is not written in

    def test_a_name_in_another_repository_does_not_resolve(self) -> None:
        c = _collector()
        _workflow(c, "acme/other", 1, ".github/workflows/a.yml", "Build", {})
        _, env = _workflow(c, "acme/app", 3, ".github/workflows/c.yml", "After", {"workflow_run": {"workflows": ["Build"]}})
        edges: list[dict] = []
        c._emit_workflow_triggers(edges)
        assert edges == []
        assert env["node"]["configuration"]["trigger_resolution"] == {"resolved": 0, "unresolved": ["Build"]}
        assert ("warn", "WORKFLOW_TRIGGER_UNRESOLVED") in c.events  # type: ignore[attr-defined]


# --------------------------------------------------------------------------------------------
# Edge schemas, through the service layer
# --------------------------------------------------------------------------------------------


@pytest.mark.django_db
class TestSchemas:
    def test_calls_workflow_requires_the_secrets_posture(self) -> None:
        job = _create("github_core__workflow_job", {"full_name": "o/r", "job_key": "tap"})
        wf = _create("github_core__github_workflow", {"full_name": "o/gate", "workflow_id": 1, "name": "plugin-ci"})
        with pytest.raises(EdgePropertyValidationError):
            create_edge(job.entity, wf.entity, "CALLS_WORKFLOW__github_core",
                        {"declared_ref": "main", "pin_kind": "unresolved", "is_pinned": False,
                         "resolution": "unobservable", "same_repository": False})
        edge = create_edge(job.entity, wf.entity, "CALLS_WORKFLOW__github_core",
                           {"declared_ref": "main", "pin_kind": "unresolved", "is_pinned": False,
                            "resolution": "unobservable", "same_repository": False, "secrets_inherit": True})
        assert edge.properties["secrets_inherit"] is True

    def test_calls_workflow_cannot_contradict_itself(self) -> None:
        """Same rule as USES_ACTION (PR #51 review): a writer outside this collector cannot mint
        an `unresolved` call that reads as pinned, or a `local` call with a ref."""
        job = _create("github_core__workflow_job", {"full_name": "o/r", "job_key": "tap"})
        wf = _create("github_core__github_workflow", {"full_name": "o/gate", "workflow_id": 1, "name": "plugin-ci"})
        base = {"same_repository": False, "secrets_inherit": False}
        for props in (
            {**base, "declared_ref": "main", "pin_kind": "unresolved", "is_pinned": True, "resolution": "unobservable"},
            {**base, "declared_ref": "", "pin_kind": "local", "is_pinned": True, "resolution": "literal"},
            {**base, "declared_ref": "main", "pin_kind": "branch", "is_pinned": False, "resolution": "unobservable"},
            {**base, "declared_ref": "v1", "pin_kind": "tag", "is_pinned": False, "resolution": "in_scope"},
        ):
            with pytest.raises(EdgePropertyValidationError):
                create_edge(job.entity, wf.entity, "CALLS_WORKFLOW__github_core", props)

    def test_triggers_workflow_refuses_a_guessed_conclusion_filter(self) -> None:
        a = _create("github_core__github_workflow", {"full_name": "o/r", "workflow_id": 1, "name": "capture"})
        b = _create("github_core__github_workflow", {"full_name": "o/r", "workflow_id": 2, "name": "review"})
        with pytest.raises(EdgePropertyValidationError):
            create_edge(a.entity, b.entity, "TRIGGERS_WORKFLOW__github_core",
                        {"trigger_event": "workflow_run", "declared_name": "capture", "conclusion_filter": "success"})
        edge = create_edge(a.entity, b.entity, "TRIGGERS_WORKFLOW__github_core",
                           {"trigger_event": "workflow_run", "declared_name": "capture"})
        assert edge.edge_type == "TRIGGERS_WORKFLOW__github_core"
