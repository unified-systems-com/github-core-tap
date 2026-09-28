"""Actions used: the `uses:` line as a node and an edge (req-github-core-actions-used).

Spec: plugins/github_core/specs/spec-github-core-v0.md (req-github-core-actions-used)
Issue: unified-systems-com/github-core-tap#45

The tests that matter most are about what a PIN proves. `actions/checkout@v4` is a name someone
else can repoint; the old parser called it a `tag`, which the string cannot know. On the
unified-systems-com grid every usage is SHA-pinned (80 of 80 on 2026-09-02), so the unpinned and
unresolved cases are fixtured here rather than waited for.
"""

from __future__ import annotations

from typing import Any

import pytest
import tap_plugin.github_core.models as github  # noqa: F401 — trigger model registration
from tap_plugin.github_core.collectors.github_collector.collector import GithubCollector
from tap_plugin.github_core.collectors.github_collector.identity import (
    github_action_id,
    uses_action_edge_id,
    workflow_job_id,
)
from tap_plugin.github_core.collectors.github_collector.parser import (
    is_pinned,
    parse_workflow_yaml,
    split_uses,
)

from tap_grid.exceptions import EdgePropertyValidationError
from tap_grid.models import Entity
from tap_grid.registry import get_model_class
from tap_grid.services import create_edge, create_node

from .envelopes import envelope_key


def _create(type_slug: str, payload: dict):
    result = create_node(type_slug, payload)
    assert result.success, f"create_node failed: {result.errors}"
    entity = Entity.objects.get(pk=result.entity_id)
    return get_model_class(type_slug).objects.get(entity=entity)


# --------------------------------------------------------------------------------------------
# Identity
# --------------------------------------------------------------------------------------------


class TestIdentity:
    def test_the_derivation_is_pinned_to_a_literal(self) -> None:
        """A natural key cannot change once nodes exist; guard the derivation, not `f(x) == f(x)`.

        Pinned to the REF string since github_core adopted assigned identity (Issue# 162): the
        node's id is core's to assign and is no longer a function of anything here, but the key
        the collector names the source object by still is, and it is what a second run must
        reproduce exactly for `find_existing` to find the first run's row.
        """
        assert (
            str(github_action_id("actions/checkout"))
            == "github_core__github_action:actions/checkout"
        )

    def test_one_action_is_one_node_however_many_repositories_use_it(self) -> None:
        """Platform-global, like `github_app`: a repository parameter here would mint one
        `actions/checkout` per repo and turn fan-in into a string comparison."""
        assert github_action_id.__code__.co_argcount == 1

    def test_a_subdirectory_action_is_a_different_node(self) -> None:
        assert github_action_id("actions/cache") != github_action_id("actions/cache/restore")

    def test_the_edge_id_includes_the_declared_ref(self) -> None:
        """A job calling the same action at two refs has made two trust decisions. An id over
        (job, action) alone would keep only the last after envelope collapse — silently."""
        job = workflow_job_id("o/r", 1, "build")
        action = github_action_id("actions/checkout")
        assert str(uses_action_edge_id(job, action, "v4")) == "b8e8a365-d0d1-574a-9363-e6ea8a917d1a"
        assert uses_action_edge_id(job, action, "v4") != uses_action_edge_id(job, action, "a" * 40)


# --------------------------------------------------------------------------------------------
# Parser — what the string proves, and only that
# --------------------------------------------------------------------------------------------


class TestSplitUses:
    def test_a_commit_sha_is_a_pin(self) -> None:
        parsed = split_uses("actions/checkout@" + "a" * 40)
        assert parsed["pin_kind"] == "sha" and is_pinned("sha")
        assert parsed["repository_full_name"] == "actions/checkout" and parsed["subpath"] == ""

    def test_a_name_is_unresolved_never_a_tag(self) -> None:
        """`v4` and `main` are the same shape to the parser. Calling either a tag is a guess."""
        assert split_uses("actions/checkout@v4")["pin_kind"] == "unresolved"
        assert split_uses("acme/tool@main")["pin_kind"] == "unresolved"
        assert not is_pinned("unresolved")

    def test_no_ref_is_unpinned(self) -> None:
        assert split_uses("acme/tool")["pin_kind"] == "unpinned"

    def test_a_subdirectory_action_keeps_its_repository_and_subpath_apart(self) -> None:
        parsed = split_uses("actions/cache/restore@v4")
        assert parsed["action_path"] == "actions/cache/restore"
        assert parsed["owner"] == "actions"
        assert parsed["repository_full_name"] == "actions/cache"
        assert parsed["subpath"] == "restore"

    def test_a_docker_digest_is_a_pin_and_an_image_tag_is_not(self) -> None:
        digest = split_uses("docker://alpine@sha256:" + "b" * 64)
        assert digest["kind"] == "docker" and digest["pin_kind"] == "digest" and is_pinned("digest")
        assert digest["action_path"] == "docker://alpine"
        tag = split_uses("docker://ghcr.io/org/image:1.2")
        assert tag["pin_kind"] == "tag" and tag["ref"] == "1.2" and not is_pinned("tag")
        assert tag["action_path"] == "docker://ghcr.io/org/image"
        assert tag["owner"] == "" and tag["repository_full_name"] == ""

    def test_a_malformed_digest_is_not_a_pin(self) -> None:
        """`sha256:` proves nothing without 64 hex characters after it (PR #51 review)."""
        assert split_uses("docker://alpine@sha256:not-a-digest")["pin_kind"] == "unresolved"
        assert split_uses("docker://alpine@sha256:")["pin_kind"] == "unresolved"

    def test_owner_and_repository_are_canonicalized_but_the_subpath_is_not(self) -> None:
        """GitHub resolves repository names case-insensitively; `Actions/Checkout` is
        `actions/checkout` and must be ONE node (PR #51 review). A subpath is a filesystem path."""
        upper = split_uses("Actions/Cache/Restore@v4")
        assert upper["action_path"] == "actions/cache/Restore"
        assert upper["repository_full_name"] == "actions/cache" and upper["owner"] == "actions"
        assert github_action_id(upper["action_path"]) == github_action_id("actions/cache/Restore")
        assert github_action_id(split_uses("Actions/Checkout@v4")["action_path"]) == github_action_id(
            "actions/checkout"
        )

    def test_a_registry_port_is_not_mistaken_for_an_image_tag(self) -> None:
        parsed = split_uses("docker://localhost:5000/image")
        assert parsed["action_path"] == "docker://localhost:5000/image"
        assert parsed["pin_kind"] == "unpinned"

    def test_the_parser_carries_the_split_into_action_refs(self) -> None:
        parsed = parse_workflow_yaml(
            "on: push\njobs:\n  j:\n    steps:\n      - uses: ./local\n      - uses: actions/checkout@v4\n"
        )
        refs = parsed["jobs"][0]["action_refs"]
        assert [r["action_path"] for r in refs] == ["actions/checkout"]
        assert refs[0]["step_index"] == 1 and refs[0]["kind"] == "repository"


# --------------------------------------------------------------------------------------------
# Collector — resolution against what it holds, and nothing it does not
# --------------------------------------------------------------------------------------------


def _collector(config: dict[str, Any] | None = None) -> GithubCollector:
    c = GithubCollector.__new__(GithubCollector)
    c._config = config or {}
    c._refs_by_repo = {}
    c._action_usage = {"actions": set(), "edges": 0, "unpinned": 0, "unobservable": 0}
    c.warnings = []  # type: ignore[attr-defined]
    c.record_warn = lambda site, code, message, **kw: c.warnings.append(code)  # type: ignore[method-assign]
    return c


def _in_scope_repo(name: str, *, tags: dict[str, str] | None = None, branches: dict[str, str] | None = None) -> dict:
    """A config-layer repository node shaped like `GithubGraphQLClient.refs` expects."""
    return {
        "nameWithOwner": name,
        "defaultBranchRef": {"name": "main", "target": {"oid": "0" * 40}},
        "branchRefs": {
            "totalCount": len(branches or {}),
            "nodes": [{"name": n, "target": {"oid": sha}} for n, sha in (branches or {}).items()],
        },
        "tagRefs": {
            "totalCount": len(tags or {}),
            "nodes": [{"name": n, "target": {"oid": sha, "__typename": "Commit"}} for n, sha in (tags or {}).items()],
        },
    }


def _emit(c: GithubCollector, refs: list[dict]) -> tuple[list[dict], list[dict]]:
    nodes: list[dict] = []
    edges: list[dict] = []
    dims = {
        "git.host": "github.com",
        "github.owner": "acme",
        "github.repo": "app",
        "github.surface": "actions",
        "github.observation": "declaration",
    }
    c._emit_used_actions("acme/app", workflow_job_id("acme/app", 1, "build"), refs, dims, nodes, edges)
    return nodes, edges


class TestResolution:
    def test_out_of_scope_name_is_unobservable_not_a_tag(self) -> None:
        """The state a view must never render as reassurance."""
        _, edges = _emit(_collector(), [split_uses("actions/checkout@v4") | {"step_index": 0}])
        props = edges[0]["edge"]["properties"]
        assert props["pin_kind"] == "unresolved"
        assert props["resolution"] == "unobservable"
        assert props["is_pinned"] is False
        assert "resolved_sha" not in props

    def test_in_scope_tag_resolves_with_its_commit(self) -> None:
        c = _collector({"acme/tool": _in_scope_repo("acme/tool", tags={"v1": "c" * 40})})
        _, edges = _emit(c, [split_uses("acme/tool@v1") | {"step_index": 0}])
        props = edges[0]["edge"]["properties"]
        assert props["pin_kind"] == "tag" and props["resolution"] == "in_scope"
        assert props["resolved_sha"] == "c" * 40 and props["is_pinned"] is False

    def test_in_scope_branch_resolves_as_a_branch(self) -> None:
        c = _collector({"acme/tool": _in_scope_repo("acme/tool", branches={"main": "d" * 40})})
        _, edges = _emit(c, [split_uses("acme/tool@main") | {"step_index": 0}])
        assert edges[0]["edge"]["properties"]["pin_kind"] == "branch"
        assert edges[0]["edge"]["properties"]["resolved_sha"] == "d" * 40

    def test_in_scope_but_no_such_ref_stays_unresolved_and_warns(self) -> None:
        """Looked and did not find is a different answer from could not look."""
        c = _collector({"acme/tool": _in_scope_repo("acme/tool", tags={"v1": "c" * 40})})
        _, edges = _emit(c, [split_uses("acme/tool@v2") | {"step_index": 0}])
        props = edges[0]["edge"]["properties"]
        assert props["pin_kind"] == "unresolved" and props["resolution"] == "in_scope"
        assert c.warnings == ["ACTION_REF_NOT_FOUND"]  # type: ignore[attr-defined]

    def test_a_sha_pin_is_literal_and_carries_itself_as_resolved(self) -> None:
        sha = "a" * 40
        _, edges = _emit(_collector(), [split_uses(f"actions/checkout@{sha}") | {"step_index": 0}])
        props = edges[0]["edge"]["properties"]
        assert props == {
            "declared_ref": sha,
            "pin_kind": "sha",
            "is_pinned": True,
            "resolution": "literal",
            "step_indexes": [0],
            "resolved_sha": sha,
        }


class TestEmission:
    def test_the_same_action_at_two_refs_is_two_edges(self) -> None:
        refs = [
            split_uses("actions/checkout@v4") | {"step_index": 0},
            split_uses("actions/checkout@" + "a" * 40) | {"step_index": 3},
        ]
        nodes, edges = _emit(_collector(), refs)
        assert len(edges) == 2
        assert len({envelope_key(e) for e in edges}) == 2
        assert len({envelope_key(n) for n in nodes}) == 1

    def test_the_same_ref_in_two_steps_is_one_edge_with_both_positions(self) -> None:
        refs = [
            split_uses("actions/checkout@v4") | {"step_index": 2},
            split_uses("actions/checkout@v4") | {"step_index": 0},
        ]
        _, edges = _emit(_collector(), refs)
        assert len(edges) == 1
        assert edges[0]["edge"]["properties"]["step_indexes"] == [0, 2]

    def test_the_node_carries_no_repository_and_the_edge_carries_the_caller(self) -> None:
        """`actions/checkout` belongs to no one repository in scope; the USAGE is acme/app's."""
        nodes, edges = _emit(_collector(), [split_uses("actions/checkout@v4") | {"step_index": 0}])
        assert "github.repo" not in nodes[0]["entity"]["dimensions"]
        assert nodes[0]["entity"]["dimensions"]["github.observation"] == "declaration"
        assert edges[0]["entity"]["dimensions"]["github.repo"] == "app"
        assert edges[0]["entity"]["dimensions"]["github.owner"] == "acme"

    def test_the_run_tally_counts_unpinned_and_unobservable_separately(self) -> None:
        c = _collector({"acme/tool": _in_scope_repo("acme/tool", tags={"v1": "c" * 40})})
        _emit(
            c,
            [
                split_uses("actions/checkout@v4") | {"step_index": 0},
                split_uses("acme/tool@v1") | {"step_index": 1},
                split_uses("actions/cache@" + "a" * 40) | {"step_index": 2},
            ],
        )
        assert c._action_usage["edges"] == 3
        assert c._action_usage["unpinned"] == 2
        assert c._action_usage["unobservable"] == 1
        assert c._action_usage["actions"] == {"actions/checkout", "acme/tool", "actions/cache"}


# --------------------------------------------------------------------------------------------
# Model and edge, through the service layer
# --------------------------------------------------------------------------------------------


@pytest.mark.django_db
class TestActionNode:
    def test_the_node_is_created_and_named_by_its_path(self) -> None:
        action = _create("github_core__github_action", {"action_path": "actions/checkout", "kind": "repository"})
        assert action.get_name() == "actions/checkout"
        action.entity.refresh_from_db()
        assert action.entity.dimensions.get("github.observation") == "declaration"
        assert "github.repo" not in action.entity.dimensions

    def test_kind_is_constrained(self) -> None:
        result = create_node("github_core__github_action", {"action_path": "x/y", "kind": "orb"})
        assert not result.success


@pytest.mark.django_db
class TestUsesActionEdge:
    def _ends(self):
        job = _create("github_core__workflow_job", {"full_name": "o/r", "job_key": "build"})
        action = _create("github_core__github_action", {"action_path": "actions/checkout"})
        return job, action

    def test_a_fully_stated_pin_is_accepted(self) -> None:
        job, action = self._ends()
        edge = create_edge(
            job.entity,
            action.entity,
            "USES_ACTION__github_core",
            {
                "declared_ref": "v4",
                "pin_kind": "unresolved",
                "is_pinned": False,
                "resolution": "unobservable",
                "step_indexes": [0],
            },
        )
        assert edge.properties["resolution"] == "unobservable"

    def test_a_bare_edge_is_refused(self) -> None:
        """Finding 2 of the corpus: an edge that only says the relationship exists produces
        confident nonsense in any risk view. The schema requires the pin."""
        job, action = self._ends()
        with pytest.raises(EdgePropertyValidationError):
            create_edge(job.entity, action.entity, "USES_ACTION__github_core", {})

    def test_a_contradictory_pin_is_refused(self) -> None:
        """`is_pinned` is derived from `pin_kind`; a writer outside this collector cannot mint an
        `unresolved` edge that reads as pinned, and an unobservable one cannot carry a SHA
        (PR #51 review)."""
        job, action = self._ends()
        for props in (
            {"declared_ref": "v4", "pin_kind": "unresolved", "is_pinned": True, "resolution": "literal", "step_indexes": [0]},
            {"declared_ref": "a" * 40, "pin_kind": "sha", "is_pinned": False, "resolution": "literal", "step_indexes": [0]},
            {"declared_ref": "v4", "pin_kind": "tag", "is_pinned": False, "resolution": "unobservable", "step_indexes": [0]},
            {"declared_ref": "v4", "pin_kind": "unresolved", "is_pinned": False, "resolution": "unobservable",
             "resolved_sha": "a" * 40, "step_indexes": [0]},
            {"declared_ref": "v1", "pin_kind": "tag", "is_pinned": False, "resolution": "in_scope", "step_indexes": [0]},
        ):
            with pytest.raises(EdgePropertyValidationError):
                create_edge(job.entity, action.entity, "USES_ACTION__github_core", props)

    def test_a_guessed_pin_kind_is_refused(self) -> None:
        job, action = self._ends()
        with pytest.raises(EdgePropertyValidationError):
            create_edge(
                job.entity,
                action.entity,
                "USES_ACTION__github_core",
                {
                    "declared_ref": "v4",
                    "pin_kind": "probably-a-tag",
                    "is_pinned": False,
                    "resolution": "literal",
                    "step_indexes": [0],
                },
            )
