"""Status checks: where the gate and the machinery meet (req-github-core-status-checks).

Spec: plugins/github_core/specs/spec-github-core-v0.md (req-github-core-status-checks)
Issue: unified-systems-com/github-core-tap#61

The tests that matter: a refused ruleset detail must be COUNTED, never read as a ruleset that
requires nothing; and a producer derived from a matrix template must say so.
"""

from __future__ import annotations

from typing import Any

import pytest
import tap_plugin.github_core.models as github  # noqa: F401 — trigger model registration
from tap_plugin.github_core.collectors.github_collector.collector import GithubCollector, _check_name_confidence
from tap_plugin.github_core.collectors.github_collector.identity import ruleset_id, status_check_id, workflow_id

from tap_grid.exceptions import EdgePropertyValidationError
from tap_grid.models import Entity
from tap_grid.registry import get_model_class
from tap_grid.services import create_edge, create_node

from .envelopes import edge_from


def _create(type_slug: str, payload: dict):
    result = create_node(type_slug, payload)
    assert result.success, f"create_node failed: {result.errors}"
    entity = Entity.objects.get(pk=result.entity_id)
    return get_model_class(type_slug).objects.get(entity=entity)


def _collector() -> GithubCollector:
    c = GithubCollector.__new__(GithubCollector)
    c.events = []  # type: ignore[attr-defined]
    c.record_warn = lambda site, code, message, **kw: c.events.append(("warn", code, kw.get("message_data")))  # type: ignore[method-assign]
    c.record_info = lambda site, code, message, **kw: c.events.append(("info", code, kw.get("message_data")))  # type: ignore[method-assign]
    return c


_DIMS = {"git.host": "github.com", "github.owner": "acme", "github.surface": "rules"}


def _rule(contexts: list[dict[str, Any]], *, strict: bool = False, on_create: bool = False) -> dict[str, Any]:
    return {
        "type": "required_status_checks",
        "parameters": {
            "required_status_checks": contexts,
            "strict_required_status_checks_policy": strict,
            "do_not_enforce_on_create": on_create,
        },
    }


def _job(c: GithubCollector, repo: str, wf_id: int, key: str, name: str | None = None) -> Any:
    wf = workflow_id(repo, wf_id)
    c._walk_state()["job_names"].append(
        {"owner": repo.partition("/")[0], "repo": repo, "wf_uuid": wf, "job_key": key, "job_name": name or key,
         "dims": {"git.host": "github.com", "github.owner": repo.partition("/")[0],
                  "github.repo": repo.partition("/")[2], "github.surface": "actions"}}
    )
    return wf


def _emit(c: GithubCollector) -> tuple[list[dict], list[dict]]:
    nodes: list[dict] = []
    edges: list[dict] = []
    c._emit_status_checks(nodes, edges)
    return nodes, edges


class TestIdentity:
    def test_owner_scoped_and_case_preserving(self) -> None:
        assert status_check_id("acme", "gate") != status_check_id("other", "gate")
        assert status_check_id("acme", "Gate") != status_check_id("acme", "gate")
        assert status_check_id.__code__.co_argcount == 2, "(owner, context) — never a repository"


class TestNameConfidence:
    def test_exact_and_matrix_template_and_nothing(self) -> None:
        assert _check_name_confidence("gate", "gate") == "exact"
        assert _check_name_confidence("test", "test (3.12)") == "matrix_template"
        assert _check_name_confidence("test", "tests") is None
        assert _check_name_confidence("gate", "gate / build") is None  # reusable-workflow composition: a gap


class TestRequirements:
    def test_one_node_per_context_with_the_rule_qualifiers_on_the_edge(self) -> None:
        c = _collector()
        rs = ruleset_id("acme", 1)
        c._register_required_checks("acme", rs, "main", [_rule([{"context": "gate", "integration_id": 15368}], strict=True)], _DIMS)
        nodes, edges = _emit(c)
        assert [n["entity"]["entity_type"] for n in nodes] == ["github_core__status_check"]
        assert nodes[0]["node"] == {"owner_login": "acme", "context": "gate", "name": "gate", "configuration": {}, "tags": {}}
        assert "github.repo" not in nodes[0]["entity"]["dimensions"]
        req = [e for e in edges if e["edge"]["edge_type"] == "REQUIRES_CHECK__github_core"]
        assert len(req) == 1 and edge_from(req[0]) == str(rs)
        assert req[0]["edge"]["properties"] == {"integration_id": 15368, "strict": True, "do_not_enforce_on_create": False}

    def test_two_rulesets_requiring_one_context_fan_in(self) -> None:
        c = _collector()
        c._register_required_checks("acme", ruleset_id("acme", 1), "a", [_rule([{"context": "gate", "integration_id": None}])], _DIMS)
        c._register_required_checks("acme", ruleset_id("acme", 2), "b", [_rule([{"context": "gate", "integration_id": 15368}])], _DIMS)
        nodes, edges = _emit(c)
        assert len(nodes) == 1
        assert sum(1 for e in edges if e["edge"]["edge_type"] == "REQUIRES_CHECK__github_core") == 2

    def test_a_refused_detail_is_counted_not_read_as_no_requirement(self) -> None:
        """The type-only GraphQL fallback: a rule with no parameters. Nothing is minted, the
        ruleset is warned about, and the summary carries the count."""
        c = _collector()
        c._register_required_checks("acme", ruleset_id("acme", 1), "main", [{"type": "required_status_checks"}], _DIMS)
        nodes, edges = _emit(c)
        assert nodes == [] and edges == []
        warn = next(e for e in c.events if e[1] == "REQUIRED_CHECKS_UNOBSERVABLE")  # type: ignore[attr-defined]
        assert warn[2] == {"ruleset": "main", "owner": "acme"}
        summary = next(e for e in c.events if e[1] == "STATUS_CHECKS")  # type: ignore[attr-defined]
        assert summary[2]["unobservable"] == 1 and summary[2]["contexts"] == 0

    def test_nothing_required_nothing_said(self) -> None:
        c = _collector()
        c._register_required_checks("acme", ruleset_id("acme", 1), "main", [{"type": "deletion"}], _DIMS)
        assert _emit(c) == ([], [])
        assert c.events == []  # type: ignore[attr-defined]


class TestProducers:
    def test_an_exact_job_name_in_any_repository_of_the_owner_produces_the_check(self) -> None:
        c = _collector()
        c._register_required_checks("acme", ruleset_id("acme", 1), "main", [_rule([{"context": "gate", "integration_id": 15368}])], _DIMS)
        wf_a = _job(c, "acme/a", 1, "tap", name="gate")
        wf_b = _job(c, "acme/b", 2, "gate")
        _job(c, "other/c", 3, "gate")  # another owner: not this requirement's scope
        _, edges = _emit(c)
        produces = [e for e in edges if e["edge"]["edge_type"] == "PRODUCES_CHECK__github_core"]
        assert {edge_from(e) for e in produces} == {str(wf_a), str(wf_b)}
        assert all(e["edge"]["properties"]["confidence"] == "exact" for e in produces)
        assert next(e for e in produces if edge_from(e) == str(wf_a))["edge"]["properties"]["job_key"] == "tap"
        assert produces[0]["entity"]["dimensions"]["github.repo"] in {"a", "b"}

    def test_a_matrix_template_is_reported_as_inference(self) -> None:
        c = _collector()
        c._register_required_checks("acme", ruleset_id("acme", 1), "main", [_rule([{"context": "test (3.12)", "integration_id": None}])], _DIMS)
        _job(c, "acme/a", 1, "test")
        _, edges = _emit(c)
        produces = [e for e in edges if e["edge"]["edge_type"] == "PRODUCES_CHECK__github_core"]
        assert len(produces) == 1 and produces[0]["edge"]["properties"]["confidence"] == "matrix_template"

    def test_an_app_produced_requirement_gets_no_workflow_producer(self) -> None:
        """SonarCloud's check is not a job's; deriving a producer from a same-named job would be
        a false join."""
        c = _collector()
        c._register_required_checks("acme", ruleset_id("acme", 1), "main", [_rule([{"context": "SonarCloud", "integration_id": 12345}])], _DIMS)
        _job(c, "acme/a", 1, "SonarCloud")
        nodes, edges = _emit(c)
        assert len(nodes) == 1
        assert not [e for e in edges if e["edge"]["edge_type"] == "PRODUCES_CHECK__github_core"]
        assert next(e for e in c.events if e[1] == "STATUS_CHECKS")[2]["unproduced"] == []  # type: ignore[attr-defined]

    def test_mixed_requirements_keep_compatibility_on_the_requirement_edge(self) -> None:
        """Two rulesets name one context: one App-only, one Actions. The shared node carries
        the workflow producer the second admits; the first's REQUIRES_CHECK still says 12345,
        which is what a traversal must read before calling the producer satisfying
        (PR #62 review)."""
        c = _collector()
        c._register_required_checks("acme", ruleset_id("acme", 1), "app-only", [_rule([{"context": "gate", "integration_id": 12345}])], _DIMS)
        c._register_required_checks("acme", ruleset_id("acme", 2), "actions", [_rule([{"context": "gate", "integration_id": 15368}])], _DIMS)
        _job(c, "acme/a", 1, "gate")
        nodes, edges = _emit(c)
        assert len(nodes) == 1
        assert sum(1 for e in edges if e["edge"]["edge_type"] == "PRODUCES_CHECK__github_core") == 1
        by_ruleset = {edge_from(e): e["edge"]["properties"]["integration_id"]
                      for e in edges if e["edge"]["edge_type"] == "REQUIRES_CHECK__github_core"}
        assert by_ruleset == {str(ruleset_id("acme", 1)): 12345, str(ruleset_id("acme", 2)): 15368}

    def test_two_rulesets_in_two_repositories_naming_one_context_share_one_owner_scoped_node(self) -> None:
        """The node's dims come from the type's defaults plus the owner, never from whichever
        ruleset named the context first (PR #62 review): two repository rulesets in two repos
        → one node, no `github.repo`, both REQUIRES_CHECK edges."""
        c = _collector()
        c._register_required_checks("acme", ruleset_id("acme", 1), "a-main", [_rule([{"context": "gate", "integration_id": None}])], {**_DIMS, "github.repo": "a"})
        c._register_required_checks("acme", ruleset_id("acme", 2), "b-main", [_rule([{"context": "gate", "integration_id": None}])], {**_DIMS, "github.repo": "b"})
        nodes, edges = _emit(c)
        assert len(nodes) == 1
        dims = nodes[0]["entity"]["dimensions"]
        assert "github.repo" not in dims
        assert dims == {"github.observation": "declaration", "git.host": "github.com",
                        "github.surface": "rules", "github.owner": "acme"}
        assert sum(1 for e in edges if e["edge"]["edge_type"] == "REQUIRES_CHECK__github_core") == 2

    def test_the_site_tokens_are_well_formed(self) -> None:
        """The two sites that carry the unobservability signal (PR #62 review: they were a
        split-and-empty pair, which no monkeypatched test could see)."""
        import re
        from tap_plugin.github_core.collectors.github_collector import collector as mod

        for name in ("_SITE_REQUIRED_CHECKS_UNOBSERVABLE", "_SITE_STATUS_CHECKS"):
            assert re.fullmatch(r"[0-9a-f]{4}", getattr(mod, name)), name
        assert mod._SITE_REQUIRED_CHECKS_UNOBSERVABLE != mod._SITE_STATUS_CHECKS

    def test_a_producible_context_with_no_producer_is_named_in_the_summary(self) -> None:
        c = _collector()
        c._register_required_checks("acme", ruleset_id("acme", 1), "main", [_rule([{"context": "gate", "integration_id": 15368}])], _DIMS)
        _job(c, "acme/a", 1, "build")
        _emit(c)
        assert next(e for e in c.events if e[1] == "STATUS_CHECKS")[2]["unproduced"] == ["acme#gate"]  # type: ignore[attr-defined]


@pytest.mark.django_db
class TestSchemas:
    def test_produces_check_requires_a_stated_confidence(self) -> None:
        wf = _create("github_core__github_workflow", {"full_name": "o/r", "workflow_id": 1, "name": "ci"})
        check = _create("github_core__status_check", {"owner_login": "o", "context": "gate"})
        with pytest.raises(EdgePropertyValidationError):
            create_edge(wf.entity, check.entity, "PRODUCES_CHECK__github_core", {"job_key": "gate", "job_name": "gate"})
        with pytest.raises(EdgePropertyValidationError):
            create_edge(wf.entity, check.entity, "PRODUCES_CHECK__github_core",
                        {"job_key": "gate", "job_name": "gate", "confidence": "probably"})
        edge = create_edge(wf.entity, check.entity, "PRODUCES_CHECK__github_core",
                           {"job_key": "gate", "job_name": "gate", "confidence": "exact"})
        assert edge.properties["confidence"] == "exact"

    def test_requires_check_carries_the_qualifiers_and_refuses_enforcement(self) -> None:
        rs = _create(
            "github_core__github_ruleset",
            {"ruleset_id": 1, "name": "main", "bypass_observability": "unobservable", "bypass_actor_count": None},
        )
        check = _create("github_core__status_check", {"owner_login": "o", "context": "gate"})
        with pytest.raises(EdgePropertyValidationError):
            create_edge(rs.entity, check.entity, "REQUIRES_CHECK__github_core",
                        {"strict": True, "do_not_enforce_on_create": False, "enforcement": "active"})
        edge = create_edge(rs.entity, check.entity, "REQUIRES_CHECK__github_core",
                           {"integration_id": None, "strict": True, "do_not_enforce_on_create": False})
        assert edge.properties["integration_id"] is None

    def test_the_node_is_owner_scoped_rules_surface(self) -> None:
        check = _create("github_core__status_check", {"owner_login": "o", "context": "gate"})
        check.entity.refresh_from_db()
        assert check.entity.dimensions.get("github.surface") == "rules"
        assert check.get_name() == "gate"
