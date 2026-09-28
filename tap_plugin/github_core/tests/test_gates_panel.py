"""The gates panel: one row per repository, three states, never two (req-github-core-gates-panel).

Spec: plugins/github_core/specs/spec-github-core-gates-panel.md
Issue: unified-systems-com/github-core-tap#65

Two layers. ``build_rows`` is pure over envelopes, so the derivation is pinned against hand-built
graphs. One test builds the graph through the service layer and reads it back through the
panel's own Gryphon queries — the load-bearing proof that the multi-hop envelopes carry the
edges ``build_rows`` folds (an assumption a pure test cannot make).
"""

from __future__ import annotations

from typing import Any

import pytest
import tap_plugin.github_core.models as github  # noqa: F401 — trigger model registration
from tap_plugin.github_core.panels.gates import (
    GITHUB_ACTIONS_INTEGRATION_ID,
    QUERIES,
    GatesPanelType,
    _fetch,
    build_rows,
)

from tap_grid.models import Entity
from tap_grid.registry import get_model_class
from tap_grid.services import create_edge, create_node

# ---------------------------------------------------------------------------
# hand-built envelopes
# ---------------------------------------------------------------------------


def _node(
    entity_id: str, entity_type: str, spine_name: str, **data: Any
) -> dict[str, Any]:
    return {
        "entity_id": entity_id,
        "entity_type": entity_type,
        "name": spine_name,
        "dimensions": {},
        "data": data,
    }


def _edge(from_id: str, to_id: str, edge_type: str, **props: Any) -> dict[str, Any]:
    return {
        "entity_id": f"e-{from_id}-{to_id}-{edge_type}",
        "entity_type": "edge",
        "data": {
            "from_entity_id": from_id,
            "to_entity_id": to_id,
            "edge_type": edge_type,
            "properties": props,
        },
    }


def _repo(rid: str, full_name: str, default_branch: str = "main") -> dict[str, Any]:
    return _node(
        rid,
        "github_core__github_repository",
        full_name,
        full_name=full_name,
        owner_login=full_name.partition("/")[0],
        name=full_name.rpartition("/")[2],
        default_branch=default_branch,
        html_url=f"https://github.com/{full_name}",
    )


def _ruleset(
    rid: str,
    name: str,
    *,
    rules: list[dict[str, Any]] | None = None,
    bypass: str = "unobservable",
    count: int | None = None,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    target: str | None = "branch",
    enforcement: str = "active",
) -> dict[str, Any]:
    return _node(
        rid,
        "github_core__github_ruleset",
        name,
        target=target,
        enforcement=enforcement,
        conditions={
            "ref_name": {
                "include": include if include is not None else ["~DEFAULT_BRANCH"],
                "exclude": exclude or [],
            }
        },
        rules=rules or [],
        bypass_observability=bypass,
        bypass_actor_count=count,
    )


def _check(cid: str, context: str) -> dict[str, Any]:
    return _node(
        cid, "github_core__status_check", context, owner_login="acme", context=context
    )


def _workflow(wid: str, name: str) -> dict[str, Any]:
    return _node(
        wid,
        "github_core__github_workflow",
        name,
        name=name,
        path=f".github/workflows/{name}.yml",
    )


_RSC_RULE = {
    "type": "required_status_checks",
    "parameters": {"required_status_checks": [{"context": "gate"}]},
}
_RSC_TYPE_ONLY = {"type": "required_status_checks"}
_PR_RULE = {"type": "pull_request"}


def _env(
    *,
    repos=(),
    rulesets=(),
    checks=(),
    workflows=(),
    protects=(),
    requires=(),
    produces=(),
    defines=(),
) -> dict:
    """Assemble the five envelopes the way ``_fetch`` returns them (nodes per query, edges per chain)."""
    return {
        "repositories": {"nodes": list(repos), "edges": []},
        "protects": {
            "nodes": [*rulesets, *repos],
            "edges": [
                _edge(a, b, "PROTECTS_REPOSITORY__github_core") for a, b in protects
            ],
        },
        "requires": {
            "nodes": [*rulesets, *checks],
            "edges": [
                _edge(
                    a,
                    b,
                    "REQUIRES_CHECK__github_core",
                    integration_id=i,
                    strict=False,
                    do_not_enforce_on_create=False,
                )
                for a, b, i in requires
            ],
        },
        "produces": {
            "nodes": [*workflows, *checks],
            "edges": [
                _edge(
                    a,
                    b,
                    "PRODUCES_CHECK__github_core",
                    job_key=k,
                    job_name=k,
                    confidence=c,
                )
                for a, b, k, c in produces
            ],
        },
        "defines": {
            "nodes": [*repos, *workflows],
            "edges": [_edge(a, b, "DEFINES_WORKFLOW__github_core") for a, b in defines],
        },
    }


def _row(rows: list[dict[str, Any]], full_name: str) -> dict[str, Any]:
    return next(r["data"] for r in rows if r["data"]["full_name"] == full_name)


class TestBuildRows:
    def test_no_protects_edge_reads_no_ruleset_observed_never_unprotected(self) -> None:
        rows = build_rows(_env(repos=[_repo("r1", "acme/a")]))
        d = _row(rows, "acme/a")
        assert d["gate_state"] == "no ruleset observed"
        assert d["bypass"] == "no ruleset observed"
        assert d["requires_pr"] is None
        assert "unprotected" not in str(d)

    def test_workflow_app_and_nothing_are_three_columns(self) -> None:
        env = _env(
            repos=[_repo("r1", "acme/a")],
            rulesets=[
                _ruleset(
                    "rs1",
                    "main-required-checks",
                    rules=[_RSC_RULE, _PR_RULE],
                    bypass="unobservable",
                )
            ],
            checks=[
                _check("c-gate", "gate"),
                _check("c-sonar", "SonarCloud Code Analysis"),
                _check("c-lint", "lint"),
            ],
            workflows=[_workflow("w1", "ci")],
            protects=[("rs1", "r1")],
            requires=[
                ("rs1", "c-gate", GITHUB_ACTIONS_INTEGRATION_ID),
                ("rs1", "c-sonar", 12526),
                ("rs1", "c-lint", None),
            ],
            produces=[("w1", "c-gate", "gate", "exact")],
            defines=[("r1", "w1")],
        )
        d = _row(build_rows(env), "acme/a")
        assert d["checks_workflow"] == ["gate ← ci"]
        assert d["checks_app"] == ["SonarCloud Code Analysis (app 12526)"]
        assert d["checks_unproduced"] == ["lint"]
        assert d["gate_state"] == "nothing produces a check"
        assert d["requires_pr"] is True
        assert d["bypass"] == "not observable"
        assert d["rulesets_text"] == "main-required-checks (active)"

    def test_a_producer_in_another_repository_does_not_satisfy_this_gate(self) -> None:
        env = _env(
            repos=[_repo("r1", "acme/a"), _repo("r2", "acme/b")],
            rulesets=[_ruleset("rs1", "org-checks", rules=[_RSC_RULE])],
            checks=[_check("c-gate", "gate")],
            workflows=[_workflow("w2", "ci")],
            protects=[("rs1", "r1"), ("rs1", "r2")],
            requires=[("rs1", "c-gate", None)],
            produces=[("w2", "c-gate", "gate", "matrix_template")],
            defines=[("r2", "w2")],
        )
        rows = build_rows(env)
        assert _row(rows, "acme/b")["checks_workflow"] == [
            "gate ← ci (matrix_template)"
        ]
        a = _row(rows, "acme/a")
        assert a["checks_unproduced"] == ["gate (only elsewhere: ci (matrix_template))"]
        assert a["gate_state"] == "nothing produces a check"
        # worst first
        assert [r["data"]["full_name"] for r in rows] == ["acme/a", "acme/b"]

    def test_type_only_rule_reads_not_observable_never_none_required(self) -> None:
        env = _env(
            repos=[_repo("r1", "acme/a")],
            rulesets=[_ruleset("rs1", "refused", rules=[_RSC_TYPE_ONLY])],
            protects=[("rs1", "r1")],
        )
        d = _row(build_rows(env), "acme/a")
        assert d["gate_state"] == "required checks not observable"
        assert d["checks_state"] == "required checks not observable"
        assert d["checks_required"] == []

    def test_bypass_is_the_worst_of_the_governing_rulesets(self) -> None:
        env = _env(
            repos=[_repo("r1", "acme/a"), _repo("r2", "acme/b"), _repo("r3", "acme/c")],
            rulesets=[
                _ruleset("rs-obs", "observed-empty", bypass="observed", count=0),
                _ruleset("rs-cnt", "counted", bypass="counted", count=2),
                _ruleset("rs-un", "hidden", bypass="unobservable"),
                _ruleset("rs-obs3", "observed-three", bypass="observed", count=3),
            ],
            protects=[
                ("rs-obs", "r1"),
                ("rs-un", "r1"),
                ("rs-cnt", "r2"),
                ("rs-obs3", "r3"),
            ],
        )
        rows = build_rows(env)
        assert _row(rows, "acme/a")["bypass"] == "not observable"
        assert _row(rows, "acme/b")["bypass"] == "counted: 2"
        assert _row(rows, "acme/c")["bypass"] == "observed: 3"

    def test_an_observed_empty_bypass_list_is_a_fact(self) -> None:
        env = _env(
            repos=[_repo("r1", "acme/a")],
            rulesets=[_ruleset("rs", "x", bypass="observed", count=0)],
            protects=[("rs", "r1")],
        )
        assert _row(build_rows(env), "acme/a")["bypass"] == "observed: none"

    def test_missing_vs_peers_names_the_outlier(self) -> None:
        env = _env(
            repos=[_repo("r1", "acme/a"), _repo("r2", "acme/b"), _repo("r3", "acme/c")],
            rulesets=[
                _ruleset("rs-full", "full", rules=[_RSC_RULE]),
                _ruleset("rs-thin", "thin", rules=[_RSC_RULE]),
            ],
            checks=[_check("c-gate", "gate"), _check("c-dco", "dco")],
            workflows=[
                _workflow("w1", "ci"),
                _workflow("w2", "ci"),
                _workflow("w3", "ci"),
            ],
            protects=[("rs-full", "r1"), ("rs-full", "r2"), ("rs-thin", "r3")],
            requires=[
                ("rs-full", "c-gate", None),
                ("rs-full", "c-dco", None),
                ("rs-thin", "c-gate", None),
            ],
            produces=[
                ("w1", "c-gate", "gate", "exact"),
                ("w1", "c-dco", "dco", "exact"),
                ("w2", "c-gate", "gate", "exact"),
                ("w2", "c-dco", "dco", "exact"),
                ("w3", "c-gate", "gate", "exact"),
            ],
            defines=[("r1", "w1"), ("r2", "w2"), ("r3", "w3")],
        )
        rows = build_rows(env)
        assert _row(rows, "acme/c")["missing_vs_peers"] == ["dco"]
        assert _row(rows, "acme/a")["missing_vs_peers"] == []

    def test_tag_and_non_default_branch_rulesets_do_not_govern(self) -> None:
        env = _env(
            repos=[_repo("r1", "acme/a")],
            rulesets=[
                _ruleset("rs-tag", "tags", target="tag", include=["refs/tags/**"]),
                _ruleset("rs-rel", "release", include=["refs/heads/release/*"]),
            ],
            protects=[("rs-tag", "r1"), ("rs-rel", "r1")],
        )
        assert _row(build_rows(env), "acme/a")["gate_state"] == "no ruleset observed"

    def test_default_branch_named_explicitly_governs(self) -> None:
        env = _env(
            repos=[_repo("r1", "acme/a", default_branch="trunk")],
            rulesets=[
                _ruleset(
                    "rs", "trunk-only", include=["refs/heads/trunk"], rules=[_PR_RULE]
                )
            ],
            protects=[("rs", "r1")],
        )
        d = _row(build_rows(env), "acme/a")
        assert d["gate_state"] == "gated"
        assert d["requires_pr"] is True
        assert d["checks_state"] == "none required"

    def test_evaluate_and_disabled_rulesets_are_listed_but_gate_nothing(self) -> None:
        env = _env(
            repos=[_repo("r1", "acme/a")],
            rulesets=[
                _ruleset(
                    "rs-eval", "dry-run", rules=[_PR_RULE], enforcement="evaluate"
                ),
                _ruleset(
                    "rs-off", "switched-off", rules=[_PR_RULE], enforcement="disabled"
                ),
            ],
            protects=[("rs-eval", "r1"), ("rs-off", "r1")],
        )
        d = _row(build_rows(env), "acme/a")
        assert d["gate_state"] == "no ruleset observed"
        assert d["requires_pr"] is None
        assert (
            d["rulesets_text"]
            == "dry-run (evaluate, not enforced); switched-off (disabled, not enforced)"
        )

    def test_an_exclude_token_beats_an_include_and_a_missing_target_fails_closed(
        self,
    ) -> None:
        env = _env(
            repos=[_repo("r1", "acme/a"), _repo("r2", "acme/b"), _repo("r3", "acme/c")],
            rulesets=[
                _ruleset(
                    "rs-x",
                    "all-but-default",
                    include=["~ALL"],
                    exclude=["~DEFAULT_BRANCH"],
                    rules=[_PR_RULE],
                ),
                _ruleset(
                    "rs-n",
                    "all-but-main",
                    include=["~ALL"],
                    exclude=["refs/heads/main"],
                    rules=[_PR_RULE],
                ),
                _ruleset("rs-t", "no-target", target=None, rules=[_PR_RULE]),
            ],
            protects=[("rs-x", "r1"), ("rs-n", "r2"), ("rs-t", "r3")],
        )
        rows = build_rows(env)
        assert {r["data"]["gate_state"] for r in rows} == {"no ruleset observed"}

    def test_peers_are_the_same_owner_only(self) -> None:
        env = _env(
            repos=[
                _repo("a1", "acme/a"),
                _repo("a2", "acme/b"),
                _repo("b1", "beta/x"),
                _repo("b2", "beta/y"),
            ],
            rulesets=[
                _ruleset("rs-beta", "beta-checks", rules=[_RSC_RULE]),
                _ruleset("rs-acme", "acme-pr", rules=[_PR_RULE]),
            ],
            checks=[_check("c-dco", "dco")],
            workflows=[_workflow("w1", "ci"), _workflow("w2", "ci")],
            protects=[
                ("rs-beta", "b1"),
                ("rs-beta", "b2"),
                ("rs-acme", "a1"),
                ("rs-acme", "a2"),
            ],
            requires=[("rs-beta", "c-dco", None)],
            produces=[("w1", "c-dco", "dco", "exact"), ("w2", "c-dco", "dco", "exact")],
            defines=[("b1", "w1"), ("b2", "w2")],
        )
        rows = build_rows(env)
        assert _row(rows, "acme/a")["missing_vs_peers"] == []
        assert _row(rows, "beta/x")["missing_vs_peers"] == []

    def test_repository_name_is_the_short_name(self) -> None:
        rows = build_rows(_env(repos=[_repo("r1", "acme/a")]))
        assert rows[0]["data"]["name"] == "a"
        assert rows[0]["data"]["owner"] == "acme"

    def test_rows_are_node_shaped_for_the_table_renderer(self) -> None:
        rows = build_rows(_env(repos=[_repo("r1", "acme/a")]))
        assert rows[0]["entity_id"] == "r1"
        assert rows[0]["entity_type"] == "github_core__github_repository"
        assert rows[0]["data"]["name"] == "a"
        assert rows[0]["data"]["html_url"] == "https://github.com/acme/a"


# ---------------------------------------------------------------------------
# through the graph
# ---------------------------------------------------------------------------


def _create(type_slug: str, payload: dict[str, Any]):
    result = create_node(type_slug, payload)
    assert result.success, f"create_node failed: {result.errors}"
    entity = Entity.objects.get(pk=result.entity_id)
    return get_model_class(type_slug).objects.get(entity=entity)


@pytest.mark.django_db(transaction=True, databases=["default", "search_readonly"])
class TestThroughTheGraph:
    def test_the_declared_queries_carry_the_edges_the_fold_needs(self) -> None:
        """Service-layer graph in, panel queries out: PROTECTS, REQUIRES_CHECK, PRODUCES_CHECK and
        DEFINES_WORKFLOW all arrive as chain edges of the multi-hop envelope, and the row says
        what the graph says."""
        repo = _create(
            "github_core__github_repository",
            {
                "full_name": "acme/a",
                "name": "a",
                "owner_login": "acme",
                "default_branch": "main",
                "html_url": "https://github.com/acme/a",
            },
        )
        other = _create(
            "github_core__github_repository",
            {
                "full_name": "acme/b",
                "name": "b",
                "owner_login": "acme",
                "default_branch": "main",
            },
        )
        rs = _create(
            "github_core__github_ruleset",
            {
                "owner_login": "acme",
                "ruleset_id": 1,
                "name": "main-required-checks",
                "target": "branch",
                "enforcement": "active",
                "source": "acme",
                "source_type": "Organization",
                "conditions": {
                    "ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}
                },
                "rules": [_RSC_RULE, _PR_RULE],
                "bypass_observability": "unobservable",
            },
        )
        gate = _create(
            "github_core__status_check", {"owner_login": "acme", "context": "gate"}
        )
        sonar = _create(
            "github_core__status_check",
            {"owner_login": "acme", "context": "SonarCloud Code Analysis"},
        )
        wf = _create(
            "github_core__github_workflow",
            {
                "full_name": "acme/a",
                "workflow_id": 7,
                "name": "ci",
                "path": ".github/workflows/ci.yml",
            },
        )
        create_edge(
            rs.entity,
            repo.entity,
            "PROTECTS_REPOSITORY__github_core",
            {},
        )
        create_edge(
            rs.entity,
            gate.entity,
            "REQUIRES_CHECK__github_core",
            {
                "integration_id": GITHUB_ACTIONS_INTEGRATION_ID,
                "strict": False,
                "do_not_enforce_on_create": False,
            },
        )
        create_edge(
            rs.entity,
            sonar.entity,
            "REQUIRES_CHECK__github_core",
            {
                "integration_id": 12526,
                "strict": False,
                "do_not_enforce_on_create": False,
            },
        )
        create_edge(
            wf.entity,
            gate.entity,
            "PRODUCES_CHECK__github_core",
            {"job_key": "gate", "job_name": "gate", "confidence": "exact"},
        )
        create_edge(repo.entity, wf.entity, "DEFINES_WORKFLOW__github_core", {})

        rows = build_rows(_fetch(QUERIES))
        a = _row(rows, "acme/a")
        assert a["gate_state"] == "gated"
        assert a["checks_workflow"] == ["gate ← ci"]
        assert a["checks_app"] == ["SonarCloud Code Analysis (app 12526)"]
        assert a["checks_unproduced"] == []
        assert a["bypass"] == "not observable"
        assert a["requires_pr"] is True
        b = _row(rows, "acme/b")
        assert b["gate_state"] == "no ruleset observed"
        assert other.entity_id  # the unprotected repository is a row, not an absence
        # the extended layer gives the row a viewer url, like any table row
        assert "display" in next(r for r in rows if r["data"]["full_name"] == "acme/a")

    def test_get_view_context_returns_the_table_contract(self) -> None:
        from django.test import RequestFactory

        from tap_web.models import Panel

        _create(
            "github_core__github_repository",
            {"full_name": "acme/a", "name": "a", "owner_login": "acme"},
        )
        panel = Panel.objects.create(
            slug="gates", name="Gates", view=GatesPanelType.view, config={}
        )
        ctx = GatesPanelType.get_view_context(
            panel, RequestFactory().get("/panel/gates/")
        )
        assert ctx["table_error"] is None
        assert [r["data"]["full_name"] for r in ctx["table_nodes"]] == ["acme/a"]
        assert ctx["table_meta"]["total_count"] == 1
        assert [c["field"] for c in ctx["table_columns"]][:2] == [
            "data.name",
            "data.gate_state",
        ]
        assert ctx["table_data_script_id"].endswith(str(panel.entity_id))
