"""github-gates — one row per repository: what gates its default branch, and what we cannot see.

Spec: plugins/github_core/specs/spec-github-core-gates-panel.md (req-github-core-gates-panel).
Issue: unified-systems-com/github-core-tap#65.

The gate posture of a repository is a join the graph already holds, edge by edge:

    ruleset -PROTECTS->        repository       which rulesets govern it (org rulesets are ONE node
                                                protecting many repositories; the association is
                                                the edge, never a dimension on the ruleset)
    ruleset -REQUIRES_CHECK->  status_check     the contexts a commit must pass (#62)
    workflow -PRODUCES_CHECK-> status_check     what produces each context, derived from job
                                                display names and SAYING so (`confidence`)
    repository -DEFINES_WORKFLOW-> workflow     whether the producer lives in THIS repository

This panel folds those into a row per repository and hands the rows to the standard table
renderer (``tap_web/panels/table_panel.html`` + ``panel-table.js``) shaped like search-envelope
nodes, so the declarative ``columns`` / formatters / header tooltips / refresh of a table panel
apply unchanged. It is a panel *type* rather than a declarative table because a table panel
renders one row per node of one search, and this row is a four-edge join with per-row
aggregation — Gryphon's only aggregate is ``COUNT`` (req-grid-gryphon-count).

Reads go through Gryphon (``execute_gryphon_raw``, the sanctioned raw-query chokepoint gated on
``grid.read``); no model is imported on the read path. The five reads are over the STRUCTURAL
nodes of the observed account — repositories, rulesets, workflows, required checks — never runs
or jobs, so their size is the account's shape, not its history; a table over them is whole or
it is wrong, which is why they carry no LIMIT. Every fact rendered is derived ONCE here
from the collected edges — the panel never re-derives a producer from a job name; that is the
collector's derivation (`_emit_status_checks`), and it is what the ``PRODUCES_CHECK`` edge is for.

Three states, never two — the whole reason this product exists:

- a repository with no ``PROTECTS`` edge reads *no ruleset observed*, not "unprotected";
- a governing ruleset whose ``required_status_checks`` rule came back type-only (detail refused,
  #64) reads *required checks not observable*, never "none required";
- the bypass cell is the worst of the governing rulesets' ``bypass_observability`` —
  ``unobservable`` > ``counted`` > ``observed`` — and an ``observed`` empty list is a fact.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import TYPE_CHECKING, Any, ClassVar

from tap_web.panel import TABULATOR_CSS, TABULATOR_JS

if TYPE_CHECKING:
    from django.http import HttpRequest

    from tap_grid.grift.subgraph import SubgraphLayer
    from tap_web.models import Panel

logger = logging.getLogger(__name__)

#: GitHub's own Actions integration id — a required check carrying it (or no integration at all)
#: may be produced by a workflow; any other id names an App, and no workflow can satisfy it.
GITHUB_ACTIONS_INTEGRATION_ID = 15368

#: The ruleset condition token GitHub uses for "whatever the default branch is".
DEFAULT_BRANCH_TOKEN = "~DEFAULT_BRANCH"

#: Fraction of gated repositories that must require a context for it to count as what the
#: account "shares" (req-git-serious-configured-the-same-1). Half, so a check required by the
#: majority is a peer expectation and a check required by one repository is not.
PEER_SHARE_FRACTION = 0.5

# The declared reads. Bare-variable RETURN on a chain is the multi-hop graph envelope
# (req-grid-gryphon-multihop-envelope-2): the named nodes plus the edges connecting them.
QUERIES: dict[str, str] = {
    "repositories": "MATCH (r:github_core__github_repository) RETURN r",
    "protects": (
        "MATCH (rs:github_core__github_ruleset)-[:PROTECTS_REPOSITORY__github_core]->(r:github_core__github_repository) "
        "RETURN rs, r"
    ),
    "requires": (
        "MATCH (rs:github_core__github_ruleset)-[:REQUIRES_CHECK__github_core]->(c:github_core__status_check) "
        "RETURN rs, c"
    ),
    "produces": (
        "MATCH (w:github_core__github_workflow)-[:PRODUCES_CHECK__github_core]->(c:github_core__status_check) "
        "RETURN w, c"
    ),
    "defines": (
        "MATCH (r:github_core__github_repository)-[:DEFINES_WORKFLOW__github_core]->(w:github_core__github_workflow) "
        "RETURN r, w"
    ),
}

#: Bypass observability, worst first. Unknown values sort as unobservable — a value the
#: collector did not define must not read as reassuring.
_BYPASS_RANK = {"unobservable": 0, "counted": 1, "observed": 2}

#: Gate state, worst first — the default row order.
_GATE_RANK = {
    "no ruleset observed": 0,
    "required checks not observable": 1,
    "nothing produces a check": 2,
    "gated": 3,
}

DEFAULT_COLUMNS: list[dict[str, Any]] = [
    {
        "field": "data.name",
        "title": "Repository",
        "widthGrow": 1,
        "formatter": "link",
        "formatter_params": {"href_field": "data.html_url"},
        "header_tooltip": "The repository within the observed account. Opens it on GitHub.",
    },
    {
        "field": "data.gate_state",
        "title": "Gate",
        "width": 200,
        "header_tooltip": (
            "The worst thing true of this repository's default branch: no ruleset observed (nothing "
            "governs it, or the credential could not see what does); required checks not observable "
            "(a ruleset requires checks but GitHub withheld WHICH); nothing produces a check (a required "
            "context no observed workflow or app produces — the branch cannot merge); gated."
        ),
    },
    {
        "field": "data.rulesets_text",
        "title": "Governed by",
        "widthGrow": 2,
        "tooltip": "full_value",
        "header_tooltip": "The rulesets whose conditions cover the default branch, with their enforcement.",
    },
    {
        "field": "data.requires_pr",
        "title": "PR",
        "width": 56,
        "formatter": "tickDash",
        "header_tooltip": "A pull_request rule is in force: no direct push to the default branch.",
    },
    {
        "field": "data.checks_workflow_text",
        "title": "Checks · workflow",
        "widthGrow": 2,
        "tooltip": "full_value",
        "header_tooltip": (
            "Required contexts a workflow IN THIS REPOSITORY produces, with the producing workflow "
            "and how sure the collector is (exact job name, or a matrix template)."
        ),
    },
    {
        "field": "data.checks_app_text",
        "title": "Checks · app",
        "widthGrow": 1,
        "tooltip": "full_value",
        "header_tooltip": "Required contexts an installed App produces (integration id shown). No workflow can satisfy these.",
    },
    {
        "field": "data.checks_unproduced_text",
        "title": "Nothing produces",
        "widthGrow": 2,
        "tooltip": "full_value",
        "header_tooltip": (
            "Required contexts with no observed producer in this repository. A workflow elsewhere in the "
            "account that produces the same context is named — it does not satisfy THIS repository's gate."
        ),
    },
    {
        "field": "data.bypass",
        "title": "Bypass",
        "width": 150,
        "header_tooltip": (
            "Who may bypass the governing rulesets: not observable (the credential cannot read the list — "
            "an empty answer is NOT nobody), counted (how many, never who), or observed with the count."
        ),
    },
    {
        "field": "data.missing_vs_peers_text",
        "title": "Missing vs peers",
        "widthGrow": 2,
        "tooltip": "full_value",
        "header_tooltip": (
            "Contexts at least half of the account's gated repositories require and this one does not."
        ),
    },
]


class GatesPanelType:
    """Per-repository gate posture, rendered through the standard table panel template (via its own view template)."""

    slug: ClassVar[str] = "github-gates"
    label: ClassVar[str] = "GitHub Gates"
    # The page view resolves a Panel row to its type by this path (tap_web.views._get_panel_type_for_panel),
    # so it must be this type's own; the template includes the table panel's.
    view: ClassVar[str] = "github_core/panels/gates.html"
    # The renderer's assets are the table panel's own — derived from its declaration, not copied.
    css: ClassVar[list[str]] = [*TABULATOR_CSS]
    js: ClassVar[list[str]] = [*TABULATOR_JS]
    config_defaults: ClassVar[dict[str, Any]] = {
        "columns": DEFAULT_COLUMNS,
        "quick_filter": True,
    }

    @classmethod
    def get_view_context(cls, panel: Panel, request: HttpRequest) -> dict[str, Any]:
        """Execute the declared reads, fold them into rows, and return the table template's context."""
        try:
            from tap_web.panels.table_panel import _script_ids
        except (
            ImportError
        ):  # core older than tap#305 (2026-09-03): same id grammar, one place
            _script_ids = _script_ids_fallback

        config = dict(cls.config_defaults)
        config.update(panel.config or {})
        try:
            rows = build_rows(_fetch(QUERIES))
        except (
            Exception
        ):  # noqa: BLE001 — the panel renders its failure, never a blank frame
            logger.exception(
                "[4c40] Gates panel read failed for panel %s", panel.entity_id
            )
            return {
                "table_nodes": [],
                "table_meta": {},
                "table_search": None,
                # The exception text stays in the log: an executor message can carry query
                # fragments, and the panel body is not the place for them (Codacy, PR #66).
                "table_error": "Gate reads failed — see the server log ([4c40]).",
                **_script_ids(panel),
            }
        meta = {
            "total_count": len(rows),
            "showing": len(rows),
            "page_size": len(rows),
            "page_size_options": [],
            "has_prev": False,
            "has_next": False,
            "prev_offset": 0,
            "next_offset": 0,
        }
        return {
            "table_nodes": rows,
            "table_meta": meta,
            "table_search": None,
            "table_columns": config.get("columns"),
            "table_height": config.get("height"),
            "table_refresh_seconds": config.get("refresh_seconds"),
            "table_group_by": config.get("group_by"),
            "table_error": None,
            **_script_ids(panel),
        }


def _script_ids_fallback(panel: Panel) -> dict[str, str]:
    """The table renderer's json_script id grammar, for a core that predates tap#305.

    Mirrors ``tap_web.panels.table_panel._script_ids`` (``tap-table-<kind>-<panel id>``, the
    contract ``panel-table.js`` rebuilds from ``data-tap-table-panel-id``). Dead code the moment
    the plugin's harness pin passes tap#305; kept so the panel imports on the pinned harness.
    """
    pid = panel.entity_id
    return {
        "table_data_script_id": f"tap-table-data-{pid}",
        "table_columns_script_id": f"tap-table-columns-{pid}",
        "table_groupby_script_id": f"tap-table-groupby-{pid}",
    }


def _fetch(queries: dict[str, str]) -> dict[str, dict[str, Any]]:
    """Run every declared query; the repository read at the extended layer so rows carry a viewer url."""
    from tap_grid.gryphon.executor import execute_gryphon_raw

    out: dict[str, dict[str, Any]] = {}
    for key, query in queries.items():
        layer: SubgraphLayer = "extended" if key == "repositories" else "full"
        out[key] = execute_gryphon_raw(query, {}, layer=layer)
    return out


def _nodes_by_id(envelope: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(n.get("entity_id")): n for n in envelope.get("nodes", [])}


def _pairs(
    envelope: dict[str, Any], edge_type: str
) -> list[tuple[str, str, dict[str, Any]]]:
    """(from_id, to_id, properties) for every edge of one type in a multi-hop envelope."""
    pairs: list[tuple[str, str, dict[str, Any]]] = []
    for edge in envelope.get("edges", []):
        data = edge.get("data") or {}
        if data.get("edge_type") != edge_type:
            continue
        pairs.append(
            (
                str(data.get("from_entity_id")),
                str(data.get("to_entity_id")),
                dict(data.get("properties") or {}),
            )
        )
    return pairs


def _covers_default_branch(ruleset: dict[str, Any], default_branch: str) -> bool:
    """A branch ruleset whose ref conditions select the default branch, by token or by name.

    Fail closed on shape: a ruleset with no ``target`` is not assumed to be a branch ruleset,
    and an ``exclude`` naming the default branch — by ``~DEFAULT_BRANCH``, ``~ALL`` or its
    ``refs/heads/`` name — wins over any include (PR #66 review, Codex + Grok seats).
    """
    data = ruleset.get("data") or {}
    if data.get("target") != "branch":
        return False
    ref_name = ((data.get("conditions") or {}).get("ref_name")) or {}
    include = {str(x) for x in (ref_name.get("include") or [])}
    exclude = {str(x) for x in (ref_name.get("exclude") or [])}
    named = f"refs/heads/{default_branch}" if default_branch else ""
    selectors = {DEFAULT_BRANCH_TOKEN, "~ALL"} | ({named} if named else set())
    if exclude & selectors:
        return False
    return bool(include & selectors)


def _governs_default_branch(ruleset: dict[str, Any], default_branch: str) -> bool:
    """Covers the default branch AND is enforced. ``evaluate`` and ``disabled`` rulesets are
    reported beside the governing ones (``rulesets_text``) but gate nothing."""
    return (
        _covers_default_branch(ruleset, default_branch)
        and str((ruleset.get("data") or {}).get("enforcement") or "") == "active"
    )


def _rule_types(ruleset: dict[str, Any]) -> list[dict[str, Any]]:
    rules = (ruleset.get("data") or {}).get("rules") or []
    return [r for r in rules if isinstance(r, dict)]


def _checks_type_only(ruleset: dict[str, Any], requires_from: set[str]) -> bool:
    """The refused-detail fallback: a required_status_checks rule with no parameters and no edge (#64)."""
    for rule in _rule_types(ruleset):
        if rule.get("type") != "required_status_checks":
            continue
        params = rule.get("parameters") or {}
        if not params.get("required_status_checks") and not requires_from:
            return True
    return False


def _bypass_text(ruleset: dict[str, Any]) -> tuple[int, str]:
    data = ruleset.get("data") or {}
    state = str(data.get("bypass_observability") or "unobservable")
    rank = _BYPASS_RANK.get(state, 0)
    count = data.get("bypass_actor_count")
    if state == "observed":
        return rank, "observed: none" if not count else f"observed: {count}"
    if state == "counted":
        return rank, f"counted: {count}" if count is not None else "counted"
    return rank, "not observable"


def build_rows(env: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Fold the five envelopes into one node-shaped row per repository, worst gate first.

    Pure: takes the envelopes ``_fetch`` returned and no database, so the derivation is testable
    against hand-built graphs.
    """
    repos = _nodes_by_id(env["repositories"])
    rulesets = _nodes_by_id(env["protects"])
    checks = _nodes_by_id(env["requires"])
    checks.update(_nodes_by_id(env["produces"]))
    workflows = _nodes_by_id(env["produces"])
    workflows.update(_nodes_by_id(env["defines"]))

    protects: dict[str, list[str]] = defaultdict(list)  # repo -> rulesets
    for rs_id, repo_id, _ in _pairs(
        env["protects"], "PROTECTS_REPOSITORY__github_core"
    ):
        if rs_id in rulesets and repo_id in repos:
            protects[repo_id].append(rs_id)
    requires: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(
        list
    )  # ruleset -> (check, props)
    for rs_id, check_id, props in _pairs(
        env["requires"], "REQUIRES_CHECK__github_core"
    ):
        requires[rs_id].append((check_id, props))
    produces: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(
        list
    )  # check -> (workflow, props)
    for wf_id, check_id, props in _pairs(
        env["produces"], "PRODUCES_CHECK__github_core"
    ):
        produces[check_id].append((wf_id, props))
    workflow_repo: dict[str, str] = {}
    for repo_id, wf_id, _ in _pairs(env["defines"], "DEFINES_WORKFLOW__github_core"):
        workflow_repo[wf_id] = repo_id

    rows: list[dict[str, Any]] = []
    for repo_id, repo in repos.items():
        rdata = repo.get("data") or {}
        default_branch = str(rdata.get("default_branch") or "")
        covering = [
            rulesets[rs_id]
            for rs_id in dict.fromkeys(protects.get(repo_id, []))
            if _covers_default_branch(rulesets[rs_id], default_branch)
        ]
        governing = [
            rs for rs in covering if _governs_default_branch(rs, default_branch)
        ]
        not_enforced = [
            f"{rs.get('name')} ({(rs.get('data') or {}).get('enforcement') or 'unknown'}, not enforced)"
            for rs in covering
            if rs not in governing
        ]
        full_name = str(rdata.get("full_name") or repo.get("name") or "")
        row_data: dict[str, Any] = {
            "full_name": full_name,
            "name": full_name.rpartition("/")[2] or full_name,
            "owner": str(rdata.get("owner_login") or full_name.partition("/")[0]),
            "html_url": rdata.get("html_url") or "",
            "default_branch": default_branch,
            "rulesets": [],
            "rulesets_not_enforced": not_enforced,
            "rulesets_text": "; ".join(not_enforced),
            "ruleset_count": len(governing),
            "enforcement": "",
            "requires_pr": None,
            "checks_required": [],
            "checks_workflow": [],
            "checks_workflow_text": "",
            "checks_app": [],
            "checks_app_text": "",
            "checks_unproduced": [],
            "checks_unproduced_text": "",
            "checks_state": "no ruleset observed",
            "bypass": "no ruleset observed",
            "bypass_state": "none",
            "missing_vs_peers": [],
            "missing_vs_peers_text": "",
            "gate_state": "no ruleset observed",
        }
        if governing:
            _fill_gated_row(
                row_data,
                repo_id,
                governing,
                requires,
                produces,
                checks,
                workflows,
                workflow_repo,
            )
        rows.append(
            {
                **{k: v for k, v in repo.items() if k != "data"},
                "data": row_data,
            }
        )

    _fill_missing_vs_peers(rows)
    rows.sort(
        key=lambda r: (
            _GATE_RANK.get(r["data"]["gate_state"], 0),
            r["data"]["full_name"],
        )
    )
    return rows


def _fill_gated_row(
    row: dict[str, Any],
    repo_id: str,
    governing: list[dict[str, Any]],
    requires: dict[str, list[tuple[str, dict[str, Any]]]],
    produces: dict[str, list[tuple[str, dict[str, Any]]]],
    checks: dict[str, dict[str, Any]],
    workflows: dict[str, dict[str, Any]],
    workflow_repo: dict[str, str],
) -> None:
    """Everything a repository with at least one governing ruleset can say about its gate."""
    names = []
    enforcement = set()
    requires_pr = False
    type_only = False
    bypass_rank, bypass_text = 99, ""
    required: dict[str, dict[str, Any]] = {}  # context -> {"integration_id": ...}
    for rs in governing:
        rs_id = str(rs.get("entity_id"))
        data = rs.get("data") or {}
        enf = str(data.get("enforcement") or "")
        enforcement.add(enf)
        names.append(f"{rs.get('name')} ({enf})" if enf else str(rs.get("name")))
        if any(r.get("type") == "pull_request" for r in _rule_types(rs)):
            requires_pr = True
        edges = requires.get(rs_id, [])
        if _checks_type_only(rs, {c for c, _ in edges}):
            type_only = True
        for check_id, props in edges:
            context = str(
                (checks.get(check_id) or {}).get("data", {}).get("context") or ""
            )
            if not context:
                continue
            entry = required.setdefault(
                context, {"check_id": check_id, "integration_id": None}
            )
            if props.get("integration_id") is not None:
                entry["integration_id"] = props.get("integration_id")
        rank, text = _bypass_text(rs)
        if rank < bypass_rank:
            bypass_rank, bypass_text = rank, text

    workflow_hits: list[str] = []
    app_hits: list[str] = []
    unproduced: list[str] = []
    for context in sorted(required):
        entry = required[context]
        integration = entry["integration_id"]
        if integration is not None and integration != GITHUB_ACTIONS_INTEGRATION_ID:
            app_hits.append(f"{context} (app {integration})")
            continue
        here: list[str] = []
        elsewhere: list[str] = []
        for wf_id, props in produces.get(entry["check_id"], []):
            wf = workflows.get(wf_id) or {}
            label = str(wf.get("name") or (wf.get("data") or {}).get("path") or wf_id)
            confidence = str(props.get("confidence") or "")
            tag = (
                f"{label} ({confidence})"
                if confidence and confidence != "exact"
                else label
            )
            if workflow_repo.get(wf_id) == repo_id:
                here.append(tag)
            else:
                elsewhere.append(tag)
        if here:
            workflow_hits.append(f"{context} ← {', '.join(here)}")
        elif elsewhere:
            unproduced.append(f"{context} (only elsewhere: {', '.join(elsewhere)})")
        else:
            unproduced.append(context)

    row.update(
        {
            "rulesets": [str(rs.get("name")) for rs in governing],
            "rulesets_text": "; ".join([*names, *row.get("rulesets_not_enforced", [])]),
            "enforcement": (
                "active"
                if "active" in enforcement
                else ", ".join(sorted(e for e in enforcement if e))
            ),
            "requires_pr": requires_pr,
            "checks_required": sorted(required),
            "checks_workflow": workflow_hits,
            "checks_workflow_text": "; ".join(workflow_hits),
            "checks_app": app_hits,
            "checks_app_text": "; ".join(app_hits),
            "checks_unproduced": unproduced,
            "checks_unproduced_text": "; ".join(unproduced),
            "bypass": bypass_text,
            "bypass_state": next(
                (s for s, r in _BYPASS_RANK.items() if r == bypass_rank), "unobservable"
            ),
        }
    )
    if type_only:
        row["checks_state"] = "required checks not observable"
        row["gate_state"] = "required checks not observable"
    elif unproduced:
        row["checks_state"] = "nothing produces a check"
        row["gate_state"] = "nothing produces a check"
    elif required:
        row["checks_state"] = "observed"
        row["gate_state"] = "gated"
    else:
        row["checks_state"] = "none required"
        row["gate_state"] = "gated"


def _fill_missing_vs_peers(rows: list[dict[str, Any]]) -> None:
    """Name what an owner's gated repositories share that a row lacks (configured-the-same).

    Peers are the repositories of the SAME owner: one graph may hold several accounts, and a
    check one organisation requires is not a requirement on another (PR #66 review).
    """
    by_owner: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        by_owner[r["data"]["owner"]].append(r)
    for peers in by_owner.values():
        gated = [
            r
            for r in peers
            if r["data"]["ruleset_count"]
            and r["data"]["checks_state"] != "required checks not observable"
        ]
        tally: dict[str, int] = defaultdict(int)
        for r in gated:
            for context in r["data"]["checks_required"]:
                tally[context] += 1
        shared = sorted(
            c for c, n in tally.items() if n >= max(2, PEER_SHARE_FRACTION * len(gated))
        )
        if not shared:
            continue
        for r in peers:
            if r["data"]["checks_state"] == "required checks not observable":
                r["data"]["missing_vs_peers_text"] = "not observable"
                continue
            missing = [c for c in shared if c not in r["data"]["checks_required"]]
            r["data"]["missing_vs_peers"] = missing
            r["data"]["missing_vs_peers_text"] = "; ".join(missing)
