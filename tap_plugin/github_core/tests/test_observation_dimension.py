"""The DCOM observation layer is a positive fact on both sides.

Spec: plugins/github_core/specs/spec-github-core-v0.md
(req-github-core-dimensions-4, -5, -6)

The property under test is not "runs are executions" — that was already true.
It is that the *config* layer is stated rather than implied, so a query for it
reads `observation = "declaration"` and never `NOT observation = "execution"`.
An object that declares no layer is a defect these tests are here to catch.
"""

import json
from pathlib import Path

import tap_plugin.github_core.models as github_models

EDGES_DIR = Path(github_models.__file__).parent.parent / "edges"

# ActionsCache is a BYPRODUCT of a run, not configuration someone wrote — it exists
# because a workflow executed and wrote it.
# The OUTPUTS (github-core#31) are all products of execution: a release was published, an
# artifact was uploaded by a run (github-core#14 shape C — an immutable event), a package
# version was pushed. A release rides the config-layer GraphQL transport, and transport is
# not layer.
EXECUTION_MODELS = {"GithubActionsRun", "GithubActionsJob", "ActionsCache", "RuleSuite",
                    "GithubRelease", "ActionsArtifact", "GithubPackage", "GithubPackageVersion",
                    # A pull request is an act — someone opened it — and carries the executed
                    # check rollup on its head; it is not configuration anyone wrote (github-core#82).
                    "PullRequest",
                    # Code scanning (github-core#89): an analysis is a scanner RUN and an alert is what
                    # that run reported — outputs of execution, not configuration anyone wrote.
                    "CodeScanningAlert", "CodeScanningAnalysis",
                    # A Dependabot alert is what GitHub's scanner reported about a manifest — the
                    # output of a scan, like a code scanning alert (github-core#68).
                    "DependabotAlert",
                    # A collection scope is a statement about ONE RUN — what its credential could
                    # reach at that moment — perceived-true-at-a-time like a runner execution
                    # (github-core#145). Configuration is the installation it points at.
                    "CollectionScope"}
# SCOPED_TO_REF is sourced on actions_cache, which is execution — the layer follows the
# source model rather than a second map (req-github-core-dimensions-6).
# TRIGGERED_EVALUATION / BYPASSED_RULE / EVALUATED_ON are all sourced on rule_suite, which is execution.
# Output edges follow their SOURCE: run-sourced (BUILDS_RELEASE, UPLOADS_ARTIFACT,
# BUILDS_PACKAGE_VERSION), release-sourced (TARGETS_REF) and package-sourced
# (PUBLISHES_PACKAGE_VERSION) are execution; the repository/account containment edges
# (PUBLISHES_RELEASE, STORES_ARTIFACT, PUBLISHES_PACKAGE) are declaration, like STORES_CACHE.
EXECUTION_EDGES = {"EXECUTES_WORKFLOW", "RUNS_JOB", "EXECUTED_ON_RUNNER", "SCOPED_TO_REF",
                   "TRIGGERED_EVALUATION", "BYPASSED_RULE", "EVALUATED_ON_REF",
                   "BUILDS_RELEASE", "UPLOADS_ARTIFACT", "BUILDS_PACKAGE_VERSION", "TARGETS_REF",
                   # Pull-request edges follow their pull-request end (github-core#82): the
                   # author's act, and the proposal's joins onto the neutral refs and commit.
                   "OPENS_PULL_REQUEST", "PROPOSES_REF", "TARGETS_BASE_REF", "PROPOSES_COMMIT",
                   # Code scanning edges follow their execution-layer source (github-core#89): the
                   # alert behind a finding, and the analysis's joins onto the repository and commit.
                   "DETAILS_FINDING", "ANALYZES_REPOSITORY", "ANALYZES_COMMIT",
                   "PUBLISHES_PACKAGE_VERSION",
                   # Scope edges follow their execution-layer source (github-core#145): the
                   # statement about a run, and the grant it was derived from.
                   "SCOPES_RUN", "DERIVED_FROM_INSTALLATION"}
# Sources span both layers, so the layer belongs to the endpoint, not the edge
# type; the collector sets it per emitted edge (req-github-core-dimensions-6).
LAYER_SPANNING_EDGES = {"REFERENCES_RESOURCE"}


def _plugin_models() -> dict[str, type]:
    return {
        name: obj
        for name, obj in vars(github_models).items()
        if isinstance(obj, type) and hasattr(obj, "DEFAULT_DIMENSIONS") and hasattr(obj, "ENTITY_TYPE")
    }


def _edge_definitions() -> dict[str, dict]:
    return {p.name.removesuffix(".edge.json"): json.loads(p.read_text()) for p in sorted(EDGES_DIR.glob("*.edge.json"))}


class TestModelObservationLayer:
    def test_every_model_declares_a_layer(self) -> None:
        """No model may be in neither layer — absence is a defect, not a default."""
        missing = [
            name for name, cls in _plugin_models().items() if "github.observation" not in cls.DEFAULT_DIMENSIONS
        ]
        assert not missing, f"models with no github.observation layer: {sorted(missing)}"

    def test_layer_matches_what_the_model_records(self) -> None:
        for name, cls in _plugin_models().items():
            expected = "execution" if name in EXECUTION_MODELS else "declaration"
            assert cls.DEFAULT_DIMENSIONS["github.observation"] == expected, name

    def test_both_layers_are_populated(self) -> None:
        """A one-sided axis is the defect this requirement exists to prevent."""
        layers = {cls.DEFAULT_DIMENSIONS.get("github.observation") for cls in _plugin_models().values()}
        assert layers == {"declaration", "execution"}


class TestEdgeObservationLayer:
    def test_every_edge_declares_a_layer_or_is_named_as_spanning(self) -> None:
        undeclared = {
            name
            for name, definition in _edge_definitions().items()
            if "github.observation" not in definition.get("default_dimensions", {})
        }
        assert undeclared == LAYER_SPANNING_EDGES, (
            "an edge with no default observation must be a deliberate layer-spanning edge "
            f"named in the spec; unexpected: {sorted(undeclared - LAYER_SPANNING_EDGES)}"
        )

    def test_layer_matches_what_the_edge_connects(self) -> None:
        for name, definition in _edge_definitions().items():
            if name in LAYER_SPANNING_EDGES:
                continue
            expected = "execution" if name in EXECUTION_EDGES else "declaration"
            assert definition["default_dimensions"]["github.observation"] == expected, name

    def test_spanning_edge_really_does_span(self) -> None:
        """Guards the exemption: it holds only while the sources actually disagree."""
        models_by_type = {cls.ENTITY_TYPE: cls for cls in _plugin_models().values()}
        for name in LAYER_SPANNING_EDGES:
            sources = _edge_definitions()[name]["sources"]
            layers = {
                models_by_type[s].DEFAULT_DIMENSIONS.get("github.observation")
                for s in sources
                if s in models_by_type
            }
            assert len(layers) > 1, f"{name} no longer spans layers — give it a default observation"


class TestLinkEdgeDerivation:
    def test_link_edge_inherits_the_source_layer(self) -> None:
        """req-github-core-dimensions-6: derived from the source model, not a second map."""
        from tap_plugin.github_core.collectors.github_collector.enrichment import _dimensions_for_rule

        base = {"git.host": "github.com"}
        declaration = _dimensions_for_rule(base, "github_core__github_workflow")
        execution = _dimensions_for_rule(base, "github_core__github_actions_run")

        assert declaration["github.observation"] == "declaration"
        assert execution["github.observation"] == "execution"
        assert base == {"git.host": "github.com"}, "the base dimensions must not be mutated"
