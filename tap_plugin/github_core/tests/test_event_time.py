"""Event time (core's req-grid-entity-event-time, tap 0.4.7): what each github_core model declares.

The first class holds every model's EVENT_TIME to the declaration chosen for it, so a model added
later without one, or a declaration that drifts to another field, fails here, and asks core's own
check to accept each. The second applies core's derivation to plain values for the shapes whose
reading is not obvious from the declaration alone: an open end, a draft release, a reopened pull
request and an artifact whose retention end GitHub states.
"""

from datetime import UTC, datetime

from tap_plugin.github_core.models import (
    ActionsArtifact,
    ActionsCache,
    ActionsSecret,
    AppInstallation,
    CodeScanningAlert,
    CodeScanningAnalysis,
    CollectionScope,
    CommitObservation,
    DependabotAlert,
    GithubAccount,
    GithubAction,
    GithubActionsJob,
    GithubActionsRun,
    GithubApp,
    GithubCustomProperty,
    GithubEnvironment,
    GithubPackage,
    GithubPackageVersion,
    GithubPlatform,
    GithubRelease,
    GithubRepository,
    GithubRuleset,
    GithubRunner,
    GithubWorkflow,
    PullRequest,
    RuleSuite,
    StatusCheck,
    WorkflowJob,
)

from tap_grid.event_time import NO_EVENT_TIME, Interval, Moment, declaration_problems, derive
from tap_grid.registry import get_model_class, list_entity_types

DECLARED = {
    # Things GitHub performed or that happened once.
    GithubActionsRun: Interval(start="run_started_at", kind="occurred", end="completed_at"),
    GithubActionsJob: Interval(start="started_at", kind="occurred", end="completed_at"),
    RuleSuite: Moment(field="pushed_at", kind="occurred"),
    CodeScanningAnalysis: Moment(field="created_at", kind="occurred"),
    GithubRelease: Moment(field="published_at", kind="published"),
    # Long-lived objects, from the time GitHub says they came to exist.
    AppInstallation: Interval(start="installed_at", kind="created"),
    ActionsSecret: Interval(start="created_at", kind="created"),
    ActionsCache: Interval(start="created_at", kind="created"),
    GithubPackage: Interval(start="created_at", kind="created"),
    GithubPackageVersion: Interval(start="created_at", kind="created"),
    ActionsArtifact: Interval(start="created_at", kind="created", end="expires_at"),
    PullRequest: Interval(start="created_at", kind="created", end="closed_at"),
    CodeScanningAlert: Interval(start="created_at", kind="created"),
    DependabotAlert: Interval(start="created_at", kind="created"),
    # No source time stored, or collection time only.
    GithubPlatform: NO_EVENT_TIME,
    GithubAccount: NO_EVENT_TIME,
    GithubRepository: NO_EVENT_TIME,
    GithubWorkflow: NO_EVENT_TIME,
    GithubRunner: NO_EVENT_TIME,
    GithubApp: NO_EVENT_TIME,
    WorkflowJob: NO_EVENT_TIME,
    CommitObservation: NO_EVENT_TIME,
    GithubRuleset: NO_EVENT_TIME,
    StatusCheck: NO_EVENT_TIME,
    GithubEnvironment: NO_EVENT_TIME,
    GithubAction: NO_EVENT_TIME,
    GithubCustomProperty: NO_EVENT_TIME,
    CollectionScope: NO_EVENT_TIME,
}

OPENED = datetime(2026, 11, 2, 9, 30, tzinfo=UTC)
CLOSED = datetime(2026, 11, 2, 10, 15, tzinfo=UTC)


def _spine(model, values):
    derived = derive(model.EVENT_TIME, values.get)
    return derived.event_start, derived.event_end, derived.kind


class TestDeclarations:
    def test_every_model_of_the_plugin_decides(self) -> None:
        own = {get_model_class(slug) for slug in list_entity_types() if slug.startswith("github_core__")}
        assert own == set(DECLARED)
        assert {model: model.EVENT_TIME for model in own} == DECLARED

    def test_core_accepts_each_declaration(self) -> None:
        for model in DECLARED:
            assert declaration_problems(model) == [], model.__name__


class TestDerivation:
    def test_a_finished_run_spans_its_latest_attempt(self) -> None:
        values = {"created_at": OPENED, "run_started_at": OPENED, "completed_at": CLOSED}
        assert _spine(GithubActionsRun, values) == (OPENED, CLOSED, "occurred")

    def test_a_job_still_running_has_no_end(self) -> None:
        values = {"started_at": OPENED, "completed_at": None}
        assert _spine(GithubActionsJob, values) == (OPENED, None, "occurred")

    def test_a_draft_release_has_no_event_time(self) -> None:
        # A draft has a created_at (the commit's date, by GitHub's own documentation) and no published_at.
        values = {"created_at": OPENED, "published_at": None}
        assert _spine(GithubRelease, values) == (None, None, None)

    def test_a_reopened_pull_request_is_open_again(self) -> None:
        assert _spine(PullRequest, {"created_at": OPENED, "closed_at": CLOSED}) == (OPENED, CLOSED, "created")
        assert _spine(PullRequest, {"created_at": OPENED, "closed_at": None}) == (OPENED, None, "created")

    def test_an_artifact_holds_until_its_stated_expiry(self) -> None:
        values = {"created_at": OPENED, "expires_at": CLOSED, "updated_at": CLOSED}
        assert _spine(ActionsArtifact, values) == (OPENED, CLOSED, "created")

    def test_a_cache_is_never_closed_by_its_last_access(self) -> None:
        values = {"created_at": OPENED, "last_accessed_at": CLOSED}
        assert _spine(ActionsCache, values) == (OPENED, None, "created")
