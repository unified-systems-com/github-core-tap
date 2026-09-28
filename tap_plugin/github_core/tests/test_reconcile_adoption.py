"""Phase 3 proof (github-core#151): one run against the fake GitHub records a completeness
statement with a surface per listing walked, and a candidate record beside it.

Through `run_collection`, exactly as the worker runs it: the collector reads the account
listing (config layer), each repository's workflows, environments and declared jobs, submits
its GRIFT batch, and records one surface per listing against that batch
(req-grid-reconcile-evidence); the task body derives the candidates from those surfaces
(req-grid-reconcile-candidates) with authority off. Verdicts are NOT OBSERVED here: the
reconcile verb (tap#652) is not in the core this plugin is pinned against, and this test says
so rather than asserting either way.

The listing helper's own contract is checked directly below: what a refused listing, a capped
walk and an unread file each record.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from tap_plugin.github_core.collectors.github_collector import collector as collector_module
from tap_plugin.github_core.collectors.github_collector.collector import GithubCollector
from tap_plugin.github_core.collectors.github_collector.graphql_client import GithubGraphQLClient
from tap_plugin.github_core.collectors.github_collector.identity import workflow_id
from tap_plugin.github_core.models.github_account import GithubAccount
from tap_plugin.github_core.models.github_repository import GithubRepository
from tap_plugin.github_core.models.github_workflow import GithubWorkflow

from tap.pytest_harness import isolated_registry
from tap_cares.models import CollectionJobStatus
from tap_cares.registry import collector_registry
from tap_cares.services import LIFECYCLE_BATCH_SOURCE, run_collection
from tap_grid.candidates import candidates_of
from tap_grid.completeness import completeness_of
from tap_grid.falsifiers import verdicts_of
from tap_grid.models import Batch, Edge

from .fake_estate import OWNER, REPO, Secret, config_repo, fake_rest, register


def _assigned(model: Any, **natural_key: Any) -> str:
    """The id core ASSIGNED the row this natural key names, as the surface's subject cites it.

    Since github_core adopted assigned identity (Issue# 162) a surface's subject is no longer a
    value a test can derive: the collector sends a batch-local ref, core resolves it through the
    model's ``NATURAL_KEY``, and the id it hands back is what the completeness statement carries.
    Looking it up through the declared key is the honest read — and it is a second assertion for
    free, because a lookup on the declared key finding exactly one row is the same search the
    importer ran.
    """
    return str(model.objects.get(**natural_key).entity_id)


def _lifecycle_batch(job: Any) -> Batch:
    edge = Edge.objects.filter(edge_type="HAS_COLLECTION_JOB", to_entity_id=job.entity_id).first()
    assert edge is not None
    batch = Batch.objects.filter(source=LIFECYCLE_BATCH_SOURCE, entity_id=edge.batch_id).first()
    assert isinstance(batch, Batch), "the job's HAS_COLLECTION_JOB edge rides its lifecycle batch"
    return batch


@pytest.mark.django_db(transaction=True, databases=["default", "search_readonly"])
class TestOneRunAgainstTheFakeGithub:
    @pytest.mark.spec("req-grid-reconcile-evidence-1")
    @pytest.mark.spec("req-grid-reconcile-candidates-1")
    def test_the_run_records_a_surface_per_listing_and_a_candidate_record(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with isolated_registry(collector_registry):
            self._run_and_assert(monkeypatch)

    @staticmethod
    def _run_and_assert(monkeypatch: pytest.MonkeyPatch) -> None:
        fake = fake_rest()
        monkeypatch.setattr(collector_module, "resolve_github_secret", lambda *a, **k: Secret())
        monkeypatch.setattr(collector_module, "GithubClient", lambda **kw: fake)
        monkeypatch.setattr(GithubGraphQLClient, "fetch_config_layer", lambda self, login: ([config_repo()], []))
        monkeypatch.setattr(GithubGraphQLClient, "fetch_pull_request_layer", lambda self, login: ({}, []))

        job = run_collection(register(GithubCollector))
        job.refresh_from_db()
        assert job.status == CollectionJobStatus.SUCCESSFUL.value, job.summary

        batch = _lifecycle_batch(job)
        statement = completeness_of(batch)
        assert statement is not None, "the run recorded a completeness statement"
        by_relation = {(s["relation"], s["subject"]): s for s in statement["surfaces"]}
        assert {r for r, _ in by_relation} == {
            "account.repositories",
            "repository.workflows",
            "repository.environments",
            "repository.secrets",
            "workflow.jobs",
        }
        repos = by_relation[("account.repositories", _assigned(GithubAccount, login=OWNER))]
        workflows = by_relation[("repository.workflows", _assigned(GithubRepository, full_name=REPO))]
        environments = by_relation[
            ("repository.environments", _assigned(GithubRepository, full_name=REPO))
        ]
        secrets = by_relation[("repository.secrets", _assigned(GithubRepository, full_name=REPO))]
        jobs = by_relation[
            ("workflow.jobs", _assigned(GithubWorkflow, full_name=REPO, workflow_id=100))
        ]
        assert repos["edge_type"] == "OWNS_REPO__github_core" and repos["count_observed"] == 1
        assert workflows["edge_type"] == "DEFINES_WORKFLOW__github_core" and workflows["count_observed"] == 1
        assert environments["edge_type"] == "DECLARES_ENVIRONMENT__github_core" and environments["count_observed"] == 1
        # The fake estate declares no secrets at all; the repository-scope listing is still a
        # completeness surface — it was read to the end and found nothing, which is a fact.
        assert secrets["edge_type"] == "DEFINES_SECRET__github_core" and secrets["count_observed"] == 0
        assert jobs["edge_type"] == "DEFINES_JOB__github_core" and jobs["count_observed"] == 1
        for surface in statement["surfaces"]:
            # Every listing cites the collection batch; the recorder derived `applied` from its commit.
            assert surface["applied"] is True, surface
            assert surface["reconcilable"] is True, surface
            assert surface["source_consistent"] == "unknown" and "source_consistent" in surface["reasons"]

        record = candidates_of(batch)
        assert record is not None, "the task body derived a candidate record from the statement"
        assert record["authority"] == "off"
        outcomes = {(e["relation"], e["outcome"]) for e in record["surfaces"]}
        # Every parent was observed by this run and every child listed was written: derived, none absent.
        assert outcomes == {
            ("account.repositories", "derived"),
            ("repository.workflows", "derived"),
            ("repository.environments", "derived"),
            ("repository.secrets", "derived"),
            ("workflow.jobs", "derived"),
        }
        assert all(e["candidates"] == [] for e in record["surfaces"])

        # The reconcile verb (tap#652, in tap v0.2.0) runs as the run's final phase with this
        # collector's authority OFF (the default; the operator's switch is tap#655): it probes
        # nothing and records that on the run — a verdict record with authority "off" and no
        # entries, since no candidate was derived. Absent authority is recorded, not silent.
        verdicts = verdicts_of(batch)
        assert verdicts is not None, "the verb ran as the final phase and recorded its refusal to judge"
        assert verdicts["authority"] == "off" and verdicts["entries"] == [] and verdicts["candidates"] == 0
        assert verdicts["applied"]["authority"] == "off" and verdicts["applied"]["applied"] == 0


@pytest.mark.django_db(transaction=True, databases=["default", "search_readonly"])
class TestAFailedRepositoryDoesNotLeaveAnAdmittedSurface:
    """Codex on PR# 154: a repository that lists its workflows and then fails part-way must not
    leave a complete, admitted `repository.workflows` surface behind for candidates to be
    derived from — its children never all reached the batch."""

    @pytest.mark.spec("req-grid-reconcile-evidence-6")
    def test_the_failed_repository_surfaces_are_not_admitted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        with isolated_registry(collector_registry):
            self._run_and_assert(monkeypatch)

    @staticmethod
    def _run_and_assert(monkeypatch: pytest.MonkeyPatch) -> None:
        fake = fake_rest()
        broken = "acme/broken"
        fake.answer(
            f"/repos/{broken}/actions/workflows",
            {"workflows": [{"id": 200, "path": ".github/workflows/ci.yml", "name": "ci", "state": "active"}]},
        )
        fake.refuse(f"/repos/{broken}/actions/runs", 502)  # after the workflows listing, before the runs
        second = {**config_repo(), "nameWithOwner": broken, "name": "broken", "databaseId": 11}
        monkeypatch.setattr(collector_module, "resolve_github_secret", lambda *a, **k: Secret())
        monkeypatch.setattr(collector_module, "GithubClient", lambda **kw: fake)
        monkeypatch.setattr(
            GithubGraphQLClient, "fetch_config_layer", lambda self, login: ([config_repo(), second], [])
        )
        monkeypatch.setattr(GithubGraphQLClient, "fetch_pull_request_layer", lambda self, login: ({}, []))

        job = run_collection(register(GithubCollector))
        job.refresh_from_db()
        assert job.status == CollectionJobStatus.SUCCESSFUL.value, job.summary
        statement = completeness_of(_lifecycle_batch(job))
        assert statement is not None
        by_key = {(s["relation"], s["subject"]): s for s in statement["surfaces"]}
        healthy = by_key[("repository.workflows", _assigned(GithubRepository, full_name=REPO))]
        failed = by_key[("repository.workflows", _assigned(GithubRepository, full_name=broken))]
        assert healthy["admitted"] is True and healthy["reconcilable"] is True
        assert failed["enumeration_complete"] is True, "the listing itself was read to the end"
        assert failed["admitted"] is False and failed["reconcilable"] is False
        assert failed["reasons"]["admitted"].startswith("collection_failed: acme/broken")
        for relation in ("repository.environments", "repository.secrets", "workflow.jobs"):
            broken_surfaces = [s for k, s in by_key.items() if k[0] == relation and s["admitted"] is False]
            assert broken_surfaces, f"{relation}: the failed repository's surface is withdrawn too"
        account = by_key[("account.repositories", _assigned(GithubAccount, login=OWNER))]
        assert account["admitted"] is False and account["reasons"]["admitted"].startswith("collection_partial")
        record = candidates_of(_lifecycle_batch(job))
        assert record is not None
        skipped = {e["subject"]: e["reason"] for e in record["surfaces"] if e["outcome"] == "skipped"}
        broken_id = _assigned(GithubRepository, full_name=broken)
        assert broken_id in skipped and "surface_not_reconcilable" in skipped[broken_id]


class TestListingContract:
    """What `_note_listing` records for the states a walk can end in."""

    @staticmethod
    def _collector() -> GithubCollector:
        c = GithubCollector.__new__(GithubCollector)
        c.results = {"info": [], "warn": [], "error": []}
        return c

    def test_a_refused_listing_is_unauthorized_unenumerated_and_not_admitted(self) -> None:
        c = self._collector()
        c._note_listing(
            "repository.workflows", "DEFINES_WORKFLOW__github_core", uuid.uuid4(), datetime.now(UTC), refused=403
        )
        [surface] = c._listing_state()["listings"]
        assert (surface["scope_authorized"], surface["enumeration_complete"], surface["admitted"]) == (
            False,
            False,
            False,
        )
        assert surface["count_observed"] is None
        assert surface["reasons"]["scope_authorized"].startswith("http_403")

    def test_a_refusal_that_is_not_a_permission_answer_is_not_determinable(self) -> None:
        c = self._collector()
        c._note_listing(
            "repository.workflows", "DEFINES_WORKFLOW__github_core", uuid.uuid4(), datetime.now(UTC), refused=502
        )
        [surface] = c._listing_state()["listings"]
        assert surface["scope_authorized"] is None and surface["enumeration_complete"] is False

    def test_a_capped_walk_is_incomplete_with_its_reason(self) -> None:
        c = self._collector()
        c._note_listing(
            "account.repositories",
            "OWNS_REPO__github_core",
            uuid.uuid4(),
            datetime.now(UTC),
            complete=False,
            count=100,
            reasons={"enumeration_complete": "walk_capped: page cap"},
        )
        [surface] = c._listing_state()["listings"]
        assert surface["enumeration_complete"] is False and surface["reasons"]["enumeration_complete"].startswith(
            "walk_capped"
        )
        assert surface["source_consistent"] == "unknown" and surface["reasons"]["source_consistent"].startswith(
            "no_promise"
        )

    def test_an_undeterminable_walk_says_so(self) -> None:
        c = self._collector()
        c._note_listing(
            "repository.environments",
            "DECLARES_ENVIRONMENT__github_core",
            uuid.uuid4(),
            datetime.now(UTC),
            complete=None,
        )
        [surface] = c._listing_state()["listings"]
        assert surface["enumeration_complete"] is None
        assert surface["reasons"]["enumeration_complete"].startswith("not_determinable")

    def test_an_unread_workflow_file_lists_no_jobs(self) -> None:
        c = self._collector()
        c._emit_declared_jobs(
            REPO, workflow_id(REPO, 7), 7, ".github/workflows/x.yml", {"jobs": []}, {}, [], [], file_read=False
        )
        [surface] = c._listing_state()["listings"]
        assert surface["relation"] == "workflow.jobs"
        assert (surface["enumeration_complete"], surface["admitted"], surface["count_observed"]) == (False, False, None)
        assert surface["reasons"]["enumeration_complete"].startswith("workflow_yaml_missing")
