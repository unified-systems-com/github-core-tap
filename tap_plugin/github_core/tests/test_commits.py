"""Commits after github-core#76: the neutral half is git_core's, the observed half is ours.

The `CommitSlice` parsing (three signature states, identity as observed) is unchanged. What
changed is where the pieces land: intrinsic metadata becomes `git_core__git_commit` under the
global `(sha1, oid)` identity with `STORES_COMMIT` / `RESOLVES_COMMIT`; the logins GitHub
resolved and its signature verdict become `github_core__commit_observation`, keyed per host +
repository stable id + commit, with `OBSERVES_COMMIT` and `OBSERVED_IN_REPOSITORY`.
"""

from __future__ import annotations

import pytest
import tap_plugin.github_core.models as github  # noqa: F401 — trigger model registration
from tap_plugin.git_core.identity import git_commit_id, git_ref_id, git_repository_id
from tap_plugin.github_core.collectors.github_collector.collector import GithubCollector
from tap_plugin.github_core.collectors.github_collector.graphql_client import (
    GithubGraphQLClient,
)
from tap_plugin.github_core.collectors.github_collector.identity import (
    commit_observation_id,
    repository_id,
)

from tap_grid.models import Entity
from tap_grid.registry import get_model_class
from tap_grid.service_types import WriteOperation
from tap_grid.services import create_edge, create_node, write_batch

from .envelopes import edge_from, edge_to, envelope_key
from tap_plugin.github_core.tests.conftest import dimension_containment


def _create(type_slug: str, payload: dict):
    result = create_node(type_slug, payload)
    assert result.success, f"create_node failed: {result.errors}"
    entity = Entity.objects.get(pk=result.entity_id)
    return get_model_class(type_slug).objects.get(entity=entity)


_SIGNED = {
    "oid": "e" * 40,
    "committedDate": "2026-08-31T17:46:58Z",
    "authoredDate": "2026-08-31T17:46:58Z",
    "author": {
        "name": "George Chamales",
        "email": "george@example.com",
        "user": {"login": "notgeorge"},
    },
    "committer": {
        "name": "George Chamales",
        "email": "george@example.com",
        "user": {"login": "notgeorge"},
    },
    "signature": {
        "__typename": "SshSignature",
        "isValid": True,
        "state": "VALID",
        "wasSignedByGitHub": False,
        "signer": {"login": "notgeorge"},
    },
}
_UNSIGNED = {
    "oid": "c" * 40,
    "committedDate": "2026-08-09T15:33:22Z",
    "authoredDate": "2026-08-09T15:33:22Z",
    "author": {"name": "Someone", "email": "nobody@example.com", "user": None},
    "committer": {"name": "Someone", "email": "nobody@example.com", "user": None},
    "signature": None,
}

GITHUB_ID = 4242
GIT_REPO = git_repository_id("github.com", str(GITHUB_ID))


class TestIdentity:
    def test_the_observation_is_scoped_by_host_and_stable_repository_id(self) -> None:
        a = commit_observation_id("github.com", GITHUB_ID, "sha1", "A" * 40)
        assert a == commit_observation_id("github.com", GITHUB_ID, "sha1", "a" * 40)
        assert a != commit_observation_id(
            "github.com", GITHUB_ID + 1, "sha1", "a" * 40
        ), "another repository, another record"
        assert a != commit_observation_id("ghe.example", GITHUB_ID, "sha1", "a" * 40)

    def test_the_commit_itself_is_global(self) -> None:
        """One commit node per oid however many repositories store it — the observation is what is scoped."""
        assert git_commit_id("sha1", "a" * 40) == git_commit_id("sha1", "A" * 40)


class TestCommitSlice:
    def test_a_signed_commit_keeps_kind_state_validity_and_signer(self) -> None:
        s = GithubGraphQLClient.commit_slice(_SIGNED, _SIGNED["oid"])
        assert s and s["signature_kind"] == "ssh" and s["signature_state"] == "valid"
        assert (
            s["signature_valid"] is True
            and s["signer_login"] == "notgeorge"
            and s["signed_by_github"] is False
        )

    def test_a_null_signature_is_unsigned_with_a_null_validity_not_false(self) -> None:
        s = GithubGraphQLClient.commit_slice(_UNSIGNED, _UNSIGNED["oid"])
        assert (
            s
            and s["signature_state"] == "unsigned"
            and s["signature_valid"] is None
            and s["signature_kind"] == ""
        )

    def test_an_unresolved_author_is_an_empty_login_not_a_missing_field(self) -> None:
        s = GithubGraphQLClient.commit_slice(_UNSIGNED, _UNSIGNED["oid"])
        assert s and s["author_login"] == "" and s["author_name"] == "Someone"

    def test_a_signature_key_that_was_not_answered_is_unobservable_not_unsigned(
        self,
    ) -> None:
        body = {k: v for k, v in _SIGNED.items() if k != "signature"}
        s = GithubGraphQLClient.commit_slice(body, body["oid"])
        assert (
            s
            and s["signature_state"] == "unobservable"
            and s["signature_valid"] is None
        )

    def test_nulls_inside_a_present_signature_stay_null(self) -> None:
        partial = {
            **_SIGNED,
            "signature": {
                "__typename": "GpgSignature",
                "isValid": None,
                "state": "VALID",
            },
        }
        slice_ = GithubGraphQLClient.commit_slice(partial, "e" * 40)
        assert (
            slice_ is not None
            and slice_["signature_valid"] is None
            and slice_["signature_kind"] == "gpg"
        )

    def test_a_body_without_the_fragment_is_no_slice_at_all(self) -> None:
        """A degraded field, or a stub without the fragment: nothing to observe, so None —
        never a node of empty strings that would read as an unsigned commit by nobody.
        """
        assert GithubGraphQLClient.commit_slice({"oid": "d" * 40}, "d" * 40) is None
        assert GithubGraphQLClient.commit_slice(_SIGNED, "") is None


def _repo_node() -> dict:
    return {
        "databaseId": GITHUB_ID,
        "defaultBranchRef": {"name": "main"},
        "branchRefs": {
            "totalCount": 2,
            "nodes": [
                {"name": "main", "target": {"__typename": "Commit", **_SIGNED}},
                {
                    "name": "topic",
                    "target": {"__typename": "Commit", "oid": "f" * 40},
                },  # no slice: degraded
            ],
        },
        "tagRefs": {
            "totalCount": 2,
            "nodes": [
                {"name": "v1", "target": {"__typename": "Commit", **_UNSIGNED}},
                {
                    "name": "v2",
                    "target": {
                        "__typename": "Tag",
                        "oid": "1" * 40,
                        "target": {"__typename": "Commit", **_SIGNED},
                    },
                },
            ],
        },
    }


class TestPrunedErrors:
    def test_a_field_error_removes_the_key_so_null_cannot_be_read_as_an_answer(
        self,
    ) -> None:
        from tap_plugin.github_core.collectors.github_collector.graphql_client import (
            prune_errored_paths,
        )

        data = {
            "repositoryOwner": {
                "repositories": {
                    "nodes": [
                        {
                            "branchRefs": {
                                "nodes": [
                                    {
                                        "name": "main",
                                        "target": {
                                            "oid": "e" * 40,
                                            "committedDate": "x",
                                            "signature": None,
                                        },
                                    }
                                ]
                            }
                        }
                    ]
                }
            }
        }
        errors = [
            {
                "type": "FORBIDDEN",
                "path": [
                    "repositoryOwner",
                    "repositories",
                    "nodes",
                    0,
                    "branchRefs",
                    "nodes",
                    0,
                    "target",
                    "signature",
                ],
            }
        ]
        assert prune_errored_paths(data, errors) == 1
        target = data["repositoryOwner"]["repositories"]["nodes"][0]["branchRefs"][
            "nodes"
        ][0]["target"]
        assert "signature" not in target and target["committedDate"] == "x"
        assert (
            GithubGraphQLClient.commit_slice(target, "e" * 40)["signature_state"]
            == "unobservable"
        )

    def test_an_unresolvable_path_is_skipped_not_fatal(self) -> None:
        from tap_plugin.github_core.collectors.github_collector.graphql_client import (
            prune_errored_paths,
        )

        assert (
            prune_errored_paths(
                {"a": {}},
                [{"path": ["a", "b", "c"]}, {"path": []}, {"message": "root"}],
            )
            == 0
        )


class TestRefShaping:
    def test_the_commit_rides_the_ref_and_an_annotated_tag_reaches_the_nested_commit(
        self,
    ) -> None:
        refs = {r["ref"]: r for r in GithubGraphQLClient.refs(_repo_node())[0]}
        assert refs["refs/heads/main"]["commit"]["sha"] == "e" * 40
        assert (
            refs["refs/tags/v2"]["commit"]["sha"] == "e" * 40
        )  # the commit, not the tag object
        assert refs["refs/tags/v2"]["target_sha"] == "1" * 40
        assert refs["refs/tags/v1"]["commit"]["signature_state"] == "unsigned"

    def test_a_ref_whose_commit_was_not_answered_carries_none(self) -> None:
        refs = {r["ref"]: r for r in GithubGraphQLClient.refs(_repo_node())[0]}
        assert refs["refs/heads/topic"]["commit"] is None


class TestEmission:
    @staticmethod
    def _collector() -> GithubCollector:
        c = GithubCollector.__new__(GithubCollector)
        c._config = {"acme/widget": _repo_node()}
        c._default_refs = set()
        c.record_warn = lambda *a, **k: None  # type: ignore[method-assign]
        return c

    @staticmethod
    def _emit(c: GithubCollector) -> tuple[list[dict], list[dict]]:
        nodes: list[dict] = []
        edges: list[dict] = []
        dims = {
            "git.host": "github.com",
            "github.owner": "acme",
            "github.repo": "widget",
        }
        c._emit_refs(
            "acme/widget",
            repository_id("acme/widget"),
            GIT_REPO,
            GITHUB_ID,
            dims,
            nodes,
            edges,
        )
        return nodes, edges

    def test_one_neutral_commit_per_oid_and_the_resolve_edge_from_each_ref(
        self,
    ) -> None:
        nodes, edges = self._emit(self._collector())
        commits = [
            n for n in nodes if n["entity"]["entity_type"] == "git_core__git_commit"
        ]
        resolves = [
            e for e in edges if e["edge"]["edge_type"] == "RESOLVES_COMMIT__git_core"
        ]
        # main and v2 share one commit (emitted twice, same id — collapse keeps one); v1 is
        # another; topic carried no slice and gets neither node nor edge.
        assert {envelope_key(n) for n in commits} == {
            str(git_commit_id("sha1", "e" * 40)),
            str(git_commit_id("sha1", "c" * 40)),
        }
        assert len(resolves) == 3
        assert {edge_from(e) for e in resolves} == {
            str(git_ref_id(GIT_REPO, "refs/heads/main")),
            str(git_ref_id(GIT_REPO, "refs/tags/v1")),
            str(git_ref_id(GIT_REPO, "refs/tags/v2")),
        }

    def test_the_neutral_rows_carry_only_git_core_dimensions_and_intrinsic_fields(
        self,
    ) -> None:
        nodes, edges = self._emit(self._collector())
        ref = next(
            n for n in nodes if n["entity"]["entity_type"] == "git_core__git_ref"
        )
        assert (
            ref["entity"]["dimensions"] == {"git.host": "github.com"}
            and "full_name" not in ref["node"]
        )
        commit = next(
            n for n in nodes if n["entity"]["entity_type"] == "git_core__git_commit"
        )
        assert commit["entity"]["dimensions"] == {"git.host": "github.com"}
        assert set(commit["node"]) == {
            "hash_algorithm",
            "oid",
            "authored_date",
            "committed_date",
            "author_name",
            "author_email",
            "committer_name",
            "committer_email",
        }
        declares = [
            e for e in edges if e["edge"]["edge_type"] == "DECLARES_REF__git_core"
        ]
        stores = [
            e for e in edges if e["edge"]["edge_type"] == "STORES_COMMIT__git_core"
        ]
        assert len(declares) == 4 and all(
            edge_from(e) == str(GIT_REPO) for e in declares
        )
        assert {edge_to(e) for e in stores} == {
            envelope_key(n)
            for n in nodes
            if n["entity"]["entity_type"] == "git_core__git_commit"
        }

    def test_the_observation_carries_the_github_facts_and_is_repository_scoped(
        self,
    ) -> None:
        nodes, edges = self._emit(self._collector())
        obs = [
            n
            for n in nodes
            if n["entity"]["entity_type"] == "github_core__commit_observation"
        ]
        signed = next(n for n in obs if n["node"]["sha"] == "e" * 40)
        assert envelope_key(signed) == str(
            commit_observation_id("github.com", GITHUB_ID, "sha1", "e" * 40)
        )
        assert (
            signed["node"]["full_name"] == "acme/widget"
            and signed["node"]["repository_github_id"] == GITHUB_ID
        )
        assert (
            signed["node"]["author_login"] == "notgeorge"
            and signed["node"]["signature_state"] == "valid"
        )
        assert signed["entity"]["dimensions"]["github.repo"] == "widget"
        # `github.surface: git` is retired (github-core#168): it marked github's write to
        # the neutral layer, and the neutral layer no longer carries github's vocabulary.
        assert "github.surface" not in signed["entity"]["dimensions"]
        observes = next(
            e
            for e in edges
            if e["edge"]["edge_type"] == "OBSERVES_COMMIT__github_core"
            and edge_from(e) == envelope_key(signed)
        )
        assert edge_to(observes) == str(git_commit_id("sha1", "e" * 40))
        observed_in = next(
            e
            for e in edges
            if e["edge"]["edge_type"] == "OBSERVED_IN_REPOSITORY__github_core"
            and edge_from(e) == envelope_key(signed)
        )
        assert edge_to(observed_in) == str(repository_id("acme/widget"))

    def test_a_target_without_a_typename_gets_its_kind_from_the_peel(self) -> None:
        """Live collection 2026-09-08: refs whose target carried no `__typename` failed git_core's
        target_type-when-target_sha rule. The peel decides: differs from head -> tag object, else commit.
        """
        c = self._collector()
        node = _repo_node()
        for ref in node["branchRefs"]["nodes"] + node["tagRefs"]["nodes"]:
            ref["target"].pop("__typename", None)
        c._config = {"acme/widget": node}
        nodes, _edges = self._emit(c)
        by_ref = {
            n["node"]["ref"]: n["node"]
            for n in nodes
            if n["entity"]["entity_type"] == "git_core__git_ref"
        }
        assert by_ref["refs/heads/main"]["target_type"] == "commit"
        assert by_ref["refs/tags/v1"]["target_type"] == "commit"
        assert (
            by_ref["refs/tags/v2"]["target_type"] == "tag"
            and by_ref["refs/tags/v2"]["target_sha"] == "1" * 40
        )

    def test_no_neutral_repository_means_no_refs_and_no_commits(self) -> None:
        nodes: list[dict] = []
        edges: list[dict] = []
        c = self._collector()
        out = c._emit_refs(
            "acme/widget",
            repository_id("acme/widget"),
            None,
            None,
            {"git.host": "github.com"},
            nodes,
            edges,
        )
        assert out == {} and nodes == [] and edges == []


@pytest.mark.django_db
class TestModelAndEdge:
    def test_unsigned_stores_a_null_validity(self) -> None:
        obs = _create(
            "github_core__commit_observation",
            {
                "host": "github.com",
                "full_name": "o/r",
                "sha": "c" * 40,
                "signature_state": "unsigned",
                "signature_valid": None,
            },
        )
        assert obs.signature_valid is None and obs.get_name() == "o/r@" + "c" * 12

    def test_signature_kind_is_constrained_and_sha_must_be_lower_case(self) -> None:
        assert not create_node(
            "github_core__commit_observation",
            {"host": "github.com", "full_name": "o/r", "sha": "c" * 40, "signature_kind": "pgp"},
        ).success
        assert not create_node(
            "github_core__commit_observation", {"host": "github.com", "full_name": "o/r", "sha": "C" * 40}
        ).success

    def test_observes_commit_is_observation_to_commit_and_property_free(self) -> None:
        obs = _create(
            "github_core__commit_observation", {"host": "github.com", "full_name": "o/r", "sha": "c" * 40}
        )
        commit = _create(
            "git_core__git_commit", {"hash_algorithm": "sha1", "oid": "c" * 40}
        )
        edge = create_edge(
            obs.entity, commit.entity, "OBSERVES_COMMIT__github_core", {}
        )
        assert (
            edge.edge_type == "OBSERVES_COMMIT__github_core" and edge.properties == {}
        )
        assert (
            edge.from_entity_id == obs.entity_id
            and edge.to_entity_id == commit.entity_id
        )


@pytest.mark.django_db
@pytest.mark.spec("req-github-core-dimensions-1")
class TestOneHostIsOneFilter:
    """One key, one meaning, both layers (github-core#168, git-core-tap#11).

    github_core mints two kinds of row: its own forge records and the neutral `git_core`
    substrate. Before this ruling those carried different tenancy spellings — `github.platform`
    on one side, nothing but `git.object` on the other — so "every node on this instance" was a
    union of two filters, and the neutral half could not answer it at all.

    The property under test is the one that ruling bought: ONE dimension filter, `git.host`,
    returns both layers. It is asserted on the dimensions the COLLECTOR actually stamps rather
    than on hand-written ones, so a collector that stopped stamping would fail here.
    """

    @staticmethod
    def _emitted() -> tuple[list[dict], list[dict]]:
        return TestEmission._emit(TestEmission._collector())

    def test_every_envelope_the_collector_mints_carries_the_host(self) -> None:
        """Both layers, every node and every edge, one key — and none of the retired ones."""
        nodes, edges = self._emitted()
        assert nodes and edges
        assert {n["entity"]["entity_type"].split("__")[0] for n in nodes} == {
            "git_core",
            "github_core",
        }, "this fixture must mint BOTH layers or it proves nothing about either"
        for envelope in [*nodes, *edges]:
            what = envelope["entity"]["entity_type"], envelope["entity"].get("name")
            dimensions = envelope["entity"]["dimensions"]
            assert dimensions.get("git.host") == "github.com", what
            assert "github.platform" not in dimensions, what
            assert "git.object" not in dimensions, what
            assert dimensions.get("github.surface") != "git", what

    def test_the_neutral_rows_carry_the_host_and_none_of_githubs_vocabulary(self) -> None:
        """The host travels to the substrate; owner, repo and surface deliberately do not."""
        nodes, _edges = self._emitted()
        neutral = [
            n for n in nodes if n["entity"]["entity_type"].startswith("git_core__")
        ]
        assert neutral
        for envelope in neutral:
            assert envelope["entity"]["dimensions"] == {"git.host": "github.com"}

    def test_one_dimension_filter_returns_both_layers(self) -> None:
        """The done-test: a search for every node on one instance, in a single filter.

        Both rows are landed carrying exactly what the collector stamps on them — the forge
        record from its model default, the neutral commit from the envelope the collector built.
        """
        nodes, _edges = self._emitted()
        neutral_dimensions = next(
            n["entity"]["dimensions"]
            for n in nodes
            if n["entity"]["entity_type"] == "git_core__git_commit"
        )
        observation = _create(
            "github_core__commit_observation",
            {"host": "github.com", "full_name": "acme/widget", "sha": "e" * 40},
        )
        landed = write_batch(
            [
                WriteOperation(
                    verb="create_node",
                    type_slug="git_core__git_commit",
                    payload={"hash_algorithm": "sha1", "oid": "e" * 40},
                    dimensions=dict(neutral_dimensions),
                )
            ]
        )
        assert landed.success, landed.errors

        on_this_host = Entity.objects.filter(
            dimensions__contains=dimension_containment("git.host", "github.com")
        )
        types = set(on_this_host.values_list("entity_type", flat=True))
        assert {"github_core__commit_observation", "git_core__git_commit"} <= types, (
            "one filter must return both layers; got " + repr(sorted(types))
        )
        assert observation.entity_id in set(on_this_host.values_list("id", flat=True))
        # And the retired spelling answers nothing — the union that made this two filters is gone.
        assert not Entity.objects.filter(
            dimensions__has_key="github.platform"
        ).exists()
