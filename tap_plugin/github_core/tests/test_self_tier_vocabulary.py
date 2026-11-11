"""The self-tier vocabulary: declared jobs, refs, rulesets, environments, caches, installations.

Spec: plugins/github_core/specs/spec-github-core-v0.md
      (req-github-core-declared-jobs, -refs, -rulesets, -environments, -caches,
       -app-installations, -app-auth)
Design record: plugins/github_core/specs/spec-github-core-vocabulary.md

The tests that matter most here are the ones about what an EMPTY answer means. A ruleset with no
visible bypass actors, a repository with no visible tags, an App inventory collected by a token
that cannot see one — each is a blank that reads as reassurance and must not.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
import tap_plugin.github_core.models as github  # noqa: F401 — trigger model registration
from tap_plugin.git_core.identity import git_ref_id, git_repository_id
from tap_plugin.github_core.collectors.github_collector.app_jwt import (
    GithubAppAuthError,
)
from tap_plugin.github_core.collectors.github_collector.auth import (
    PREFER_APP,
    PREFER_PAT,
    GithubAuth,
)
from tap_plugin.github_core.collectors.github_collector.collector import GithubCollector, OrgSecretReach
from tap_plugin.github_core.collectors.github_collector.graphql_client import (
    GithubGraphQLClient,
)
from tap_plugin.github_core.collectors.github_collector.identity import (
    actions_secret_id,
    ruleset_id,
    workflow_job_id,
)
from tap_plugin.github_core.collectors.github_collector.manifest import (
    load_collection_manifest,
)
from tap_plugin.github_core.collectors.github_collector.parser import (
    parse_workflow_yaml,
)
from tap_plugin.github_core.collectors.github_collector.secret import (
    GITHUB_SCHEMA,
    SCHEMA_BY_KIND,
    normalize_credentials,
)

from tap_grid.models import Entity
from tap_grid.registry import get_model_class
from tap_grid.services import create_node

from .envelopes import edge_to


def _create(type_slug: str, payload: dict):
    result = create_node(type_slug, payload)
    assert result.success, f"create_node failed: {result.errors}"
    entity = Entity.objects.get(pk=result.entity_id)
    return get_model_class(type_slug).objects.get(entity=entity)


# --------------------------------------------------------------------------------------------
# Identity
# --------------------------------------------------------------------------------------------


class TestIdentity:
    def test_ids_are_deterministic(self) -> None:
        """Pinned to literals, not compared against themselves.

        A natural key cannot be changed once nodes exist, so what needs guarding is the
        DERIVATION — its input string. `f(x) == f(x)` cannot fail for a pure function and
        would stay green through a change that silently re-keyed every node on every existing
        grid.

        github_core's own types are pinned to the batch-local REF since Issue# 162: their ids
        are assigned by core and the ref is the whole of what identifies the source object.
        git_core has not adopted, so its ids are still derived and still pinned as UUIDs.
        """
        assert (
            str(workflow_job_id("o/r", 1, "build"))
            == "github_core__workflow_job:o/r#1#build"
        )
        # Refs are git_core's since github-core#76: repository identity + full path, minted there —
        # pinned here too, because this collector's emitted ids depend on that derivation.
        assert (
            str(git_ref_id(git_repository_id("github.com", "1"), "refs/heads/main"))
            == "d23f94cb-47b2-54f0-ab39-b335586fd80d"
        )
        assert str(ruleset_id("o", 7)) == "github_core__github_ruleset:o#7"

    def test_a_branch_and_a_tag_of_the_same_name_are_different_nodes(self) -> None:
        """The reason identity keys on the full ref path rather than the short name."""
        repo = git_repository_id("github.com", "1")
        assert git_ref_id(repo, "refs/heads/release") != git_ref_id(
            repo, "refs/tags/release"
        )

    def test_one_ruleset_is_one_node_however_many_repositories_it_protects(
        self,
    ) -> None:
        """An organization ruleset is a single object. Keying it per repository would turn
        "what does this ruleset protect" into a string comparison across duplicates.

        Asserted as a pinned literal keyed on owner + id ALONE. Comparing the call against
        itself — the previous form — cannot detect a repo-scoped key, because it never varies
        a repository; and a natural key cannot be changed once nodes exist, so the derivation
        is pinned rather than merely exercised. The signature assertion is the actual guard:
        a repository parameter appearing here would mint one node per repo (measured on the
        fixture org: 3 organization rulesets x 19 repositories = 57 attachments).
        """
        assert (
            str(ruleset_id("acme", 20613528))
            == "github_core__github_ruleset:acme#20613528"
        )
        assert ruleset_id.__code__.co_argcount == 2, (
            "ruleset_id takes (owner, ruleset_id) and nothing else — a third parameter would "
            "let a caller scope the key by repository"
        )

    def test_a_declared_job_is_not_keyed_on_its_display_name(self) -> None:
        """`name:` is free text an author retitles without changing what the job is."""
        assert workflow_job_id("o/r", 1, "build") != workflow_job_id(
            "o/r", 1, "Build & Test"
        )


# --------------------------------------------------------------------------------------------
# Models
# --------------------------------------------------------------------------------------------


@pytest.mark.django_db
class TestDeclaredJobNode:
    def test_inherited_and_empty_permissions_are_not_the_same_value(self) -> None:
        """The distinction the whole type exists to preserve.

        No `permissions:` block means the job inherits the workflow's. `permissions: {}` means the
        job's token is granted nothing at all. Collapsing them reads the most locked-down job in a
        repository as the most permissive one.
        """
        inherits = _create(
            "github_core__workflow_job",
            {"full_name": "o/r", "job_key": "inherits", "permissions": None},
        )
        nothing = _create(
            "github_core__workflow_job",
            {"full_name": "o/r", "job_key": "nothing", "permissions": {}},
        )
        assert inherits.permissions is None
        assert nothing.permissions == {}
        assert inherits.permissions != nothing.permissions

    def test_declaration_dimension_separates_it_from_the_executed_job(self) -> None:
        job = _create(
            "github_core__workflow_job", {"full_name": "o/r", "job_key": "build"}
        )
        job.entity.refresh_from_db()
        assert job.entity.dimensions.get("github.observation") == "declaration"

    def test_checkout_ref_is_a_column_not_a_blob_key(self) -> None:
        job = _create(
            "github_core__workflow_job",
            {
                "full_name": "o/r",
                "job_key": "pwn",
                "checkout_ref": "${{ github.event.pull_request.head.sha }}",
            },
        )
        assert "pull_request.head.sha" in job.checkout_ref


@pytest.mark.django_db
class TestGitRefNode:
    """The ref is git_core's type (github-core#76); this plugin only emits it. One type, both kinds."""

    def test_branch_and_tag_are_one_type(self) -> None:
        branch = _create(
            "git_core__git_ref",
            {"ref": "refs/heads/main", "ref_type": "branch", "name": "main"},
        )
        tag = _create(
            "git_core__git_ref",
            {"ref": "refs/tags/v1", "ref_type": "tag", "name": "v1"},
        )
        assert type(branch) is type(tag)

    def test_ref_type_is_constrained(self) -> None:
        result = create_node(
            "git_core__git_ref", {"ref": "refs/heads/x", "ref_type": "commit"}
        )
        assert not result.success


@pytest.mark.django_db
class TestRulesetNode:
    def test_unobservable_bypass_carries_a_null_count_not_a_zero(self) -> None:
        """A zero is a claim. Null is the absence of one, and that is the honest value when the
        credential could not read the list at all."""
        ruleset = _create(
            "github_core__github_ruleset",
            {
                "ruleset_id": 1,
                "name": "main",
                "bypass_observability": "unobservable",
                "bypass_actor_count": None,
            },
        )
        assert ruleset.bypass_actor_count is None

    def test_observability_state_is_constrained_to_the_two_it_can_be(self) -> None:
        result = create_node(
            "github_core__github_ruleset",
            {"ruleset_id": 2, "bypass_observability": "probably_fine"},
        )
        assert not result.success


@pytest.mark.django_db
class TestRemainingNodes:
    def test_environment_branch_policy_absent_is_null_not_empty(self) -> None:
        env = _create(
            "github_core__github_environment",
            {
                "full_name": "o/r",
                "name": "production",
                "deployment_branch_policy": None,
            },
        )
        assert env.deployment_branch_policy is None

    def test_cache_carries_the_ref_that_produced_it(self) -> None:
        cache = _create(
            "github_core__actions_cache",
            {
                "full_name": "o/r",
                "cache_id": 1,
                "key": "k",
                "ref": "refs/pull/42/merge",
            },
        )
        assert cache.ref == "refs/pull/42/merge"

    def test_installation_holds_the_granted_permissions_not_the_app(self) -> None:
        """The split: permissions belong to one account's grant, not to the application that is
        shared by every account that installed it."""
        installation = _create(
            "github_core__app_installation",
            {
                "installation_id": 157103378,
                "app_slug": "git-serious-exploratory",
                "account_login": "acme",
                "repository_selection": "all",
                "permissions": {"contents": "read"},
            },
        )
        assert installation.permissions == {"contents": "read"}
        assert installation.get_name() == "git-serious-exploratory @ acme"


# --------------------------------------------------------------------------------------------
# Parser — the declaration side
# --------------------------------------------------------------------------------------------


_PWN_REQUEST = """
name: Gate
on:
  pull_request_target:
    branches: [main]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    permissions: {}
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: actions/cache@0c45773b623bea8c8e75f6c82b208c3cf94ea4f9
        with:
          key: ${{ runner.os }}-x
          restore-keys: |
            a-
            b-
  deploy:
    needs: build
    if: github.ref == 'refs/heads/main'
    environment:
      name: production
    runs-on: [self-hosted, linux]
    steps:
      - run: ./deploy.sh
"""


@pytest.fixture(scope="module")
def jobs() -> dict:
    """The declared jobs of a workflow written in the shape the corpus keeps finding."""
    return {j["id"]: j for j in parse_workflow_yaml(_PWN_REQUEST)["jobs"]}


class TestDeclaredJobParsing:

    def test_absent_permissions_block_is_none_and_empty_one_is_a_dict(
        self, jobs
    ) -> None:
        assert jobs["build"]["permissions"] == {}
        assert jobs["deploy"]["permissions"] is None

    def test_checkout_ref_is_lifted_out_of_the_steps(self, jobs) -> None:
        assert (
            jobs["build"]["checkout_ref"] == "${{ github.event.pull_request.head.sha }}"
        )
        assert jobs["deploy"]["checkout_ref"] == ""

    def test_runs_on_is_a_list_whichever_form_was_written(self, jobs) -> None:
        assert jobs["build"]["runs_on"] == ["ubuntu-latest"]
        assert jobs["deploy"]["runs_on"] == ["self-hosted", "linux"]

    def test_runs_on_absent_is_none_not_an_empty_list(self) -> None:
        """A reusable-workflow call declares no runner. None says "not declared"; [] would say
        "declared as nothing", which is not a thing a workflow can say."""
        parsed = parse_workflow_yaml(
            "on: push\njobs:\n  call:\n    uses: ./.github/workflows/x.yml\n"
        )
        assert parsed["jobs"][0]["runs_on"] is None

    def test_runner_group_form_is_flattened_with_its_group_named(self) -> None:
        parsed = parse_workflow_yaml(
            "on: push\njobs:\n  j:\n    runs-on:\n      group: ubuntu-runners\n      labels: [gpu]\n"
        )
        assert parsed["jobs"][0]["runs_on"] == ["gpu", "group:ubuntu-runners"]

    def test_environment_accepts_both_written_forms(self, jobs) -> None:
        assert jobs["deploy"]["environment"] == "production"
        assert (
            parse_workflow_yaml("on: push\njobs:\n  j:\n    environment: staging\n")[
                "jobs"
            ][0]["environment"]
            == "staging"
        )

    def test_cache_key_is_kept_as_an_expression_never_guessed_at(self, jobs) -> None:
        cache = jobs["build"]["cache_steps"][0]
        assert cache["key_expression"] == "${{ runner.os }}-x"
        assert cache["restore_keys"] == ["a-", "b-"]
        assert cache["mode"] == "restore_and_write"

    def test_a_name_pin_is_unresolved_because_the_string_cannot_say_tag_from_branch(
        self, jobs
    ) -> None:
        """`@v4` used to parse as `tag`. Nothing in the string says so — `@main` parsed the same
        way — and a declaration that exists and is false is worse than none. The collector
        upgrades it to `tag`/`branch` only against an in-scope repository's refs
        (req-github-core-actions-used-3)."""
        refs = {r["action"]: r for r in jobs["build"]["action_refs"]}
        assert refs["actions/checkout"]["pin_kind"] == "unresolved"
        assert refs["actions/cache"]["pin_kind"] == "sha"

    def test_an_unpinned_action_is_named_as_such(self) -> None:
        parsed = parse_workflow_yaml(
            "on: push\njobs:\n  j:\n    steps:\n      - uses: foo/bar\n"
        )
        assert parsed["jobs"][0]["action_refs"][0]["pin_kind"] == "unpinned"

    def test_local_actions_are_not_reported_as_third_party_pins(self) -> None:
        parsed = parse_workflow_yaml(
            "on: push\njobs:\n  j:\n    steps:\n      - uses: ./.github/actions/x\n"
        )
        assert parsed["jobs"][0]["action_refs"] == []

    def test_the_if_condition_survives_parsing(self, jobs) -> None:
        assert jobs["deploy"]["if"] == "github.ref == 'refs/heads/main'"

    def test_a_malformed_job_body_does_not_take_the_file_down(self) -> None:
        parsed = parse_workflow_yaml("on: push\njobs:\n  broken: 'just a string'\n")
        assert parsed["jobs"][0]["id"] == "broken"
        assert parsed["jobs"][0]["permissions"] is None


# --------------------------------------------------------------------------------------------
# GraphQL shaping
# --------------------------------------------------------------------------------------------


def _repo_node(**overrides) -> dict:
    node = {
        "nameWithOwner": "acme/widget",
        "defaultBranchRef": {"name": "main", "target": {"oid": "a" * 40}},
        "branchRefs": {
            "totalCount": 2,
            "nodes": [
                {"name": "main", "target": {"oid": "a" * 40}},
                {"name": "topic", "target": {"oid": "b" * 40}},
            ],
        },
        "tagRefs": {
            "totalCount": 2,
            "nodes": [
                {"name": "v1", "target": {"oid": "c" * 40, "__typename": "Commit"}},
                {
                    "name": "v2",
                    "target": {
                        "oid": "d" * 40,
                        "__typename": "Tag",
                        "target": {"oid": "e" * 40},
                    },
                },
            ],
        },
    }
    node.update(overrides)
    return node


class TestGraphQLRefShaping:
    def test_a_lightweight_tag_points_straight_at_its_commit(self) -> None:
        refs = {r["ref"]: r for r in GithubGraphQLClient.refs(_repo_node())[0]}
        assert refs["refs/tags/v1"]["head_sha"] == "c" * 40
        assert refs["refs/tags/v1"]["target_sha"] == "c" * 40

    def test_an_annotated_tag_keeps_the_tag_object_and_the_commit_apart(self) -> None:
        """A re-tag that swaps only the tag object moves one and not the other; one field could
        not show that."""
        refs = {r["ref"]: r for r in GithubGraphQLClient.refs(_repo_node())[0]}
        assert refs["refs/tags/v2"]["target_sha"] == "d" * 40
        assert refs["refs/tags/v2"]["head_sha"] == "e" * 40

    def test_the_default_branch_is_marked_and_nothing_else_is(self) -> None:
        refs = {r["ref"]: r for r in GithubGraphQLClient.refs(_repo_node())[0]}
        assert refs["refs/heads/main"]["is_default"] is True
        assert refs["refs/heads/topic"]["is_default"] is False
        assert refs["refs/tags/v1"]["is_default"] is False

    def test_a_truncated_ref_list_reports_what_it_left_behind(self) -> None:
        """A page cap that goes unreported turns a missing tag into a deleted one."""
        node = _repo_node()
        node["tagRefs"]["totalCount"] = 400
        _, truncated = GithubGraphQLClient.refs(node)
        assert truncated == {"tag": 398}

    def test_a_complete_walk_reports_no_truncation(self) -> None:
        assert GithubGraphQLClient.refs(_repo_node())[1] == {}


class TestGraphQLRulesetShaping:
    @staticmethod
    def _node(**overrides) -> dict:
        ruleset = {
            "databaseId": 20613528,
            "name": "main-required-checks",
            "enforcement": "ACTIVE",
            "target": "BRANCH",
            "conditions": {"refName": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
            "rules": {"nodes": [{"type": "REQUIRED_STATUS_CHECKS"}]},
            "bypassActors": {"totalCount": 0, "nodes": []},
        }
        ruleset.update(overrides)
        return {"rulesets": {"nodes": [ruleset]}}

    def test_graphql_shouting_is_lowered_to_the_casing_github_documents(self) -> None:
        shaped = GithubGraphQLClient.rulesets(self._node())[0]
        assert shaped["enforcement"] == "active"
        assert shaped["target"] == "branch"
        assert shaped["rules"] == [{"type": "required_status_checks"}]

    def test_an_empty_bypass_list_is_not_treated_as_proof(self) -> None:
        assert GithubGraphQLClient.rulesets(self._node())[0]["bypass_proven"] is False

    def test_a_non_empty_bypass_list_proves_itself(self) -> None:
        node = self._node(
            bypassActors={
                "totalCount": 1,
                "nodes": [
                    {
                        "bypassMode": "ALWAYS",
                        "actor": {"__typename": "App", "slug": "x"},
                    }
                ],
            }
        )
        assert GithubGraphQLClient.rulesets(node)[0]["bypass_proven"] is True


# --------------------------------------------------------------------------------------------
# Bypass observability — the derivation the product's honesty rests on
# --------------------------------------------------------------------------------------------


class TestBypassObservability:
    """`observable = REST carried the key OR GraphQL returned a non-empty list`.

    Measured 2026-08-27: GitHub returns a ruleset's bypass actors only to a caller with write
    access to it. REST then omits `bypass_actors` entirely; GraphQL answers with an empty
    connection and NO error. So a non-empty GraphQL answer proves itself — a filtered connection
    cannot invent actors — while an empty one proves nothing.
    """

    @staticmethod
    def _ruleset(actors: list | None = None) -> dict:
        return {"name": "main", "bypass_actors": actors or [], "rules": []}

    def test_rest_carrying_the_key_is_observation_even_when_the_list_is_empty(
        self,
    ) -> None:
        state = GithubCollector._bypass_observability(
            self._ruleset(), {"bypass_actors": []}
        )
        assert state["state"] == "observed"
        assert state["count"] == 0
        assert state["source"] == "rest_ruleset_detail"

    def test_a_non_empty_graphql_answer_is_observation(self) -> None:
        actors = [
            {
                "bypassMode": "ALWAYS",
                "actor": {"__typename": "App", "slug": "ci", "databaseId": 1},
            }
        ]
        state = GithubCollector._bypass_observability(self._ruleset(actors), {})
        assert state["state"] == "observed"
        assert state["count"] == 1
        assert state["source"] == "graphql_bypass_actors"

    def test_both_silent_is_unobservable_and_never_zero(self) -> None:
        """The failure this guards: rendering "we could not look" as "nobody can bypass" — the
        most reassuring possible message, on no evidence."""
        state = GithubCollector._bypass_observability(self._ruleset(), {})
        assert state["state"] == "unobservable"
        assert state["count"] is None

    def test_a_missing_ruleset_detail_does_not_become_an_observation(self) -> None:
        state = GithubCollector._bypass_observability(self._ruleset(), None)
        assert state["state"] == "unobservable"

    def test_actors_without_a_node_type_are_counted_rather_than_dropped(self) -> None:
        """Understating who can bypass is the one direction that must never happen, so a team or
        an org-admin role is kept as data even though neither has a node type yet."""
        actors = [
            {
                "bypassMode": "ALWAYS",
                "actor": {"__typename": "App", "slug": "ci", "databaseId": 1},
            },
            {
                "bypassMode": "PULL_REQUEST",
                "actor": {"__typename": "Team", "slug": "platform"},
            },
            {"bypassMode": "ALWAYS", "organizationAdmin": True, "actor": {}},
        ]
        state = GithubCollector._bypass_observability(self._ruleset(actors), {})
        assert state["count"] == 3
        assert [a["slug"] for a in state["actors"]] == ["ci"]
        assert {a["actor_type"] for a in state["unmodelled"]} == {
            "Team",
            "OrganizationAdmin",
        }


class TestDefaultRefIsRepoScoped:
    """`~DEFAULT_BRANCH` resolves per repository, not per ref path.

    The bug this exists for: one repository defaulting to `main` and another to `master` — with a
    bare ref path as the key, the first repo's default would mark the second repo's same-named
    branch as protected by a ruleset that does not protect it.
    """

    @staticmethod
    def _collector() -> GithubCollector:
        collector = GithubCollector.__new__(GithubCollector)
        collector._default_refs = {"acme/a#refs/heads/main"}
        return collector

    def test_the_default_of_one_repo_does_not_mark_another(self) -> None:
        collector = self._collector()
        assert collector._is_default_ref("acme/a", "refs/heads/main") is True
        assert collector._is_default_ref("acme/b", "refs/heads/main") is False


class TestRefPatternMatching:
    """Ruleset conditions are GitHub's tokens, matched as tokens rather than as text."""

    def test_default_branch_token_matches_only_the_default(self) -> None:
        assert (
            GithubCollector._matching_pattern(
                "refs/heads/main", ["~DEFAULT_BRANCH"], True
            )
            == "~DEFAULT_BRANCH"
        )
        assert (
            GithubCollector._matching_pattern(
                "refs/heads/topic", ["~DEFAULT_BRANCH"], False
            )
            is None
        )

    def test_all_token_matches_anything(self) -> None:
        assert (
            GithubCollector._matching_pattern("refs/tags/v9", ["~ALL"], False) == "~ALL"
        )

    def test_globs_match_over_the_full_ref_path(self) -> None:
        assert GithubCollector._matching_pattern(
            "refs/heads/release/1", ["refs/heads/release/*"], False
        )
        assert (
            GithubCollector._matching_pattern(
                "refs/heads/main", ["refs/heads/release/*"], False
            )
            is None
        )

    def test_no_pattern_matches_nothing(self) -> None:
        assert GithubCollector._matching_pattern("refs/heads/main", [], True) is None


# --------------------------------------------------------------------------------------------
# Credentials and the auth seam
# --------------------------------------------------------------------------------------------


class TestCredentialEnvelope:
    """One envelope carries an App, a token, or both — because neither sees everything."""

    def test_the_current_kind_and_the_legacy_ones_are_all_accepted(self) -> None:
        """samsite's shipped record still declares `github_pat`; breaking its boot to tidy a kind
        name would be a poor trade."""
        assert set(SCHEMA_BY_KIND) == {"github", "github_pat", "github_app"}

    def test_an_envelope_must_carry_at_least_one_credential(self) -> None:
        import jsonschema

        jsonschema.validate(
            {"owner": "acme", "app": {"app_id": 1, "private_key": "pem"}}, GITHUB_SCHEMA
        )
        jsonschema.validate({"owner": "acme", "pat": {"token": "ghp_x"}}, GITHUB_SCHEMA)
        jsonschema.validate(
            {
                "owner": "acme",
                "app": {"app_id": 1, "private_key": "pem"},
                "pat": {"token": "ghp_x"},
            },
            GITHUB_SCHEMA,
        )
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate({"owner": "acme"}, GITHUB_SCHEMA)

    def test_credential_material_cannot_sit_at_the_top_level(self) -> None:
        """A token pasted beside `owner` instead of inside `pat` is caught at load rather than at
        401 — strict schemas are the cheap half of credential hygiene."""
        import jsonschema

        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate({"owner": "acme", "token": "ghp_x"}, GITHUB_SCHEMA)

    def test_legacy_envelopes_fold_into_the_current_shape(self) -> None:
        """One place converts, so nothing above the auth seam branches on which kind arrived."""
        folded_pat = normalize_credentials(
            "github_pat", {"token": "ghp_x", "owner": "acme"}
        )
        assert folded_pat == {"owner": "acme", "pat": {"token": "ghp_x"}}
        folded_app = normalize_credentials(
            "github_app",
            {"app_id": 1, "app_slug": "s", "private_key": "pem", "owner": "acme"},
        )
        assert folded_app == {
            "owner": "acme",
            "app": {"app_id": 1, "app_slug": "s", "private_key": "pem"},
        }


class TestAuthSeam:
    @staticmethod
    def _app_auth(
        installations: list[dict], owner: str = "acme", *, pat: bool = False
    ) -> GithubAuth:
        data: dict = {"owner": owner, "app": {"app_id": 1, "private_key": "pem"}}
        if pat:
            data["pat"] = {"token": "ghp_x"}
        auth = GithubAuth(
            kind="github", data=data, api_base_url="https://api.github.com"
        )
        auth._installations = installations
        return auth

    def test_a_token_only_envelope_reaches_no_app_surface(self) -> None:
        auth = GithubAuth(
            kind="github",
            data={"owner": "acme", "pat": {"token": "t"}},
            api_base_url="x",
        )
        assert auth.has_pat and not auth.has_app
        assert auth.token() == "t"
        assert auth.installations() == []

    def test_there_is_no_mode_to_branch_on(self) -> None:
        """Under a combined envelope "which mode am I" has no correct answer, and any default it
        were given would leave every call site compiling while quietly changing meaning. Capability
        predicates force each caller to say what it needs."""
        assert not hasattr(GithubAuth, "mode")

    def test_the_app_wins_the_bare_token_when_both_are_present(self) -> None:
        """Short-lived, least-privilege and org-owned beats a person's long-lived token for every
        call that does not specifically need the token. If a present PAT won by default, the
        product credential would stop being used and nothing would say so."""
        both = self._app_auth([{"id": 2, "account": {"login": "acme"}}], pat=True)
        assert both.held == [PREFER_APP, PREFER_PAT]

    def test_a_caller_that_needs_the_token_gets_the_token(self) -> None:
        """The ruleset detail asks for the PAT specifically: GitHub returns bypass actors only to
        a caller with write access to the ruleset, which a read-only App never has. A global
        "prefer the App" order would lose that on exactly the deployments that placed both.
        """
        auth = self._app_auth([], pat=True)
        assert auth.token(prefer=PREFER_PAT) == "ghp_x"

    def test_a_missing_credential_says_which_one_would_have_shown_more(self) -> None:
        """This is what turns an unobservable cell into something an operator can act on."""
        app_only = self._app_auth([])
        assert "write access to the ruleset" in app_only.absent_note(PREFER_PAT)
        assert app_only.absent_note(PREFER_APP) == ""

        token_only = GithubAuth(
            kind="github",
            data={"owner": "acme", "pat": {"token": "t"}},
            api_base_url="x",
        )
        assert "GitHub App would show them" in token_only.absent_note(PREFER_APP)
        assert token_only.absent_note(PREFER_PAT) == ""

    def test_holding_both_leaves_nothing_to_explain(self) -> None:
        both = self._app_auth([], pat=True)
        assert both.absent_note(PREFER_APP) == ""
        assert both.absent_note(PREFER_PAT) == ""

    def test_a_token_only_envelope_cannot_mint_an_app_jwt(self) -> None:
        auth = GithubAuth(
            kind="github", data={"owner": "a", "pat": {"token": "t"}}, api_base_url="x"
        )
        with pytest.raises(GithubAppAuthError):
            auth.app_jwt()

    def test_the_installation_is_chosen_by_the_envelope_owner(
        self, monkeypatch
    ) -> None:
        """An App installed into several accounts must be told which one. Taking the first would
        collect one account's repositories under another account's name — silently, and with
        results that look entirely plausible."""
        auth = self._app_auth(
            [
                {"id": 1, "account": {"login": "other"}},
                {"id": 2, "account": {"login": "acme"}},
            ]
        )
        monkeypatch.setattr(auth, "app_jwt", lambda: "jwt")
        monkeypatch.setattr(
            "tap_plugin.github_core.collectors.github_collector.auth.exchange_installation_token",
            lambda base, jwt, installation_id: (f"token-for-{installation_id}", ""),
        )
        assert auth.token() == "token-for-2"
        assert auth.installation["account"]["login"] == "acme"

    def test_an_app_not_installed_on_the_named_account_refuses(self) -> None:
        auth = self._app_auth([{"id": 1, "account": {"login": "other"}}])
        with pytest.raises(GithubAppAuthError, match="not installed"):
            auth.token()

    def test_several_installations_and_no_owner_is_refused_rather_than_guessed(
        self,
    ) -> None:
        auth = self._app_auth(
            [
                {"id": 1, "account": {"login": "a"}},
                {"id": 2, "account": {"login": "b"}},
            ],
            owner="",
        )
        with pytest.raises(GithubAppAuthError, match="several installations"):
            auth.token()

    def test_the_jwt_derivation_lives_in_one_place(self) -> None:
        """The host-side verification script proves a credential the way the collector will use
        it, because both load the same module. A second copy is how "verified" and "works" drift.
        """
        from pathlib import Path

        skill = Path(__file__).resolve().parents[1] / "skills" / "create-github-app"
        verify = (skill / "verify_app.py").read_text()
        assert 'load("app_jwt")' in verify
        assert "def mint_jwt" not in verify
        # And the envelope FOLD, for the same reason (github-core#25: a private kind check in
        # this script refused the very envelope create_app.py writes).
        for script in ("verify_app.py", "create_app.py"):
            text = (skill / script).read_text()
            assert 'load("credential_shape")' in text, script
            assert "def normalize_credentials" not in text, script


# --------------------------------------------------------------------------------------------
# Vocabulary registration
# --------------------------------------------------------------------------------------------


class TestAppInventoryScope:
    """`/app/installations` and `/orgs/{owner}/installations` answer different questions, and the
    difference is the whole reason the App is the product credential."""

    @staticmethod
    def _collector(auth_mode: str = PREFER_APP) -> GithubCollector:
        collector = GithubCollector.__new__(GithubCollector)
        collector._emitted_app_ids = set()
        collector._emitted_installation_ids = set()
        # (level, site, code, message) — the message matters here: the fallback's whole job is to
        # SAY that the answer is about ourselves rather than about the account.
        collector.records: list[tuple] = []
        collector.record_warn = lambda *a, **k: collector.records.append(
            ("warn", *a[:3])
        )
        collector.record_info = lambda *a, **k: collector.records.append(
            ("info", *a[:3])
        )

        class _Auth:
            has_app = auth_mode == PREFER_APP
            has_pat = auth_mode == PREFER_PAT
            held = [auth_mode]

            def absent_note(self, prefer):
                return (
                    ""
                    if (prefer == PREFER_APP and self.has_app)
                    else "a GitHub App would show more here"
                )

            def installations(self):
                return [
                    {
                        "id": 1,
                        "app_slug": "ours",
                        "app_id": 10,
                        "account": {"login": "acme"},
                    }
                ]

        collector._auth = _Auth()
        return collector

    def test_the_account_wide_inventory_is_preferred(self) -> None:
        collector = self._collector()

        class _Client:
            def get_paginated(self, path, **_):
                assert path == "/orgs/acme/installations"
                return [
                    {
                        "id": 1,
                        "app_slug": "renovate",
                        "app_id": 11,
                        "account": {"login": "acme"},
                        "repository_selection": "all",
                        "permissions": {"contents": "write"},
                    },
                    {
                        "id": 2,
                        "app_slug": "sonar",
                        "app_id": 12,
                        "account": {"login": "acme"},
                        "repository_selection": "selected",
                        "permissions": {"contents": "read"},
                    },
                ]

        nodes: list[dict] = []
        edges: list[dict] = []
        collector._collect_app_installations(_Client(), "acme", nodes, edges)
        installs = [
            n
            for n in nodes
            if n["entity"]["entity_type"] == "github_core__app_installation"
        ]
        assert {n["node"]["app_slug"] for n in installs} == {"renovate", "sonar"}
        assert any(
            e["edge"]["edge_type"] == "REGISTERS_INSTALLATION__github_core"
            for e in edges
        )
        assert any(
            e["edge"]["edge_type"] == "INSTALLED_ON_ACCOUNT__github_core" for e in edges
        )

    def test_a_refused_account_inventory_falls_back_and_says_so(self) -> None:
        """The fallback answer is about ourselves. Reporting it as the account's inventory would
        say "one App reaches your repositories" when the truth is "we could not look".
        """
        from tap_plugin.github_core.collectors.github_collector.api_client import (
            GithubAPIError,
        )

        collector = self._collector()

        class _Client:
            def get_paginated(self, path, **_):
                raise GithubAPIError(status=403, url=path, body="{}")

        nodes: list[dict] = []
        collector._collect_app_installations(_Client(), "acme", nodes, [])
        assert [
            n["node"]["app_slug"]
            for n in nodes
            if n["entity"]["entity_type"] == "github_core__app_installation"
        ] == ["ours"]
        assert any(
            r[0] == "warn" and "APP_INVENTORY_PARTIAL_403" in r[2]
            for r in collector.records
        )
        assert any(
            r[0] == "info" and "own only" in r[3] for r in collector.records
        ), "the run must say the inventory is about this App, not about the account"

    def test_a_token_only_envelope_emits_nothing_and_claims_nothing(self) -> None:
        """Without an App the surface is unreachable, not empty — and the run must say which,
        naming the credential that would have answered."""
        collector = self._collector(auth_mode=PREFER_PAT)
        nodes: list[dict] = []
        collector._collect_app_installations(object(), "acme", nodes, [])
        assert nodes == []
        unreachable = [
            r for r in collector.records if "APP_INVENTORY_UNREACHABLE" in str(r)
        ]
        assert (
            unreachable
        ), "an empty inventory must be reported as unreachable, not as empty"
        assert "GitHub App" in unreachable[0][3]


class TestAppEndpointHygiene:
    """The App JWT and the installation token minted from it cross this transport."""

    def test_a_non_https_base_url_is_refused_before_anything_moves(self) -> None:
        """`urlopen` honours whatever scheme it is handed: an http:// base would send the JWT in
        cleartext to a host the envelope chose, and file:// would turn an API call into a local
        file read. The schema refuses both at load; this refuses them again at the call.
        """
        from tap_plugin.github_core.collectors.github_collector import app_jwt

        for bad in (
            "http://api.github.com",
            "file:///etc",
            "ftp://x",
            "api.github.com",
        ):
            with pytest.raises(GithubAppAuthError, match="https|host"):
                app_jwt.app_get(bad, "/app/installations", "jwt")

    def test_the_envelope_schema_refuses_a_non_https_base_url_too(self) -> None:
        import jsonschema

        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(
                {
                    "owner": "acme",
                    "pat": {"token": "t"},
                    "api_base_url": "http://api.github.com",
                },
                GITHUB_SCHEMA,
            )

    def test_the_installation_walk_follows_pagination(self, monkeypatch) -> None:
        """GitHub's default page is 30, and this list is what `owner` is matched against. A
        truncated walk does not produce a short list — it produces "App is not installed on
        <account>" for an account it IS installed on."""
        from tap_plugin.github_core.collectors.github_collector import app_jwt

        pages = {1: [{"id": i} for i in range(100)], 2: [{"id": 100}]}
        seen: list[str] = []

        def _fake_get(base, path, jwt, **_):
            seen.append(path)
            page = int(path.rsplit("page=", 1)[1])
            app_jwt._LAST_LINK_HEADER[0] = '<...>; rel="next"' if page == 1 else ""
            return pages[page]

        monkeypatch.setattr(app_jwt, "app_get", _fake_get)
        result = app_jwt.list_installations("https://api.github.com", "jwt")
        assert len(result) == 101
        assert seen == [
            "/app/installations?per_page=100&page=1",
            "/app/installations?per_page=100&page=2",
        ]

    def test_a_single_short_page_stops_immediately(self) -> None:
        """One request for the overwhelmingly common case — an App installed once."""
        from tap_plugin.github_core.collectors.github_collector import app_jwt

        calls: list[str] = []
        original = app_jwt.app_get
        try:
            app_jwt.app_get = lambda base, path, jwt, **_: (
                calls.append(path) or [{"id": 1}]
            )
            assert len(app_jwt.list_installations("https://api.github.com", "jwt")) == 1
            assert len(calls) == 1
        finally:
            app_jwt.app_get = original


class TestVocabularyIsDeclared:
    @staticmethod
    def _manifest() -> dict:
        import tomllib
        from pathlib import Path

        path = Path(__file__).resolve().parents[1] / "tap-plugin.toml"
        return tomllib.loads(path.read_text())

    def test_every_new_model_is_registered(self) -> None:
        models = self._manifest()["models"]
        assert {
            "github_core__workflow_job",
            "github_core__commit_observation",
            "github_core__github_ruleset",
            "github_core__github_environment",
            "github_core__actions_cache",
            "github_core__app_installation",
        } <= set(models)

    def test_every_new_edge_is_registered_and_its_file_exists(self) -> None:
        from pathlib import Path

        root = Path(__file__).resolve().parents[1]
        edges = self._manifest()["edges"]
        expected = {
            "DEFINES_JOB__github_core",
            "DEPENDS_ON_JOB__github_core",
            "HOSTS_REPOSITORY__github_core",
            "OBSERVES_COMMIT__github_core",
            "OBSERVED_IN_REPOSITORY__github_core",
            "PROTECTS_REPOSITORY__github_core",
            "PROTECTS_REF__github_core",
            "EXEMPTS_ACTOR__github_core",
            "DECLARES_ENVIRONMENT__github_core",
            "USES_ENVIRONMENT__github_core",
            "STORES_CACHE__github_core",
            "SCOPED_TO_REF__github_core",
            "REGISTERS_INSTALLATION__github_core",
            "INSTALLED_ON_ACCOUNT__github_core",
        }
        assert expected <= set(edges)
        for slug in expected:
            assert (
                root / edges[slug]
            ).is_file(), f"{slug} declares a file that is not there"

    def test_the_bypasses_edge_documents_that_its_absence_proves_nothing(self) -> None:
        """The edge cannot carry the absence signal, so its description must send a reader to the
        node that can. This assertion exists because the corpus originally put `observable` on the
        edge alone."""
        from pathlib import Path

        root = Path(__file__).resolve().parents[1]
        edge = json.loads((root / "edges" / "EXEMPTS_ACTOR.edge.json").read_text())
        assert "observable" in edge["property_schema"]["properties"]
        assert "ABSENCE OF THIS EDGE IS NOT ABSENCE OF BYPASS" in edge["description"]

    def test_every_source_declares_a_permission_or_says_why_it_needs_none(self) -> None:
        """The App's permission set is DERIVED from these declarations, so a source that quietly
        omits one narrows what the credential is allowed to see with nobody deciding to.

        The exemption is deliberate and narrow: `/app/installations` is an App-JWT-level endpoint
        about the App itself rather than a grant over anyone's resources, and inventing a triple
        for it would corrupt the derived set. So it must SAY so.
        """
        for source in load_collection_manifest()["sources"]:
            assert source.get("permission") or source.get(
                "permission_not_applicable"
            ), f"{source['name']} declares neither a permission nor a reason it needs none"

    def test_the_derived_permission_set_is_exactly_what_the_sources_ask_for(
        self,
    ) -> None:
        """The exemption must not become a back door into the least-privilege set, and the one
        organization-surface permission must be there BECAUSE a source declares it.

        `organization:administration:read` is the only entry that is not repository-scoped. It
        buys the account-wide installed-App inventory (`/orgs/{owner}/installations`), which is
        the question the product exists to ask about Apps; without it the answer is one row about
        ourselves. Read-only, declared, and asserted here so it cannot drift into an unexplained
        extra on the App.
        """
        import importlib.util
        from pathlib import Path

        skill = (
            Path(__file__).resolve().parents[1]
            / "skills"
            / "create-github-app"
            / "manifest.py"
        )
        spec = importlib.util.spec_from_file_location("gs_manifest_perms", skill)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        repo_perms, org_perms = module.derive_permissions()
        # `pull_requests`, `checks` and `statuses` arrived with the pull-request surface
        # (github-core#82): the rows, and the two halves of the head commit's check rollup. All
        # three were already granted on the product App as recommended reads. `security_events`
        # arrived with code scanning (github-core#89): the alert and analysis listings, each alert
        # minted as a compliance_core finding. A sensitive read, recommended before it was derived.
        # `secrets` arrived with the secret-name surface (github-core#104) and covers both the
        # repository and the environment listings. Names only — GitHub's API returns no value
        # field at any scope — which is the fact that makes a read-only credential asking for it
        # proportionate.
        assert repo_perms == {
            "metadata": "read",
            "actions": "read",
            "contents": "read",
            "administration": "read",
            "secrets": "read",
            "pull_requests": "read",
            "checks": "read",
            "statuses": "read",
            "security_events": "read",
            # `vulnerability_alerts` arrived with the Dependabot surface (github-core#68): the
            # alert listing, each alert minted as a compliance_core finding. A sensitive read,
            # recommended before it was derived and already held by the installed App.
            "vulnerability_alerts": "read",
            # `environments` arrived with the settings surfaces (github-core#110): the REST
            # environment detail is the only transport for required reviewers, admin bypass and
            # the deployment branch policy. Recommended on the product App before it was derived.
            "environments": "read",
        }
        # `packages` arrived with the outputs (github-core#31) and is the one permission an
        # existing installation must re-accept; `custom_properties` (github-core#77) was already
        # granted on the product App as an exploratory read and is now derived from its two
        # sources; every other surface reads under the prior set.
        # Organisation `secrets` is NOT optional alongside the repository key: the estate's
        # most-shared referenced names live at organisation scope and in no repository, so
        # resolving references without it reports working references as broken (github-core#104).
        assert org_perms == {
            "administration": "read",
            "secrets": "read",
            "packages": "read",
            "custom_properties": "read",
        }
        assert all(
            level == "read" for level in {**repo_perms, **org_perms}.values()
        ), "the collector never asks for write"


# --------------------------------------------------------------------------------------------
# The per-repo walk, end to end against stub transports
# --------------------------------------------------------------------------------------------


_WORKFLOW_YAML = """
name: Gate
on: [pull_request_target]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    permissions: {}
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: actions/cache@v4
        with:
          key: ${{ runner.os }}-deps
  deploy:
    needs: build
    environment: production
    runs-on: ubuntu-latest
    steps:
      - run: ./ship.sh
        env:
          # Three references in one file, each exercising a different resolution outcome: the
          # injected token (never a stored secret), a name written in the case the organisation
          # did not use, and a name that exists nowhere.
          GH: ${{ secrets.GITHUB_TOKEN }}
          KEY: ${{ secrets.shared_api_key }}
          MISSING: ${{ secrets.NOT_ANYWHERE }}
"""

#: A GraphQL config-layer node shaped exactly as the live API returns it (verified 2026-08-27
#: against a real organization), so the emitters are exercised against the real shape rather than
#: against a shape invented to make them pass.
_CONFIG_NODE = {
    "nameWithOwner": "acme/widget",
    "name": "widget",
    "databaseId": 42,
    "isArchived": False,
    "isFork": False,
    "visibility": "PRIVATE",
    "url": "https://github.com/acme/widget",
    "defaultBranchRef": {"name": "main", "target": {"oid": "a" * 40}},
    "rulesets": {
        "nodes": [
            {
                "databaseId": 555,
                "name": "main-required-checks",
                "enforcement": "ACTIVE",
                "target": "BRANCH",
                "conditions": {
                    "refName": {"include": ["~DEFAULT_BRANCH"], "exclude": []}
                },
                "rules": {"nodes": [{"type": "REQUIRED_STATUS_CHECKS"}]},
                "bypassActors": {"totalCount": 0, "nodes": []},
            }
        ]
    },
    "environments": {
        "nodes": [
            {"databaseId": 9, "name": "production", "protectionRules": {"nodes": []}}
        ]
    },
    "branchRefs": {
        "totalCount": 2,
        "nodes": [
            {"name": "main", "target": {"oid": "a" * 40}},
            {"name": "topic", "target": {"oid": "b" * 40}},
        ],
    },
    "tagRefs": {
        "totalCount": 1,
        "nodes": [{"name": "v1", "target": {"oid": "c" * 40, "__typename": "Commit"}}],
    },
    "object": {
        "entries": [
            {
                "name": "gate.yml",
                "path": ".github/workflows/gate.yml",
                "object": {"byteSize": 1, "isTruncated": False, "text": _WORKFLOW_YAML},
            }
        ]
    },
}


class _StubClient:
    """A REST client that answers the endpoints the per-repo walk actually calls, and counts them."""

    # Mirrors the real client's class-attribute default. The secret listings read it to tell a
    # complete enumeration from one that stopped at the page cap, and a double that omitted it
    # would fail on the interface rather than on the behaviour under test.
    last_walk_complete = True

    def __init__(self) -> None:
        self.calls: list[str] = []

    def get(self, path, **_):
        self.calls.append(path)
        if path == "/users/acme" or path == "/orgs/acme":
            return {
                "login": "acme",
                "id": 1,
                "type": "Organization",
                "html_url": "https://github.com/acme",
            }
        if path == "/repos/acme/widget/rulesets/555":
            # REST detail WITHOUT `bypass_actors` — the read-only case: GitHub withholds the key.
            return {
                "id": 555,
                "source": "acme",
                "source_type": "Repository",
                "current_user_can_bypass": "never",
                "_links": {
                    "html": {"href": "https://github.com/acme/widget/rules/555"}
                },
                "rules": [
                    {
                        "type": "required_status_checks",
                        "parameters": {
                            "required_status_checks": [
                                {"context": "gate", "integration_id": 15368}
                            ]
                        },
                    }
                ],
            }
        if path == "/repos/acme/widget/actions/caches":
            return {
                "total_count": 2,
                "actions_caches": [
                    {
                        "id": 1,
                        "ref": "refs/heads/main",
                        "key": "k1",
                        "version": "v",
                        "size_in_bytes": 10,
                        "created_at": "2026-08-01T00:00:00Z",
                        "last_accessed_at": "2026-08-02T00:00:00Z",
                    },
                    {
                        "id": 2,
                        "ref": "refs/pull/7/merge",
                        "key": "k2",
                        "version": "v",
                        "size_in_bytes": 10,
                        "created_at": "2026-08-01T00:00:00Z",
                        "last_accessed_at": "2026-08-02T00:00:00Z",
                    },
                ],
            }
        return {}

    def get_paginated(self, path, **_):
        self.calls.append(path)
        if path.endswith("/actions/workflows"):
            return [
                {
                    "id": 7,
                    "path": ".github/workflows/gate.yml",
                    "name": "Gate",
                    "state": "active",
                    "html_url": "https://github.com/acme/widget/actions/workflows/gate.yml",
                }
            ]
        if path.endswith("/actions/runners"):
            return []
        return []


def _walk_one_repo(
    monkeypatch,
    runs: list[dict] | None = None,
    org_secrets: dict[str, list[Any]] | None = None,
) -> tuple[list[dict], list[dict], _StubClient, list[tuple]]:
    """Run `_collect_repo` against the stubs and return (nodes, edges, client, warnings).

    `org_secrets` stands in for the account-scope listing the real run reads once before the
    walk. Default empty AND unobserved, which is the honest default for a harness that never
    asked: `scopes_read` must then omit `organization`.
    """
    collector = GithubCollector.__new__(GithubCollector)
    collector._config = {"acme/widget": _CONFIG_NODE}
    collector._emitted_app_ids = set()
    collector._org_secrets = dict(org_secrets or {})
    collector._org_secrets_observed = org_secrets is not None
    # Production writes a reach beside every organisation secret, so the harness does too —
    # `all` being the ordinary case (github-core#107).
    collector._org_secret_reach = {k: OrgSecretReach("all", frozenset()) for k in (org_secrets or {})}
    collector._emitted_installation_ids = set()
    collector._ruleset_details = {}
    collector._default_refs = set()
    # No token in this envelope: the ruleset detail goes through the App client, and the bypass
    # list comes back withheld — which is the case worth exercising by default, because it is the
    # one whose blank cell must not read as "nobody can bypass".
    collector._pat_client = None
    collector._pat_ruleset_status = "untried"
    collector._run_index = {}
    collector._repo_envelopes = {}

    class _AppOnlyAuth:
        has_app = True
        has_pat = False

        def absent_note(self, prefer):
            return (
                "an owner-minted fine-grained token would show them"
                if prefer == "pat"
                else ""
            )

    collector._auth = _AppOnlyAuth()
    warnings: list[tuple] = []
    collector.record_warn = lambda *a, **k: warnings.append(a)
    collector.record_info = lambda *a, **k: None
    monkeypatch.setattr(
        GithubCollector, "_fetch_run_window", lambda self, c, f, limit: list(runs or [])
    )
    monkeypatch.setattr(
        GithubCollector, "_fetch_non_terminal_refresh", lambda self, c, f, **kw: []
    )

    nodes: list[dict] = []
    edges: list[dict] = []
    client = _StubClient()
    collector._collect_repo(
        client, "acme/widget", 10, nodes, edges, "00000000-0000-0000-0000-000000000001"
    )
    return nodes, edges, client, warnings


class TestPerRepoWalk:
    """The whole self-tier emission, exercised against payloads shaped like the live API."""

    @staticmethod
    def _by_type(nodes: list[dict]) -> dict[str, list[dict]]:
        out: dict[str, list[dict]] = {}
        for n in nodes:
            out.setdefault(n["entity"]["entity_type"], []).append(n)
        return out

    def test_every_self_tier_type_is_emitted(self, monkeypatch) -> None:
        nodes, _edges, _client, _warns = _walk_one_repo(monkeypatch)
        by_type = self._by_type(nodes)
        assert (
            len(by_type["git_core__git_repository"]) == 1
        )  # the neutral repository the record hosts
        assert (
            len(by_type["git_core__git_ref"]) == 3
        )  # 2 branches + 1 tag, git_core's type
        assert len(by_type["github_core__github_ruleset"]) == 1
        assert len(by_type["github_core__github_environment"]) == 1
        assert len(by_type["github_core__workflow_job"]) == 2  # build + deploy
        assert len(by_type["github_core__actions_cache"]) == 2

    def test_the_ruleset_resolves_to_the_default_branch_only(self, monkeypatch) -> None:
        """`~DEFAULT_BRANCH` is a token, not a pattern: it must select `main` and nothing else."""
        _nodes, edges, _client, _warns = _walk_one_repo(monkeypatch)
        resolved = [
            e for e in edges if e["edge"]["edge_type"] == "PROTECTS_REF__github_core"
        ]
        assert len(resolved) == 1
        assert resolved[0]["edge"]["properties"]["ref_pattern"] == "~DEFAULT_BRANCH"

    def test_rest_rule_parameters_win_over_the_type_only_graphql_list(
        self, monkeypatch
    ) -> None:
        """The gate view needs the required check CONTEXTS, which only the REST detail carries."""
        nodes, _edges, _client, _warns = _walk_one_repo(monkeypatch)
        ruleset = self._by_type(nodes)["github_core__github_ruleset"][0]["node"]
        contexts = ruleset["rules"][0]["parameters"]["required_status_checks"]
        assert contexts == [{"context": "gate", "integration_id": 15368}]

    def test_a_withheld_bypass_list_is_unobservable_and_warns(
        self, monkeypatch
    ) -> None:
        """Both transports silent: the node says `unobservable` with a null count, and the run
        says so out loud rather than leaving a blank cell to be read as safety."""
        nodes, _edges, _client, warnings = _walk_one_repo(monkeypatch)
        ruleset = self._by_type(nodes)["github_core__github_ruleset"][0]["node"]
        assert ruleset["bypass_observability"] == "unobservable"
        assert ruleset["bypass_actor_count"] is None
        assert any("RULESET_BYPASS_UNOBSERVABLE" in w for w in warnings)

    def test_a_cache_from_a_pull_request_ref_gets_no_ref_edge(
        self, monkeypatch
    ) -> None:
        """The absence IS the signal: an entry scoped to a PR ref was written from outside the
        branch a privileged job restores it on."""
        _nodes, edges, _client, _warns = _walk_one_repo(monkeypatch)
        scoped = [
            e for e in edges if e["edge"]["edge_type"] == "SCOPED_TO_REF__github_core"
        ]
        assert len(scoped) == 1  # refs/heads/main resolves; refs/pull/7/merge does not

    def test_the_declared_jobs_carry_the_pull_request_target_shape(
        self, monkeypatch
    ) -> None:
        nodes, _edges, _client, _warns = _walk_one_repo(monkeypatch)
        jobs = {
            n["node"]["job_key"]: n["node"]
            for n in self._by_type(nodes)["github_core__workflow_job"]
        }
        assert (
            jobs["build"]["checkout_ref"] == "${{ github.event.pull_request.head.sha }}"
        )
        assert jobs["build"]["configuration"]["workflow_triggers"] == [
            "pull_request_target"
        ]
        assert jobs["build"]["permissions"] == {}  # declared empty
        assert jobs["deploy"]["permissions"] is None  # inherits

    def test_the_needs_graph_and_the_environment_link_are_emitted(
        self, monkeypatch
    ) -> None:
        _nodes, edges, _client, _warns = _walk_one_repo(monkeypatch)
        types = [e["edge"]["edge_type"] for e in edges]
        assert types.count("DEPENDS_ON_JOB__github_core") == 1
        assert types.count("USES_ENVIRONMENT__github_core") == 1
        assert types.count("DEFINES_JOB__github_core") == 2

    def test_a_secret_reference_resolves_across_scopes_and_ignores_case(self, monkeypatch) -> None:
        """The walk resolves `${{ secrets.shared_api_key }}` to an ORGANISATION secret named
        `SHARED_API_KEY`, and reports the one name that exists nowhere.

        Both halves matter and both were wrong in the first cut. Repository-only resolution made
        the estate's most-shared credentials look nonexistent; case-sensitive matching did the
        same to two of nine referenced names. `GITHUB_TOKEN` is absent from every listing by
        design and must not appear as unresolved.
        """
        org_secret = actions_secret_id("organization", "acme", "", "", "SHARED_API_KEY")
        nodes, edges, _client, _warns = _walk_one_repo(monkeypatch, org_secrets={"SHARED_API_KEY": [org_secret]})

        workflow = next(n["node"] for n in nodes if n["entity"]["entity_type"] == "github_core__github_workflow")
        refs = workflow["tags"]["secret_refs"]
        assert refs["referenced"] == ["NOT_ANYWHERE", "shared_api_key"]
        assert refs["unresolved"] == ["NOT_ANYWHERE"]
        # The harness repo declares `production`, so its environment listing is read too.
        assert refs["scopes_read"] == ["organization", "repository", "environment"]

        # Exactly one edge, to the organisation secret — never to the unresolved name, which has
        # no node and must not acquire one on the evidence that somebody typed it.
        targets = [
            str(edge_to(e)) for e in edges if e["edge"]["edge_type"] == "REFERENCES_SECRET__github_core"
        ]
        assert targets == [str(org_secret)]

    def test_an_unread_organisation_scope_is_absent_from_scopes_read(self, monkeypatch) -> None:
        """Default harness: no organisation listing was read, so the tag may not claim one.

        This is what stops "unresolved" being read as "does not exist" after a run whose
        credential simply could not see the account's secrets.
        """
        nodes, _edges, _client, _warns = _walk_one_repo(monkeypatch)
        workflow = next(n["node"] for n in nodes if n["entity"]["entity_type"] == "github_core__github_workflow")
        assert workflow["tags"]["secret_refs"]["scopes_read"] == [
            "repository",
            "environment",
        ]
        assert "organization" not in workflow["tags"]["secret_refs"]["scopes_read"]

    def test_each_run_is_fetched_for_jobs_once(self, monkeypatch) -> None:
        """The EXECUTED_ON_RUNNER pass reuses the job payloads instead of walking every run a second
        time — at account scope that second walk was one extra API call per RUN, and runs are the
        largest thing collected. It cost a 10-minute collection its boot timeout before it was
        found."""
        seen: list[int] = []
        monkeypatch.setattr(
            GithubCollector,
            "_fetch_run_jobs",
            lambda self, c, f, run_id: (
                seen.append(run_id) or [{"id": 1, "name": "build"}]
            ),
        )
        _walk_one_repo(
            monkeypatch, runs=[{"id": 100, "run_number": 1, "workflow_id": 7}]
        )
        assert seen == [100], f"each run's jobs should be fetched once, got {seen}"
