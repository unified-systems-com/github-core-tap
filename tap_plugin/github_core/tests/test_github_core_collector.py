"""Unit tests for the github_core collector building blocks.

Spec: plugins/github_core/specs/spec-github-core-v0.md
"""

from __future__ import annotations

import json
from typing import Any

import jsonschema
import pytest
from tap_plugin.github_core.collectors.github_collector.identity import (
    account_id,
    edge_id,
    job_id,
    repository_id,
    run_id,
    runner_id,
    workflow_id,
)
from tap_plugin.github_core.collectors.github_collector.manifest import (
    load_collection_manifest,
    load_link_manifest,
)
from tap_plugin.github_core.collectors.github_collector.parser import parse_workflow_yaml
from tap_plugin.github_core.collectors.github_collector.secret import (
    GITHUB_APP_SCHEMA,
    GITHUB_PAT_SCHEMA,
    GITHUB_SCHEMA,
    api_base_url,
    initial_run_limit,
)

from .envelopes import edge_to, envelope_key


class TestManifests:
    def test_collection_manifest_loads(self) -> None:
        manifest = load_collection_manifest()
        assert manifest["manifest_version"] == "0"
        assert {s["name"] for s in manifest["sources"]} >= {
            "account",
            "repository",
            "workflows",
            "workflow_yaml",
            "runs",
            "jobs",
            "runners",
        }

    def test_link_manifest_loads(self) -> None:
        manifest = load_link_manifest()
        assert manifest["manifest_version"] == "0"
        edge_types = {r["edge_type"] for r in manifest["rules"]}
        # YAML-ref rules emit REFERENCES_RESOURCE; the structural OIDC rule emits
        # FEDERATES_VIA_PROVIDER (repo -> aws_iam_oidc_provider); the issuer-convergence
        # rule emits TRUSTS_ISSUER (aws_iam_oidc_provider -> identity_core__oidc_issuer),
        # the generic identity_core-owned edge type this github enrichment rule emits.
        assert edge_types == {
            "REFERENCES_RESOURCE__github_core",
            "FEDERATES_VIA_PROVIDER__github_core",
            "TRUSTS_ISSUER__identity_core",
        }

    def test_link_manifest_oneof_source_enforced(self) -> None:
        """Schema must reject rules with both source_field_path and source_constant."""
        import jsonschema
        from tap_plugin.github_core.collectors.github_collector.manifest import (
            LINK_MANIFEST_SCHEMA_PATH,
        )

        schema = __import__("json").loads(LINK_MANIFEST_SCHEMA_PATH.read_text())
        bad = {
            "manifest_version": "0",
            "rules": [
                {
                    "name": "bad",
                    "source_entity_type": "github_core__github_repository",
                    "source_field_path": "x.y",
                    "source_constant": "z",
                    "target_entity_type": "aws_core__aws_iam_oidc_provider",
                    "target_field": "url",
                    "edge_type": "REFERENCES_RESOURCE__github_core",
                    "match_mode": "exact",
                }
            ],
        }
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(bad, schema)

    def test_link_manifest_includes_oidc_rule(self) -> None:
        manifest = load_link_manifest()
        oidc = [r for r in manifest["rules"] if r.get("target_entity_type") == "aws_core__aws_iam_oidc_provider"]
        assert len(oidc) == 1
        rule = oidc[0]
        assert rule["source_constant"] == "token.actions.githubusercontent.com"
        assert rule["near_match_pattern"] == r"(?i)githubusercontent\.com"
        # The federation rule emits the dedicated FEDERATES_VIA_PROVIDER edge (not the
        # generic REFERENCES_RESOURCE) — repo -> aws_iam_oidc_provider.
        assert rule["edge_type"] == "FEDERATES_VIA_PROVIDER__github_core"


class TestInstallationSelection:
    """github-core#141: what this run may weigh in on, recorded before it weighs in."""

    @staticmethod
    def _collector(auth):
        from tap_plugin.github_core.collectors.github_collector.collector import GithubCollector

        c = GithubCollector.__new__(GithubCollector)
        c.results = {"info": [], "warn": [], "error": []}
        c._auth = auth
        return c

    class _Auth:
        def __init__(self, *, app: bool, pat_token: str = "", selection: str = "selected"):
            self.has_app, self.has_pat = app, bool(pat_token)
            self._pat_token = pat_token
            self.installation = {"id": 7, "repository_selection": selection} if app else None

        def token(self, prefer=None):
            return self._pat_token

    class _Client:
        def __init__(self, rows, total=None, status=None, complete=True):
            self.rows, self.total, self.status, self.complete = rows, total, status, complete
            self.calls: list[str] = []
            self.last_walk_complete = True

        def get(self, path, *, params=None):
            from tap_plugin.github_core.collectors.github_collector.api_client import GithubAPIError

            self.calls.append(path)
            if self.status:
                raise GithubAPIError(status=self.status, url=path, body="{}")
            return {"total_count": self.total if self.total is not None else len(self.rows), "repositories": self.rows}

        def get_paginated(self, path, *, params=None, item_path=None, max_pages=100):
            self.calls.append(path)
            self.last_walk_complete = self.complete
            return list(self.rows)

    def test_selected_app_records_the_ids_and_reconciles_the_count(self) -> None:
        c = self._collector(self._Auth(app=True))
        client = self._Client([{"id": 1, "full_name": "o/a"}, {"id": 2, "full_name": "o/b"}])
        c._collect_installation_selection(client)
        (event,) = c.results["info"]
        assert event["message_code"] == "INSTALLATION_SELECTION"
        assert event["message_data"] == {
            "credential": "app", "kind": "selected", "repository_ids": [1, 2], "count": 2, "total_count": 2, "complete": True,
        }
        assert client.calls == ["/installation/repositories", "/installation/repositories"]

    def test_a_count_that_disagrees_with_the_walk_is_incomplete_not_shorter(self) -> None:
        c = self._collector(self._Auth(app=True, selection="all"))
        client = self._Client([{"id": 1}], total=3)
        c._collect_installation_selection(client)
        (event,) = c.results["info"]
        assert event["message_data"]["complete"] is False and event["message_data"]["total_count"] == 3
        assert "INCOMPLETE" in event["message"]

    def test_a_capped_walk_is_incomplete(self) -> None:
        c = self._collector(self._Auth(app=True))
        client = self._Client([{"id": 1}], complete=False)
        c._collect_installation_selection(client)
        assert c.results["info"][0]["message_data"]["complete"] is False

    def test_a_refused_listing_is_recorded_with_the_declared_kind(self) -> None:
        c = self._collector(self._Auth(app=True))
        client = self._Client([], status=403)
        c._collect_installation_selection(client)
        assert c.results["info"] == []
        (warn,) = c.results["warn"]
        assert warn["message_code"] == "INSTALLATION_SELECTION_UNREADABLE_403"
        # The full selection shape, observed-nothing fields null and `complete` false, so the
        # scope node reads "declared selected, members unobserved" (github-core#145).
        assert warn["message_data"] == {
            "credential": "app", "kind": "selected", "repository_ids": None, "count": None,
            "total_count": None, "complete": False, "status": 403,
        }

    def test_a_missing_total_count_is_incomplete_not_complete(self) -> None:
        """Codex on PR #144: an unreconcilable selection is not one absence may be weighed against."""
        c = self._collector(self._Auth(app=True))
        client = self._Client([{"id": 1}])
        client.get = lambda path, *, params=None: {"repositories": client.rows}  # no total_count
        c._collect_installation_selection(client)
        (event,) = c.results["info"]
        assert event["message_data"]["total_count"] is None and event["message_data"]["complete"] is False

    def test_any_pat_is_unknown_reach_and_the_token_never_lands(self) -> None:
        """Codex on PR #144: a classic token's scopes do not establish its effective reach (no
        `repo`, outside the org, SSO-blocked), so `all` was a claim, not a measurement. Both token
        kinds are unknown until the seam exposes `X-OAuth-Scopes`; the kind is recorded, the
        value never is."""
        for token, token_kind in (("ghp_" + "x" * 36, "classic"), ("github_pat_" + "y" * 22, "fine_grained")):
            c = self._collector(self._Auth(app=False, pat_token=token))
            c._collect_installation_selection(self._Client([]))
            (event,) = c.results["info"]
            md = event["message_data"]
            assert md["credential"] == "pat" and md["token_kind"] == token_kind and md["kind"] == "unknown"
            assert md["repository_ids"] is None and md["complete"] is False
            assert token not in json.dumps(event)
# Not key material: the same non-armour marker test_credential_shape.py uses, so no scanner
# (ours or Codacy's gitleaks) reads a test fixture as a hard-coded credential.
_APP = {"app_id": 1, "private_key": "-----BEGIN PEM-----"}


class TestScopeRuleIsOneRuleForEveryKind:
    """github-core#139: a repos-only scope was valid with a PAT alone or an App alone and
    invalid the moment both were supplied. Any token we are given is a valid starting point;
    the schema must say so once, for every kind."""

    @pytest.mark.parametrize("kind_schema", [GITHUB_PAT_SCHEMA, GITHUB_APP_SCHEMA, GITHUB_SCHEMA])
    def test_neither_owner_nor_repos_is_rejected_by_every_kind(self, kind_schema) -> None:
        credential = {"token": "ghp_x"} if kind_schema is GITHUB_PAT_SCHEMA else (_APP if kind_schema is GITHUB_APP_SCHEMA else {"pat": {"token": "ghp_x"}})
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(credential, kind_schema)

    def test_combined_kind_accepts_repos_only(self) -> None:
        jsonschema.validate({"app": _APP, "pat": {"token": "ghp_x"}, "repos": ["notgeorge/samsite"]}, GITHUB_SCHEMA)
        jsonschema.validate({"app": _APP, "repos": ["notgeorge/samsite"]}, GITHUB_SCHEMA)
        jsonschema.validate({"pat": {"token": "ghp_x"}, "repos": ["notgeorge/samsite"]}, GITHUB_SCHEMA)

    def test_combined_kind_still_needs_a_credential(self) -> None:
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate({"owner": "acme", "repos": ["acme/x"]}, GITHUB_SCHEMA)

    def test_combined_kind_owner_only_and_owner_with_filter_still_valid(self) -> None:
        jsonschema.validate({"app": _APP, "owner": "acme"}, GITHUB_SCHEMA)
        jsonschema.validate({"pat": {"token": "ghp_x"}, "owner": "acme", "repos": ["acme/x"]}, GITHUB_SCHEMA)

    def test_combined_kind_without_owner_refuses_several_installations_before_collecting(self, monkeypatch) -> None:
        """The relaxation is safe only because the runtime selector fails closed: a repos-only
        envelope names no account, so an App installed into several accounts is refused rather
        than guessed (auth.py `_mint_installation_token`). Proven here through the combined kind,
        which the schema now admits — not only through the App-only kind the existing test uses."""
        from tap_plugin.github_core.collectors.github_collector.auth import GithubAppAuthError, GithubAuth

        auth = GithubAuth(kind="github", data={"app": _APP, "pat": {"token": "ghp_x"}, "repos": ["a/x"]}, api_base_url="https://api.github.com")
        monkeypatch.setattr(auth, "installations", lambda: [{"id": 1, "account": {"login": "a"}}, {"id": 2, "account": {"login": "b"}}])
        with pytest.raises(GithubAppAuthError, match="several installations"):
            auth.token()

    def test_combined_kind_without_owner_takes_the_one_unambiguous_installation(self, monkeypatch) -> None:
        from tap_plugin.github_core.collectors.github_collector.auth import GithubAuth

        auth = GithubAuth(kind="github", data={"app": _APP, "pat": {"token": "ghp_x"}, "repos": ["a/x"]}, api_base_url="https://api.github.com")
        monkeypatch.setattr(auth, "installations", lambda: [{"id": 9, "account": {"login": "a"}}])
        monkeypatch.setattr(
            "tap_plugin.github_core.collectors.github_collector.auth.exchange_installation_token",
            lambda base, jwt, installation_id: (f"token-for-{installation_id}", ""),
        )
        monkeypatch.setattr(auth, "app_jwt", lambda: "jwt")
        assert auth.token() == "token-for-9"
        assert auth.installation["account"]["login"] == "a"

    def test_the_scope_rule_is_derived_once(self) -> None:
        """Three schemas, one `_SCOPE_ANY_OF` — the file already drifted once (its own comment)."""
        from tap_plugin.github_core.collectors.github_collector import secret as secret_mod

        rule = secret_mod._SCOPE_ANY_OF
        assert GITHUB_PAT_SCHEMA["anyOf"] is rule and GITHUB_APP_SCHEMA["anyOf"] is rule
        assert any(clause.get("anyOf") is rule for clause in GITHUB_SCHEMA["allOf"])


class TestPATSchema:
    def test_minimal_valid_pat(self) -> None:
        jsonschema.validate(
            {"token": "ghp_x", "repos": ["notgeorge/samsite"]},
            GITHUB_PAT_SCHEMA,
        )

    def test_pat_with_optional_fields(self) -> None:
        jsonschema.validate(
            {
                "token": "ghp_x",
                "api_base_url": "https://github.enterprise.example/api/v3",
                "repos": ["notgeorge/samsite", "notgeorge/another"],
                "initial_run_limit": 25,
            },
            GITHUB_PAT_SCHEMA,
        )

    def test_pat_missing_token_rejected(self) -> None:
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate({"repos": ["notgeorge/samsite"]}, GITHUB_PAT_SCHEMA)

    def test_pat_owner_only_valid(self) -> None:
        """req-github-core-org-scope: an account scope needs no repo list."""
        jsonschema.validate({"token": "ghp_x", "owner": "unified-systems-com"}, GITHUB_PAT_SCHEMA)

    def test_pat_owner_with_repos_filter_valid(self) -> None:
        jsonschema.validate(
            {"token": "ghp_x", "owner": "unified-systems-com", "repos": ["unified-systems-com/tap"]},
            GITHUB_PAT_SCHEMA,
        )

    def test_pat_neither_owner_nor_repos_rejected(self) -> None:
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate({"token": "ghp_x"}, GITHUB_PAT_SCHEMA)

    def test_pat_malformed_owner_rejected(self) -> None:
        for bad in ("", "-leading", "has/slash", "trailing-"):
            with pytest.raises(jsonschema.ValidationError):
                jsonschema.validate({"token": "ghp_x", "owner": bad}, GITHUB_PAT_SCHEMA)

    def test_pat_api_base_url_must_be_https_and_bare(self) -> None:
        """The value is interpolated into every request URL and handed to `urlopen`, which
        honours whatever scheme it is given. Constrained at the schema — where the value enters
        the system — rather than at each of the two clients that consume it."""
        for good in ("https://api.github.com", "https://ghe.example.com/api/v3"):
            jsonschema.validate({"token": "ghp_x", "owner": "acme", "api_base_url": good}, GITHUB_PAT_SCHEMA)
        for bad in (
            "http://api.github.com",       # PAT would travel in cleartext
            "file:///etc/passwd",          # urlopen reads local files
            "https://u:p@evil.example",    # credentials in the URL
            "https://api.github.com?x=1",  # query smuggling
            "api.github.com",              # no scheme
            "https://",                    # no host
        ):
            with pytest.raises(jsonschema.ValidationError):
                jsonschema.validate(
                    {"token": "ghp_x", "owner": "acme", "api_base_url": bad}, GITHUB_PAT_SCHEMA
                )

    def test_every_schema_field_is_described(self) -> None:
        """House rule: JSON structures carry descriptions — top level and every property."""
        assert GITHUB_PAT_SCHEMA["description"]
        for name, prop in GITHUB_PAT_SCHEMA["properties"].items():
            assert prop.get("description"), f"{name} has no description"

    def test_pat_empty_repos_rejected(self) -> None:
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate({"token": "ghp_x", "repos": []}, GITHUB_PAT_SCHEMA)

    def test_pat_malformed_repo_rejected(self) -> None:
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate({"token": "ghp_x", "repos": ["just-a-name"]}, GITHUB_PAT_SCHEMA)

    def test_pat_extra_fields_rejected(self) -> None:
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(
                {"token": "ghp_x", "repos": ["a/b"], "collect_variables": True},
                GITHUB_PAT_SCHEMA,
            )

    def test_helpers_apply_defaults(self) -> None:
        assert api_base_url({}) == "https://api.github.com"
        assert initial_run_limit({}) == 10
        assert api_base_url({"api_base_url": "https://custom/"}) == "https://custom/"
        assert initial_run_limit({"initial_run_limit": 50}) == 50


class TestIdentity:
    def test_uuids_are_deterministic(self) -> None:
        assert account_id("notgeorge") == account_id("notgeorge")
        assert repository_id("notgeorge/samsite") == repository_id("notgeorge/samsite")
        assert workflow_id("notgeorge/samsite", 12345) == workflow_id("notgeorge/samsite", 12345)
        assert run_id("notgeorge/samsite", 999) == run_id("notgeorge/samsite", 999)
        assert job_id("notgeorge/samsite", 8888) == job_id("notgeorge/samsite", 8888)
        assert runner_id("notgeorge/samsite", 7) == runner_id("notgeorge/samsite", 7)

    def test_different_inputs_yield_different_uuids(self) -> None:
        assert account_id("notgeorge") != account_id("someone-else")
        assert workflow_id("a/b", 1) != workflow_id("a/b", 2)
        assert workflow_id("a/b", 1) != workflow_id("c/d", 1)

    def test_edge_id_includes_endpoints(self) -> None:
        a = account_id("notgeorge")
        b = repository_id("notgeorge/samsite")
        c = repository_id("notgeorge/other")
        assert edge_id("OWNS_REPO__github_core", a, b) != edge_id("OWNS_REPO__github_core", a, c)
        assert edge_id("OWNS_REPO__github_core", a, b) != edge_id("DEFINES_WORKFLOW__github_core", a, b)


class TestParser:
    def test_minimal_workflow(self) -> None:
        yaml_text = """\
name: Deploy
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
        config = parse_workflow_yaml(yaml_text)
        assert config["triggers"] == ["push"]
        assert config["jobs"][0]["id"] == "build"
        # `runs_on` is canonicalized to a list whichever of the three written forms was used
        # (req-github-core-declared-jobs-5), so one query shape answers "which jobs run on a
        # self-hosted label".
        assert config["jobs"][0]["runs_on"] == ["ubuntu-latest"]
        assert config["raw_yaml"] == yaml_text

    def test_triggers_normalized(self) -> None:
        yaml_text = "on:\n  push:\n  pull_request:\njobs: {}\n"
        config = parse_workflow_yaml(yaml_text)
        assert config["triggers"] == ["pull_request", "push"]

    def test_refs_categorized(self) -> None:
        yaml_text = """\
on: push
env:
  AWS_REGION: us-east-1
  DOMAIN_NAME: samaydlette.com
  CF_DIST: E2QWERTYUIOPAS
  IGNORED: just-some-string
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo done
"""
        config = parse_workflow_yaml(yaml_text)
        refs = config["refs"]
        assert "us-east-1" in refs["aws_regions"]
        assert "samaydlette.com" in refs["domain_names"]
        assert "E2QWERTYUIOPAS" in refs["cloudfront_distribution_ids"]
        assert "just-some-string" not in refs["domain_names"]

    def test_empty_yaml_safe(self) -> None:
        config = parse_workflow_yaml("")
        assert config["triggers"] == []
        assert config["jobs"] == []
        assert config["refs"] == {"domain_names": [], "aws_regions": [], "cloudfront_distribution_ids": []}
        assert config["local_action_refs"] == []

    def test_local_action_refs_detected(self) -> None:
        """Local composite-action `uses: ./...` references are flagged for the
        collector to warn on (req-github-core-workflow-parse-3)."""
        yaml_text = """\
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ./.github/actions/setup-foo
      - uses: ./local-helper
      - run: echo "hello"
  release:
    uses: ./.github/workflows/release.yml
"""
        config = parse_workflow_yaml(yaml_text)
        refs = config["local_action_refs"]
        # Two local-action refs in the `build` job; the `release` job's
        # `./.github/workflows/release.yml` is a reusable workflow call,
        # NOT a local action — must NOT be flagged.
        uses_strings = sorted(r["uses"] for r in refs)
        assert uses_strings == sorted(["./.github/actions/setup-foo", "./local-helper"])
        job_ids = {r["job_id"] for r in refs}
        assert job_ids == {"build"}

    def test_reusable_workflow_call_not_flagged_as_local_action(self) -> None:
        """`uses: ./.github/workflows/x.yml` is a reusable workflow call, not
        a local action — explicitly NOT flagged so an operator isn't told to
        investigate something that's a different category entirely."""
        yaml_text = """\
on: push
jobs:
  call:
    uses: ./.github/workflows/build.yaml
"""
        config = parse_workflow_yaml(yaml_text)
        assert config["local_action_refs"] == []


class TestCollectorRegistration:
    def test_collector_registered_in_tap_cares(self) -> None:
        from tap_cares.registry import get_collector

        cls = get_collector("github_core")
        assert cls.__name__ == "GithubCollector"


class TestSelfTest:
    """Self-test exercises the four readiness checks with mocked dependencies.

    Spec: plugins/github_core/specs/spec-github-core-v0.md
    (req-github-core-collector self-test). Live happy-path is exercised
    against the loaded samsite secret manually; unit tests cover the failure
    paths and the per-repo specificity that's the value-add over the default
    base-class self_test.
    """

    def test_unconfigured_when_secret_missing(self, monkeypatch) -> None:
        from tap_plugin.github_core.collectors.github_collector import collector as mod

        from tap_cares.exceptions import SecretNotFoundError

        def _raise(_ref):
            raise SecretNotFoundError("github_core/collector secret not found")

        monkeypatch.setattr(mod, "resolve_github_secret", _raise)
        result = mod.GithubCollector.self_test()
        assert result.status == "unconfigured"
        assert not result.runnable
        assert any(c.is_failure and c.code == "GITHUB_SECRET_PRESENT" for c in result.checks)

    def test_misconfigured_when_secret_schema_fails(self, monkeypatch) -> None:
        from tap_plugin.github_core.collectors.github_collector import collector as mod

        from tap_cares.exceptions import SecretValidationError

        def _raise(_ref):
            raise SecretValidationError("bad shape: 'token' missing")

        monkeypatch.setattr(mod, "resolve_github_secret", _raise)
        result = mod.GithubCollector.self_test()
        assert result.status == "misconfigured"
        assert any(c.is_failure and c.code == "GITHUB_SECRET_VALID" for c in result.checks)

    def test_per_repo_failure_surfaces_each_repo_separately(self, monkeypatch) -> None:
        """A 404 on one repo records that repo's failure by name; healthy
        repos still get their per-repo PASS row so the operator sees the
        whole picture, not just the first broken thing."""
        from tap_plugin.github_core.collectors.github_collector import collector as mod
        from tap_plugin.github_core.collectors.github_collector.api_client import GithubAPIError

        from tap_cares.secrets.models import Secret, SecretRef

        def _good_secret(_ref):
            return Secret(
                ref=SecretRef(scope="github_core", key="collector"),
                kind="github_pat",
                description="test",
                data={"token": "ghp_x", "repos": ["good/repo", "bad/repo"]},
                source_path="/test",
                metadata={},
            )

        class _StubClient:
            def __init__(self, **kwargs):
                pass

            def get(self, path, **_):
                if path == "/rate_limit":
                    return {"rate": {"limit": 5000, "used": 0}}
                if path == "/repos/bad/repo":
                    raise GithubAPIError(status=404, url=path, body='{"message":"Not Found"}')
                return {}

        monkeypatch.setattr(mod, "resolve_github_secret", _good_secret)
        monkeypatch.setattr(mod, "GithubClient", _StubClient)
        result = mod.GithubCollector.self_test()
        assert result.status == "error"
        codes = {c.code: c.is_failure for c in result.checks}
        assert codes["GITHUB_REPO_ACCESS:good/repo"] is False
        assert codes["GITHUB_REPO_ACCESS:bad/repo"] is True
        # Per-repo specificity check: the failing repo name appears in the
        # check message so an operator can act on it without reading code.
        bad_check = next(c for c in result.checks if c.code == "GITHUB_REPO_ACCESS:bad/repo")
        assert "bad/repo" in bad_check.message


class TestAccountScope:
    """req-github-core-org-scope: the account's repositories are enumerated, filtered, and
    the enumeration recorded on the run — including whether the walk was complete."""

    @staticmethod
    def _collector():
        from tap_plugin.github_core.collectors.github_collector.collector import GithubCollector

        c = GithubCollector.__new__(GithubCollector)  # no CollectorConfig needed for scope resolution
        c.results = {"info": [], "warn": [], "error": []}
        return c

    class _Client:
        def __init__(self, org_repos=None, user_repos=None, complete=True, repo_status=None):
            self.org_repos, self.user_repos, self.complete = org_repos, user_repos, complete
            self.repo_status: dict[str, int] = repo_status or {}  # full_name -> HTTP status to raise
            self.calls: list[str] = []
            self.last_walk_complete = True

        def get(self, path, *, params=None):
            from tap_plugin.github_core.collectors.github_collector.api_client import GithubAPIError

            self.calls.append(path)
            assert path.startswith("/repos/"), path
            full_name = path[len("/repos/"):]
            status = self.repo_status.get(full_name)
            if status:
                raise GithubAPIError(status=status, url=path, body='{"message":"nope"}')
            return {"full_name": full_name, "id": abs(hash(full_name)) % 10**6}

        def get_paginated(self, path, *, params=None, item_path=None, max_pages=100):
            from tap_plugin.github_core.collectors.github_collector.api_client import GithubAPIError

            self.calls.append(path)
            if path.startswith("/orgs/"):
                if self.org_repos is None:
                    raise GithubAPIError(status=404, url=path, body='{"message":"Not Found"}')
                self.last_walk_complete = self.complete
                return [{"full_name": n} for n in self.org_repos]
            if path.startswith("/users/"):
                self.last_walk_complete = self.complete
                return [{"full_name": n} for n in (self.user_repos or [])]
            raise AssertionError(path)

    def test_repos_only_is_the_degenerate_scope_and_is_resolved_up_front(self) -> None:
        """github-core#140: the list IS the config, so each listed repo is resolved before the
        loop; nothing is enumerated; the listing is recorded complete by construction."""
        c = self._collector()
        client = self._Client(org_repos=["x/should-not-be-touched"])
        assert c._resolve_repos(client, None, ["notgeorge/samsite"]) == ["notgeorge/samsite"]
        assert client.calls == ["/repos/notgeorge/samsite"]
        (event,) = c.results["info"]
        assert event["message_code"] == "SCOPE_RESOLVED"
        assert event["message_data"] == {
            "configured": 1, "unreadable": [], "unresolved": [], "complete": True, "filtered": False,
        }
        assert c.results["warn"] == [] and c.results["error"] == []

    def test_repos_only_listed_repo_not_found_aborts_as_a_config_error(self) -> None:
        """404 is 'does not exist OR not visible to this credential' — GitHub answers it for both.
        Either way the envelope and the credential disagree, and the message says exactly that."""
        from tap_plugin.github_core.collectors.github_collector.collector import GithubCollectorError

        c = self._collector()
        client = self._Client(repo_status={"notgeorge/typo": 404})
        with pytest.raises(GithubCollectorError):
            c._resolve_repos(client, None, ["notgeorge/samsite", "notgeorge/typo"])
        (error,) = c.results["error"]
        assert error["message_code"] == "SCOPE_REPO_NOT_FOUND" and "notgeorge/typo" in error["message"]
        assert "not allowed to see it" in error["message"] and "does not exist" not in error["message"].split("either")[0]
        assert c.results["info"] == []  # no SCOPE_RESOLVED: the run stopped

    def test_repos_only_listed_repo_this_credential_cannot_read_is_recorded_and_kept(self) -> None:
        c = self._collector()
        client = self._Client(repo_status={"notgeorge/private": 403})
        assert c._resolve_repos(client, None, ["notgeorge/samsite", "notgeorge/private"]) == [
            "notgeorge/samsite", "notgeorge/private",
        ]
        (warn,) = c.results["warn"]
        assert warn["message_code"] == "SCOPE_REPO_UNREADABLE_403"
        assert warn["message_data"] == {"repo": "notgeorge/private", "status": 403}
        (event,) = c.results["info"]
        assert event["message_data"]["unreadable"] == [{"repo": "notgeorge/private", "status": 403}]
        assert event["message_data"]["complete"] is True

    @pytest.mark.parametrize("status", [401, 429, 500, 502])
    def test_repos_only_statuses_that_prove_nothing_are_unresolved_and_the_listing_is_incomplete(self, status) -> None:
        """Codex/Grok on PR #143: 401, 429 and 5xx do not establish that a repository exists, so
        they must not read as 'exists but unreadable' and must not leave `complete: True` for a
        tombstone pass to trust."""
        c = self._collector()
        client = self._Client(repo_status={"notgeorge/flaky": status})
        assert c._resolve_repos(client, None, ["notgeorge/samsite", "notgeorge/flaky"]) == [
            "notgeorge/samsite", "notgeorge/flaky",
        ]
        (warn,) = c.results["warn"]
        assert warn["message_code"] == f"SCOPE_REPO_UNRESOLVED_{status}"
        assert "not a statement about whether it exists" in warn["message"]
        (event,) = c.results["info"]
        assert event["message_data"]["unresolved"] == [{"repo": "notgeorge/flaky", "status": status}]
        assert event["message_data"]["unreadable"] == []
        assert event["message_data"]["complete"] is False and "INCOMPLETE" in event["message"]

    def test_org_enumerated_and_recorded(self) -> None:
        c = self._collector()
        client = self._Client(org_repos=["o/a", "o/b", "o/c"])
        assert c._resolve_repos(client, "o", []) == ["o/a", "o/b", "o/c"]
        assert client.calls == ["/orgs/o/repos"]
        (event,) = c.results["info"]
        assert event["message_code"] == "SCOPE_ENUMERATED"
        assert event["message_data"] == {
            "owner": "o", "account_kind": "org", "enumerated": 3, "collecting": 3, "filtered": False, "complete": True,
        }

    def test_user_fallback_on_org_404(self) -> None:
        c = self._collector()
        client = self._Client(org_repos=None, user_repos=["u/one"])
        assert c._resolve_repos(client, "u", []) == ["u/one"]
        assert client.calls == ["/orgs/u/repos", "/users/u/repos"]
        assert c.results["info"][0]["message_data"]["account_kind"] == "user"

    def test_repos_filter_over_enumeration_with_unmatched_warning(self) -> None:
        c = self._collector()
        client = self._Client(org_repos=["o/a", "o/b"])
        assert c._resolve_repos(client, "o", ["o/b", "o/zzz"]) == ["o/b"]
        (warn,) = c.results["warn"]
        assert warn["message_code"] == "SCOPE_FILTER_UNMATCHED" and warn["message_data"]["unmatched"] == ["o/zzz"]
        assert c.results["info"][0]["message_data"]["filtered"] is True

    def test_incomplete_walk_is_labelled_not_hidden(self) -> None:
        c = self._collector()
        client = self._Client(org_repos=["o/a"], complete=False)
        c._resolve_repos(client, "o", [])
        event = c.results["info"][0]
        assert event["message_data"]["complete"] is False and "INCOMPLETE" in event["message"]

    def test_self_test_owner_access_bounded_to_one_walk(self, monkeypatch) -> None:
        """Account-scoped self-test proves enumeration with ONE listing walk (no per-repo probes)."""
        from tap_plugin.github_core.collectors.github_collector import collector as mod

        from tap_cares.secrets.models import Secret, SecretRef

        def _secret(_ref):
            return Secret(
                ref=SecretRef(scope="github_core", key="collector"), kind="github_pat", description="t",
                data={"token": "ghp_x", "owner": "o"}, source_path="/test", metadata={},
            )

        calls: list[str] = []

        class _Stub:
            last_walk_complete = True

            def __init__(self, **kwargs):
                pass

            def get(self, path, **_):
                calls.append(path)
                return {"rate": {"limit": 5000, "used": 1}}

            def get_paginated(self, path, **_):
                calls.append(path)
                return [{"full_name": "o/a"}, {"full_name": "o/b"}]

        monkeypatch.setattr(mod, "resolve_github_secret", _secret)
        monkeypatch.setattr(mod, "GithubClient", _Stub)
        result = mod.GithubCollector.self_test()
        assert result.runnable, [c.message for c in result.checks]
        codes = {c.code: c.is_failure for c in result.checks}
        assert codes["GITHUB_OWNER_ACCESS:o"] is False
        assert not [k for k in codes if k.startswith("GITHUB_REPO_ACCESS:")]
        # Two /rate_limit calls, and both earn their place: the first proves the TOKEN is alive
        # on its own (liveness is per credential — a dead token beside a live App must not pass),
        # the second is the shared API-reachability check. The point of this test is the single
        # LISTING walk that follows, with no per-repo probe behind it.
        assert calls == ["/rate_limit", "/rate_limit", "/orgs/o/repos"]


class TestEnrichmentDegrade:
    def test_rule_with_uninstalled_target_type_is_skipped_not_fatal(self, monkeypatch) -> None:
        """req-github-core-grid-links-8: a composition without the target plugin (git-serious
        without aws_core) still enriches what it can and records what it skipped."""
        from tap_plugin.github_core.collectors.github_collector import enrichment as mod

        monkeypatch.setattr("tap_grid.registry.list_entity_types", lambda: ["github_core__github_repository", "github_core__github_workflow"])
        calls: list[str] = []
        monkeypatch.setattr(mod, "_fetch_source_nodes", lambda *a, **k: calls.append("fetched") or [])
        manifest = {"rules": [
            {"name": "to-aws", "source_entity_type": "github_core__github_workflow", "target_entity_type": "aws_core__aws_route53_zone",
             "target_field": "name", "edge_type": "REFERENCES_RESOURCE", "source_field": "x"},
            {"name": "from-aws", "source_entity_type": "aws_core__aws_iam_oidc_provider", "target_entity_type": "github_core__github_repository",
             "target_field": "name", "edge_type": "TRUSTS_ISSUER", "source_field": "x"},
            {"name": "to-repo", "source_entity_type": "github_core__github_workflow", "target_entity_type": "github_core__github_repository",
             "target_field": "name", "edge_type": "REFERENCES_RESOURCE", "source_field": "x"},
        ]}
        result = mod.resolve_links(link_manifest=manifest, repos=["o/r"], edge_default_dimensions={})
        assert [(r.rule_name, r.missing_entity_type) for r in result.skipped_rules] == [
            ("to-aws", "aws_core__aws_route53_zone"), ("from-aws", "aws_core__aws_iam_oidc_provider")]
        assert calls == ["fetched"]  # only the installed-target rule was evaluated


class TestEnvelopeCollapse:
    """req-github-core-org-scope: a scope's shared nodes (account, platform, OIDC issuer) are
    emitted once per repo by the per-repo walk. At 19 repos that produced 43 duplicate entity ids
    and GRIFT rejected the whole batch — every repo lost for one repeated envelope."""

    @staticmethod
    def _env(eid, name):
        return {"entity": {"entity_id": eid, "name": name}, "node": {"name": name}}

    def test_last_occurrence_wins_and_order_is_preserved(self) -> None:
        from tap_plugin.github_core.collectors.github_collector.collector import GithubCollector

        out, removed = GithubCollector._collapse_by_entity_id([
            self._env("a", "platform"), self._env("b", "repo-1"),
            self._env("a", "platform-again"), self._env("c", "repo-2"),
        ])
        assert removed == 1
        assert [envelope_key(e) for e in out] == ["a", "b", "c"]
        assert out[0]["entity"]["name"] == "platform-again", "the freshest observation should win"

    def test_nothing_to_collapse_is_a_no_op(self) -> None:
        from tap_plugin.github_core.collectors.github_collector.collector import GithubCollector

        envs = [self._env("a", "x"), self._env("b", "y")]
        out, removed = GithubCollector._collapse_by_entity_id(envs)
        assert removed == 0 and out == envs

    def test_envelopes_without_an_id_pass_through(self) -> None:
        """An id-less envelope is a different bug; GRIFT should report it, not this helper."""
        from tap_plugin.github_core.collectors.github_collector.collector import GithubCollector

        out, removed = GithubCollector._collapse_by_entity_id([{"node": {"name": "orphan"}}, self._env("a", "x")])
        assert removed == 0 and len(out) == 2

    def test_a_repeated_ref_collapses_the_same_way_a_repeated_id_does(self) -> None:
        """The reason this helper still matters after assigned identity (Issue# 162).

        A node now names itself by a batch-local `ref`, and a ref used twice in one batch is a
        hard GRIFT error (`duplicate_ref`) that rejects the batch exactly as a repeated
        `entity_id` did. Asserted with refs rather than only ids because the whole failure this
        helper was written for — 43 repeated envelopes at a 19-repo scope, nothing landing —
        would come back unchanged if the collapse still looked only at `entity_id`.
        """
        from tap_plugin.github_core.collectors.github_collector.collector import GithubCollector

        def _ref(ref: str, name: str) -> dict[str, Any]:
            return {"entity": {"ref": ref, "name": name}, "node": {"name": name}}

        out, removed = GithubCollector._collapse_by_entity_id([
            _ref("github_core__github_account:acme", "acme"),
            self._env("b", "repo-1"),
            _ref("github_core__github_account:acme", "acme-again"),
        ])
        assert removed == 1
        assert [envelope_key(e) for e in out] == ["github_core__github_account:acme", "b"]
        assert out[0]["entity"]["name"] == "acme-again"

    def test_a_cross_batch_endpoint_is_exactly_what_the_guard_drops(self) -> None:
        """Why `_append_scope_installation_edge` must run AFTER the guard, not before.

        `DERIVED_FROM_INSTALLATION` runs from the `collection_scope`, which rode its own earlier
        batch and is therefore a real grid id that by construction is NOT among this batch's
        node keys. The guard keeps an edge only when both endpoints are, so appending before it
        would silently drop the run's provenance join (Codex on PR# 163 - github-core; the
        ordering is correct today and nothing asserted it).

        This pins the hazard rather than the line numbers: the guard is batch-local on purpose
        and should keep dropping such an edge. What must not change is which side of it the
        append happens on.
        """
        from tap_plugin.github_core.collectors.github_collector.collector import GithubCollector

        scope_id_from_an_earlier_batch = "01a0be43-5179-765e-8d1c-a47a81ca3303"
        edge = {
            "entity": {"entity_id": "e"},
            "edge": {
                "from_entity_id": scope_id_from_an_earlier_batch,
                "to_ref": "github_core__app_installation:7",
                "edge_type": "DERIVED_FROM_INSTALLATION__github_core",
            },
        }
        kept, dropped = GithubCollector._drop_dangling_edges([edge], {"github_core__app_installation:7"})
        assert kept == [] and dropped == ["DERIVED_FROM_INSTALLATION__github_core"]

    def test_a_dangling_ref_endpoint_is_dropped_like_a_dangling_id(self) -> None:
        """An edge endpoint naming no node of its batch is `unknown_ref` — a rejected batch, not
        one dropped edge — so it has to be caught here on the ref as well as on the id."""
        from tap_plugin.github_core.collectors.github_collector.collector import GithubCollector

        def _edge(src: str, tgt: str, by_ref: bool) -> dict[str, Any]:
            keys = ("from_ref", "to_ref") if by_ref else ("from_entity_id", "to_entity_id")
            return {"entity": {"entity_id": "e"}, "edge": {keys[0]: src, keys[1]: tgt, "edge_type": "T"}}

        kept, dropped = GithubCollector._drop_dangling_edges(
            [
                _edge("r:a", "r:b", by_ref=True),
                _edge("r:a", "r:gone", by_ref=True),
                _edge("r:a", "id-1", by_ref=False),
            ],
            {"r:a", "r:b", "id-1"},
        )
        assert len(kept) == 2 and dropped == ["T"], "the mixed ref/id edge survives; only the dangling one goes"


class TestPerRepoContainment:
    """req-github-core-org-scope: at org scale a transient API error is a certainty. One bad repo
    must not discard the other eighteen — but a partially-collected run must say so, because
    tombstoning may not read absence as deletion (tap#140)."""

    def test_partial_marks_collection_incomplete(self) -> None:
        from tap_plugin.github_core.collectors.github_collector import collector as mod

        c = mod.GithubCollector.__new__(mod.GithubCollector)
        c.results = {"info": [], "warn": [], "error": []}
        c.record_warn(mod._SITE_COLLECTION_PARTIAL, "COLLECTION_PARTIAL", "x",
                      message_data={"collected": 18, "failed": ["o/bad"], "collection_complete": False})
        (w,) = c.results["warn"]
        assert w["message_data"]["collection_complete"] is False
        assert w["message_data"]["collected"] == 18


def test_collapse_is_reachable_from_an_instance() -> None:
    """Regression: the collapse helper was called as a bare function from run() while defined as a
    staticmethod, so the class-level tests passed and the live run raised NameError. Exercise the
    instance path the collector actually uses."""
    from tap_plugin.github_core.collectors.github_collector.collector import GithubCollector

    c = GithubCollector.__new__(GithubCollector)
    out, removed = c._collapse_by_entity_id([
        {"entity": {"entity_id": "a"}}, {"entity": {"entity_id": "a"}},
    ])
    assert removed == 1 and len(out) == 1


class TestDanglingEdgeGuard:
    """A workflow run can name a workflow that has since been deleted. At one repo that never
    happened; at nineteen it made GRIFT reject the batch and NOTHING landed."""

    @staticmethod
    def _edge(src, tgt, etype="EXECUTES_WORKFLOW__github_core"):
        return {"entity": {"entity_id": f"{src}->{tgt}"},
                "edge": {"from_entity_id": src, "to_entity_id": tgt, "edge_type": etype}}

    def test_edge_to_uncollected_node_is_dropped_and_named(self) -> None:
        from tap_plugin.github_core.collectors.github_collector.collector import GithubCollector

        kept, dropped = GithubCollector._drop_dangling_edges(
            [self._edge("run", "gone"), self._edge("run", "wf")], {"run", "wf"})
        assert [edge_to(e) for e in kept] == ["wf"]
        assert dropped == ["EXECUTES_WORKFLOW__github_core"]

    def test_edge_from_uncollected_node_is_also_dropped(self) -> None:
        from tap_plugin.github_core.collectors.github_collector.collector import GithubCollector

        kept, dropped = GithubCollector._drop_dangling_edges([self._edge("ghost", "wf")], {"wf"})
        assert kept == [] and len(dropped) == 1

    def test_fully_resolved_batch_is_untouched(self) -> None:
        from tap_plugin.github_core.collectors.github_collector.collector import GithubCollector

        edges = [self._edge("a", "b")]
        kept, dropped = GithubCollector._drop_dangling_edges(edges, {"a", "b"})
        assert kept == edges and dropped == []


class TestGraphQLConfigLayer:
    """req-github-core-graphql-config: the config layer (metadata, rulesets, environments, workflow
    YAML) comes from one GraphQL request; the operation layer stays REST because GitHub's GraphQL
    API exposes no workflow runs or jobs."""

    @staticmethod
    def _repo(name="o/r", files=(("ci.yml", "on: push"),), truncated=False):
        return {
            "nameWithOwner": name, "name": name.split("/")[1], "databaseId": 7,
            "isArchived": False, "isFork": False, "visibility": "PUBLIC",
            "url": f"https://github.com/{name}",
            "defaultBranchRef": {"name": "main", "target": {"oid": "abc"}},
            "object": {"entries": [
                {"name": f, "path": f, "object": {"byteSize": len(txt), "isTruncated": truncated, "text": txt}}
                for f, txt in files]},
        }

    def test_workflow_files_are_keyed_by_repo_path(self) -> None:
        from tap_plugin.github_core.collectors.github_collector.graphql_client import GithubGraphQLClient

        files = GithubGraphQLClient.workflow_files(self._repo(files=(("a.yml", "x"), ("b.yml", "y"))))
        assert files == {".github/workflows/a.yml": "x", ".github/workflows/b.yml": "y"}

    def test_truncated_blobs_are_omitted_not_half_parsed(self) -> None:
        """A partial YAML parses into a workflow that is not the one in the repository. A missing
        entry is honest; a wrong one is not."""
        from tap_plugin.github_core.collectors.github_collector.graphql_client import GithubGraphQLClient

        assert GithubGraphQLClient.workflow_files(self._repo(truncated=True)) == {}

    def test_graphql_node_shapes_like_the_rest_payload(self) -> None:
        from tap_plugin.github_core.collectors.github_collector.collector import GithubCollector

        p = GithubCollector._repo_payload_from_config(self._repo())
        assert p["full_name"] == "o/r" and p["owner"]["login"] == "o"
        assert p["default_branch"] == "main" and p["visibility"] == "public" and p["id"] == 7

    def test_workflow_config_prefers_the_prefetched_yaml(self, monkeypatch) -> None:
        """The whole point: no Contents call when the config layer already carries the file."""
        from tap_plugin.github_core.collectors.github_collector.collector import GithubCollector

        c = GithubCollector.__new__(GithubCollector)
        c._config = {"o/r": self._repo(files=(("ci.yml", "on: push\njobs: {}"),))}
        called = []
        monkeypatch.setattr(GithubCollector, "_fetch_workflow_config",
                            lambda self, cl, fn, p: called.append(p) or ("", {}))
        raw, parsed = c._workflow_config(None, "o/r", ".github/workflows/ci.yml")
        assert raw.startswith("on: push") and called == []

    def test_falls_back_to_rest_when_the_file_is_not_in_the_config_layer(self, monkeypatch) -> None:
        from tap_plugin.github_core.collectors.github_collector.collector import GithubCollector

        c = GithubCollector.__new__(GithubCollector)
        c._config = {"o/r": self._repo(files=())}
        called = []
        monkeypatch.setattr(GithubCollector, "_fetch_workflow_config",
                            lambda self, cl, fn, p: called.append(p) or ("rest", {}))
        raw, _ = c._workflow_config(None, "o/r", ".github/workflows/ci.yml")
        assert raw == "rest" and called == [".github/workflows/ci.yml"]

    def test_ghes_endpoint_is_derived_not_guessed(self) -> None:
        from tap_plugin.github_core.collectors.github_collector.graphql_client import GithubGraphQLClient

        assert GithubGraphQLClient(token="t")._endpoint == "https://api.github.com/graphql"
        ghes = GithubGraphQLClient(token="t", api_base_url="https://ghe.example/api/v3")
        assert ghes._endpoint == "https://ghe.example/api/graphql"


class TestCreateAppSkillIsHostRunnable:
    """req-github-core-app-auth: the App-creation flow runs on the OPERATOR's machine, not in the
    container, because the instance mounts its secrets root read-only and must never write its own
    credentials. Host-runnable means stdlib-only — there is no dependency set out there to lean on.
    Same discipline as `tap/git_invocation.py`."""

    @staticmethod
    def _imports(path):
        import ast, sys
        mods = set()
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Import):
                mods |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                mods.add(node.module.split(".")[0])
        return {m for m in mods if m not in sys.stdlib_module_names}

    def test_host_side_scripts_import_only_the_standard_library(self) -> None:
        from pathlib import Path as P

        skill = P(__file__).resolve().parents[1] / "skills" / "create-github-app"
        # Sibling modules in the skill directory are part of the host flow, not dependencies.
        siblings = {"manifest", "api_url", "collector_modules"}
        for name in ("create_app.py", "manifest.py", "api_url.py", "collector_modules.py"):
            extra = self._imports(skill / name) - siblings
            assert not extra, f"{name} imports non-stdlib modules: {sorted(extra)}"
        # What the host flow PATH-LOADS runs on the operator's machine too, so it is held to the
        # same rule: the credential fold must stay stdlib-only (github-core#25).
        shape = P(__file__).resolve().parents[1] / "collectors" / "github_collector" / "credential_shape.py"
        assert not self._imports(shape), "credential_shape.py must stay stdlib-only"

    def test_api_base_url_must_be_https_and_bare(self) -> None:
        """req-github-core-app-auth-4 / the SonarCloud SSRF finding on PR #3: the API base URL
        reaches `urlopen` from outside the program — a CLI flag in create_app, an envelope field
        in verify_app. `urlopen` honours whatever scheme it is handed, so an `http://` base sends
        the one-time manifest code (which converts into the App's private key) in cleartext to a
        host of the caller's choosing, and a `file://` base turns the exchange into a local read."""
        import importlib.util
        from pathlib import Path as P

        mod_path = P(__file__).resolve().parents[1] / "skills" / "create-github-app" / "api_url.py"
        spec = importlib.util.spec_from_file_location("gs_api_url", mod_path)
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        assert mod.validate_api_base_url("https://api.github.com") == "https://api.github.com"
        assert mod.validate_api_base_url("https://api.github.com/") == "https://api.github.com"
        # GitHub Enterprise Server keeps its path.
        assert mod.validate_api_base_url("https://ghe.example.com/api/v3") == "https://ghe.example.com/api/v3"

        for bad in (
            "http://api.github.com",          # credential-bearing exchange in cleartext
            "file:///etc/passwd",             # urlopen reads local files
            "ftp://example.com/x",
            "api.github.com",                 # no scheme
            "https://",                       # no host
            "https://u:p@evil.example",       # credentials in the URL
            "https://api.github.com?x=1",     # query smuggling
        ):
            with pytest.raises(ValueError):
                mod.validate_api_base_url(bad)

    def test_permission_keys_cannot_collide_across_surfaces(self) -> None:
        """The bug this assertion exists for: repository:administration and
        organization:administration both map to a bare `administration` key unless the org surface
        is namespaced, and one silently overwrites the other."""
        import importlib.util
        from pathlib import Path as P

        skill = P(__file__).resolve().parents[1] / "skills" / "create-github-app" / "manifest.py"
        spec = importlib.util.spec_from_file_location("gs_manifest", skill)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        built = mod.build(org="o", redirect_url="http://127.0.0.1:1/callback", name="n",
                          public=False, exploratory=["organization:administration:read"])
        keys = built["default_permissions"]
        assert "administration" in keys and "organization_administration" in keys
        assert keys["administration"] == "read" and keys["organization_administration"] == "read"


class TestReadinessSummaryNamesTheScopeItWalked:
    """The readiness line reports the scope the run actually walked, not the filter list."""

    @staticmethod
    def _summary(**kwargs: Any) -> str:
        from tap_plugin.github_core.collectors.github_collector.collector import (
            _readiness_summary,
        )

        base: dict[str, Any] = {
            "repo_access_ok": True,
            "explicit_repos": 0,
            "owner": "unified-systems-com",
            "enumerated": None,
            "enumeration_complete": True,
        }
        return _readiness_summary(**(base | kwargs))

    def test_an_owner_walk_reports_what_it_enumerated(self) -> None:
        """The regression: an owner-scoped credential reported 0 while seeing a whole org.

        The count came from the EXPLICIT repo filter, which an owner-scoped credential leaves
        empty, so the line read as a dead credential while the enumeration check beside it had
        just listed every repository.
        """
        summary = self._summary(enumerated=34)
        assert "34 repo(s) enumerated under unified-systems-com" in summary
        assert "0 repo(s)" not in summary

    def test_an_explicit_filter_is_reported_as_such(self) -> None:
        assert "3 explicitly configured repo(s)" in self._summary(explicit_repos=3, enumerated=34)

    def test_a_truncated_walk_says_so(self) -> None:
        summary = self._summary(enumerated=500, enumeration_complete=False)
        assert "500 repo(s) enumerated" in summary and "INCOMPLETE" in summary

    def test_an_empty_scope_is_words_not_a_zero(self) -> None:
        """No owner and no repos is a misconfiguration, and must not render as a count."""
        summary = self._summary(owner=None, enumerated=None)
        assert "nothing is in scope" in summary
        assert "0 repo(s)" not in summary

    def test_an_empty_org_is_distinct_from_an_empty_scope(self) -> None:
        """A walk that ran and found nothing is a real observation, unlike no walk at all."""
        summary = self._summary(owner="brand-new-org", enumerated=0)
        assert "0 repo(s) enumerated under brand-new-org" in summary

    def test_an_unreachable_repo_still_wins_over_any_count(self) -> None:
        summary = self._summary(repo_access_ok=False, explicit_repos=2, enumerated=34)
        assert "cannot access one or more configured repos" in summary
        assert "34" not in summary
