"""GitHubCollector — CollectorBase subclass driving the v0 collection.

Spec: plugins/github_core/specs/spec-github-core-v0.md
(req-github-core-collector). Two-phase run: collection + enrichment, both
through `CollectorBase.submit_grift`.
"""

from __future__ import annotations

import base64
import fnmatch
import logging
import re
from datetime import UTC, datetime
from typing import Any, ClassVar, NamedTuple
from urllib.parse import quote
from uuid import UUID

from tap_plugin.git_core.identity import (
    OID_LENGTH,
    git_commit_id,
    git_ref_id,
    git_repository_id,
)
from tap_plugin.github_core.models.github_custom_property import GithubCustomProperty
from tap_plugin.github_core.models.pull_request import PullRequest
from tap_plugin.github_core.models.status_check import StatusCheck
from tap_plugin.identity_core.issuer import oidc_issuer_id, oidc_issuer_node_envelope

from tap_cares.collectors import (
    CollectorDocRef,
    CollectorReadinessStatus,
    CollectorSelfTestResult,
    check_fail,
    check_pass,
)
from tap_cares.collectors.base import CollectorBase
from tap_cares.exceptions import (
    SecretError,
    SecretNotFoundError,
    SecretValidationError,
)

from .github_call import RunBudget, Seam
from .api_client import GithubAPIError, GithubClient
from .app_jwt import GithubAppAuthError
from .auth import PREFER_APP, PREFER_PAT, GithubAuth
from .batch import (
    assemble_batch,
    endpoint_keys,
    envelope_key,
    edge_envelope,
    node_envelope,
)
from .enrichment import resolve_links
from .graphql_client import _ENVIRONMENT_PAGE_SIZE, GithubGraphQLClient, GithubGraphQLError
from .identity import (
    COMPLIANCE_FINDING_SOURCE,
    Ref,
    account_id,
    actions_artifact_id,
    actions_cache_id,
    actions_secret_id,
    app_installation_id,
    code_scanning_alert_id,
    code_scanning_analysis_id,
    code_scanning_finding_id,
    code_scanning_finding_source_key,
    collection_scope_id,
    commit_observation_id,
    custom_property_id,
    edge_id,
    environment_id,
    github_action_id,
    github_app_id,
    job_id,
    package_id,
    package_purl,
    package_version_id,
    platform_id,
    pull_request_id,
    release_id,
    repository_id,
    rule_suite_id,
    ruleset_id,
    run_id,
    runner_id,
    status_check_id,
    uses_action_edge_id,
    workflow_id,
    workflow_job_id,
)
from .manifest import collection_manifest_digest, load_collection_manifest, load_link_manifest
from .parser import (
    PIN_BRANCH,
    PIN_LOCAL,
    PIN_SHA,
    PIN_TAG,
    PIN_UNRESOLVED,
    is_pinned,
    parse_workflow_yaml,
    secret_names_in,
)
from .secret import (
    GITHUB_SECRET_REF,
    api_base_url,
    collection_owner,
    explicit_repos,
    initial_run_limit,
    resolve_github_secret,
)

logger = logging.getLogger(__name__)

# Log site tokens for the recorder. Minted via scripts/log-site-id.
_SITE_RUN_STARTED = "8fb5"
#: Seam records (spec-github-core-reliability, req-…-observability): one site per code.
_SEAM_SITES = {"RETRY": "f2d6", "PAGE_SIZE_REDUCED": "b800", "PARTIAL": "d9e2", "LAYER_DEGRADED": "4ca8", "TERMINAL": "695e", "RATE_LIMIT_LOW": "eacf", "RUN_BUDGET": "84fd", "INCOMPLETE_SURFACES": "06c1", "RUN_SKIPPED_CONCURRENT": "e33c", "UNANTICIPATED": "0002"}
_SITE_ABORT_SECRET = "64be"
_SITE_ABORT_API = "54ce"
_SITE_REPO_DONE = "d98c"
_SITE_RUNNER_DEGRADED = "b969"
_SITE_WORKFLOW_YAML_MISSING = "9573"
_SITE_BATCH_SUBMITTED = "d66b"
_SITE_ENRICHMENT_SUMMARY = "fd9e"
_SITE_RUN_JOBS_MISSING = "bcff"
_SITE_INCREMENTAL_WINDOW = "c2ca"
_SITE_NON_TERMINAL_REFRESH = "6558"
_SITE_RUN_NOT_FOUND = "f938"
_SITE_LOCAL_ACTION_DEFERRED = "b148"
_SITE_DEPENDABOT_APP = "a7c1"
_SITE_SCOPE_ENUMERATED = "462a"
_SITE_SCOPE_RESOLVED = "7c72"
_SITE_SCOPE_REPO_UNREADABLE = "6ed7"
_SITE_SCOPE_REPO_NOT_FOUND = "49f5"
_SITE_ABORT_SCOPE = "8d47"
_SITE_FILTER_UNMATCHED = "d087"
_SITE_GRAPHQL_CONFIG = "1de2"
_SITE_GRAPHQL_DEGRADED = "8630"
_SITE_EDGE_DROPPED = "0fff"
_SITE_REPO_FAILED = "4326"
_SITE_COLLECTION_PARTIAL = "11d2"
_SITE_ENVELOPE_COLLAPSED = "32c2"
_SITE_LINK_RULE_SKIPPED = "1cb8"
_SITE_REFS_TRUNCATED = "8334"
#: The hosting record carried no stable id, so no neutral git_core repository (and no refs/commits) could be minted.
_SITE_NO_STABLE_REPO_ID = "9aa2"
_SITE_RULESET_BYPASS_UNOBSERVABLE = "d75a"
_SITE_RULESET_DETAIL_DEGRADED = "21d1"
_SITE_CACHE_DEGRADED = "21fd"
class SecretListing(NamedTuple):
    """One secret listing: the rows that came back, and whether that is the whole set.

    Two fields rather than an optional list, because "asked and got a prefix" is a real third
    answer and it is the one that hides — it returns plausible names and looks like success.
    Only `complete` may be read as "this scope was enumerated".
    """

    rows: list[dict[str, Any]]
    complete: bool


class OrgSecretReach(NamedTuple):
    """Which repositories an organisation secret can actually be read from.

    GitHub's `visibility` is three-valued and only one value is self-explaining. `all` reaches
    every repository; `private` reaches the private and internal ones, which on an all-public
    estate is none of them; `selected` names a list, and that list IS readable — measured
    2026-09-11 with the plugin's own App installation token against a real `selected` secret, so
    reach is a fact to derive rather than a state to leave uncertain (github-core#107).

    `unknown` is kept for the case that remains genuinely undecidable: the repository list was
    refused or truncated. Three answers, never two.
    """

    kind: str  #: "all" | "selected" | "private" | "unknown"
    repos: frozenset[str]  #: full names; meaningful only when `kind == "selected"`

    def reaches(self, full_name: str, repo_visibility: str) -> bool | None:
        """True / False / None — None meaning the list could not be read."""
        if self.kind == "all":
            return True
        if self.kind == "selected":
            return full_name in self.repos
        if self.kind == "private":
            # GitHub shares a `private` organisation secret with private AND internal
            # repositories. A public repository is reached by neither.
            return repo_visibility.lower() in ("private", "internal")
        return None


#: Secret-scope reads. Each scope gets its own site because "which scope could not be read" is
#: the whole question a reader of `scopes_read` is asking.
_SITE_SECRETS_DEGRADED = "9fdd"
_SITE_ORG_SECRETS_DEGRADED = "8a3a"
_SITE_ORG_SECRETS_SKIPPED = "7bc8"
_SITE_ENV_SECRETS_DEGRADED = "bae3"
_SITE_SECRET_SCOPE_INCOMPLETE = "50f0"
_SITE_RULE_SUITE_DEGRADED = "3095"
_SITE_RULE_SUITE_FOUND = "3b60"
_SITE_CACHES_TRUNCATED = "0f41"
_SITE_INSTALLATIONS_UNREACHABLE = "1825"
_SITE_INSTALLATION_SELECTION = "c6cc"
_SITE_INSTALLATION_SELECTION_UNREADABLE = "cdea"
_SITE_COLLECTION_SCOPE = "f895"
_SITE_INSTALLATIONS_COLLECTED = "c3d0"
_SITE_BYPASS_ACTOR_UNMODELLED = "5dd2"
_SITE_AUTH_MODE = "3e4d"
_SITE_RELEASES_TRUNCATED = "a401"
_SITE_RELEASES_UNOBSERVABLE = "efd6"
_SITE_PACKAGES_UNREADABLE = "8478"
_SITE_PACKAGES_UNOBSERVABLE = "590d"
_SITE_PACKAGE_VERSIONS_DEGRADED = "ffd2"
_SITE_PACKAGE_VERSIONS_TRUNCATED = "e9ed"
_SITE_PACKAGES_COLLECTED = "540a"
_SITE_ACTION_REF_NOT_FOUND = "de95"
_SITE_ACTIONS_USED = "13f5"
_SITE_WORKFLOW_CALL_UNRESOLVED = "e9e5"
_SITE_WORKFLOW_CALLS = "b97e"
_SITE_WORKFLOW_TRIGGER_UNRESOLVED = "8f14"
_SITE_WORKFLOW_TRIGGERS = "3025"
_SITE_ARTIFACTS_DEGRADED = "eef3"
_SITE_ARTIFACTS_TRUNCATED = "8e7f"
_SITE_ARTIFACTS_COLLECTED = "933f"
_SITE_REQUIRED_CHECKS_UNOBSERVABLE = "d66c"
_SITE_STATUS_CHECKS = "9409"
_SITE_ACTION_REF_UNOBSERVABLE = "a288"
_SITE_ACTION_REF_BUDGET = "c9a3"
_SITE_ACTION_REF_MALFORMED = "45b3"
_SITE_CUSTOM_PROPERTIES_UNOBSERVABLE = "a404"
_SITE_CUSTOM_PROPERTIES_VALUES_UNOBSERVABLE = "fd72"
_SITE_CUSTOM_PROPERTIES_COLLECTED = "3cba"
_SITE_CUSTOM_PROPERTIES_SKIPPED = "906a"
_SITE_CUSTOM_PROPERTIES_REPOSITORY_UNLISTED = "6d8f"
_SITE_PULL_REQUESTS_UNOBSERVABLE = "0f32"
_SITE_PULL_REQUESTS_TRUNCATED = "fb60"
_SITE_PULL_REQUESTS_COLLECTED = "7376"
_SITE_PULL_REQUEST_CHECKS_TRUNCATED = "2ce1"
_SITE_GRAPHQL_PULLS = "8d2d"
_SITE_GRAPHQL_PULLS_FAILED = "7e0f"
_SITE_PULL_REQUEST_CHECKS_UNOBSERVABLE = "323f"
_SITE_PULL_REQUEST_LISTS_TRUNCATED = "ace8"
_SITE_CODE_SCANNING_UNOBSERVABLE = "c723"
_SITE_CODE_SCANNING_NOT_ENABLED = "8cab"
_SITE_CODE_SCANNING_ALERTS_TRUNCATED = "5a88"
_SITE_CODE_SCANNING_ANALYSES_TRUNCATED = "5314"
_SITE_CODE_SCANNING_COLLECTED = "5c6f"
# settings surfaces (req-github-core-settings)
_SITE_ORG_SETTINGS_PUBLIC_ONLY = "89ed"
_SITE_ORG_SETTINGS_UNOBSERVABLE = "3abc"
_SITE_ACTIONS_POLICY_UNOBSERVABLE = "2f13"
_SITE_REPO_SETTINGS_UNOBSERVABLE = "28ca"
_SITE_ENVIRONMENT_DETAIL_UNOBSERVABLE = "700b"
_SITE_ORG_SETTINGS_SKIPPED = "f8f9"

#: Distinct (action repository, declared ref) pairs looked up over REST per run. Each costs one to
#: three calls against a repository that is NOT in scope; past the cap an edge lands as
#: `resolution: not_attempted` and the run says how many, rather than spending the rate limit.
_ACTION_REF_RESOLUTION_CAP = 400
#: What may reach an authenticated API path from a workflow file's `uses:` line. The repository is
#: exactly `owner/repo` (no dots-only segments, no extra segments) and the ref is a git refname
#: fragment: no `..`, no leading/trailing `/`, no empty segment — a crafted `../../orgs/x` must fail
#: HERE, never travel as a request (Grok seat on PR #67).
_SAFE_REPOSITORY_RE = re.compile(
    r"^(?!\.\.?/)[A-Za-z0-9_.-]+/(?!\.\.?$)[A-Za-z0-9_.-]+$"
)
_SAFE_REF_RE = re.compile(
    r"^(?!/)(?!.*(?:^|/)\.\.?(?:/|$))(?!.*//)[A-Za-z0-9_.@+/-]+(?<!/)$"
)
#: An annotated tag may point at another tag object; peel that many levels before giving up.
_TAG_PEEL_MAX_DEPTH = 3
_SHA40_RE = re.compile(r"^[0-9a-f]{40}$")

#: GitHub Actions' own App id — the integration that produces a workflow job's check run.
_GITHUB_ACTIONS_INTEGRATION_ID = 15368

#: The dimension keys that scope an envelope to ONE repository. Stripped from a node shared
#: across the scope (an action, an app), kept on the edges that use it.
_REPO_SCOPED_DIMENSION_KEYS = ("github.owner", "github.repo")


def _check_name_confidence(job_name: str, context: str) -> str | None:
    """How a declared job's display name relates to a required check context, or None.

    A GitHub Actions check run is named after the job's display name; a matrix job expands it
    to `name (value, …)`. The template is a prefix, not the context, so it is reported as
    `matrix_template` rather than claimed as a match.
    """
    if job_name == context:
        return "exact"
    if context.startswith(f"{job_name} (") and context.endswith(")"):
        return "matrix_template"
    return None


def _group_action_calls(
    action_refs: list[dict[str, Any]],
) -> dict[tuple[str, str], dict[str, Any]]:
    """Fold a job's per-step action refs into one entry per (action path, declared ref).

    Two steps calling the same action at the same ref are one relationship with two positions;
    the same action at two refs is two relationships.
    """
    by_call: dict[tuple[str, str], dict[str, Any]] = {}
    for ref in action_refs:
        action_path = str(ref.get("action_path") or ref.get("action") or "")
        if not action_path:
            continue
        entry = by_call.setdefault(
            (action_path, str(ref.get("ref") or "")), {**ref, "step_indexes": []}
        )
        entry["step_indexes"].append(int(ref.get("step_index", 0)))
    return by_call


# GitHub surfaces enabled platform apps (Dependabot) in the Actions workflow
# list under synthetic ``dynamic/<app>/...`` paths. These are not repo CI
# workflows — they are platform apps enabled on the repo — so we reclassify
# them as github_app + ENABLED_ON_REPOSITORY instead of github_workflow. Map the synthetic
# path prefix to the app's stable slug + display metadata.
_SYNTHETIC_APP_BY_PATH_PREFIX: dict[str, dict[str, str]] = {
    "dynamic/dependabot/": {
        "slug": "dependabot",
        "name": "Dependabot",
        # Generic app page — the fallback when the observed owner is a user account.
        "html_url": "https://github.com/apps/dependabot",
        # For an organization the app's own page is the org's security-settings
        # page, where Dependabot is enabled and configured for every repository;
        # `{owner}` is the account login. The generic apps/ page is documentation.
        "org_html_url": "https://github.com/organizations/{owner}/settings/security_analysis",
        "description": "GitHub's managed dependency-update and security-alert app.",
    },
}

_DOCS = (
    CollectorDocRef(
        plugin="github_core",
        doc="collector",
        section="self-test",
        label="GitHub Core collector self-test",
    ),
)

# GitHub Actions `status` values that are non-terminal — runs in any of these
# states are re-fetched on every collection until they reach `completed`
# (`req-github-core-collector-4`). Enumerating terminal-vs-not is more robust
# than enumerating "the non-terminal ones": GitHub may add new in-flight
# states (`waiting`, `pending`, `requested`, `action_required`, etc.) and
# anything we don't recognize is safer treated as "keep watching."
_TERMINAL_RUN_STATUSES: frozenset[str] = frozenset({"completed"})

# `configuration.completed_at_source` on a run node — which of the three states in
# `GithubCollector._run_completed_at` produced its `completed_at` (github-core#46).
COMPLETED_AT_FROM_JOBS = "jobs"
COMPLETED_AT_FROM_UPDATED_AT = "updated_at"
COMPLETED_AT_IN_FLIGHT = "in_flight"

# How many cache entries to pull per repository. GitHub returns them most-recently-accessed
# first, so a cap keeps the freshest — and the collector says how many it left, because a
# truncated cache list that reads as complete would make "no cache from that ref" a wrong answer.
_CACHE_LIMIT_PER_REPO = 100
#: Artifacts per repository per run, newest first; the total is reported alongside. One
#: repository measured 3,831 on 2026-09-02, so a cap is a necessity, not a nicety.
_ARTIFACT_LIMIT_PER_REPO = 100
#: Rule suites collected per repository per run. Bypasses only, so this is a ceiling on
#: FINDINGS rather than on traffic — a repository with more than this many bypasses in the
#: window has a bigger problem than truncation.
_RULE_SUITE_LIMIT_PER_REPO = 100
#: ALWAYS sent. Omitting `time_period` makes GitHub default to `day`, so a repository with a
#: month of bypasses reads as a quiet one (req-github-core-rule-suites-5).
_RULE_SUITE_WINDOW = "month"

#: Packages per type and versions per package. Both endpoints are newest-first; GitHub's own
#: `version_count` says what the version cap left behind (measured 1,973 on one image).
_PACKAGE_LIMIT_PER_TYPE = 100
_PACKAGE_VERSION_LIMIT = 100
#: GitHub's closed set of package types, as the REST `package_type` parameter spells them. One
#: listing call per type: the endpoint refuses to enumerate without one.
_PACKAGE_TYPES: tuple[str, ...] = (
    "container",
    "npm",
    "maven",
    "rubygems",
    "docker",
    "nuget",
)
#: The image-tag convention `publish-images` uses: `sha-<short commit>`. The only derivation that
#: joins a registry version to the run that built it; everything else is left unjoined and said so.
_CONTAINER_TAG_SHA_PREFIX = "sha-"
#: The shortest abbreviation accepted after `sha-`: git's default `--short` and
#: docker/metadata-action's default `type=sha` both emit seven. Shorter is not a commit reference.
_CONTAINER_TAG_SHA_MIN_HEX = 7
#: Output surfaces the repository node qualifies, in the order the machinery view renders them.
_OUTPUT_SURFACES: tuple[str, ...] = ("releases", "artifacts", "packages")
_OBSERVED = "observed"
_UNOBSERVABLE = "unobservable"
#: A settings surface that exists only on organizations, asked of a user account.
_NOT_APPLICABLE = "not_applicable"
#: `GET /orgs/{org}` answered, but only with the half every credential sees — none of the
#: policy keys below arrived, so the credential is not an owner / organization-administration
#: reader. Distinct from `unobservable` (refused) and from `observed` (the policy is on the node).
_PUBLIC_ONLY = "public_only"


def plan_from_org_detail(detail: dict[str, Any] | None) -> str:
    """The account's plan as the `collection_scope` node records it: GitHub's `plan.name`,
    lower-cased (`enterprise` / `team` / `free`), or `unknown` when the detail carries no plan
    — the key is owner-only, so a non-administrator credential never sees it (github-core#145)."""
    plan = (detail or {}).get("plan")
    name = plan.get("name") if isinstance(plan, dict) else plan
    return str(name).strip().lower() if name else "unknown"

# ---------- settings surfaces (req-github-core-settings) ----------
#: Keys of `GET /orgs/{org}` copied VERBATIM onto `github_account.configuration`. GitHub's own
#: names, unrenamed, so a reader can hold the node against the API reference and the conformance
#: lane can hold the manifest against GitHub's published schema without a rename table.
#: The public half arrives for any caller; the policy half arrives only for an owner or an
#: `organization:administration:read` App — and its ABSENCE is how the collector learns which
#: credential it holds (`settings_observability`), never a default.
_ORG_SETTING_KEYS_PUBLIC: tuple[str, ...] = (
    "is_verified",
    "has_organization_projects",
    "has_repository_projects",
    "public_repos",
)
_ORG_SETTING_KEYS_POLICY: tuple[str, ...] = (
    "two_factor_requirement_enabled",
    "default_repository_permission",
    "default_repository_branch",
    "members_allowed_repository_creation_type",
    "members_can_create_repositories",
    "members_can_create_public_repositories",
    "members_can_create_private_repositories",
    "members_can_create_internal_repositories",
    "members_can_create_pages",
    "members_can_create_public_pages",
    "members_can_create_private_pages",
    "members_can_fork_private_repositories",
    "members_can_change_repo_visibility",
    "members_can_delete_repositories",
    "members_can_delete_issues",
    "members_can_invite_outside_collaborators",
    "members_can_create_teams",
    "members_can_view_dependency_insights",
    "readers_can_create_discussions",
    "web_commit_signoff_required",
    "advanced_security_enabled_for_new_repositories",
    "dependabot_alerts_enabled_for_new_repositories",
    "dependabot_security_updates_enabled_for_new_repositories",
    "dependency_graph_enabled_for_new_repositories",
    "secret_scanning_enabled_for_new_repositories",
    "secret_scanning_push_protection_enabled_for_new_repositories",
    "secret_scanning_push_protection_custom_link_enabled",
    "deploy_keys_enabled_for_repositories",
    "display_commenter_full_name_setting_enabled",
    "total_private_repos",
    "owned_private_repos",
    "plan",
)
#: Keys of `GET /repos/{owner}/{repo}` copied verbatim onto `github_repository.configuration`.
#: `security_and_analysis` is the admin-only one: GitHub omits the key for a non-admin caller, and
#: that omission is recorded as `security_settings_observability`, not read as "off".
_REPO_SETTING_KEYS: tuple[str, ...] = (
    "private",
    "fork",
    "archived",
    "disabled",
    "is_template",
    "allow_forking",
    "allow_auto_merge",
    "allow_merge_commit",
    "allow_rebase_merge",
    "allow_squash_merge",
    "allow_update_branch",
    "delete_branch_on_merge",
    "web_commit_signoff_required",
    "has_issues",
    "has_projects",
    "has_wiki",
    "has_pages",
    "has_discussions",
    "has_downloads",
    "topics",
    "security_and_analysis",
)
#: Third state for the code-scanning surface (req-github-core-code-scanning): GitHub said the
#: feature is off for this repository — a 404 `no analysis found`, or a 403 naming Advanced
#: Security on a private repository without it. Distinct from `unobservable`, which is the
#: CREDENTIAL being refused: "off" is a fact about the repository, "refused" a fact about us.
_NOT_ENABLED = "not_enabled"
#: Page size for both code-scanning listings (GitHub's maximum).
_CODE_SCANNING_PAGE_SIZE = 100
#: How the 403/404 bodies say "the feature is off" rather than "you may not look" — matched
#: case-insensitively against the response body, as GitHub's own sentences rather than loose
#: words, so a credential refusal whose body happens to contain a word like "enabled" cannot be
#: misread as the softer state. `no analysis found` is the documented 404 for a repository that
#: never uploaded SARIF (captured verbatim 2026-09-09, tests/fixtures); "Advanced Security must be
#: enabled" is GitHub's 403 for a private repository without GHAS; "code scanning is not enabled"
#: is the 404 GitHub documents for a repository with the feature switched off. A credential
#: refusal reads "Resource not accessible by integration" and matches none of them.
_CODE_SCANNING_NOT_ENABLED_MARKERS = (
    "advanced security must be enabled",
    "no analysis found",
    "code scanning is not enabled",
)
#: Alert states GitHub publishes; the substrate finding folds `dismissed` and `fixed` to `resolved`.
_CODE_SCANNING_OPEN = "open"

# Ruleset condition tokens GitHub uses in place of a ref pattern.
_REF_TOKEN_DEFAULT_BRANCH = (
    "~DEFAULT_BRANCH"  # nosec B105 — GitHub ref token, not a secret
)
_REF_TOKEN_ALL = "~ALL"  # nosec B105 — GitHub ref token, not a secret

# Which ref type a ruleset's target governs. A `push` ruleset restricts the push itself (file
# sizes, secret scanning) rather than a named ref, so it resolves to no refs at all.
_REF_TYPE_BY_RULESET_TARGET = {"branch": "branch", "tag": "tag"}

# The platform instance every collected account/repo/workflow hangs under.
# v0 is github.com only; a GHES host would key on its own hostname.
_PLATFORM_HOST = "github.com"
_PLATFORM_DIMENSIONS = {"git.host": _PLATFORM_HOST}

# The neutral git_core rows carry only git_core's own partition key (spec-git_core-v0.md
# req-git-core-dimensions): `git.host`, the forge instance identity already rests on. The
# forge's own VOCABULARY — owner, repo, surface — is a fact about the OBSERVER and lives on
# the hosting record and the commit observation, never on the substrate. github_core writes
# `git.host` because it depends on git_core and so legitimately writes git_core's vocabulary;
# the same key, the same meaning, on both layers, so "every node on this host" is one filter
# rather than a union of two spellings (github-core#168, git-core-tap#11). The value is
# DERIVED from the host the record hangs off, never authored a second time.

# GitHub Actions' OIDC issuer URL — the identity convergence node github enables
# on every repo. The node itself (id, canonical host, provider, display name) is
# minted by identity_core's general-case helper from this URL; github owns none
# of that vocabulary any more (see plugins/identity_core).
_OIDC_ISSUER_URL = "https://token.actions.githubusercontent.com"


class GithubCollectorError(Exception):
    """Unrecoverable error during the github_core collection run."""


def _iso_datetime(value: Any) -> datetime | None:
    """Parse a GitHub timestamp (`2026-09-01T18:11:47Z`), or `None` when it is not one.

    A degrade, not an abort: the per-repo boundary in `collect` catches only
    `GithubAPIError`, so an unparseable stamp raising here would fail the whole
    collection over one job. The caller treats `None` as "no usable end".
    """
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _login_of(user: Any) -> str:
    """The `login` of a GitHub user object, or `""` when the payload carried none.

    Runs name their `actor` and `triggering_actor` as full user objects; the node
    stores the login alone (github-core#47). `""` is observed-empty, which is what
    an absent or null actor is: the payload was read and named nobody.
    """
    if not isinstance(user, dict):
        return ""
    return str(user.get("login") or "")


def _owner_of(full_name: str) -> str:
    """`owner` from `owner/repo`. Ruleset identity keys on the owner, not the repository."""
    return full_name.partition("/")[0]


class GithubCollector(CollectorBase):
    """GitHub Actions collector — one credential, account-scoped (or explicit repos), two-phase run.

    Transport is a deliberate hybrid (req-github-core-graphql-config): the CONFIG layer arrives via
    GraphQL in one request per 100 repositories, the OPERATION layer (runs, jobs, runners) via REST
    because GitHub's GraphQL API exposes no Actions executions.
    """

    # Config layer keyed by `owner/repo`, populated in run(); empty for a repos-only scope and on
    # any path that does not go through run(), so every reader must treat it as optional.
    _config: ClassVar[dict[str, Any]] = {}
    # Settings surfaces (req-github-core-settings): class-level defaults so a collector built
    # without its constructor — the seeded tests do this — still reads "not yet asked".
    _org_detail: dict[str, Any] | None = None
    _org_detail_state: str = ""
    _org_actions_policy: dict[str, Any] | None = None
    _org_actions_policy_state: str = ""

    @classmethod
    def self_test(cls) -> CollectorSelfTestResult:
        """Operator-facing readiness check for the github_core collector.

        Checks in order; each short-circuits the rest on failure with an actionable readiness
        status:
          1. GITHUB_SECRET_PRESENT — a collector credential is placed
          2. GITHUB_SECRET_VALID   — it is a kind this collector accepts and its schema validates
          3. GITHUB_CREDENTIAL_USABLE — the credential yields a bearer token. For a PAT that is
             the token itself; for an App it means the key signs a JWT, the App is installed on
             the named account, and the installation mints a token — the whole chain, before
             anything relies on it (req-github-core-app-auth-9)
          4. GITHUB_API_REACHABLE  — `GET /rate_limit` succeeds within budget
          4. GITHUB_OWNER_ACCESS   — the account scope enumerates (`/orgs|/users/{owner}/repos`)
             GITHUB_REPO_ACCESS    — per-explicit-repo `GET /repos/{owner}/{repo}`
                                     succeeds; surfaces which repo(s) fail

        The empty-body-404 retry in `api_client` is deliberately disabled for
        self-test paths: a real auth/access 404 should surface immediately,
        not after the full backoff budget (which won't change the outcome).
        """
        checks: list = []

        # 1. Secret present.
        try:
            secret = resolve_github_secret(GITHUB_SECRET_REF)
        except SecretNotFoundError as exc:
            checks.append(
                check_fail(
                    "GITHUB_SECRET_PRESENT",
                    f"No collector credential is configured: {exc}",
                    readiness_status=CollectorReadinessStatus.UNCONFIGURED,
                    docs=_DOCS,
                )
            )
            return CollectorSelfTestResult.from_checks(
                checks,
                summary="No collector credential is configured.",
                docs=_DOCS,
            )
        except (SecretValidationError, SecretError) as exc:
            # 2. Secret malformed (schema failed).
            checks.append(
                check_fail(
                    "GITHUB_SECRET_VALID",
                    f"Collector credential is unusable: {exc}",
                    readiness_status=CollectorReadinessStatus.MISCONFIGURED,
                    docs=_DOCS,
                )
            )
            return CollectorSelfTestResult.from_checks(
                checks,
                summary="Collector credential is unusable.",
                docs=_DOCS,
            )
        checks.append(
            check_pass(
                "GITHUB_SECRET_VALID",
                f"Collector credential resolves; kind {secret.kind!r}.",
                context={"kind": secret.kind},
                docs=_DOCS,
            )
        )

        data = dict(secret.data)
        owner = collection_owner(data)
        repos: list[str] = explicit_repos(data)

        # 3. The credential yields a bearer token. For an App this exercises the entire chain —
        # key signs a JWT, the App is installed on the named account, the installation mints a
        # token — which is exactly the part an operator cannot check by reading the envelope.
        auth = GithubAuth(kind=secret.kind, data=data, api_base_url=api_base_url(data))
        try:
            token = auth.token()
        except GithubAppAuthError as exc:
            checks.append(
                check_fail(
                    "GITHUB_CREDENTIAL_USABLE",
                    f"App credential could not produce an installation token: {exc}",
                    readiness_status=CollectorReadinessStatus.MISCONFIGURED,
                    docs=_DOCS,
                )
            )
            return CollectorSelfTestResult.from_checks(
                checks,
                summary="App credential could not produce an installation token.",
                docs=_DOCS,
            )
        installation = auth.installation or {}
        checks.append(
            check_pass(
                "GITHUB_CREDENTIAL_USABLE:app",
                f"App chain proven — key signs, installation {installation.get('id')} on "
                f"{(installation.get('account') or {}).get('login', '?')}, token minted.",
                context={"installation_id": installation.get("id")},
                docs=_DOCS,
            )
            if auth.has_app
            else check_pass(
                "GITHUB_CREDENTIAL_ABSENT:app",
                f"No App credential — {auth.absent_note(PREFER_APP)}.",
                context={"missing": PREFER_APP},
                docs=_DOCS,
            )
        )
        # The token gets its OWN liveness probe. A dead token beside a live App would otherwise
        # pass this check and degrade at collection time — the failure arriving through the check
        # built to catch it. A missing credential and a dead one must not read the same.
        if auth.has_pat:
            try:
                # Through GithubClient, not around it: the self-test's transport is injectable so
                # a caller can stub it, and a liveness probe that reaches past it would make a
                # stubbed self-test talk to the real GitHub.
                GithubClient(
                    token=auth.token(prefer=PREFER_PAT),
                    api_base_url=api_base_url(data),
                    retry_empty_404=False,
                ).get("/rate_limit")
            except (GithubAppAuthError, GithubAPIError) as exc:
                checks.append(
                    check_fail(
                        "GITHUB_CREDENTIAL_USABLE:pat",
                        f"A personal access token is placed but does not authenticate: {exc}. "
                        f"Surfaces only it can read — a ruleset's bypass actors — will report as "
                        f"unobservable until it is replaced.",
                        readiness_status=CollectorReadinessStatus.MISCONFIGURED,
                        docs=_DOCS,
                    )
                )
            else:
                checks.append(
                    check_pass(
                        "GITHUB_CREDENTIAL_USABLE:pat",
                        "Personal access token authenticates.",
                        docs=_DOCS,
                    )
                )
        else:
            checks.append(
                check_pass(
                    "GITHUB_CREDENTIAL_ABSENT:pat",
                    f"No personal access token — {auth.absent_note(PREFER_PAT)}.",
                    context={"missing": PREFER_PAT},
                    docs=_DOCS,
                )
            )

        # 4. API reachable + the credential authenticates — GET /rate_limit.
        # No-retry client so a real 401/403 surfaces immediately.
        client = GithubClient(
            token=token,
            api_base_url=api_base_url(data),
            retry_empty_404=False,
        )
        try:
            rate = client.get("/rate_limit")
        except GithubAPIError as exc:
            checks.append(
                check_fail(
                    "GITHUB_API_REACHABLE",
                    f"GitHub /rate_limit failed: status={exc.status} "
                    f"body={exc.body[:200] or '(empty)'}",
                    readiness_status=CollectorReadinessStatus.ERROR,
                    docs=_DOCS,
                )
            )
            return CollectorSelfTestResult.from_checks(
                checks,
                summary="GitHub API unreachable or credential auth failed.",
                docs=_DOCS,
            )
        core = rate.get("rate") or rate.get("resources", {}).get("core", {})
        checks.append(
            check_pass(
                "GITHUB_API_REACHABLE",
                f"GitHub API reachable; rate limit "
                f"{core.get('used', '?')}/{core.get('limit', '?')} used.",
                context={"rate": core},
                docs=_DOCS,
            )
        )

        # 4a. Account scope (req-github-core-org-scope): the credential can see the owner and
        # enumerate its repositories. Bounded — one listing walk, not a probe per repo, so an
        # org of hundreds of repos self-tests in seconds. Explicit repos (filter or legacy
        # scope) are still probed one by one below.
        repo_access_ok = True
        # What the owner walk actually proved reachable. None means no walk ran (no owner is
        # configured), which is NOT the same as a walk that found nothing — the summary has to
        # tell those two apart, because one is a misconfiguration and the other is an empty org.
        enumerated: int | None = None
        enumeration_complete = True
        # Distinct from repo_access_ok: an owner walk that FAILED is not the same failure as a
        # configured repo being unreachable, and the summary must not report one as the other.
        owner_walk_failed = False
        if owner is not None:
            try:
                try:
                    listing = client.get_paginated(
                        f"/orgs/{owner}/repos",
                        params={"type": "all", "per_page": "100"},
                    )
                except GithubAPIError as exc:
                    if exc.status != 404:
                        raise
                    listing = client.get_paginated(
                        f"/users/{owner}/repos",
                        params={"type": "all", "per_page": "100"},
                    )
            except GithubAPIError as exc:
                repo_access_ok = False
                owner_walk_failed = True
                checks.append(
                    check_fail(
                        f"GITHUB_OWNER_ACCESS:{owner}",
                        f"Credential cannot enumerate repositories under {owner}: status={exc.status} "
                        f"body={exc.body[:200] or '(empty)'}",
                        readiness_status=CollectorReadinessStatus.ERROR,
                        docs=_DOCS,
                    )
                )
            else:
                enumerated = len(listing)
                enumeration_complete = client.last_walk_complete
                checks.append(
                    check_pass(
                        f"GITHUB_OWNER_ACCESS:{owner}",
                        f"Credential enumerates {len(listing)} repo(s) under {owner}"
                        f"{'' if client.last_walk_complete else ' (walk INCOMPLETE — page cap hit)'}.",
                        context={
                            "owner": owner,
                            "enumerated": len(listing),
                            "complete": client.last_walk_complete,
                        },
                        docs=_DOCS,
                    )
                )
        # 4b. Per-repo access. Each failure is recorded but doesn't short-
        # circuit the rest — operator wants to see ALL the broken repos in
        # one run, not just the first.
        for repo in repos:
            try:
                client.get(f"/repos/{repo}")
            except GithubAPIError as exc:
                repo_access_ok = False
                checks.append(
                    check_fail(
                        f"GITHUB_REPO_ACCESS:{repo}",
                        f"Credential cannot access {repo}: status={exc.status} "
                        f"body={exc.body[:200] or '(empty)'}",
                        readiness_status=CollectorReadinessStatus.ERROR,
                        docs=_DOCS,
                    )
                )
            else:
                checks.append(
                    check_pass(
                        f"GITHUB_REPO_ACCESS:{repo}",
                        f"Credential has access to {repo}.",
                        context={"repo": repo},
                        docs=_DOCS,
                    )
                )

        return CollectorSelfTestResult.from_checks(
            checks,
            summary=_readiness_summary(
                repo_access_ok=repo_access_ok,
                owner_walk_failed=owner_walk_failed,
                explicit_repos=len(repos),
                owner=owner,
                enumerated=enumerated,
                enumeration_complete=enumeration_complete,
            ),
            docs=_DOCS,
        )

    def _abort(self, site: str, code: str, message: str) -> None:
        self.record_error(site, code, message)
        raise GithubCollectorError(message)

    class _SeamRecorder:
        """Adapts the seam's records onto the collector's accumulator with one site token per code."""

        def __init__(self, collector: "GithubCollector") -> None:
            self._c = collector
            self.degraded = 0

        def info(self, code: str, message: str, data: dict[str, Any]) -> None:
            self._c.record_info(_SEAM_SITES.get(code, "6a92"), code, message, message_data=data)

        def warn(self, code: str, message: str, data: dict[str, Any]) -> None:
            if code == "LAYER_DEGRADED":
                self.degraded += 1
            self._c.record_warn(_SEAM_SITES.get(code, "0002"), code, message, message_data=data)

    def _open_seam(self) -> Seam:
        """One budget and one recorder for the whole run (req-github-core-reliability-budget)."""
        self._seam_recorder = self._SeamRecorder(self)
        self._seam = Seam(budget=RunBudget(), recorder=self._seam_recorder)
        self.record_info(_SEAM_SITES["RUN_BUDGET"], "RUN_BUDGET", "Run ceilings.", message_data=self._seam.budget.report())
        return self._seam

    def _close_seam(self) -> str:
        """The end-of-run budget record and the summary suffix (`; N retries, M surfaces degraded`)."""
        seam = getattr(self, "_seam", None)
        if seam is None:
            return ""
        report = seam.budget.report()
        report["degraded_surfaces"] = self._seam_recorder.degraded
        self.record_info(_SEAM_SITES["RUN_BUDGET"], "RUN_BUDGET", "Run ceilings spent.", message_data=report)
        retries, degraded = report["retries_used"], report["degraded_surfaces"]
        if not retries and not degraded:
            return ""
        return f"; {retries} retr{'y' if retries == 1 else 'ies'}, {degraded} surface{'s' if degraded != 1 else ''} degraded"

    def run(self) -> None:
        self.record_info(
            _SITE_RUN_STARTED, "RUN_STARTED", "GitHub Core collection started."
        )
        #: When this run's scope was established — the start of the run, before anything is
        #: weighed in on (github-core#145). Stamped on the collection_scope node as `observed_at`.
        self._scope_observed_at = datetime.now(UTC)
        #: The collection_scope node's id once emitted; the installation edge lands later, beside
        #: the installation node it targets.
        self._scope_uuid: Any = None
        seam = self._open_seam()
        # github_app nodes are singletons shared across repos; dedupe the node
        # emission across the whole run (the ENABLED_ON_REPOSITORY edges still fan in).
        self._emitted_app_ids: set[str] = set()
        # Account type of the observed owner ("Organization" | "User"), learned when
        # the account node is emitted; steers owner-scoped app URLs.
        self._account_type: str = ""
        # Settings surfaces are ACCOUNT facts read once and stamped on every mint of the account
        # node (which happens per repository): the org detail payload, the Actions policy, and
        # their observability states (req-github-core-settings).
        self._org_detail: dict[str, Any] | None = None
        self._org_detail_state: str = ""
        self._org_actions_policy: dict[str, Any] | None = None
        self._org_actions_policy_state: str = ""
        #: Actor logins already emitted as accounts this run. One person bypassing in
        #: nineteen repositories is ONE account node, not nineteen.
        self._emitted_actor_logins: set[str] = set()
        # Rulesets are singletons too, and far more fan-in than apps: an
        # organization-sourced ruleset is reported by every repository it governs
        # (measured: 6 rulesets across 60 attachments on a 19-repo org).
        self._emitted_ruleset_ids: set[str] = set()

        # --- secret resolution (unrecoverable on failure) ---
        try:
            secret = resolve_github_secret(GITHUB_SECRET_REF)
        except SecretError as exc:
            self._abort(
                _SITE_ABORT_SECRET,
                "SECRET_UNUSABLE",
                f"github_pat secret unusable: {exc}",
            )
        data = dict(secret.data)
        run_limit = initial_run_limit(data)

        # One seam, two credential kinds (req-github-core-app-auth-1). Nothing below this line
        # knows which arrived, except where an App-only surface is worth attempting.
        self._auth = GithubAuth(
            kind=secret.kind, data=data, api_base_url=api_base_url(data)
        )
        try:
            token = self._auth.token()
        except GithubAppAuthError as exc:
            self._abort(
                _SITE_ABORT_SECRET,
                "GITHUB_APP_AUTH_FAILED",
                f"App credential unusable: {exc}",
            )
        self.record_info(
            _SITE_AUTH_MODE,
            "AUTH_MODE",
            "Credentials: "
            + ", ".join(
                filter(
                    None,
                    [
                        (
                            f"App (installation {(self._auth.installation or {}).get('id')})"
                            if self._auth.has_app
                            else ""
                        ),
                        "personal access token" if self._auth.has_pat else "",
                    ],
                )
            )
            + (
                ""
                if self._auth.has_app and self._auth.has_pat
                else " — one credential only; some surfaces will read as unobservable."
            ),
            message_data={"held": self._auth.held},
        )

        seam.credential_kind = "app" if self._auth.has_app else "pat"
        client = GithubClient(token=token, api_base_url=api_base_url(data), seam=seam)
        # A second client bound to the personal access token, when one is in the envelope. It
        # exists for exactly one reason: GitHub returns a ruleset's bypass actors only to a caller
        # with write access to the ruleset, and an owner's PAT has it where a read-only App never
        # will. Per-source rather than a global preference order, because "prefer the App" would
        # silently lose bypass actors on precisely the deployments that placed both credentials.
        self._pat_client = (
            GithubClient(
                token=self._auth.token(prefer=PREFER_PAT),
                api_base_url=api_base_url(data),
                seam=seam,
                credential_kind="pat",
            )
            if self._auth.has_pat
            else None
        )
        # What this run is ALLOWED to weigh in on, before it weighs in on anything: the App
        # installation's repository selection, or the PAT's reach (github-core#141) — recorded on
        # the run AND landed as this run's `collection_scope` node (github-core#145), the one
        # statement every absence decision reads before it trusts a missing item.
        owner = collection_owner(data)
        selection = self._collect_installation_selection(client)
        self._emit_collection_scope(client, owner, selection)
        # Per-run caches for objects shared across repositories: one organization ruleset applies
        # to every repository it matches, and re-fetching its detail per repo would be 19 identical
        # calls for one answer.
        self._ruleset_details: dict[tuple[str, int], dict[str, Any] | None] = {}
        # Whether the token, when present, actually answered the ruleset endpoint. "Present" and
        # "answered" are different facts, and an unreadable bypass list means something different
        # under each.
        self._pat_ruleset_status: str = "untried"
        self._emitted_installation_ids: set[str] = set()
        #: Account-scoped Actions secret names, upper-cased, read once per run. Every
        #: repository's workflow walk resolves `${{ secrets.X }}` against this map merged under
        #: its own.
        self._org_secrets: dict[str, list[Any]] = {}
        #: Each organisation secret's resolved REACH, upper-cased name -> OrgSecretReach. Built
        #: once per run alongside the listing; consulted per repository during the walk, because
        #: whether a secret reaches somewhere is a question about a repository, not about the
        #: secret alone.
        self._org_secret_reach: dict[str, OrgSecretReach] = {}
        #: Whether that listing was actually READ. False means the scope is unobserved, and no
        #: workflow may report a name as naming nothing on the strength of its absence.
        self._org_secrets_observed: bool = False
        # What `~DEFAULT_BRANCH` resolves to, keyed `owner/repo#refs/heads/x`. Repo-scoped on
        # purpose: one repository's default is `main` and another's is `master`, and a bare ref
        # path would let the first repo's default mark the second repo's same-named branch.
        self._default_refs: set[str] = set()
        #: Per-repository index of the runs in this batch — what the OUTPUT edges resolve against
        #: (`BUILDS_RELEASE`, `UPLOADS_ARTIFACT`, `BUILDS_PACKAGE_VERSION`). Packages are an
        #: account surface collected after the walk, so the index outlives `_collect_repo`.
        self._run_index: dict[str, list[dict[str, Any]]] = {}
        #: Each collected repository's node envelope, so the packages pass can stamp the third
        #: output state onto it after the walk (github-core#31: three states on the node the
        #: absence is about).
        self._repo_envelopes: dict[str, dict[str, Any]] = {}
        # Refs of an in-scope repository, `ref path -> head sha`, built on first demand from the
        # config layer already in hand. What lets `uses: acme/tool@main` be resolved to a branch
        # and a commit without a request, and what leaves `actions/checkout@v4` honestly
        # unresolved: that repository is not in scope, and nothing here goes looking.
        self._refs_by_repo: dict[str, dict[str, str]] = {}
        #: Run-level tally for the actions summary, so a run can say what it saw.
        # Built by `_usage_tally()` on first touch — ONE initializer, so a state added there cannot be
        # missing here (2026-09-03: two live runs failed on KeyError('rest') because this line carried
        # its own copy of the key set).
        self._action_usage: dict[str, Any] | None = None
        # Workflow-to-workflow reach is resolved in a POST-PASS, after every repository in scope
        # has been walked: a reusable-workflow callee is named by (repo, path) and a
        # `workflow_run` trigger by (repo, name), and either may live in a repository walked
        # later — or in none we walked at all, which is the state that must stay visible.
        self._workflow_uuid_by_path: dict[tuple[str, str], Any] = {}
        self._workflow_uuids_by_name: dict[tuple[str, str], list[Any]] = {}
        self._pending_calls: list[dict[str, Any]] = []
        self._pending_triggers: list[dict[str, Any]] = []
        self._collected_repos: set[str] = set()
        #: Completeness surfaces (req-grid-reconcile-evidence; github-core#151): one entry per
        #: listing this run walked, authored by `_note_listing` and recorded through
        #: `record_surface` at submission, once the collection batch's id is known to cite as
        #: `applied_batches`. Sourced from the walk itself (`last_walk_complete`, the config
        #: layer's caps, the file read) — the reliability seam (github-core#131/#136) is not
        #: merged, so there is no admit/degrade state to read yet.
        self._listings: list[dict[str, Any]] = []
        #: When the config layer (GraphQL) was read: the observation interval of every surface
        #: that arrives in it (environments, and the workflow files a job listing is read from).
        self._config_interval: tuple[datetime, datetime] | None = None
        #: The account listing as `_apply_filter` saw it, for the `account.repositories` surface.
        self._repo_listing: dict[str, Any] | None = None
        self._required_checks: dict[tuple[str, str], dict[str, Any]] = {}
        self._job_names: list[dict[str, Any]] = []
        self._checks_unobservable: list[dict[str, Any]] = []

        # --- scope resolution: the account's repositories, enumerated (req-github-core-org-scope).
        # `owner` was derived once at the top of the run, beside the scope statement.
        # The configuration layer arrives in one GraphQL request per 100 repositories — metadata,
        # default branch, rulesets, environments and every workflow file's YAML inlined. It
        # replaces the enumeration walk, one metadata call per repo, and one Contents call per
        # workflow file; measured on a 19-repo org that is ~85 REST calls collapsed into 1, at a
        # cost of 1 rate-limit point (req-github-core-graphql-config). REST still serves the
        # operation layer below, because GraphQL exposes no workflow runs or jobs.
        self._config: dict[str, dict[str, Any]] = {}
        listing_first = datetime.now(UTC)
        if owner is not None:
            try:
                self._config = self._fetch_config_layer(data, owner)
            except GithubGraphQLError as exc:
                self._abort(
                    _SITE_ABORT_SCOPE,
                    "GITHUB_GRAPHQL_FAILED",
                    f"config-layer fetch failed: {exc}",
                )
            self._config_interval = (listing_first, datetime.now(UTC))
            # Pull requests: a second query merged into the same map (node-limit measurement in
            # the client). Its failure degrades the surface and never aborts the run.
            self._fetch_pull_request_layer(data, owner)
        try:
            repos = self._resolve_repos(client, owner, explicit_repos(data))
        except GithubAPIError as exc:
            self._abort(
                _SITE_ABORT_SCOPE,
                f"GITHUB_SCOPE_{exc.status}",
                f"scope enumeration failed: {exc}",
            )
        listing_last = datetime.now(UTC)

        # --- manifests (load-time JSON Schema validation; errors abort) ---
        load_collection_manifest()  # validates; engine is procedural in v0
        link_manifest = load_link_manifest()

        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []

        # --- platform singleton: one github.com node per run, the top of the
        # account → repo → workflow tree. Synthesized (no API enumerates "the
        # platform"); deterministic id so re-runs upsert in place and a
        # hand-written GRIFT node with the same host upserts cleanly onto it.
        platform_uuid = platform_id(_PLATFORM_HOST)
        nodes.append(
            node_envelope(
                entity_id=platform_uuid,
                entity_type="github_core__github_platform",
                name=_PLATFORM_HOST,
                dimensions=dict(_PLATFORM_DIMENSIONS),
                fields={
                    "host": _PLATFORM_HOST,
                    "html_url": f"https://{_PLATFORM_HOST}",
                    "configuration": {},
                    "tags": {},
                },
            )
        )

        # --- OIDC issuer: GitHub Actions' identity issuer, the convergence node,
        # minted through the identity_core general-case helper (no privileged
        # creator — samsite mints the same node from its own observation and both
        # merge by deterministic id). AWS federation trusts it (TRUSTS_ISSUER,
        # resolved in enrichment) and Sigstore vouches identities by it
        # (IDENTITY_VOUCHED_BY, emitted by the sigstore consumer).
        nodes.append(oidc_issuer_node_envelope(_OIDC_ISSUER_URL))

        # --- installed Apps: an App-only surface (req-github-core-app-installations).
        self._collect_app_installations(client, owner, nodes, edges)

        # --- Actions policy: an account surface (req-github-core-settings-2), read once here and
        # stamped onto the account node each time a repository mints it below.
        self._org_actions_policy, self._org_actions_policy_state = (
            self._collect_org_actions_policy(client, owner)
        )

        # --- organisation secret NAMES: an account surface, read once and consulted by every
        # repository's workflow walk below, so it must land BEFORE the walk rather than after it
        # like packages and custom properties.
        self._org_secrets, self._org_secrets_observed = self._collect_org_secrets(
            client, owner, nodes, edges
        )

        # --- collection phase: per-repo walk ---
        failed: list[str] = []
        for full_name in repos:
            listings_before = len(self._listing_state()["listings"])
            try:
                self._collect_repo(
                    client, full_name, run_limit, nodes, edges, platform_uuid
                )
            except GithubAPIError as exc:
                # Contain the failure to its repo. A scope of one repo could treat any API error
                # as fatal; a scope of nineteen cannot, because across thousands of calls a
                # transient timeout is a certainty, and aborting throws away every repo that
                # DID collect. The run continues and reports honestly instead.
                failed.append(full_name)
                # The surfaces this repository recorded before it failed were listed, but their
                # children never all reached processing: not admitted, so nothing is derived
                # from them (Codex on PR# 154 - tap-plugin-github-core).
                self._withdraw_admission(
                    listings_before,
                    f"collection_failed: {full_name} failed after this listing was read (HTTP {exc.status}); "
                    "its children did not all reach processing",
                )
                self.record_warn(
                    _SITE_REPO_FAILED,
                    f"REPO_FAILED_{exc.status}",
                    f"Skipped {full_name}: {exc}",
                    message_data={"repo": full_name, "status": exc.status},
                )
                continue
            self.record_info(_SITE_REPO_DONE, "REPO_DONE", f"Collected {full_name}")

        # --- packages: an ACCOUNT surface, collected once after the walk so every repository's
        # runs are indexed before a registry version looks for the run that built it.
        packages_state, packages_note = self._collect_packages(
            client, owner, nodes, edges, repo_filtered=bool(explicit_repos(data))
        )
        for envelope in self._repo_envelopes.values():
            observability = envelope["node"].setdefault("outputs_observability", {})
            observability["packages"] = packages_state
            if packages_note:
                observability.setdefault("notes", {})["packages"] = packages_note

        # --- custom properties: the organization's own metadata over its repositories, an
        # ACCOUNT surface read once after the walk so every repository envelope is in hand to be
        # stamped (req-github-core-custom-properties).
        self._collect_custom_properties(client, owner, nodes)

        # The account's repository listing as a completeness surface (github-core#14 shape B:
        # absence is evidence only under a proven-complete, unfiltered walk). A repos-only scope
        # enumerated nothing, so it records no such surface — three states, not two.
        if owner is not None and self._repo_listing is not None:
            listing = self._repo_listing
            reasons: dict[str, str] = {}
            complete: bool | None = bool(listing["complete"])
            if listing["filtered"]:
                complete = False
                reasons["enumeration_complete"] = (
                    f"client_filter: the `repos` include-filter narrowed the walk to "
                    f"{listing['collecting']} of {listing['enumerated']} enumerated repositories"
                )
            elif not complete:
                reasons["enumeration_complete"] = "walk_capped: the paginated walk stopped before the end of the chain"
            if failed:
                reasons["admitted"] = (
                    f"collection_partial: {len(failed)} of {len(repos)} repositories failed to collect; "
                    "absence within this run is not evidence of deletion"
                )
            self._note_listing(
                "account.repositories",
                "OWNS_REPO__github_core",
                account_id(owner),
                listing_first,
                last=listing_last,
                complete=complete,
                count=listing["enumerated"],
                admitted=not failed,
                reasons=reasons,
            )

        if failed and len(failed) == len(repos):
            # Everything failed: that is not a transient blip, it is a broken credential or a
            # dead API. Fail loudly rather than submitting an empty batch that looks like an
            # organization with nothing in it.
            self._abort(
                _SITE_ABORT_API,
                "GITHUB_API_ALL_REPOS_FAILED",
                f"every repo in scope failed to collect ({len(failed)}/{len(repos)})",
            )
        if failed:
            # Load-bearing for tombstoning (req-github-core-org-scope-3, tap#140): the scope was
            # completely ENUMERATED but not completely COLLECTED, so absence within this run is
            # not evidence of deletion. Anything inferring removal must read this first.
            self.record_warn(
                _SITE_COLLECTION_PARTIAL,
                "COLLECTION_PARTIAL",
                f"Collected {len(repos) - len(failed)} of {len(repos)} repo(s); "
                f"{len(failed)} skipped after API errors. Absence in this batch is NOT evidence "
                f"of deletion.",
                message_data={
                    "collected": len(repos) - len(failed),
                    "failed": sorted(failed),
                    "collection_complete": False,
                },
            )

        # --- submission phase ---
        # Collapse envelopes that repeat across repos before submission. Several nodes and
        # edges are legitimately shared by every repo in a scope — the account, the platform,
        # the OIDC issuer and its ENABLED_ON_REPOSITORY edges — and the per-repo walk emits one copy each
        # time. At a one-repo scope that never showed; at 19 repos GRIFT rejected the batch
        # for duplicate entity ids and NOTHING landed. Deduping is correct rather than
        # defensive: these are the same observation seen from several repos, and identity is
        # deterministic, so the last copy is as good as the first.
        # Workflow-to-workflow reach, now that every workflow in scope has an id.
        self._emit_workflow_calls(edges)
        self._emit_workflow_triggers(edges)
        self._emit_status_checks(nodes, edges)

        nodes, node_dupes = self._collapse_by_entity_id(nodes)
        edges, edge_dupes = self._collapse_by_entity_id(edges)
        # Every edge in the COLLECTION batch must land on a node in the same batch — cross-grid
        # edges are the enrichment phase's job and are resolved against what is already on the
        # grid. A run can name a workflow that has since been deleted or renamed, which at a
        # one-repo scope never happened and at nineteen rejected the whole batch for a dangling
        # endpoint. Drop those edges and say how many, rather than losing every repo.
        edges, dropped = self._drop_dangling_edges(
            edges, {k for k in (envelope_key(n) for n in nodes) if k is not None}
        )
        if dropped:
            self.record_warn(
                _SITE_EDGE_DROPPED,
                "EDGES_DROPPED_DANGLING",
                f"Dropped {len(dropped)} edge(s) whose endpoint was not collected — most often a run "
                f"naming a workflow that no longer exists.",
                message_data={
                    "count": len(dropped),
                    "edge_types": sorted({d for d in dropped}),
                },
            )
        if node_dupes or edge_dupes:
            self.record_info(
                _SITE_ENVELOPE_COLLAPSED,
                "ENVELOPES_COLLAPSED",
                f"Collapsed {node_dupes} repeated node envelope(s) and {edge_dupes} edge envelope(s) "
                f"shared across the scope's repos.",
                message_data={"nodes": node_dupes, "edges": edge_dupes},
            )

        scope_label = owner if owner is not None else ", ".join(repos)
        batch_dims = {"git.host": _PLATFORM_HOST}
        if owner is not None:
            batch_dims["github.owner"] = owner
        # The scope's join onto the installation it was derived from lands here, beside the
        # installation node the inventory minted above (github-core#145).
        #
        # AFTER `_drop_dangling_edges`, and that ordering is load-bearing (Codex on PR# 163 -
        # github-core). This edge's SOURCE is the collection_scope, which rode its own earlier
        # batch, so it is a real grid id and by construction not among this batch's node keys —
        # the guard would drop it, silently losing the run's provenance join. The guard is
        # batch-local by design and must stay that way; it is this append that has to come
        # after it. `test_a_cross_batch_endpoint_is_exactly_what_the_guard_drops` pins the
        # hazard so the reason survives someone tidying these three lines together.
        self._append_scope_installation_edge(edges)
        github_batch = assemble_batch(
            batch_name=f"github_core collection: {scope_label}",
            description=f"GitHub Actions plumbing for {len(repos)} repo(s) in scope {scope_label}.",
            nodes=nodes,
            edges=edges,
            batch_dimensions=batch_dims,
        )
        # Every listing this run walked is recorded against the batch that carries its
        # observations; `applied` is derived by the recorder from that batch's commit. A run that
        # walked no listing at all says so (a statement with zero surfaces, not no statement).
        collection_batch_id = str(github_batch["batches"][0]["batch_entity"]["entity_id"])
        listings = self._listing_state()["listings"]
        result = self.submit_grift(github_batch)
        # A SURFACE LEAVES THE BATCH (Issue# 162). The completeness statement is recorded on the
        # RUN, not inside the document, and candidate derivation resolves its `subject` as a grid
        # entity id (`tap_grid/candidates.py::_resolve_parent`). A ref is batch-local and means
        # nothing there, so the surfaces are recorded AFTER the import — the one moment the
        # assigned ids exist — rather than before it as they were. An unresolved subject keeps
        # the ref and derivation says `subject_unresolved`: a visible skip, not a silent loss.
        for listing in listings:
            subject = self._assigned_id(result, listing["subject"])
            self.record_surface(
                **{**listing, "subject": str(subject or listing["subject"])},
                applied_batches=[collection_batch_id],
            )
        if not listings:
            self.declare_no_surfaces()
        self.record_info(
            _SITE_BATCH_SUBMITTED,
            "COLLECTION_BATCH_SUBMITTED",
            f"Submitted collection batch with {len(nodes)} node(s) + {len(edges)} edge(s).",
        )
        usage = self._usage_tally()
        self.record_info(
            _SITE_ACTIONS_USED,
            "ACTIONS_USED",
            f"{len(usage['actions'])} distinct action(s) across {usage['edges']} job usage(s); "
            f"{usage['unpinned']} usage(s) pinned to a mutable name or nothing, of which "
            f"{usage['rest']} resolved over REST against out-of-scope repositories, {usage['unresolved']} named "
            f"a ref that exists as neither tag nor branch, {usage['unobservable']} could not be looked up "
            f"(refused or failed) and {usage['not_attempted']} were not attempted (resolution cap "
            f"{_ACTION_REF_RESOLUTION_CAP}; {self._action_ref_state()['lookups']} REST lookup(s) spent). "
            f"A zero here with workflows in scope means no `uses:` lines, not a clean bill — check the "
            f"workflow count.",
            message_data={
                "actions": len(usage["actions"]),
                "usages": usage["edges"],
                "unpinned": usage["unpinned"],
                "unobservable": usage["unobservable"],
                "rest": usage["rest"],
                "unresolved": usage["unresolved"],
                "not_attempted": usage["not_attempted"],
                "rest_lookups": self._action_ref_state()["lookups"],
            },
        )
        if self._action_ref_state()["skipped"]:
            self.record_warn(
                _SITE_ACTION_REF_BUDGET,
                "ACTION_REF_BUDGET_EXHAUSTED",
                f"{self._action_ref_state()['skipped']} distinct action ref(s) were not looked up: the per-run "
                f"resolution cap ({_ACTION_REF_RESOLUTION_CAP}) was reached. Their edges carry "
                f"`resolution: not_attempted`; an unresolved pin kind there is a budget fact, not an observation.",
                message_data={
                    "skipped": self._action_ref_state()["skipped"],
                    "cap": _ACTION_REF_RESOLUTION_CAP,
                },
            )

        # --- enrichment phase (link resolution against landed nodes) ---
        enrichment_dims = {"git.host": _PLATFORM_HOST}
        enrichment = resolve_links(
            link_manifest=link_manifest,
            repos=repos,
            edge_default_dimensions=enrichment_dims,
        )
        if enrichment.edge_envelopes:
            enrichment_batch = assemble_batch(
                batch_name=f"github_core enrichment: {scope_label}",
                description="Cross-grid link edges (REFERENCES_RESOURCE, FEDERATES_VIA_PROVIDER) resolved from the grid-link manifest.",
                nodes=[],
                edges=enrichment.edge_envelopes,
            )
            self.submit_grift(enrichment_batch)
        self._record_enrichment_summary(enrichment)

        self.summary = (
            f"Collected {len(repos)} repo(s): {len(nodes)} node(s), "
            f"{len(edges)} spine edge(s), "
            f"{len(enrichment.edge_envelopes)} link edge(s)." + self._close_seam()
        )

    # ---------- config layer (GraphQL) ----------

    def _fetch_config_layer(
        self, data: dict[str, Any], owner: str
    ) -> dict[str, dict[str, Any]]:
        """Fetch every repository's configuration for ``owner`` in one query, keyed by full name."""
        gql = GithubGraphQLClient(
            token=self._auth.token(), api_base_url=api_base_url(data), seam=self._seam
        )
        repos, notes = gql.fetch_config_layer(owner)
        config = {str(r["nameWithOwner"]): r for r in repos if r.get("nameWithOwner")}
        self.record_info(
            _SITE_GRAPHQL_CONFIG,
            "GRAPHQL_CONFIG_FETCHED",
            f"Config layer for {owner}: {len(config)} repo(s), "
            f"{sum(len(GithubGraphQLClient.workflow_files(r)) for r in repos)} workflow file(s), "
            f"cost {gql.last_cost} point(s).",
            message_data={
                "repos": len(config),
                "cost": gql.last_cost,
                "remaining": gql.last_remaining,
            },
        )
        for note in notes:
            # A field the credential could not read. Surfaced, never swallowed: a silently missing
            # ruleset list is indistinguishable from an account that has no rulesets.
            self.record_warn(
                _SITE_GRAPHQL_DEGRADED,
                "GRAPHQL_FIELD_DEGRADED",
                f"Config layer partially unreadable — {note}",
                message_data={"detail": note},
            )
        return config

    def _fetch_pull_request_layer(self, data: dict[str, Any], owner: str) -> None:
        """Fetch every repository's pull requests for ``owner`` and merge them into the config map.

        A second GraphQL query (five repositories a page) rather than more fields on the config
        layer — see `graphql_client._PULL_REQUEST_QUERY` for the node- and time-limit measurements. Merged
        under each repository's `pullRequests` key so `_emit_pull_requests` reads one map; a
        repository the query did not answer for gets NO key, and a query that fails outright
        leaves every key absent, so both read as `unobservable` downstream rather than as "no
        pull requests" (req-github-core-pull-requests).
        """
        gql = GithubGraphQLClient(token=self._auth.token(), api_base_url=api_base_url(data), seam=self._seam)
        try:
            by_repo, notes = gql.fetch_pull_request_layer(owner)
        except GithubGraphQLError as exc:
            self.record_warn(
                _SITE_GRAPHQL_PULLS_FAILED,
                "GRAPHQL_PULLS_FAILED",
                f"Pull-request layer for {owner} failed — pull requests NOT observed for any repository, "
                f"which is not the same as none being open: {exc}",
                message_data={"owner": owner},
            )
            return
        merged = 0
        for full_name, node in by_repo.items():
            if "pullRequests" not in node:
                continue  # degraded and pruned: absence stays absence
            self._config.setdefault(full_name, {})["pullRequests"] = node["pullRequests"]
            merged += 1
        self.record_info(
            _SITE_GRAPHQL_PULLS,
            "GRAPHQL_PULLS_FETCHED",
            f"Pull-request layer for {owner}: {merged} of {len(by_repo)} repo(s) answered, "
            f"cost {gql.last_cost} point(s).",
            message_data={"repos": len(by_repo), "answered": merged, "cost": gql.last_cost, "remaining": gql.last_remaining},
        )
        for note in notes:
            self.record_warn(
                _SITE_GRAPHQL_DEGRADED,
                "GRAPHQL_FIELD_DEGRADED",
                f"Pull-request layer partially unreadable — {note}",
                message_data={"detail": note},
            )

    @staticmethod
    def _repo_payload_from_config(gql: dict[str, Any]) -> dict[str, Any]:
        """Shape a GraphQL repository node like the REST payload the emitters already consume."""
        branch = gql.get("defaultBranchRef") or {}
        owner_login = str(gql.get("nameWithOwner", "/")).split("/", 1)[0]
        return {
            "full_name": gql.get("nameWithOwner"),
            "name": gql.get("name"),
            "id": gql.get("databaseId"),
            "owner": {"login": owner_login},
            "default_branch": branch.get("name"),
            "visibility": (gql.get("visibility") or "").lower(),
            "archived": bool(gql.get("isArchived")),
            "fork": bool(gql.get("isFork")),
            "html_url": gql.get("url"),
        }

    def _workflow_config(
        self, client: GithubClient, full_name: str, path: str
    ) -> tuple[str, dict[str, Any]]:
        """Workflow YAML from the config layer when present, else the Contents API.

        The GraphQL path is the reason the per-file Contents calls disappear — they were both the
        bulk of the request count and the ones that timed out at org scale.
        """
        gql = self._config.get(full_name)
        if gql and path:
            files = GithubGraphQLClient.workflow_files(gql)
            raw = files.get(path)
            if raw is not None:
                return raw, parse_workflow_yaml(raw)
        return self._fetch_workflow_config(client, full_name, path)

    # ---------- envelope hygiene ----------

    @staticmethod
    def _drop_dangling_edges(
        edges: list[dict[str, Any]], node_ids: set[str]
    ) -> tuple[list[dict[str, Any]], list[str]]:
        """Drop edges with an endpoint outside ``node_ids``; return the survivors and their types.

        Applies to the collection batch only, where both endpoints are always emitted alongside
        the edge. Enrichment edges resolve against the grid and must never be filtered this way.

        ``node_ids`` holds whatever each node envelope names itself by — a ref for a type that
        has adopted assigned identity, an entity id for one that has not — and an edge endpoint
        is compared on the same footing (``endpoint_keys``). A ref endpoint that names no node
        of this batch is a hard GRIFT error (``unknown_ref``) rather than a dangling id, so
        catching it here is the difference between dropping one edge and losing the batch.
        """
        kept: list[dict[str, Any]] = []
        dropped: list[str] = []
        for env in edges:
            e = env.get("edge") or {}
            src, tgt = endpoint_keys(env)
            if src in node_ids and tgt in node_ids:
                kept.append(env)
            else:
                dropped.append(str(e.get("edge_type", "unknown")))
        return kept, dropped

    @staticmethod
    def _assigned_id(result: Any, value: Any) -> UUID | None:
        """The entity id core assigned to a batch-local ref, read off the import result.

        The only supported way a collector learns what a ref became (`tap_grid/grift/refs.py`:
        "the ref -> id map is returned on the import result, which is where a collector learns
        what it was given"). The map is reported per IMPORTED batch, so a rejected or skipped
        batch yields None rather than a plausible-looking id.

        Takes the ref by VALUE rather than by type: a ref that has been through `str()` on its
        way into a per-run record (`_note_listing` stores its subject as text) is still the same
        key in the map. A value that is already an id passes straight through, and anything that
        is neither is None — three states, never two.
        """
        key = str(value)
        for batch in getattr(result, "imported_batches", None) or []:
            assigned = (getattr(batch, "resolved_refs", None) or {}).get(key)
            if assigned:
                return UUID(str(assigned))
        if isinstance(value, Ref):
            return None
        try:
            return UUID(key)
        except (ValueError, AttributeError, TypeError):
            return None

    @staticmethod
    def _collapse_by_entity_id(
        envelopes: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], int]:
        """Return the envelopes with a duplicate identity collapsed, and the count removed.

        The identity is the envelope's ``ref`` or its ``entity_id``, whichever it carries
        (``envelope_key``). Collapsing by ref is not merely the analogue of collapsing by id —
        it is load-bearing: a repeated ref is a hard GRIFT error (``duplicate_ref``) that
        rejects the whole batch, so the same account or action seen from nineteen repositories
        MUST arrive once.

        Order is preserved and the LAST occurrence wins, so the freshest observation of a shared
        node survives. Envelopes that name themselves neither way pass through untouched rather
        than being silently dropped — that is a different bug and GRIFT should be the one to
        say so.
        """
        seen: dict[str, int] = {}
        out: list[dict[str, Any]] = []
        removed = 0
        for env in envelopes:
            key = envelope_key(env)
            if key is None:
                out.append(env)
                continue
            if key in seen:
                out[seen[key]] = env
                removed += 1
            else:
                seen[key] = len(out)
                out.append(env)
        return out, removed

    # ---------- scope resolution ----------

    def _resolve_repos(
        self, client: GithubClient, owner: str | None, explicit: list[str]
    ) -> list[str]:
        """The `owner/repo` full names this run collects (req-github-core-org-scope).

        With an `owner`: enumerate the account's repositories (``/orgs/{owner}/repos`` with a
        404 fallback to ``/users/{owner}/repos``), apply the explicit list as an include-filter
        if given, and record the enumeration on the run — including whether the paginated walk
        was COMPLETE, which is the assertion node-level absence (tombstoning, tap#140) will
        need before "not seen" can mean "gone". Without an `owner`: the explicit list is the
        scope (the degenerate run config, tap#142) and nothing is enumerated.
        """
        if owner is None:
            return self._resolve_explicit(client, explicit)
        if self._config:
            # Already enumerated by the config-layer query; do not walk REST again.
            enumerated = sorted(self._config)
            return self._apply_filter(
                owner, enumerated, explicit, account_kind="graphql", complete=True
            )
        params = {"type": "all", "per_page": "100"}
        try:
            listing = client.get_paginated(f"/orgs/{owner}/repos", params=params)
            account_kind = "org"
        except GithubAPIError as exc:
            if exc.status != 404:
                raise
            listing = client.get_paginated(f"/users/{owner}/repos", params=params)
            account_kind = "user"
        complete = bool(client.last_walk_complete)
        enumerated = [
            str(item["full_name"])
            for item in listing
            if isinstance(item, dict) and item.get("full_name")
        ]
        return self._apply_filter(
            owner, enumerated, explicit, account_kind=account_kind, complete=complete
        )

    def _resolve_explicit(self, client: GithubClient, explicit: list[str]) -> list[str]:
        """Resolve a repos-only scope BEFORE the per-repository loop (github-core#140).

        Without an `owner` the explicit list IS the configuration, so a listed repository that
        cannot be found is a config error of the same class as "the org named in the envelope
        cannot be found" — George's ruling (2026-09-14): error out and stop, do not degrade. The
        per-repo loop's containment (`REPO_FAILED_<status>`, continue) is right for TRANSIENT
        failures across a nineteen-repo org and wrong for a typo in the envelope, which it would
        turn into a warning and a quietly smaller run.

        One `GET /repos/{owner}/{repo}` per listed repository, up front — the root-of-trust step
        for this scope shape: the tree still starts at the platform, the account is named from the
        listed repos' owner, and each step records whether it could introspect. Three answers:

        - **404 aborts, naming the repository.** GitHub answers 404 both for a name that does not
          exist and for a private repository this credential may not see — the two are
          indistinguishable here, and BOTH mean the envelope and the credential disagree, which
          is a configuration problem. The message says so; it never claims "does not exist".
        - **403 is recorded and the repository kept**: it exists, this credential cannot read it,
          and the loop will record its own refusal per surface.
        - **Anything else (401, 429, 5xx) proves nothing** about the repository: recorded as
          unresolved, kept in scope, and the resolve step's `complete` is FALSE — absence cannot be
          weighed against a listing whose members could not all be established. Reliability 1a/1b
          add retry-within-budget under this call; until then a transient failure here is honest
          rather than retried.

        `SCOPE_RESOLVED.complete` is the assertion a tombstone pass reads
        (`req-github-core-reliability-absence`): true only when every listed repository answered.
        """
        unreadable: list[dict[str, Any]] = []
        unresolved: list[dict[str, Any]] = []
        for full_name in explicit:
            try:
                client.get(f"/repos/{full_name}")
            except GithubAPIError as exc:
                if exc.status == 404:
                    self._abort(
                        _SITE_SCOPE_REPO_NOT_FOUND,
                        "SCOPE_REPO_NOT_FOUND",
                        f"Configured repository {full_name} was not found (404): either it does "
                        f"not exist or this credential is not allowed to see it — GitHub answers "
                        f"404 for both. The explicit `repos` list is the collection scope, so the "
                        f"envelope and the credential disagree; fix one and rerun.",
                    )
                if exc.status == 403:
                    unreadable.append({"repo": full_name, "status": exc.status})
                    self.record_warn(
                        _SITE_SCOPE_REPO_UNREADABLE,
                        f"SCOPE_REPO_UNREADABLE_{exc.status}",
                        f"Configured repository {full_name} exists but this credential cannot read "
                        f"it ({exc.status}); it stays in scope and its surfaces will read as "
                        f"unobservable.",
                        message_data={"repo": full_name, "status": exc.status},
                    )
                    continue
                unresolved.append({"repo": full_name, "status": exc.status})
                self.record_warn(
                    _SITE_SCOPE_REPO_UNREADABLE,
                    f"SCOPE_REPO_UNRESOLVED_{exc.status}",
                    f"Configured repository {full_name} could not be resolved ({exc.status}: not "
                    f"a statement about whether it exists); it stays in scope, and absence cannot "
                    f"be weighed against this run's listing.",
                    message_data={"repo": full_name, "status": exc.status},
                )
        complete = not unresolved
        self.record_info(
            _SITE_SCOPE_RESOLVED,
            "SCOPE_RESOLVED",
            f"Resolved {len(explicit)} configured repositor{'y' if len(explicit) == 1 else 'ies'}"
            f" (repos-only scope): {len(unreadable)} unreadable, {len(unresolved)} unresolved; "
            f"listing {'complete' if complete else 'INCOMPLETE — absence cannot be weighed against it'}.",
            message_data={
                "configured": len(explicit),
                "unreadable": unreadable,
                "unresolved": unresolved,
                "complete": complete,
                "filtered": False,
            },
        )
        return list(explicit)

    def _apply_filter(
        self,
        owner: str,
        enumerated: list[str],
        explicit: list[str],
        *,
        account_kind: str,
        complete: bool,
    ) -> list[str]:
        """Apply the optional include-filter to an enumerated scope and record the enumeration."""
        repos = enumerated
        if explicit:
            wanted = set(explicit)
            repos = [name for name in enumerated if name in wanted]
            unmatched = sorted(wanted - set(enumerated))
            if unmatched:
                self.record_warn(
                    _SITE_FILTER_UNMATCHED,
                    "SCOPE_FILTER_UNMATCHED",
                    f"{len(unmatched)} filtered repo(s) not found under {owner}: {', '.join(unmatched)}",
                    message_data={"owner": owner, "unmatched": unmatched},
                )
        self._repo_listing = {
            "complete": complete,
            "filtered": bool(explicit),
            "enumerated": len(enumerated),
            "collecting": len(repos),
        }
        self.record_info(
            _SITE_SCOPE_ENUMERATED,
            "SCOPE_ENUMERATED",
            f"Enumerated {len(enumerated)} repo(s) under {account_kind} {owner}"
            f"{' (walk INCOMPLETE — page cap hit)' if not complete else ''}; collecting {len(repos)}.",
            message_data={
                "owner": owner,
                "account_kind": account_kind,
                "enumerated": len(enumerated),
                "collecting": len(repos),
                "filtered": bool(explicit),
                "complete": complete,
            },
        )
        return repos

    # ---------- per-repo collection ----------

    def _collect_repo(
        self,
        client: GithubClient,
        full_name: str,
        run_limit: int,
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
        platform_uuid: Any,
    ) -> None:
        owner, _, repo = full_name.partition("/")
        repo_dims = {
            "git.host": _PLATFORM_HOST,
            "github.owner": owner,
            "github.repo": repo,
        }
        actions_dims = {**repo_dims, "github.surface": "actions"}
        observation_dims = {**actions_dims, "github.observation": "execution"}
        self._walk_state()["collected_repos"].add(full_name)

        # account
        account_payload = self._fetch_account(client, owner)
        account_uuid = account_id(account_payload["login"])
        self._account_type = str(account_payload.get("type") or "")
        nodes.append(
            node_envelope(
                entity_id=account_uuid,
                entity_type="github_core__github_account",
                name=account_payload["login"],
                dimensions={**repo_dims},  # owner+repo carried even on account
                fields={
                    "login": account_payload["login"],
                    "github_id": account_payload.get("id"),
                    "account_type": account_payload.get("type", ""),
                    "html_url": account_payload.get("html_url", ""),
                    "configuration": self._account_configuration(client, account_payload),
                    "tags": {},
                },
            )
        )
        # platform hosts this account — top-of-tree containment. Deterministic
        # edge id dedupes across repos that share an owner.
        edges.append(
            self._edge(
                "HOSTS_ACCOUNT__github_core",
                platform_uuid,
                account_uuid,
                dict(_PLATFORM_DIMENSIONS),
            )
        )

        # repository. Prefer the config layer already in hand; fall back to REST for a
        # repos-only scope, where no GraphQL enumeration ran.
        gql = self._config.get(full_name)
        repo_payload = (
            self._repo_payload_from_config(gql)
            if gql
            else client.get(f"/repos/{full_name}")
        )
        # The settings half of the repository (forking, archive state, merge policy, the
        # admin-only security_and_analysis block) is REST-only; when the config layer supplied
        # the identity half this is the one extra call per repository, and a refusal is
        # recorded rather than read as defaults (req-github-core-settings-3).
        settings_payload = (
            self._fetch_repository_settings(client, full_name) if gql else repo_payload
        )
        repo_uuid = repository_id(full_name)
        repo_envelope = node_envelope(
            entity_id=repo_uuid,
            entity_type="github_core__github_repository",
            name=full_name,
            dimensions=repo_dims,
            fields={
                "full_name": full_name,
                "owner_login": owner,
                "name": full_name,
                "github_id": repo_payload.get("id"),
                "default_branch": repo_payload.get("default_branch", ""),
                "visibility": repo_payload.get("visibility", ""),
                "html_url": repo_payload.get("html_url", ""),
                # Filled in below, once the output surfaces have been attempted. `{}` here would
                # read as "never looked", which is the honest value until then.
                "outputs_observability": {},
                # Stamped after the walk by `_collect_custom_properties`, an account surface. Until
                # then `""` is "never looked" — the honest value, never an empty map that reads as
                # "none set" (req-github-core-custom-properties).
                "custom_properties": {},
                "custom_properties_observability": "",
                # Stamped by `_emit_pull_requests` once the config layer has been read for this
                # repository; `""` is "never asked" (req-github-core-pull-requests).
                "pull_requests_observability": "",
                "pull_requests_total": None,
                # Stamped by `_collect_code_scanning` after workflows and commits are indexed;
                # `""` is "never asked" (req-github-core-code-scanning). Four states, because
                # "the feature is off" and "we were refused" are different facts.
                "code_scanning_observability": "",
                "configuration": self._repository_configuration(settings_payload),
                "tags": {},
            },
        )
        nodes.append(repo_envelope)
        self._repo_envelopes[full_name] = repo_envelope
        edges.append(
            self._edge("OWNS_REPO__github_core", account_uuid, repo_uuid, repo_dims)
        )

        # The neutral git_core repository this record HOSTS (github-core#76): identity is the
        # host plus GitHub's stable numeric id, never the name, so a rename changes a field and a
        # mirror elsewhere is another repository. Refs and commits hang off THIS node.
        repository_github_id = repo_payload.get("id")
        git_repo_uuid = None
        if repository_github_id is not None:
            git_repo_uuid = git_repository_id(
                repo_dims["git.host"], str(repository_github_id)
            )
            default_branch = repo_payload.get("default_branch", "") or ""
            nodes.append(
                node_envelope(
                    entity_id=git_repo_uuid,
                    entity_type="git_core__git_repository",
                    name=full_name,
                    dimensions={"git.host": repo_dims["git.host"]},
                    fields={
                        "forge": repo_dims["git.host"],
                        "stable_id": str(repository_github_id),
                        "name": full_name,
                        "default_ref": (
                            f"refs/heads/{default_branch}" if default_branch else ""
                        ),
                        "hash_algorithm": "sha1",
                        "configuration": {},
                        "tags": {},
                    },
                )
            )
            edges.append(
                self._edge(
                    "HOSTS_REPOSITORY__github_core", repo_uuid, git_repo_uuid, repo_dims
                )
            )
        else:
            self.record_warn(
                _SITE_NO_STABLE_REPO_ID,
                "NO_STABLE_REPOSITORY_ID",
                f"{full_name}: the repository payload carried no `id`, so no neutral git_core repository, "
                "refs or commits were minted for it. Absence of refs here is NOT evidence there are none.",
                message_data={"repo": full_name},
            )

        # The Actions OIDC issuer (synthesized once as a platform singleton) is
        # enabled for every repo's workflows to mint identity tokens — mirror the
        # github_app ENABLED_ON_REPOSITORY pattern so it connects into the repo it serves.
        edges.append(
            self._edge(
                "ENABLED_ON_REPOSITORY__github_core",
                oidc_issuer_id(_OIDC_ISSUER_URL),
                repo_uuid,
                repo_dims,
            )
        )

        # --- configuration layer: refs, rulesets, environments.
        # All three arrive in the GraphQL config layer already in hand, so this costs no request.
        # They are emitted BEFORE the workflow walk because the declared jobs point at
        # environments, and the ruleset->ref resolution needs the refs.
        ref_uuid_by_ref = self._emit_refs(
            full_name,
            repo_uuid,
            git_repo_uuid,
            repository_github_id,
            repo_dims,
            nodes,
            edges,
        )
        self._emit_rulesets(
            client, full_name, repo_uuid, repo_dims, ref_uuid_by_ref, nodes, edges
        )
        env_uuid_by_name = self._emit_environments(
            full_name, repo_uuid, repo_dims, nodes, edges, client=client
        )
        # Secret NAMES, before the workflow walk, so a workflow's `${{ secrets.X }}` reference can
        # resolve against something already in hand rather than dangling. Three scopes feed one
        # lookup: the organisation's (read once per run, before the walk), this repository's, and
        # each of its environments'.
        repo_secrets, secret_scopes_read = self._collect_secrets(
            client, full_name, repo_uuid, repo_dims, env_uuid_by_name, nodes, edges
        )
        # Merged by CONCATENATION, not by override. `{**org, **repo}` silently dropped the
        # organisation secret whenever a repository held the same name, so a workflow naming it
        # got one edge to whichever scope happened to be written last.
        secret_uuid_by_name: dict[str, list[Any]] = {
            name: list(uuids) for name, uuids in self._org_secrets.items()
        }
        for name, uuids in repo_secrets.items():
            secret_uuid_by_name.setdefault(name, []).extend(uuids)
        if self._org_secrets_observed:
            secret_scopes_read = ["organization", *secret_scopes_read]
        # Pull requests come from the pull-request layer merged into the same config map; the
        # head/base edges target the neutral refs and commits emitted just above, and dangle (are
        # dropped) when those were not seen.
        self._emit_pull_requests(full_name, repo_envelope, git_repo_uuid, repo_dims, nodes, edges)

        # workflows + workflow YAML. The listing is a completeness surface of the repository
        # (github-core#14 shape A children): a refusal is recorded on the run before it
        # propagates, so a repository that fails here still says what it could not list.
        workflows_first = datetime.now(UTC)
        try:
            workflows = client.get_paginated(
                f"/repos/{full_name}/actions/workflows", item_path="workflows"
            )
        except GithubAPIError as exc:
            self._note_listing(
                "repository.workflows",
                "DEFINES_WORKFLOW__github_core",
                repo_uuid,
                workflows_first,
                refused=exc.status,
            )
            raise
        self._note_listing(
            "repository.workflows",
            "DEFINES_WORKFLOW__github_core",
            repo_uuid,
            workflows_first,
            complete=bool(client.last_walk_complete),
            count=len(workflows),
            reasons=(
                {}
                if client.last_walk_complete
                else {"enumeration_complete": "walk_capped: the paginated walk stopped before the end of the chain"}
            ),
        )
        for wf in workflows:
            path = wf.get("path", "")
            # Synthetic platform-app entries (e.g. Dependabot) come back here but
            # are not repo CI workflows; reclassify them as github_app + ENABLED_ON_REPOSITORY
            # and skip the YAML fetch (no real file exists at the dynamic/ path).
            app_meta = next(
                (
                    meta
                    for prefix, meta in _SYNTHETIC_APP_BY_PATH_PREFIX.items()
                    if path.startswith(prefix)
                ),
                None,
            )
            if app_meta is not None:
                self._emit_github_app(
                    app_meta, full_name, repo_uuid, repo_dims, nodes, edges
                )
                continue

            wf_uuid = workflow_id(full_name, wf["id"])
            file_first = datetime.now(UTC)
            raw_yaml, parsed_config = self._workflow_config(
                client, full_name, wf.get("path", "")
            )
            wf_display_name = wf.get("name") or wf.get("path") or str(wf["id"])
            wf_envelope = node_envelope(
                entity_id=wf_uuid,
                entity_type="github_core__github_workflow",
                name=wf_display_name,
                dimensions=actions_dims,
                fields={
                    "full_name": full_name,
                    "workflow_id": wf["id"],
                    "path": wf.get("path", ""),
                    "name": wf_display_name,
                    "state": wf.get("state", ""),
                    "html_url": wf.get("html_url", ""),
                    "configuration": parsed_config,
                    "tags": {},
                },
            )
            nodes.append(wf_envelope)
            edges.append(
                self._edge(
                    "DEFINES_WORKFLOW__github_core", repo_uuid, wf_uuid, actions_dims
                )
            )
            # Which secrets this file NAMES, and which of those names resolve to a secret that
            # exists. A reference that resolves to nothing is the interesting case: GitHub hands
            # the job an empty string rather than failing, so the workflow runs and quietly does
            # the wrong thing. It is recorded ON the workflow rather than as a node, because
            # minting a secret node from a reference would assert that a credential exists on the
            # evidence that somebody typed its name.
            #
            # `scopes_read` rides along because "unresolved" is only a claim about the scopes that
            # were actually readable. Three states, never two: resolved, unresolved, or not
            # observable — a reader must be able to tell an unset secret from a refused listing.
            # ONE EDGE PER DEFINING SCOPE. A name held at both organisation and repository
            # scope is two credentials, and this edge asserts "this file names a secret that
            # exists HERE" — it is a statement about the file, as its declaration says, not a
            # prediction of which one a run receives. Resolving by GitHub's precedence instead
            # would require knowing which environment the job selects, which is chosen at
            # runtime and is a named blind spot; picking one would manufacture a claim this
            # collector cannot support.
            referenced = secret_names_in(raw_yaml)
            unresolved = []
            reach_uncertain = []
            repo_visibility = str(repo_payload.get("visibility", ""))
            for secret_name in sorted(referenced):
                key = secret_name.upper()
                targets = secret_uuid_by_name.get(key) or []
                if not targets:
                    unresolved.append(secret_name)
                    continue
                # A name held at repository or environment scope is readable here by definition.
                # One held ONLY by the organisation has to clear its sharing policy first: a
                # `selected` secret does not reach the rest of the organisation, and a `private`
                # one reaches no public repository at all.
                reach: bool | None = True
                if key not in repo_secrets:
                    # Defaulting to `unknown` rather than `all`: an organisation secret always
                    # gets a reach entry written beside it, so a missing one is an internal
                    # inconsistency, and guessing `all` there would claim reach we never derived.
                    reach = self._org_secret_reach.get(
                        key, OrgSecretReach("unknown", frozenset())
                    ).reaches(full_name, repo_visibility)
                if reach is False:
                    # The secret exists and this workflow names it, but this repository cannot
                    # read it, so at runtime the step receives an empty string — operationally
                    # identical to the name not existing, which is what `unresolved` means. No
                    # edge: a credential this workflow cannot read is not one it uses.
                    unresolved.append(secret_name)
                    continue
                if reach is None:
                    # The repository list was refused or truncated. Not reachable, not
                    # unreachable — its own answer rather than a rounding to either.
                    reach_uncertain.append(secret_name)
                for target in targets:
                    edges.append(
                        self._edge("REFERENCES_SECRET__github_core", wf_uuid, target, actions_dims)
                    )
            # Written whenever a BODY was read, including when it names no secret — an empty
            # `referenced` is "read, and it references none", which is a different claim from the
            # tag being absent ("this file was never read"). Forty of this estate's 117 workflows
            # carry no body at all, and collapsing the two would let a third of the estate read as
            # secret-free.
            if raw_yaml:
                wf_envelope["node"]["tags"]["secret_refs"] = {
                    "referenced": sorted(referenced),
                    "unresolved": unresolved,
                    "reach_uncertain": reach_uncertain,
                    "scopes_read": secret_scopes_read,
                }
            self._register_workflow(
                full_name,
                wf.get("path", ""),
                wf_display_name,
                wf_uuid,
                wf_envelope,
                parsed_config,
                actions_dims,
            )
            # The DECLARED jobs inside this file — the level every privilege decision is made at.
            self._emit_declared_jobs(
                full_name,
                wf_uuid,
                wf["id"],
                wf.get("path", ""),
                parsed_config,
                env_uuid_by_name,
                nodes,
                edges,
                client=client,
                file_read=bool(raw_yaml),
                listing_first=file_first,
            )
            # Local-action surfacing per req-github-core-workflow-parse-3.
            for ref in parsed_config.get("local_action_refs") or []:
                self.record_warn(
                    _SITE_LOCAL_ACTION_DEFERRED,
                    "LOCAL_ACTION_DEFERRED",
                    f"{full_name} workflow {wf.get('path', '')}: local/composite "
                    f"action reference {ref.get('uses')!r} at {ref.get('path')} "
                    f"(job {ref.get('job_id')!r}); v0 does not parse action.yml bodies.",
                )

        # runs — incremental fetch per req-github-core-collector-3:
        #   - First population (no on-grid runs): latest `run_limit` runs.
        #   - Later populations: runs created since the latest on-grid
        #     `run_started_at` for this repo, using GitHub's `created` filter.
        run_payloads = self._fetch_run_window(client, full_name, run_limit)

        # Non-terminal refresh per req-github-core-collector-4: pull every
        # on-grid run for this repo whose status is not in
        # _TERMINAL_RUN_STATUSES and re-fetch it singly. Skips any run_id
        # already in this batch's run_payloads (the incremental fetch may
        # already have re-fetched it).
        refreshed = self._fetch_non_terminal_refresh(
            client, full_name, already_fetched_run_ids={r["id"] for r in run_payloads}
        )
        run_payloads.extend(refreshed)
        # Held for the EXECUTED_ON_RUNNER pass below rather than re-fetched: the runner match needs
        # the same job payloads, and at account scope a second walk is one extra API call per
        # RUN — the single largest cost in the whole collection.
        jobs_by_run: dict[int, list[dict[str, Any]]] = {}
        for r in run_payloads:
            jobs_by_run[r["id"]] = self._emit_run_with_jobs(
                client, full_name, r, observation_dims, nodes, edges
            )

        # runners (graceful-degrade on 403 per req-github-core-collector-5)
        try:
            runners = client.get_paginated(
                f"/repos/{full_name}/actions/runners", item_path="runners"
            )
        except GithubAPIError as exc:
            if exc.status == 403:
                self.record_warn(
                    _SITE_RUNNER_DEGRADED,
                    "RUNNER_CONFIG_FORBIDDEN",
                    f"Runner config inaccessible for {full_name}: {exc.body[:120]}",
                )
                runners = []
            else:
                raise
        runner_uuid_by_id: dict[int, Any] = {}
        for rn in runners:
            rn_uuid = runner_id(full_name, rn["id"])
            runner_uuid_by_id[rn["id"]] = rn_uuid
            rn_display_name = rn.get("name") or str(rn["id"])
            nodes.append(
                node_envelope(
                    entity_id=rn_uuid,
                    entity_type="github_core__github_runner",
                    name=rn_display_name,
                    dimensions=actions_dims,
                    fields={
                        "full_name": full_name,
                        "runner_id": rn["id"],
                        "name": rn_display_name,
                        "os": rn.get("os", ""),
                        "status": rn.get("status", ""),
                        "busy": bool(rn.get("busy", False)),
                        "labels": [
                            lab.get("name") if isinstance(lab, dict) else lab
                            for lab in rn.get("labels", [])
                        ],
                        "configuration": {},
                        "tags": {},
                    },
                )
            )

        # The runs in this batch, indexed for the OUTPUT edges below and for the packages pass
        # after the walk. `run_id` is what an artifact names; `head_sha`/`head_branch`/`event`
        # are what a release or an image tag can be matched against.
        run_index = [
            {
                "run_id": r["id"],
                "uuid": run_id(full_name, r["id"]),
                "head_sha": str(r.get("head_sha") or ""),
                "head_branch": str(r.get("head_branch") or ""),
                "event": str(r.get("event") or ""),
            }
            for r in run_payloads
        ]
        self._run_index[full_name] = run_index

        # --- outputs (github-core#31): what the pipeline PRODUCES. Each surface reports one of
        # three states onto the repository node — observed, or unobservable with the reason —
        # because a view that reads only the output nodes cannot tell "none" from "could not look".
        outputs: dict[str, Any] = {"notes": {}}
        outputs["releases"] = self._collect_releases(
            full_name,
            repo_uuid,
            {
                **repo_dims,
                "github.surface": "releases",
                "github.observation": "execution",
            },
            ref_uuid_by_ref,
            run_index,
            nodes,
            edges,
            outputs["notes"],
        )
        outputs["artifacts"] = self._collect_artifacts(
            client,
            full_name,
            repo_uuid,
            observation_dims,
            run_index,
            nodes,
            edges,
            outputs["notes"],
        )
        repo_envelope["node"]["outputs_observability"] = outputs

        # stored cache entries (REST; graceful-degrade like runners). Observation dimensions:
        # a cache entry is something that HAPPENED, not something declared.
        self._collect_caches(
            client,
            full_name,
            repo_uuid,
            observation_dims,
            ref_uuid_by_ref,
            nodes,
            edges,
        )
        # Bypass EVENTS. Deliberately after refs: EVALUATED_ON resolves against ref_uuid_by_ref,
        # and a suite naming a ref we did not collect simply carries no edge.
        self._collect_rule_suites(
            client, full_name, observation_dims, ref_uuid_by_ref, nodes, edges
        )
        # Code-scanning alerts and analyses (req-github-core-code-scanning). After the workflow
        # walk and the refs/commits, because a finding in a workflow file joins to that workflow
        # by path and an analysis joins to its commit only when that commit is in this batch.
        self._collect_code_scanning(
            client,
            full_name,
            repo_uuid,
            repo_envelope,
            {**repo_dims, "github.surface": "security", "github.observation": "execution"},
            nodes,
            edges,
        )

        # EXECUTED_ON_RUNNER edges (only when an observed job runner_id matches a durable runner node).
        # Reuses the job payloads collected above — the runner nodes simply were not known yet
        # when the jobs were first walked, which is an ordering constraint, not a reason to fetch
        # them again.
        for r in run_payloads:
            for j in jobs_by_run.get(r["id"], []):
                if j.get("runner_id") and j["runner_id"] in runner_uuid_by_id:
                    j_uuid = job_id(full_name, j["id"])
                    rn_uuid = runner_uuid_by_id[j["runner_id"]]
                    edges.append(
                        self._edge(
                            "EXECUTED_ON_RUNNER__github_core",
                            j_uuid,
                            rn_uuid,
                            observation_dims,
                        )
                    )

    # ---------- helpers ----------

    # ---------- configuration-layer emitters ----------

    def _emit_run_with_jobs(
        self,
        client: GithubClient,
        full_name: str,
        r: dict[str, Any],
        observation_dims: dict[str, str],
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Emit one run node, its latest-attempt job nodes, and the edges between them.

        The jobs are fetched FIRST (latest-attempt endpoint per
        req-github-core-collector-8) because the run's end time is derived from
        them — see `_run_completed_at` (github-core#46). Returns the job payloads
        (empty when the endpoint degraded) so the caller can hold them for the
        EXECUTED_ON_RUNNER pass without a second walk.

        Args:
            client: The REST client for this collection.
            full_name: `owner/repo` of the run's repository.
            r: The run payload as GitHub returned it.
            observation_dims: Dimensions stamped on every execution node.
            nodes: Node envelopes to append to.
            edges: Edge envelopes to append to.

        Returns:
            The run's job payloads; `[]` when they were not observable.
        """
        run_uuid = run_id(full_name, r["id"])
        wf_ref_uuid = (
            workflow_id(full_name, r["workflow_id"]) if r.get("workflow_id") else None
        )
        jobs = self._fetch_run_jobs(client, full_name, r["id"])
        completed_at, completed_at_source = self._run_completed_at(r, jobs)
        nodes.append(
            node_envelope(
                entity_id=run_uuid,
                entity_type="github_core__github_actions_run",
                name=f"Run #{r.get('run_number', r['id'])}",
                dimensions=observation_dims,
                fields={
                    "full_name": full_name,
                    "run_id": r["id"],
                    "run_number": r.get("run_number"),
                    "event": r.get("event", ""),
                    "status": r.get("status", ""),
                    "conclusion": r.get("conclusion") or "",
                    "head_sha": r.get("head_sha", ""),
                    "head_branch": r.get("head_branch", ""),
                    "created_at": r.get("created_at"),
                    "run_started_at": r.get("run_started_at"),
                    "completed_at": completed_at,
                    "run_attempt": r.get("run_attempt"),
                    # Logins only (github-core#47): the actor objects carry avatar URLs, node
                    # ids and a dozen API links — the login is the join key and the answer.
                    "actor_login": _login_of(r.get("actor")),
                    "triggering_actor_login": _login_of(r.get("triggering_actor")),
                    "html_url": r.get("html_url", ""),
                    "configuration": {
                        "workflow_id": r.get("workflow_id"),
                        "raw_payload_keys": sorted(r.keys()),
                        "completed_at_source": completed_at_source,
                    },
                    "tags": {},
                },
            )
        )
        if wf_ref_uuid is not None:
            edges.append(
                self._edge(
                    "EXECUTES_WORKFLOW__github_core",
                    run_uuid,
                    wf_ref_uuid,
                    observation_dims,
                )
            )

        for j in jobs or []:
            j_uuid = job_id(full_name, j["id"])
            j_display_name = j.get("name") or str(j["id"])
            nodes.append(
                node_envelope(
                    entity_id=j_uuid,
                    entity_type="github_core__github_actions_job",
                    name=j_display_name,
                    dimensions=observation_dims,
                    fields={
                        "full_name": full_name,
                        "job_id": j["id"],
                        "name": j_display_name,
                        "status": j.get("status", ""),
                        "conclusion": j.get("conclusion") or "",
                        "created_at": j.get("created_at"),
                        "started_at": j.get("started_at"),
                        "completed_at": j.get("completed_at"),
                        "html_url": j.get("html_url", ""),
                        "configuration": {
                            "runner_id": j.get("runner_id"),
                            "runner_name": j.get("runner_name"),
                            "runner_group_id": j.get("runner_group_id"),
                            "labels": j.get("labels") or [],
                            "steps": j.get("steps") or [],
                        },
                        "tags": {},
                    },
                )
            )
            edges.append(
                self._edge("RUNS_JOB__github_core", run_uuid, j_uuid, observation_dims)
            )
        return jobs or []

    @staticmethod
    def _run_completed_at(
        r: dict[str, Any], jobs: list[dict[str, Any]] | None
    ) -> tuple[str | None, str]:
        """Establish a run's end time honestly (github-core#46).

        GitHub's run payload carries no `completed_at`. Its `updated_at` moves on
        re-run, on artifact and log events and on check-suite updates, so a run
        that was touched later reads as having taken hours. The end the run
        actually had is the latest `completed_at` over its jobs.

        Three states, never two — the second element names which one applies:

        - `COMPLETED_AT_FROM_JOBS`: derived, `max(job.completed_at)` over the
          collected latest-attempt jobs.
        - `COMPLETED_AT_FROM_UPDATED_AT`: approximated from the payload's
          `updated_at`, because the run is complete but its end was not
          observable from the jobs: the jobs endpoint degraded, the run has no
          jobs (a skipped run), or the listing still carried a job without a
          parseable end — the listing is eventually consistent, and a maximum
          over the jobs that HAVE finished would understate the run. An upper
          bound, not a measurement.
        - `COMPLETED_AT_IN_FLIGHT`: null, because the run has not reached a
          terminal status. No end time exists yet; a partial `max` over the jobs
          that have finished would be a lie.

        Args:
            r: The run payload as GitHub returned it.
            jobs: The run's job payloads, or `None` when they were not observable.

        Returns:
            `(completed_at, source)` — the ISO timestamp (or `None`) and the
            source label recorded beside it in `configuration.completed_at_source`.
        """
        if r.get("status") not in _TERMINAL_RUN_STATUSES:
            return None, COMPLETED_AT_IN_FLIGHT
        ends: list[tuple[datetime, str]] = []
        for j in jobs or []:
            parsed = _iso_datetime(j.get("completed_at"))
            if parsed is None:
                # One job without a usable end makes the whole listing a non-measurement.
                ends = []
                break
            ends.append((parsed, j["completed_at"]))
        if ends:
            return max(ends)[1], COMPLETED_AT_FROM_JOBS
        return r.get("updated_at"), COMPLETED_AT_FROM_UPDATED_AT

    def _emit_refs(
        self,
        full_name: str,
        repo_uuid: Any,
        git_repo_uuid: Any,
        repository_github_id: int | str | None,
        repo_dims: dict[str, str],
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Emit every branch and tag as a neutral `git_core__git_ref`, returning ``{ref_path: uuid}``.

        The ref belongs to the neutral repository (`DECLARES_REF__git_core` from `git_repo_uuid`,
        identity = repository id + full path via git_core's helper), never to the hosting record;
        `repo_uuid` (the hosting record) is what the commit OBSERVATION is scoped to. Without a
        neutral repository (no stable id) nothing is emitted, and the run said so.

        The returned map is what makes ruleset resolution and cache scoping possible without a
        second lookup — both need to know whether a ref named elsewhere is one we actually saw.

        Tag-movement detection is not implemented here and does not need to be: the ref's
        `head_sha` is a field on a node with a deterministic id, so the grid's own field history
        records the move. Detection is a query over history, not a diff the collector keeps.
        """
        gql = self._config.get(full_name)
        if not gql or git_repo_uuid is None or repository_github_id is None:
            # A repos-only scope runs no GraphQL enumeration, and a record without a stable id
            # has no neutral repository to hang refs off. Refs are config-layer data and are
            # simply not collected in that form — stated rather than silently empty.
            return {}
        # `github.surface: git` is retired (github-core#168): it existed only to mark
        # github's write to the neutral layer, and the neutral layer no longer carries
        # github's vocabulary at all. What github OBSERVED about a commit is scoped like
        # any other github record; what it MINTED on the neutral layer carries `git.host`.
        git_dims = dict(repo_dims)
        neutral_dims = {"git.host": repo_dims["git.host"]}
        refs, truncated = GithubGraphQLClient.refs(gql)
        uuid_by_ref: dict[str, Any] = {}
        for ref in refs:
            ref_uuid = git_ref_id(git_repo_uuid, ref["ref"])
            uuid_by_ref[ref["ref"]] = ref_uuid
            if ref["is_default"]:
                self._default_refs.add(f"{full_name}#{ref['ref']}")
            # git_core requires the target's kind whenever a target is named. GitHub's
            # `__typename` supplies it when the query asked; when it did not, the peel says which:
            # a target that differs from the resolved commit is a tag object, otherwise the commit.
            target_type = ref["target_type"]
            if ref["target_sha"] and not target_type:
                target_type = (
                    "tag" if ref["target_sha"] != ref["head_sha"] else "commit"
                )
            nodes.append(
                node_envelope(
                    entity_id=ref_uuid,
                    entity_type="git_core__git_ref",
                    name=ref["name"],
                    dimensions=neutral_dims,
                    fields={
                        "ref": ref["ref"],
                        "ref_type": ref["ref_type"],
                        "name": ref["name"],
                        "head_sha": ref["head_sha"],
                        "target_sha": ref["target_sha"],
                        "target_type": target_type,
                        "is_default": ref["is_default"],
                        "configuration": {},
                        "tags": {},
                    },
                )
            )
            edges.append(
                self._edge(
                    "DECLARES_REF__git_core",
                    git_repo_uuid,
                    ref_uuid,
                    neutral_dims,
                )
            )
            self._emit_commit(
                full_name,
                ref.get("commit"),
                ref_uuid,
                git_repo_uuid,
                repo_uuid,
                repository_github_id,
                git_dims,
                neutral_dims,
                nodes,
                edges,
            )
        for ref_type, missing in sorted(truncated.items()):
            self.record_warn(
                _SITE_REFS_TRUNCATED,
                "REFS_TRUNCATED",
                f"{full_name}: {missing} {ref_type}(s) beyond the page cap were not collected. "
                f"Absence of a {ref_type} in this batch is NOT evidence it does not exist.",
                message_data={
                    "repo": full_name,
                    "ref_type": ref_type,
                    "missing": missing,
                },
            )
        return uuid_by_ref

    def _emit_commit(
        self,
        full_name: str,
        commit: dict[str, Any] | None,
        ref_uuid: Any,
        git_repo_uuid: Any,
        repo_uuid: Any,
        repository_github_id: int | str,
        git_dims: dict[str, str],
        neutral_dims: dict[str, str],
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
    ) -> None:
        """The commit at a ref's head, split into its two halves (github-core#76, rulings 0.1/0.2).

        The neutral `git_core__git_commit` carries what Git records — object id, dates, author
        and committer name and email — under the global identity `(hash_algorithm, oid)`, so the
        same commit observed from any host is ONE node; `STORES_COMMIT__git_core` from the neutral
        repository records that this repository holds it, `RESOLVES_COMMIT__git_core` from the ref
        records the peel. What GITHUB observed — the logins it resolved, its signature verdict —
        is the `github_core__commit_observation`, keyed on host + the repository's stable id +
        the commit identity, because the verification record is persisted per repository network
        and one network's verdict must never overwrite another's; `OBSERVES_COMMIT` links it to
        the commit, `OBSERVED_IN_REPOSITORY` to the hosting record.

        Nothing is emitted when the ref carried no commit slice: a config layer whose commit
        fields were degraded yields refs without commits — a node full of empty strings would read
        as an unsigned commit by someone nobody could name.
        """
        if not commit:
            return
        oid = str(commit["sha"]).lower()
        hash_algorithm = next(
            (algo for algo, n in OID_LENGTH.items() if n == len(oid)), "sha1"
        )
        commit_uuid = git_commit_id(hash_algorithm, oid)
        # Run-wide index of every commit this run emitted, so a later surface naming a sha
        # (a code-scanning analysis) can join ONLY to a commit that is in the batch.
        self._commits_seen()[oid] = commit_uuid
        nodes.append(
            node_envelope(
                entity_id=commit_uuid,
                entity_type="git_core__git_commit",
                name=oid[:12],
                dimensions=neutral_dims,
                fields={
                    "hash_algorithm": hash_algorithm,
                    "oid": oid,
                    "authored_date": commit.get("authored_date"),
                    "committed_date": commit.get("committed_date"),
                    "author_name": commit.get("author_name", ""),
                    "author_email": commit.get("author_email", ""),
                    "committer_name": commit.get("committer_name", ""),
                    "committer_email": commit.get("committer_email", ""),
                },
            )
        )
        edges.append(
            self._edge(
                "STORES_COMMIT__git_core",
                git_repo_uuid,
                commit_uuid,
                neutral_dims,
            )
        )
        edges.append(
            self._edge(
                "RESOLVES_COMMIT__git_core",
                ref_uuid,
                commit_uuid,
                neutral_dims,
            )
        )

        observation_uuid = commit_observation_id(
            git_dims["git.host"], repository_github_id, hash_algorithm, oid
        )
        nodes.append(
            node_envelope(
                entity_id=observation_uuid,
                entity_type="github_core__commit_observation",
                name=f"{full_name}@{oid[:12]}",
                dimensions=git_dims,
                fields={
                    "host": git_dims["git.host"],
                    "full_name": full_name,
                    "repository_github_id": (
                        int(repository_github_id)
                        if repository_github_id is not None
                        else None
                    ),
                    "hash_algorithm": hash_algorithm,
                    "sha": oid,
                    "author_login": commit.get("author_login", ""),
                    "committer_login": commit.get("committer_login", ""),
                    "signature_kind": commit.get("signature_kind", ""),
                    "signature_state": commit.get("signature_state", ""),
                    "signature_valid": commit.get("signature_valid"),
                    "signer_login": commit.get("signer_login", ""),
                    "signed_by_github": bool(commit.get("signed_by_github", False)),
                    "configuration": {},
                    "tags": {},
                },
            )
        )
        edges.append(
            self._edge(
                "OBSERVES_COMMIT__github_core", observation_uuid, commit_uuid, git_dims
            )
        )
        edges.append(
            self._edge(
                "OBSERVED_IN_REPOSITORY__github_core",
                observation_uuid,
                repo_uuid,
                git_dims,
            )
        )

    def _emit_pull_requests(
        self,
        full_name: str,
        repo_envelope: dict[str, Any],
        git_repo_uuid: Any,
        repo_dims: dict[str, str],
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
    ) -> None:
        """Emit the repository's pull requests with the check rollup on each head commit.

        A pull request is a forge object wrapped around a branch and a commit (github-core#82):
        the node is GitHub's, keyed on the base repository plus the number, and its edges point
        at git_core's neutral ref and commit — `PROPOSES_REF` (head, only when the head lives in
        this repository), `TARGETS_BASE_REF` (base) and `PROPOSES_COMMIT` (head commit). The ids
        are computed from the names; an endpoint that was not observed in this batch leaves the
        edge dangling and `_drop_dangling_edges` removes it, so `head_sha` on the node is the fact
        and the edge is the join when both ends were seen.

        Three states on the repository node. `observed`: the pull-request layer answered
        `pullRequests`, so zero rows is a fact. `unobservable`: the field degraded (pruned by
        `prune_errored_paths`) or the layer's query failed, so no row means nothing. `""`: a
        repos-only scope runs no account query — never asked. The cap is visible as
        `pull_requests_total` beside the rows and warned per repository, so a window of thirty is
        never read as all of them.
        """
        node = repo_envelope["node"]
        gql = self._config.get(full_name)
        if not gql:
            return
        parsed = GithubGraphQLClient.pull_requests(gql)
        if parsed is None:
            node["pull_requests_observability"] = _UNOBSERVABLE
            self.record_warn(
                _SITE_PULL_REQUESTS_UNOBSERVABLE,
                "PULL_REQUESTS_UNOBSERVABLE",
                f"{full_name}: the config-layer query did not answer the pullRequests field — pull "
                f"requests NOT observed, which is not the same as none being open.",
                message_data={"repo": full_name},
            )
            return
        pulls, missing = parsed
        node["pull_requests_observability"] = _OBSERVED
        node["pull_requests_total"] = len(pulls) + missing
        pulls_dims = {**repo_dims, "github.surface": "pulls", "github.observation": "execution"}
        by_state: dict[str, int] = {}
        checks_truncated = 0
        checks_unobservable = 0
        lists_truncated_count = 0
        for pr in pulls:
            number = pr.get("number")
            if number is None:
                continue
            pr_uuid = pull_request_id(full_name, number)
            checks_total = pr.pop("checks_total", None)
            if checks_total is not None and checks_total > len(pr["checks"]):
                checks_truncated += 1
            if pr["checks_observability"] == _UNOBSERVABLE:
                checks_unobservable += 1
            # The three capped lists: GitHub's count beside what the page held, and one flag a
            # consumer can read before trusting `review_requests` as everyone who was asked.
            list_totals = {
                key: pr.pop(f"{key}_total", None) for key in ("labels", "review_requests", "latest_reviews")
            }
            lists_truncated = any(
                total is not None and total > len(pr[key]) for key, total in list_totals.items()
            )
            if lists_truncated:
                lists_truncated_count += 1
            by_state[pr["state"]] = by_state.get(pr["state"], 0) + 1
            fields = {
                **pr,
                "full_name": full_name,
                "configuration": {
                    # The rollup's own count, so a matrix wider than the page shows as a gap.
                    "checks_total": checks_total,
                    "checks_truncated": checks_total is not None and checks_total > len(pr["checks"]),
                    "labels_total": list_totals["labels"],
                    "review_requests_total": list_totals["review_requests"],
                    "latest_reviews_total": list_totals["latest_reviews"],
                    "lists_truncated": lists_truncated,
                },
                "tags": {},
            }
            nodes.append(
                node_envelope(
                    entity_id=pr_uuid,
                    entity_type=PullRequest.ENTITY_TYPE,
                    name=f"{full_name}#{number}",
                    dimensions=pulls_dims,
                    fields=fields,
                )
            )
            self._emit_pull_request_author(pr, pr_uuid, pulls_dims, nodes, edges)
            if git_repo_uuid is not None:
                if pr["head_ref"] and pr["head_repository"] == full_name:
                    edges.append(
                        self._edge(
                            "PROPOSES_REF__github_core",
                            pr_uuid,
                            git_ref_id(git_repo_uuid, f"refs/heads/{pr['head_ref']}"),
                            pulls_dims,
                            properties={"ref_name": pr["head_ref"]},
                        )
                    )
                if pr["base_ref"]:
                    edges.append(
                        self._edge(
                            "TARGETS_BASE_REF__github_core",
                            pr_uuid,
                            git_ref_id(git_repo_uuid, f"refs/heads/{pr['base_ref']}"),
                            pulls_dims,
                            properties={"ref_name": pr["base_ref"]},
                        )
                    )
            if pr["head_sha"]:
                algorithm = next((algo for algo, n in OID_LENGTH.items() if n == len(pr["head_sha"])), "sha1")
                edges.append(
                    self._edge(
                        "PROPOSES_COMMIT__github_core",
                        pr_uuid,
                        git_commit_id(algorithm, pr["head_sha"]),
                        pulls_dims,
                    )
                )
        if missing:
            self.record_warn(
                _SITE_PULL_REQUESTS_TRUNCATED,
                "PULL_REQUESTS_TRUNCATED",
                f"{full_name}: {missing} pull request(s) beyond the most-recently-updated window were "
                f"not collected. Absence of a pull request in this batch is NOT evidence it does not exist.",
                message_data={"repo": full_name, "missing": missing, "collected": len(pulls)},
            )
        if checks_unobservable:
            self.record_warn(
                _SITE_PULL_REQUEST_CHECKS_UNOBSERVABLE,
                "PULL_REQUEST_CHECKS_UNOBSERVABLE",
                f"{full_name}: the check rollup could not be read for {checks_unobservable} pull request(s) — "
                f"their build status is NOT observed, which is not the same as nothing having run; "
                f"`checks_observability` says so on each.",
                message_data={"repo": full_name, "pull_requests": checks_unobservable},
            )
        if lists_truncated_count:
            self.record_warn(
                _SITE_PULL_REQUEST_LISTS_TRUNCATED,
                "PULL_REQUEST_LISTS_TRUNCATED",
                f"{full_name}: {lists_truncated_count} pull request(s) carry more labels, review requests or "
                f"reviews than the page of ten returned; `configuration.lists_truncated` says so on each, and "
                f"`review_requests` is then NOT everyone who was asked.",
                message_data={"repo": full_name, "pull_requests": lists_truncated_count},
            )
        if checks_truncated:
            self.record_warn(
                _SITE_PULL_REQUEST_CHECKS_TRUNCATED,
                "PULL_REQUEST_CHECKS_TRUNCATED",
                f"{full_name}: {checks_truncated} pull request(s) carry more checks than the page returned; "
                f"their `checks` list is incomplete and says so in `configuration.checks_truncated`.",
                message_data={"repo": full_name, "pull_requests": checks_truncated},
            )
        self.record_info(
            _SITE_PULL_REQUESTS_COLLECTED,
            "PULL_REQUESTS_COLLECTED",
            f"{full_name}: {len(pulls)} of {len(pulls) + missing} pull request(s) collected "
            + ", ".join(f"{n} {state.lower()}" for state, n in sorted(by_state.items()))
            + ".",
            message_data={"repo": full_name, "collected": len(pulls), "total": len(pulls) + missing, "by_state": by_state},
        )

    def _emit_pull_request_author(
        self,
        pr: dict[str, Any],
        pr_uuid: Any,
        dims: dict[str, str],
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
    ) -> None:
        """`OPENS_PULL_REQUEST` from the author — an account, or an App when GitHub says `Bot`.

        A Bot actor's login is the App's slug (`renovate`, `dependabot`), so it joins the same
        `github_app` node the installation inventory mints. A user is an ACCOUNT, minted like a
        rule-suite actor: GitHub reports the login, never what kind of principal holds it.
        """
        login = pr["author_login"]
        if not login:
            return
        properties = {"author_association": pr["author_association"]}
        if pr["author_type"] == "Bot":
            app_uuid = github_app_id(login)
            if str(app_uuid) not in self._emitted_app_ids:
                self._emitted_app_ids.add(str(app_uuid))
                nodes.append(
                    node_envelope(
                        entity_id=app_uuid,
                        entity_type="github_core__github_app",
                        name=login,
                        dimensions={**_PLATFORM_DIMENSIONS, "github.surface": "apps"},
                        fields={
                            "slug": login,
                            "name": login,
                            "app_id": None,
                            "client_id": "",
                            "html_url": f"https://github.com/apps/{login}",
                            "description": "",
                            "configuration": {},
                            "tags": {},
                        },
                    )
                )
            edges.append(self._edge("OPENS_PULL_REQUEST__github_core", app_uuid, pr_uuid, dims, properties=properties))
            return
        actor_uuid = account_id(login)
        if login not in self._emitted_actor_logins:
            self._emitted_actor_logins.add(login)
            nodes.append(
                node_envelope(
                    entity_id=actor_uuid,
                    entity_type="github_core__github_account",
                    name=login,
                    dimensions={**_PLATFORM_DIMENSIONS, "github.surface": "accounts"},
                    fields={
                        "login": login,
                        "github_id": None,
                        # GitHub's actor kind (`User`, `Organization`, `Mannequin`) is what it said,
                        # which is more than the rule-suite surface reports — and still not identity.
                        "account_type": pr["author_type"],
                        "html_url": f"https://github.com/{login}",
                        "configuration": {},
                        "tags": {},
                    },
                )
            )
        edges.append(self._edge("OPENS_PULL_REQUEST__github_core", actor_uuid, pr_uuid, dims, properties=properties))

    def _emit_rulesets(
        self,
        client: GithubClient,
        full_name: str,
        repo_uuid: Any,
        repo_dims: dict[str, str],
        ref_uuid_by_ref: dict[str, Any],
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
    ) -> None:
        """Emit the rulesets gating this repository, and what may bypass them.

        Two transports, because neither is sufficient alone. GraphQL says which rulesets apply to
        this repository and answers `bypassActors`; REST's ruleset detail is the only place the
        rules' PARAMETERS live (the required check names the gate view needs), and whether it
        carries a `bypass_actors` key at all is how we learn the credential could really see one.
        """
        gql = self._config.get(full_name)
        if not gql:
            return
        owner = full_name.partition("/")[0]
        # Deliberately NOT repo-scoped. One organization ruleset is a single node protecting many
        # repositories, and a `github.repo` dimension on it would name whichever repo happened to
        # emit it last — an assertion the node has no business making. The repository association
        # is the PROTECTS edge, which IS repo-scoped.
        ruleset_dims = {
            "git.host": repo_dims["git.host"],
            "github.owner": owner,
            "github.surface": "rules",
        }
        rules_dims = {**repo_dims, "github.surface": "rules"}
        for ruleset in GithubGraphQLClient.rulesets(gql):
            rid = ruleset["ruleset_id"]
            if rid is None:
                continue
            rs_uuid = ruleset_id(owner, rid)
            detail = self._ruleset_detail(client, full_name, rid)
            observability = self._bypass_observability(ruleset, detail)
            # When the answer is unreadable, say WHY in the operator's terms. "No token placed",
            # "a token is placed but was refused", and "the token answered but GitHub still
            # withheld the list" are three different situations with three different fixes, and
            # collapsing them into one blank is how a gap stops being actionable.
            absent_note = (
                self._bypass_absent_note()
                if observability["state"] == "unobservable"
                else ""
            )
            nodes.append(
                node_envelope(
                    entity_id=rs_uuid,
                    entity_type="github_core__github_ruleset",
                    name=ruleset["name"],
                    dimensions=ruleset_dims,
                    fields={
                        "owner_login": owner,
                        "ruleset_id": rid,
                        "name": ruleset["name"],
                        "target": ruleset["target"],
                        "enforcement": ruleset["enforcement"],
                        "source": str((detail or {}).get("source") or owner),
                        "source_type": str((detail or {}).get("source_type") or ""),
                        "conditions": ruleset["conditions"],
                        # REST detail carries each rule's parameters (the required check contexts
                        # among them); GraphQL gives only the rule TYPE, and a gate view that knows
                        # a repository requires *some* status check but not *which* is not a gate
                        # view. Fall back to the type-only list rather than to nothing.
                        "rules": list((detail or {}).get("rules") or ruleset["rules"]),
                        "bypass_observability": observability["state"],
                        "bypass_actor_count": observability["count"],
                        "html_url": str(
                            ((detail or {}).get("_links") or {})
                            .get("html", {})
                            .get("href")
                            or ""
                        ),
                        "configuration": {
                            "current_user_can_bypass": (detail or {}).get(
                                "current_user_can_bypass"
                            ),
                            "bypass_source": observability["source"],
                            "bypass_actors_unmodelled": observability["unmodelled"],
                            "bypass_absent_note": absent_note,
                        },
                        "tags": {},
                    },
                )
            )
            edges.append(
                edge_envelope(
                    entity_id=edge_id(
                        "PROTECTS_REPOSITORY__github_core", rs_uuid, repo_uuid
                    ),
                    edge_type="PROTECTS_REPOSITORY__github_core",
                    source_id=rs_uuid,
                    target_id=repo_uuid,
                    dimensions=rules_dims,
                    properties={},
                )
            )
            self._emit_protected_refs(
                ruleset, rs_uuid, full_name, ref_uuid_by_ref, rules_dims, edges
            )
            self._emit_bypass_edges(
                ruleset, rs_uuid, observability, rules_dims, nodes, edges
            )
            self._register_required_checks(
                owner,
                rs_uuid,
                ruleset["name"],
                list((detail or {}).get("rules") or ruleset["rules"]),
                ruleset_dims,
            )
            if observability["state"] == "unobservable":
                self.record_warn(
                    _SITE_RULESET_BYPASS_UNOBSERVABLE,
                    "RULESET_BYPASS_UNOBSERVABLE",
                    f"{full_name}: ruleset {ruleset['name']!r} — the bypass list is unreadable. An "
                    f"empty 'who can bypass' cell for it means UNKNOWN, not none."
                    + (f" Note: {absent_note}." if absent_note else ""),
                    message_data={
                        "repo": full_name,
                        "ruleset": ruleset["name"],
                        "ruleset_id": rid,
                        "absent_note": absent_note,
                    },
                )

    def _emit_protected_refs(
        self,
        ruleset: dict[str, Any],
        rs_uuid: Any,
        full_name: str,
        ref_uuid_by_ref: dict[str, Any],
        dims: dict[str, str],
        edges: list[dict[str, Any]],
    ) -> None:
        """Resolve the ruleset's ref patterns against refs actually observed, one edge each.

        Resolution is additive to the declared edge, never a replacement: the patterns are kept
        verbatim on the node because they are the intent, and these edges are what that intent
        turned out to cover on the day it was collected. A pattern matching nothing is a real
        answer (a ruleset protecting a branch that does not exist), not a failure.
        """
        ref_type = _REF_TYPE_BY_RULESET_TARGET.get(ruleset["target"])
        if ref_type is None:
            return
        conditions = (ruleset.get("conditions") or {}).get("ref_name") or {}
        include = list(conditions.get("include") or [])
        exclude = list(conditions.get("exclude") or [])
        for ref_path, ref_uuid in sorted(ref_uuid_by_ref.items()):
            if not ref_path.startswith(
                "refs/heads/" if ref_type == "branch" else "refs/tags/"
            ):
                continue
            is_default = self._is_default_ref(full_name, ref_path)
            pattern = self._matching_pattern(ref_path, include, is_default)
            if pattern is None or self._matching_pattern(ref_path, exclude, is_default):
                continue
            edges.append(
                edge_envelope(
                    entity_id=edge_id("PROTECTS_REF__github_core", rs_uuid, ref_uuid),
                    edge_type="PROTECTS_REF__github_core",
                    source_id=rs_uuid,
                    target_id=ref_uuid,
                    dimensions=dims,
                    properties={"ref_pattern": pattern},
                )
            )

    def _is_default_ref(self, full_name: str, ref_path: str) -> bool:
        """Whether this ref is ITS OWN repository's default branch, per the config layer."""
        return f"{full_name}#{ref_path}" in self._default_refs

    @staticmethod
    def _matching_pattern(
        ref_path: str, patterns: list[str], is_default: bool
    ) -> str | None:
        """The first pattern that selects ``ref_path``, or None.

        GitHub's condition tokens are matched as tokens, not as text: `~DEFAULT_BRANCH` names
        whichever branch is default today, and `~ALL` matches everything of the ruleset's target
        type. Everything else is an fnmatch pattern over the full ref path.
        """
        for pattern in patterns:
            if pattern == _REF_TOKEN_ALL:
                return pattern
            if pattern == _REF_TOKEN_DEFAULT_BRANCH:
                if is_default:
                    return pattern
                continue
            if fnmatch.fnmatch(ref_path, pattern):
                return pattern
        return None

    def _bypass_absent_note(self) -> str:
        """Why the bypass list could not be read, phrased as something an operator can act on."""
        if not self._auth.has_pat:
            return self._auth.absent_note(PREFER_PAT)
        if self._pat_ruleset_status.startswith("refused"):
            return (
                f"a personal access token is placed but the ruleset endpoint {self._pat_ruleset_status} "
                f"it — it has expired, or its resource owner is not this account"
            )
        return (
            "the personal access token placed does not have write access to this ruleset, which is "
            "what GitHub requires before it will disclose bypass actors at all"
        )

    @staticmethod
    def _bypass_observability(
        ruleset: dict[str, Any], detail: dict[str, Any] | None
    ) -> dict[str, Any]:
        """Decide whether the bypass list was actually READ, and by which transport.

            observable = REST carried the key  OR  GraphQL returned a non-empty list

        The asymmetry is the point (`spec-github-core-vocabulary.md`, open question 3). GitHub
        returns bypass actors only to a caller with write access to the ruleset: REST then omits
        the key entirely, while GraphQL answers with an empty connection and no error. A non-empty
        GraphQL answer proves itself — a filtered connection cannot invent actors — but an empty
        one proves nothing, and rendering it as "nobody can bypass" would tell an organization the
        single most reassuring thing it could hear on no evidence at all.
        """
        rest_actors = (detail or {}).get("bypass_actors")
        graphql_actors = list(ruleset.get("bypass_actors") or [])
        if rest_actors is not None:
            return {
                "state": "observed",
                "count": len(rest_actors),
                "source": "rest_ruleset_detail",
                "actors": [],
                "unmodelled": list(rest_actors),
            }
        if graphql_actors:
            modelled, unmodelled = GithubCollector._split_bypass_actors(graphql_actors)
            return {
                "state": "observed",
                "count": len(graphql_actors),
                "source": "graphql_bypass_actors",
                "actors": modelled,
                "unmodelled": unmodelled,
            }
        return {
            "state": "unobservable",
            "count": None,
            "source": "",
            "actors": [],
            "unmodelled": [],
        }

    @staticmethod
    def _split_bypass_actors(
        actors: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Split bypass actors into the ones this vocabulary has a node for, and the rest.

        Apps have a node (`github_app`, keyed by slug). Teams and organization-admin roles do not
        yet — `github_team` is a later tier and "organization admins" is a role, not an actor. The
        ones without a node are kept as data on the ruleset with their count, because dropping
        them would understate who can bypass, which is the one direction that must never happen.
        """
        modelled: list[dict[str, Any]] = []
        unmodelled: list[dict[str, Any]] = []
        for actor in actors:
            body = actor.get("actor") or {}
            if str(body.get("__typename")) == "App" and body.get("slug"):
                modelled.append(
                    {
                        "slug": str(body["slug"]),
                        "name": str(body.get("name") or body["slug"]),
                        "app_id": body.get("databaseId"),
                        "bypass_mode": str(actor.get("bypassMode") or "").lower(),
                    }
                )
                continue
            unmodelled.append(
                {
                    "actor_type": str(
                        body.get("__typename")
                        or (
                            "OrganizationAdmin"
                            if actor.get("organizationAdmin")
                            else ""
                        )
                    ),
                    "name": str(
                        body.get("slug")
                        or body.get("name")
                        or actor.get("repositoryRoleName")
                        or ""
                    ),
                    "bypass_mode": str(actor.get("bypassMode") or "").lower(),
                }
            )
        return modelled, unmodelled

    def _emit_bypass_edges(
        self,
        ruleset: dict[str, Any],
        rs_uuid: Any,
        observability: dict[str, Any],
        dims: dict[str, str],
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
    ) -> None:
        """Emit one EXEMPTS_ACTOR edge per actor we can name, and say what we could not name."""
        for actor in observability["actors"]:
            app_uuid = github_app_id(actor["slug"])
            if str(app_uuid) not in self._emitted_app_ids:
                self._emitted_app_ids.add(str(app_uuid))
                nodes.append(
                    node_envelope(
                        entity_id=app_uuid,
                        entity_type="github_core__github_app",
                        name=actor["name"],
                        dimensions={**dims, "github.surface": "apps"},
                        fields={
                            "slug": actor["slug"],
                            "name": actor["name"],
                            "app_id": actor.get("app_id"),
                            "client_id": "",
                            "html_url": f"https://github.com/apps/{actor['slug']}",
                            "description": "",
                            "configuration": {},
                            "tags": {},
                        },
                    )
                )
            edges.append(
                edge_envelope(
                    # Ruleset -> actor. The exemption is something the RULESET declares
                    # (it is an entry in its own bypass_actors list); nobody initiates a
                    # permission, so the declaring object is the source.
                    entity_id=edge_id("EXEMPTS_ACTOR__github_core", rs_uuid, app_uuid),
                    edge_type="EXEMPTS_ACTOR__github_core",
                    source_id=rs_uuid,
                    target_id=app_uuid,
                    dimensions=dims,
                    properties={
                        "actor_type": "Integration",
                        "bypass_mode": actor["bypass_mode"],
                        "observable": True,
                        "source": observability["source"],
                    },
                )
            )
        if observability["unmodelled"]:
            self.record_warn(
                _SITE_BYPASS_ACTOR_UNMODELLED,
                "BYPASS_ACTOR_UNMODELLED",
                f"Ruleset {ruleset['name']!r}: {len(observability['unmodelled'])} bypass actor(s) "
                f"have no node type yet (teams, org-admin roles) — counted on the ruleset, not "
                f"dropped.",
                message_data={
                    "ruleset": ruleset["name"],
                    "actors": observability["unmodelled"],
                },
            )

    def _ruleset_detail(
        self, client: GithubClient, full_name: str, rid: int
    ) -> dict[str, Any] | None:
        """REST ruleset detail, fetched once per ruleset per run and cached.

        One organization ruleset applies to every repository it matches, so without the cache this
        would be the same call once per repository. Degrades to None rather than failing the repo:
        the GraphQL side already carries enough to emit the node, just without rule parameters.
        """
        owner = full_name.partition("/")[0]
        cache_key = (owner, rid)
        if cache_key in self._ruleset_details:
            return self._ruleset_details[cache_key]
        # The PAT-bound client when the envelope carries one: this single call is the only place
        # a token sees more than the App does.
        detail_client = self._pat_client or client
        try:
            detail = detail_client.get(f"/repos/{full_name}/rulesets/{rid}")
        except GithubAPIError as exc:
            if self._pat_client is not None:
                self._pat_ruleset_status = f"refused ({exc.status})"
            self.record_warn(
                _SITE_RULESET_DETAIL_DEGRADED,
                f"RULESET_DETAIL_{exc.status}",
                f"{full_name}: ruleset {rid} detail unreadable ({exc.status}); rule parameters "
                f"(including required check names) are missing for it.",
                message_data={
                    "repo": full_name,
                    "ruleset_id": rid,
                    "status": exc.status,
                },
            )
            detail = None
        else:
            if self._pat_client is not None:
                self._pat_ruleset_status = "answered"
        self._ruleset_details[cache_key] = detail
        return detail

    def _emit_environments(
        self,
        full_name: str,
        repo_uuid: Any,
        repo_dims: dict[str, str],
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
        client: GithubClient | None = None,
    ) -> dict[str, Any]:
        """Emit deployment environments, returning ``{name: uuid}`` for the declared jobs to use.

        The config layer names the environment and its protection-rule TYPES; the REST detail
        (`GET /repos/{r}/environments/{name}`, req-github-core-settings-4) adds who the required
        reviewers are, whether admins may bypass, and the deployment branch policy. One call per
        environment; a refusal leaves the three fields null and says so on the node.
        """
        gql = self._config.get(full_name)
        if not gql:
            return {}
        deploy_dims = {**repo_dims, "github.surface": "deployments"}
        uuid_by_name: dict[str, Any] = {}
        refused: list[tuple[str, int]] = []
        for env in GithubGraphQLClient.environments(gql):
            name = env["name"]
            if not name:
                continue
            env_uuid = environment_id(full_name, name)
            uuid_by_name[name] = env_uuid
            detail = self._fetch_environment_detail(client, full_name, name)
            if isinstance(detail, int):
                refused.append((name, detail))
                detail = None
            nodes.append(
                node_envelope(
                    entity_id=env_uuid,
                    entity_type="github_core__github_environment",
                    name=name,
                    dimensions=deploy_dims,
                    fields={
                        "full_name": full_name,
                        "environment_id": env["environment_id"],
                        "name": name,
                        "protection_rules": env["protection_rules"],
                        # Null (unobserved) unless the REST detail answered — never defaulted to
                        # "none", which would assert an absence this transport never looked for.
                        "deployment_branch_policy": (
                            detail.get("deployment_branch_policy") if detail else None
                        ),
                        "can_admins_bypass": detail.get("can_admins_bypass") if detail else None,
                        "html_url": str(detail.get("html_url") or "") if detail else "",
                        "configuration": self._environment_configuration(detail, client),
                        "tags": {},
                    },
                )
            )
            edges.append(
                self._edge(
                    "DECLARES_ENVIRONMENT__github_core",
                    repo_uuid,
                    env_uuid,
                    deploy_dims,
                )
            )
        # The listing as a completeness surface of the repository (github-core#14 shape B). The
        # config query caps the connection at _ENVIRONMENT_PAGE_SIZE without a totalCount, so a
        # full page cannot say whether it was the last one; a degraded (pruned) field was refused.
        envs = GithubGraphQLClient.environments(gql)
        answered = "environments" in gql
        capped = answered and len(envs) >= _ENVIRONMENT_PAGE_SIZE
        env_reasons: dict[str, str] = {}
        if not answered:
            env_reasons["scope_authorized"] = "graphql_field_degraded: the credential could not read `environments`"
            env_reasons["enumeration_complete"] = "graphql_field_degraded: nothing was listed"
            env_reasons["admitted"] = "graphql_field_degraded: nothing to process"
        elif capped:
            env_reasons["enumeration_complete"] = (
                f"capped: the config query lists at most {_ENVIRONMENT_PAGE_SIZE} environments and reports no total"
            )
        first, last = self._listing_state()["config_interval"] or (datetime.now(UTC), datetime.now(UTC))
        self._note_listing(
            "repository.environments",
            "DECLARES_ENVIRONMENT__github_core",
            repo_uuid,
            first,
            last=last,
            complete=None if capped else answered,
            count=len(envs) if answered else None,
            authorized=answered,
            admitted=answered,
            reasons=env_reasons,
        )
        if refused:
            self.record_warn(
                _SITE_ENVIRONMENT_DETAIL_UNOBSERVABLE,
                "ENVIRONMENT_DETAIL_UNOBSERVABLE",
                f"{len(refused)} environment(s) on {full_name} refused the REST detail "
                f"({', '.join(f'{n}:{st}' for n, st in refused)}) — reviewers, admin bypass and "
                f"branch policy are NOT observed there, which is not the same as none being set. "
                f"The credential needs repository environments read.",
                message_data={"repo": full_name, "environments": refused},
            )
        return uuid_by_name

    def _emit_declared_jobs(
        self,
        full_name: str,
        wf_uuid: Any,
        workflow_id_int: int,
        workflow_path: str,
        parsed_config: dict[str, Any],
        env_uuid_by_name: dict[str, Any],
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
        client: GithubClient | None = None,
        file_read: bool = True,
        listing_first: datetime | None = None,
    ) -> None:
        """Emit one `workflow_job` per job declared in the file, plus its `needs:` graph.

        This is the declaration side of the pipeline: `permissions`, `runs-on`, `if`, the
        environment it deploys to and the ref it checks out. The execution side
        (`github_actions_job`) keeps its own nodes; the two are deliberately not merged.
        """
        declared_dims = {
            "git.host": _PLATFORM_HOST,
            "github.owner": full_name.partition("/")[0],
            "github.repo": full_name.partition("/")[2],
            "github.surface": "actions",
            "github.observation": "declaration",
        }
        jobs = parsed_config.get("jobs") or []
        # The file's job table is a completeness surface of the workflow (github-core#14 shape A:
        # complete by construction once the file was read; nothing listed when it was not).
        config_interval = self._listing_state()["config_interval"]
        first, last = (
            config_interval
            if config_interval is not None and getattr(self, "_config", {}).get(full_name)
            else (listing_first or datetime.now(UTC), datetime.now(UTC))
        )
        self._note_listing(
            "workflow.jobs",
            "DEFINES_JOB__github_core",
            wf_uuid,
            first,
            last=last,
            complete=True if file_read else False,
            count=len(jobs) if file_read else None,
            admitted=file_read,
            reasons=(
                {}
                if file_read
                else {
                    "enumeration_complete": "workflow_yaml_missing: the file was not read, so no job was listed",
                    "admitted": "workflow_yaml_missing: nothing to process",
                }
            ),
        )
        uuid_by_key: dict[str, Any] = {}
        for order, job in enumerate(jobs):
            job_key = str(job.get("id") or "")
            if not job_key:
                continue
            job_uuid = workflow_job_id(full_name, workflow_id_int, job_key)
            uuid_by_key[job_key] = job_uuid
            self._walk_state()["job_names"].append(
                {
                    "owner": full_name.partition("/")[0],
                    "repo": full_name,
                    "wf_uuid": wf_uuid,
                    "job_key": job_key,
                    "job_name": str(job.get("name") or job_key),
                    "dims": {**declared_dims, "github.surface": "actions"},
                }
            )
            job_envelope = node_envelope(
                entity_id=job_uuid,
                entity_type="github_core__workflow_job",
                name=str(job.get("name") or job_key),
                dimensions=declared_dims,
                fields={
                    "full_name": full_name,
                    "workflow_id": workflow_id_int,
                    "workflow_path": workflow_path,
                    "job_key": job_key,
                    "name": str(job.get("name") or job_key),
                    "runs_on": job.get("runs_on"),
                    # null when the job declares no block (it inherits the workflow's), {} when
                    # it declares an empty one (the token gets nothing). Not the same fact.
                    "permissions": job.get("permissions"),
                    "if_condition": str(job.get("if") or ""),
                    "environment": str(job.get("environment") or ""),
                    "uses": str(job.get("uses") or ""),
                    "needs": list(job.get("needs") or []),
                    "checkout_ref": str(job.get("checkout_ref") or ""),
                    "configuration": {
                        "steps": job.get("steps") or [],
                        "cache_steps": job.get("cache_steps") or [],
                        "action_refs": job.get("action_refs") or [],
                        # The file's own triggers and permissions, carried onto the job so a
                        # reader can adjudicate one node without walking up to the workflow:
                        # "pull_request_target + checks out the PR head" is the question, and
                        # it spans both levels.
                        "workflow_triggers": parsed_config.get("triggers") or [],
                        "workflow_permissions": parsed_config.get("permissions"),
                        # Which secrets cross into a reusable workflow this job calls — every
                        # one (`inherit`) or the named few. Names only, never material.
                        "secrets_inherit": bool(job.get("secrets_inherit")),
                        "secrets_passed": list(job.get("secrets_passed") or []),
                    },
                    "tags": {},
                },
            )
            nodes.append(job_envelope)
            if job.get("workflow_call"):
                # Resolved after every repo is walked — the callee may live in a later one.
                self._walk_state()["pending_calls"].append(
                    {
                        "envelope": job_envelope,
                        "job_uuid": job_uuid,
                        "caller": full_name,
                        "call": dict(job["workflow_call"]),
                        "secrets_inherit": bool(job.get("secrets_inherit")),
                        "dims": declared_dims,
                    }
                )
            edges.append(
                edge_envelope(
                    entity_id=edge_id("DEFINES_JOB__github_core", wf_uuid, job_uuid),
                    edge_type="DEFINES_JOB__github_core",
                    source_id=wf_uuid,
                    target_id=job_uuid,
                    dimensions=declared_dims,
                    properties={"job_key": job_key, "order": order},
                )
            )
            env_uuid = env_uuid_by_name.get(str(job.get("environment") or ""))
            if env_uuid is not None:
                edges.append(
                    self._edge(
                        "USES_ENVIRONMENT__github_core",
                        job_uuid,
                        env_uuid,
                        {**declared_dims, "github.surface": "deployments"},
                    )
                )
            # The third-party code this job hands its token to, and how each call is pinned.
            self._emit_used_actions(
                full_name,
                job_uuid,
                job.get("action_refs") or [],
                declared_dims,
                nodes,
                edges,
                client=client,
            )
        # `needs:` — emitted after every job in the file has an id, because a job may need one
        # declared below it.
        for job in jobs:
            source_uuid = uuid_by_key.get(str(job.get("id") or ""))
            if source_uuid is None:
                continue
            for needed in job.get("needs") or []:
                target_uuid = uuid_by_key.get(str(needed))
                if target_uuid is None:
                    # A `needs:` naming a job that does not exist is a broken workflow, not our
                    # bug — no edge, and the name stays visible in the node's `needs` field.
                    continue
                edges.append(
                    edge_envelope(
                        entity_id=edge_id(
                            "DEPENDS_ON_JOB__github_core", source_uuid, target_uuid
                        ),
                        edge_type="DEPENDS_ON_JOB__github_core",
                        source_id=source_uuid,
                        target_id=target_uuid,
                        dimensions=declared_dims,
                        properties={"condition": str(job.get("if") or "")},
                    )
                )

    def _emit_used_actions(
        self,
        full_name: str,
        job_uuid: Any,
        action_refs: list[dict[str, Any]],
        usage_dims: dict[str, str],
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
        client: GithubClient | None = None,
    ) -> None:
        """One `github_action` per distinct path, one `USES_ACTION` per (job, action, ref).

        The node is shared across the whole run (deterministic id; envelope collapse keeps one
        copy) and carries NO owner/repo dimension, because `actions/checkout` belongs to no one
        repository in scope. The edge keeps the calling repository's dimensions: the usage is
        that repository's fact. The pin lives on the edge — it is a fact about this job's call,
        and the same action is pinned differently by different jobs.
        """
        action_dims = {
            k: v for k, v in usage_dims.items() if k not in _REPO_SCOPED_DIMENSION_KEYS
        }
        for (action_path, declared_ref), call in sorted(
            _group_action_calls(action_refs).items()
        ):
            action_uuid = github_action_id(action_path)
            nodes.append(self._action_node(action_uuid, action_path, call, action_dims))
            properties = self._uses_action_properties(
                full_name, call, declared_ref, client=client
            )
            edges.append(
                edge_envelope(
                    entity_id=uses_action_edge_id(job_uuid, action_uuid, declared_ref),
                    edge_type="USES_ACTION__github_core",
                    source_id=job_uuid,
                    target_id=action_uuid,
                    dimensions=usage_dims,
                    properties=properties,
                )
            )
            self._tally_usage(action_path, properties)

    @staticmethod
    def _action_node(
        action_uuid: Any, action_path: str, call: dict[str, Any], dims: dict[str, str]
    ) -> dict[str, Any]:
        return node_envelope(
            entity_id=action_uuid,
            entity_type="github_core__github_action",
            name=action_path,
            dimensions=dims,
            fields={
                "action_path": action_path,
                "kind": str(call.get("kind") or "repository"),
                "owner": str(call.get("owner") or ""),
                "repository_full_name": str(call.get("repository_full_name") or ""),
                "subpath": str(call.get("subpath") or ""),
                "name": action_path,
                "configuration": {},
                "tags": {},
            },
        )

    def _uses_action_properties(
        self,
        full_name: str,
        call: dict[str, Any],
        declared_ref: str,
        client: GithubClient | None = None,
    ) -> dict[str, Any]:
        """The pin, in three states — see `_resolve_action_pin`."""
        pin_kind, resolved_sha, resolution = self._resolve_action_pin(
            full_name,
            str(call.get("kind") or ""),
            str(call.get("repository_full_name") or ""),
            declared_ref,
            str(call.get("pin_kind") or ""),
            client=client,
        )
        properties: dict[str, Any] = {
            "declared_ref": declared_ref,
            "pin_kind": pin_kind,
            "is_pinned": is_pinned(pin_kind),
            "resolution": resolution,
            "step_indexes": sorted(call["step_indexes"]),
        }
        if resolved_sha:
            properties["resolved_sha"] = resolved_sha
        return properties

    def _tally_usage(self, action_path: str, properties: dict[str, Any]) -> None:
        usage = self._usage_tally()
        usage["actions"].add(action_path)
        usage["edges"] += 1
        if not properties["is_pinned"]:
            usage["unpinned"] += 1
        if properties["resolution"] in (
            "unobservable",
            "rest",
            "unresolved",
            "not_attempted",
        ):
            usage[properties["resolution"]] += 1

    def _resolve_action_pin(
        self,
        full_name: str,
        kind: str,
        repository_full_name: str,
        declared_ref: str,
        parsed_pin: str,
        client: GithubClient | None = None,
    ) -> tuple[str, str, str]:
        """Upgrade a parsed pin to what the collector can PROVE: ``(pin_kind, resolved_sha, resolution)``.

        Three states, never two. `literal`: the string settles it (a SHA, a digest, an image
        tag, nothing written). `in_scope`: the action's repository is in the observed scope, so
        its refs are in hand and the name is a `tag` or a `branch` with a head commit — or it
        matches neither, which stays `unresolved` and is warned about. `unobservable`: the
        repository is outside the scope and no call was made; the absence of a resolved SHA
        here is not evidence of anything and must not render as one.
        """
        if parsed_pin != PIN_UNRESOLVED or kind != "repository":
            return parsed_pin, declared_ref if parsed_pin == PIN_SHA else "", "literal"
        refs = self._refs_for(repository_full_name)
        if refs is None:
            # Out of scope. With a client the name is looked up over REST — once per distinct
            # (repository, ref) per run, under a cap — and lands as `rest`, `unresolved`,
            # `unobservable` or `not_attempted` (req-github-core-actions-used-6). Without one
            # (a caller driving the walk directly) nothing was fetched: `unobservable`.
            if client is None:
                return PIN_UNRESOLVED, "", "unobservable"
            return self._resolve_action_ref_via_rest(
                client, repository_full_name, declared_ref
            )
        tag_sha = refs.get(f"refs/tags/{declared_ref}")
        if tag_sha is not None:
            return PIN_TAG, tag_sha, "in_scope"
        branch_sha = refs.get(f"refs/heads/{declared_ref}")
        if branch_sha is not None:
            return PIN_BRANCH, branch_sha, "in_scope"
        self.record_warn(
            _SITE_ACTION_REF_NOT_FOUND,
            "ACTION_REF_NOT_FOUND",
            f"{full_name} uses {repository_full_name}@{declared_ref}, whose repository is in scope "
            f"but carries no tag or branch by that name among the refs collected — a deleted ref, "
            f"or one beyond the ref page cap. Left unresolved rather than guessed.",
            message_data={
                "repo": full_name,
                "action_repo": repository_full_name,
                "ref": declared_ref,
            },
        )
        return PIN_UNRESOLVED, "", "in_scope"

    def _note_listing(
        self,
        relation: str,
        edge_type: str,
        subject: Any,
        first: datetime,
        *,
        last: datetime | None = None,
        complete: bool | None = None,
        count: int | None = None,
        authorized: bool | None = True,
        admitted: bool = True,
        refused: int | None = None,
        reasons: dict[str, str] | None = None,
    ) -> None:
        """Author one completeness surface for a listing this run walked (req-grid-reconcile-evidence).

        `subject` is the parent's grid entity id and `edge_type` the containment edge its
        relation maps to, so candidate derivation can fan out from it. `refused` is the HTTP
        status a listing was refused with: 401/403 is "not authorized", anything else "not
        determinable" — in both cases nothing was enumerated or admitted. `source_consistent`
        is always "unknown": GitHub promises no snapshot across pages (req-grid-reconcile-evidence-2).
        The surfaces are recorded just AFTER submission, once the batch they were applied by has
        an id AND the subject's batch-local ref has been resolved to the id core assigned it.
        """
        reasons = dict(reasons or {})
        if refused is not None:
            authorized = False if refused in (401, 403) else None
            complete = False
            admitted = False
            count = None
            reasons.setdefault("scope_authorized", f"http_{refused}: the listing was refused")
            reasons.setdefault("enumeration_complete", f"http_{refused}: nothing was listed")
            reasons.setdefault("admitted", f"http_{refused}: nothing to process")
        reasons.setdefault("source_consistent", "no_promise: GitHub makes no snapshot promise across pages")
        if complete is None:
            reasons.setdefault(
                "enumeration_complete", "not_determinable: the walk cannot say whether it reached the end"
            )
        if authorized is None:
            reasons.setdefault(
                "scope_authorized", "not_determinable: the credential's permission for this surface is unknown"
            )
        self._listing_state()["listings"].append(
            {
                "relation": relation,
                "edge_type": edge_type,
                "subject": str(subject),
                "interval": {"first": first.isoformat(), "last": (last or datetime.now(UTC)).isoformat()},
                "scope_authorized": authorized,
                "enumeration_complete": complete,
                "source_consistent": "unknown",
                "admitted": admitted,
                "count_observed": count,
                "reasons": reasons,
            }
        )

    def _withdraw_admission(self, start: int, reason: str) -> None:
        """Mark every surface recorded from index ``start`` on as not admitted, with ``reason``.

        A listing that was read completely but whose walk then failed part-way did not pass its
        gate: the observations it licensed never all reached the batch, and a candidate derived
        against the ones that did would name children the run simply never got to.
        """
        for surface in self._listing_state()["listings"][start:]:
            if surface["admitted"]:
                surface["admitted"] = False
                surface["reasons"]["admitted"] = reason

    def _listing_state(self) -> dict[str, Any]:
        """The completeness registers (`_listings`, `_config_interval`), created on first touch —
        lazy for the same reason as `_walk_state`."""
        if getattr(self, "_listings", None) is None:
            self._listings = []
        if not hasattr(self, "_config_interval"):
            self._config_interval = None
        return {"listings": self._listings, "config_interval": self._config_interval}

    def _walk_state(self) -> dict[str, Any]:
        """The run-wide registers the workflow-chain post-pass reads, created on first touch.

        Lazy for the same reason as `_usage_tally`: the per-repo walk is driven directly by
        tests that never call `run()`.
        """
        if getattr(self, "_workflow_uuid_by_path", None) is None:
            self._workflow_uuid_by_path = {}
            self._workflow_uuids_by_name = {}
            self._pending_calls = []
            self._pending_triggers = []
            self._collected_repos = set()
            # Required check contexts by (owner, context) -> the requirements that name them;
            # every declared job's display name; and the rulesets whose contexts could not be
            # read. All three feed `_emit_status_checks` after the whole scope is walked.
            self._required_checks = {}
            self._job_names = []
            self._checks_unobservable = []
        return {
            "by_path": self._workflow_uuid_by_path,
            "by_name": self._workflow_uuids_by_name,
            "pending_calls": self._pending_calls,
            "pending_triggers": self._pending_triggers,
            "collected_repos": self._collected_repos,
            "required_checks": self._required_checks,
            "job_names": self._job_names,
            "checks_unobservable": self._checks_unobservable,
        }

    def _register_workflow(
        self,
        full_name: str,
        path: str,
        display_name: str,
        wf_uuid: Any,
        wf_envelope: dict[str, Any],
        parsed_config: dict[str, Any],
        dims: dict[str, str],
    ) -> None:
        """Index a workflow by (repo, path) and (repo, name) for the post-pass, and queue its
        `workflow_run` trigger if it declares one."""
        state = self._walk_state()
        state["by_path"][(full_name, path)] = wf_uuid
        # Several workflows may share a display name; GitHub fires `workflow_run` on all of them.
        state["by_name"].setdefault((full_name, display_name), []).append(wf_uuid)
        workflow_run = parsed_config.get("workflow_run")
        if workflow_run:
            state["pending_triggers"].append(
                {
                    "envelope": wf_envelope,
                    "wf_uuid": wf_uuid,
                    "repo": full_name,
                    "workflow_run": workflow_run,
                    "dims": dims,
                }
            )

    def _emit_workflow_calls(self, edges: list[dict[str, Any]]) -> None:
        """`CALLS_WORKFLOW`: a declared job to the reusable workflow it calls, when that workflow
        is on the grid — and a recorded reason on the job when it is not.

        Three states, on the CALLING job's `configuration.call_resolution`, because a property
        that qualifies an absence belongs on the node the absence is about: `resolved` (edge
        emitted), `unresolved_in_scope` (the callee's repository was walked and has no workflow
        at that path — a broken call, or a workflow GitHub does not list), `out_of_scope` (the
        callee's repository was not walked; nothing is known and no node is invented).
        """
        state = self._walk_state()
        counts = {
            "resolved": 0,
            "unresolved_in_scope": 0,
            "out_of_scope": 0,
            "secrets_inherit": 0,
        }
        for pending in state["pending_calls"]:
            verdict = self._resolve_workflow_call(pending, state, edges)
            pending["envelope"]["node"]["configuration"]["call_resolution"] = verdict
            counts[verdict] += 1
            counts["secrets_inherit"] += int(
                verdict == "resolved" and bool(pending["secrets_inherit"])
            )
        if state["pending_calls"]:
            self.record_info(
                _SITE_WORKFLOW_CALLS,
                "WORKFLOW_CALLS",
                f"{len(state['pending_calls'])} reusable-workflow call(s): {counts['resolved']} resolved to a workflow on "
                f"the grid, {counts['unresolved_in_scope']} unresolved inside the scope, {counts['out_of_scope']} "
                f"calling a repository outside it (not observable — no node was invented); "
                f"{counts['secrets_inherit']} pass every secret with `secrets: inherit`.",
                message_data=counts,
            )

    def _resolve_workflow_call(
        self,
        pending: dict[str, Any],
        state: dict[str, Any],
        edges: list[dict[str, Any]],
    ) -> str:
        """One pending call → its verdict, emitting the edge when the callee is on the grid."""
        call = pending["call"]
        callee_repo = (
            pending["caller"]
            if call["same_repository"]
            else str(call["repository_full_name"])
        )
        target = state["by_path"].get((callee_repo, str(call["path"])))
        if target is None:
            if callee_repo not in state["collected_repos"]:
                return "out_of_scope"
            self.record_warn(
                _SITE_WORKFLOW_CALL_UNRESOLVED,
                "WORKFLOW_CALL_UNRESOLVED",
                f"{pending['caller']} calls {callee_repo}/{call['path']}, whose repository is in scope but "
                f"lists no workflow at that path. No edge; the call stays on the job as text.",
                message_data={
                    "caller": pending["caller"],
                    "callee_repo": callee_repo,
                    "path": call["path"],
                },
            )
            return "unresolved_in_scope"
        edges.append(
            self._edge(
                "CALLS_WORKFLOW__github_core",
                pending["job_uuid"],
                target,
                pending["dims"],
                self._calls_workflow_properties(pending, callee_repo),
            )
        )
        return "resolved"

    def _calls_workflow_properties(
        self, pending: dict[str, Any], callee_repo: str
    ) -> dict[str, Any]:
        """The pin (USES_ACTION's grammar; a `./` call is `local`) plus the secrets posture."""
        call = pending["call"]
        if call["pin_kind"] == PIN_LOCAL:
            pin_kind, resolved_sha, resolution = PIN_LOCAL, "", "literal"
        else:
            pin_kind, resolved_sha, resolution = self._resolve_action_pin(
                pending["caller"],
                "repository",
                callee_repo,
                str(call["ref"]),
                str(call["pin_kind"]),
            )
        properties: dict[str, Any] = {
            "declared_ref": str(call["ref"]),
            "pin_kind": pin_kind,
            "is_pinned": is_pinned(pin_kind),
            "resolution": resolution,
            "same_repository": bool(call["same_repository"]),
            "secrets_inherit": bool(pending["secrets_inherit"]),
        }
        if resolved_sha:
            properties["resolved_sha"] = resolved_sha
        return properties

    def _emit_workflow_triggers(self, edges: list[dict[str, Any]]) -> None:
        """`TRIGGERS_WORKFLOW`: from each workflow named in `on: workflow_run: workflows:` to the
        workflow that declares it. Names resolve within the same repository only (GitHub's
        rule), against the stored display name; every workflow sharing the name gets an edge,
        because GitHub fires on all of them. An unmatched name is recorded on the declaring
        workflow's `configuration.trigger_resolution` and warned, never guessed.
        """
        state = self._walk_state()
        emitted = 0
        unresolved_total = 0
        for pending in state["pending_triggers"]:
            matched, unresolved = self._resolve_workflow_trigger(pending, state, edges)
            emitted += matched
            unresolved_total += len(unresolved)
            pending["envelope"]["node"]["configuration"]["trigger_resolution"] = {
                "resolved": len(pending["workflow_run"].get("workflows") or [])
                - len(unresolved),
                "unresolved": unresolved,
            }
        if state["pending_triggers"]:
            self.record_info(
                _SITE_WORKFLOW_TRIGGERS,
                "WORKFLOW_TRIGGERS",
                f"{len(state['pending_triggers'])} workflow(s) declare `workflow_run`; {emitted} trigger edge(s) "
                f"emitted, {unresolved_total} declared name(s) matched nothing.",
                message_data={
                    "declaring": len(state["pending_triggers"]),
                    "edges": emitted,
                    "unresolved": unresolved_total,
                },
            )

    def _resolve_workflow_trigger(
        self,
        pending: dict[str, Any],
        state: dict[str, Any],
        edges: list[dict[str, Any]],
    ) -> tuple[int, list[str]]:
        """One declaring workflow → ``(edges emitted, names that matched nothing)``."""
        block = pending["workflow_run"]
        properties: dict[str, Any] = {"trigger_event": "workflow_run"}
        for key in ("types", "branches", "branches_ignore"):
            if key in block:
                properties[key] = list(block[key])
        emitted = 0
        unresolved: list[str] = []
        for declared_name in block.get("workflows") or []:
            sources = state["by_name"].get((pending["repo"], declared_name)) or []
            if not sources:
                unresolved.append(declared_name)
                continue
            for source in sources:
                edges.append(
                    self._edge(
                        "TRIGGERS_WORKFLOW__github_core",
                        source,
                        pending["wf_uuid"],
                        pending["dims"],
                        {**properties, "declared_name": declared_name},
                    )
                )
                emitted += 1
        if unresolved:
            self.record_warn(
                _SITE_WORKFLOW_TRIGGER_UNRESOLVED,
                "WORKFLOW_TRIGGER_UNRESOLVED",
                f"{pending['repo']}: `workflow_run` names {unresolved!r}, which match no workflow in the "
                f"repository by display name. No edge; a renamed or deleted upstream workflow, or a "
                f"trigger that can never fire.",
                message_data={"repo": pending["repo"], "unresolved": unresolved},
            )
        return emitted, unresolved

    def _register_required_checks(
        self,
        owner: str,
        rs_uuid: Any,
        ruleset_name: str,
        rules: list[dict[str, Any]],
        dims: dict[str, str],
    ) -> None:
        """Record every context a ruleset's `required_status_checks` rule names — or that it
        names some and the credential could not read which.

        A rule with no `parameters` is the type-only GraphQL fallback: the detail was refused, the
        contexts are NOT observable, and the ruleset is counted rather than read as requiring
        nothing.
        """
        state = self._walk_state()
        for rule in rules:
            if (
                not isinstance(rule, dict)
                or rule.get("type") != "required_status_checks"
            ):
                continue
            params = rule.get("parameters")
            if not isinstance(params, dict):
                state["checks_unobservable"].append(
                    {"ruleset": ruleset_name, "owner": owner}
                )
                continue
            for check in params.get("required_status_checks") or []:
                context = str((check or {}).get("context") or "")
                if not context:
                    continue
                entry = state["required_checks"].setdefault(
                    (owner, context), {"dims": dims, "requirements": {}}
                )
                entry["requirements"][str(rs_uuid)] = {
                    "rs_uuid": rs_uuid,
                    "integration_id": (check or {}).get("integration_id"),
                    "strict": bool(
                        params.get("strict_required_status_checks_policy", False)
                    ),
                    "do_not_enforce_on_create": bool(
                        params.get("do_not_enforce_on_create", False)
                    ),
                }

    def _emit_status_checks(
        self, nodes: list[dict[str, Any]], edges: list[dict[str, Any]]
    ) -> None:
        """One `status_check` per required (owner, context); `REQUIRES_CHECK` from each ruleset
        naming it; `PRODUCES_CHECK` from each workflow in the owner's scope declaring a job whose
        display name is the context (`exact`) or its matrix template — only when the
        requirement admits an Actions-produced check.
        """
        state = self._walk_state()
        produced = 0
        unproduced: list[str] = []
        for (owner, context), entry in sorted(state["required_checks"].items()):
            check_uuid = status_check_id(owner, context)
            # The node's dims are DERIVED from the type's defaults plus the owner — never
            # copied from whichever ruleset happened to name the context first, so a
            # repository ruleset's `github.repo` can never leak onto the shared node.
            node_dims = {**StatusCheck.DEFAULT_DIMENSIONS, "github.owner": owner}
            nodes.append(
                node_envelope(
                    entity_id=check_uuid,
                    entity_type="github_core__status_check",
                    name=context,
                    dimensions=node_dims,
                    fields={
                        "owner_login": owner,
                        "context": context,
                        "name": context,
                        "configuration": {},
                        "tags": {},
                    },
                )
            )
            # A producer edge says "a workflow job produces a check run with this name" — via GitHub
            # Actions, integration 15368. Whether that satisfies a GIVEN requirement is read off
            # that requirement's REQUIRES_CHECK.integration_id: with two rulesets naming one
            # context, one App-only and one Actions, the node carries producers for the second
            # and the first still requires an App. Compatibility is per requirement, never a
            # property of the shared node (PR #62 review).
            actions_may_produce = False
            for requirement in entry["requirements"].values():
                integration = requirement["integration_id"]
                actions_may_produce |= (
                    integration is None or integration == _GITHUB_ACTIONS_INTEGRATION_ID
                )
                edges.append(
                    self._edge(
                        "REQUIRES_CHECK__github_core",
                        requirement["rs_uuid"],
                        check_uuid,
                        entry["dims"],
                        {
                            "integration_id": integration,
                            "strict": requirement["strict"],
                            "do_not_enforce_on_create": requirement[
                                "do_not_enforce_on_create"
                            ],
                        },
                    )
                )
            if not actions_may_produce:
                continue
            producers = self._check_producers(owner, context, check_uuid, edges)
            produced += producers
            if not producers:
                unproduced.append(f"{owner}#{context}")
        for gap in state["checks_unobservable"]:
            self.record_warn(
                _SITE_REQUIRED_CHECKS_UNOBSERVABLE,
                "REQUIRED_CHECKS_UNOBSERVABLE",
                f"{gap['owner']}: ruleset {gap['ruleset']!r} requires status checks, but WHICH is not observable — "
                f"the ruleset detail was refused and only the rule type is known. No status_check node was "
                f"minted; this is not a ruleset with no required checks.",
                message_data=gap,
            )
        if state["required_checks"] or state["checks_unobservable"]:
            self.record_info(
                _SITE_STATUS_CHECKS,
                "STATUS_CHECKS",
                f"{len(state['required_checks'])} required check context(s), {produced} producer edge(s) from "
                f"workflow jobs, {len(unproduced)} Actions-producible context(s) with no declared producer in "
                f"scope ({', '.join(unproduced[:5])}{'…' if len(unproduced) > 5 else ''}), "
                f"{len(state['checks_unobservable'])} ruleset(s) whose required contexts could not be read.",
                message_data={
                    "contexts": len(state["required_checks"]),
                    "producers": produced,
                    "unproduced": unproduced,
                    "unobservable": len(state["checks_unobservable"]),
                },
            )

    def _check_producers(
        self, owner: str, context: str, check_uuid: Any, edges: list[dict[str, Any]]
    ) -> int:
        """`PRODUCES_CHECK` from every workflow (in the owner's scope) with a job named for the context."""
        emitted = 0
        seen: set[tuple[str, str]] = set()
        for job in self._walk_state()["job_names"]:
            if job["owner"] != owner:
                continue
            confidence = _check_name_confidence(job["job_name"], context)
            if confidence is None or (str(job["wf_uuid"]), job["job_key"]) in seen:
                continue
            seen.add((str(job["wf_uuid"]), job["job_key"]))
            edges.append(
                self._edge(
                    "PRODUCES_CHECK__github_core",
                    job["wf_uuid"],
                    check_uuid,
                    job["dims"],
                    {
                        "job_key": job["job_key"],
                        "job_name": job["job_name"],
                        "confidence": confidence,
                    },
                )
            )
            emitted += 1
        return emitted

    def _usage_tally(self) -> dict[str, Any]:
        """The run's action tally, created on first touch.

        Lazy rather than set in `run()` alone because the per-repo walk is exercised directly by
        tests that build the collector without running it, and a tally that only exists after
        `run()` would make every such walk raise on its first `uses:` line.
        """
        tally = getattr(self, "_action_usage", None)
        if tally is None:
            tally = {
                "actions": set(),
                "edges": 0,
                "unpinned": 0,
                "unobservable": 0,
                "rest": 0,
                "unresolved": 0,
                "not_attempted": 0,
            }
            self._action_usage = tally
        return tally

    def _action_ref_state(self) -> dict[str, Any]:
        """The run's REST-resolution cache and counters, created on first touch (same reason as
        `_usage_tally`: the walk is driven directly by tests that never call `run()`).
        """
        state = getattr(self, "_action_ref_resolution", None)
        if state is None:
            state = {"cache": {}, "lookups": 0, "skipped": 0}
            self._action_ref_resolution = state
        return state

    def _resolve_action_ref_via_rest(
        self, client: GithubClient, repository_full_name: str, declared_ref: str
    ) -> tuple[str, str, str]:
        """What an out-of-scope name IS, and the commit it points at, observed once per run.

        Lookup order mirrors a runner's: a tag named `v4` wins over a branch named `v4`.
        `GET /repos/{o}/{r}/git/ref/tags/{ref}`, then `.../heads/{ref}` on 404; an annotated tag's
        object is a tag, not a commit, and is peeled with `GET .../git/tags/{sha}` — the SHA a
        runner checks out is the commit. Both ride `repository:contents:read` and answer any
        credential on a public repository, which is what almost every action repository is.

        Every outcome is a named state. `rest`: found. `unresolved`: at neither path — the ref does
        not exist as written. `unobservable`: refused or failed (private repository, 403, transport)
        — warned, and NOT evidence about the pin. `not_attempted`: the run's cap was spent.
        """
        state = self._action_ref_state()
        key = (repository_full_name, declared_ref)
        cached = state["cache"].get(key)
        if cached is not None:
            return cached
        if state["lookups"] >= _ACTION_REF_RESOLUTION_CAP:
            state["skipped"] += 1
            result: tuple[str, str, str] = (PIN_UNRESOLVED, "", "not_attempted")
            state["cache"][key] = result
            return result
        if not _SAFE_REPOSITORY_RE.match(
            repository_full_name
        ) or not _SAFE_REF_RE.match(declared_ref):
            # Not a shape GitHub itself would accept in `uses:`; it does not exist as written, and it
            # never becomes a request path.
            self.record_warn(
                _SITE_ACTION_REF_MALFORMED,
                "ACTION_REF_MALFORMED",
                f"{repository_full_name}@{declared_ref}: not an `owner/repo` plus git refname; no lookup made.",
                message_data={"action_repo": repository_full_name, "ref": declared_ref},
            )
            result = (PIN_UNRESOLVED, "", "unresolved")
            state["cache"][key] = result
            return result
        state["lookups"] += 1
        encoded = quote(declared_ref, safe="/")
        result = (PIN_UNRESOLVED, "", "unresolved")
        for pin_kind, prefix in ((PIN_TAG, "tags"), (PIN_BRANCH, "heads")):
            try:
                payload = client.get(
                    f"/repos/{repository_full_name}/git/ref/{prefix}/{encoded}"
                )
            except GithubAPIError as exc:
                if exc.status == 404:
                    continue
                self.record_warn(
                    _SITE_ACTION_REF_UNOBSERVABLE,
                    f"ACTION_REF_UNOBSERVABLE_{exc.status}",
                    f"{repository_full_name}@{declared_ref}: ref lookup refused or failed ({exc.status}); the pin "
                    f"kind and resolved commit are NOT observable for this action, which is not evidence it is "
                    f"unpinned.",
                    message_data={
                        "action_repo": repository_full_name,
                        "ref": declared_ref,
                        "status": exc.status,
                    },
                )
                result = (PIN_UNRESOLVED, "", "unobservable")
                break
            obj = payload.get("object") or {}
            sha = str(obj.get("sha") or "")
            if pin_kind == PIN_TAG and str(obj.get("type") or "") == "tag" and sha:
                commit = self._peel_annotated_tag(client, repository_full_name, sha)
                if commit is None:
                    # The tag exists but its commit could not be established: say so. A tag OBJECT's
                    # SHA is not what a runner checks out, and must not be recorded as if it were.
                    self.record_warn(
                        _SITE_ACTION_REF_UNOBSERVABLE,
                        "ACTION_REF_UNOBSERVABLE_PEEL",
                        f"{repository_full_name}@{declared_ref}: the tag is annotated and its commit could not be "
                        f"read (refused, failed, or nested deeper than {_TAG_PEEL_MAX_DEPTH} tag objects); "
                        f"pin kind is `tag`, resolved commit NOT observable.",
                        message_data={
                            "action_repo": repository_full_name,
                            "ref": declared_ref,
                        },
                    )
                    result = (PIN_TAG, "", "unobservable")
                    break
                sha = commit
            result = (pin_kind, sha, "rest")
            break
        state["cache"][key] = result
        return result

    def _peel_annotated_tag(
        self, client: GithubClient, repository_full_name: str, tag_sha: str
    ) -> str | None:
        """The COMMIT behind an annotated tag object, or None when it cannot be established.

        A tag object may point at another tag object; peel until `object.type == "commit"`, at most
        `_TAG_PEEL_MAX_DEPTH` levels. A refused or failed read, a non-commit at the bottom, or a
        SHA that is not 40-hex all return None — never the tag object's own SHA dressed as the
        commit (Codex seat on PR #67).
        """
        sha = tag_sha
        for _ in range(_TAG_PEEL_MAX_DEPTH):
            if not _SHA40_RE.match(sha):
                return None
            try:
                payload = client.get(f"/repos/{repository_full_name}/git/tags/{sha}")
            except GithubAPIError:
                return None
            obj = payload.get("object") or {}
            kind = str(obj.get("type") or "")
            nxt = str(obj.get("sha") or "")
            if kind == "commit" and _SHA40_RE.match(nxt):
                return nxt
            if kind != "tag" or not nxt:
                return None
            sha = nxt
        return None

    def _refs_for(self, repository_full_name: str) -> dict[str, str] | None:
        """``{ref path: head sha}`` for an in-scope repository, or None when it is not in scope.

        Built from the config layer already fetched, so resolution costs no request. None and
        an empty dict are different answers: None is "cannot look", {} is "looked, none".
        """
        gql = getattr(self, "_config", {}).get(repository_full_name)
        if gql is None:
            return None
        by_repo: dict[str, dict[str, str]] = getattr(self, "_refs_by_repo", None) or {}
        self._refs_by_repo = by_repo
        cached = by_repo.get(repository_full_name)
        if cached is None:
            refs, _truncated = GithubGraphQLClient.refs(gql)
            cached = {str(r["ref"]): str(r.get("head_sha") or "") for r in refs}
            by_repo[repository_full_name] = cached
        return cached

    def _collect_rule_suites(
        self,
        client: GithubClient,
        full_name: str,
        dims: dict[str, str],
        ref_uuid_by_ref: dict[str, Any],
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
    ) -> None:
        """Collect pushes that went AROUND a ruleset rather than satisfying it.

        The complement to `_emit_rulesets` (`req-github-core-rule-suites`). That records who MAY
        bypass and hits a documented ceiling — GitHub returns `bypass_actors` only to a caller with
        write access. This records who DID, and answers a read-only App with names.

        Only `bypass` results are requested. A passing suite is a routine push (~47/day on one
        active repository); landing every one would swamp the grid for no finding.
        """
        try:
            suites = client.get_paginated(
                f"/repos/{full_name}/rulesets/rule-suites",
                params={
                    "rule_suite_result": "bypass",
                    # Explicit, always. The default is `day` (req-github-core-rule-suites-5).
                    "time_period": _RULE_SUITE_WINDOW,
                    "per_page": str(_RULE_SUITE_LIMIT_PER_REPO),
                },
            )
        except GithubAPIError as exc:
            if exc.status in (403, 404):
                # Refused is not empty. Landing nothing here would say "no one bypassed anything",
                # which is the most reassuring reading of a permission failure.
                self.record_warn(
                    _SITE_RULE_SUITE_DEGRADED,
                    f"RULE_SUITES_UNREADABLE_{exc.status}",
                    f"Rule suites inaccessible for {full_name} — bypass events NOT observed, "
                    f"which is not the same as none occurring: {exc.body[:120]}",
                    message_data={"repo": full_name, "status": exc.status},
                )
                return
            raise

        for suite in suites:
            suite_uuid = rule_suite_id(suite["id"])
            actor_login = str(suite.get("actor_name") or "")
            ref = str(suite.get("ref") or "")
            bypassed = self._bypassed_rules(client, full_name, suite)
            nodes.append(
                node_envelope(
                    entity_id=suite_uuid,
                    entity_type="github_core__rule_suite",
                    name=f"{actor_login or 'unknown actor'} bypassed {ref.rsplit('/', 1)[-1] or 'a ref'}",
                    dimensions=dims,
                    fields={
                        "suite_id": suite["id"],
                        "full_name": full_name,
                        "result": str(suite.get("result") or ""),
                        "ref": ref,
                        "actor_login": actor_login,
                        "actor_id": suite.get("actor_id"),
                        "before_sha": str(suite.get("before_sha") or ""),
                        "after_sha": str(suite.get("after_sha") or ""),
                        "pushed_at": suite.get("pushed_at"),
                        "bypassed_rules": bypassed,
                        "configuration": {},
                        "tags": {},
                    },
                )
            )
            if actor_login:
                # An ACCOUNT, not an identity: GitHub says login and id, never whether the login
                # belongs to a person, a bot or a machine account (req-github-core-rule-suites-2).
                actor_uuid = account_id(actor_login)
                if actor_login not in self._emitted_actor_logins:
                    self._emitted_actor_logins.add(actor_login)
                    nodes.append(
                        node_envelope(
                            entity_id=actor_uuid,
                            entity_type="github_core__github_account",
                            name=actor_login,
                            dimensions={**dims, "github.surface": "accounts"},
                            fields={
                                "login": actor_login,
                                "github_id": suite.get("actor_id"),
                                # Unobserved, not "User": this surface does not say which.
                                "account_type": "",
                                "html_url": f"https://github.com/{actor_login}",
                                "configuration": {},
                                "tags": {},
                            },
                        )
                    )
                edges.append(
                    self._edge(
                        # Account -> suite: the push is what happened, and the account is
                        # what initiated it. The passive form had the initiator as target.
                        "TRIGGERED_EVALUATION__github_core",
                        actor_uuid,
                        suite_uuid,
                        dims,
                        properties={"actor_id": suite.get("actor_id")},
                    )
                )
            ref_uuid = ref_uuid_by_ref.get(ref)
            if ref_uuid is not None:
                edges.append(
                    self._edge(
                        "EVALUATED_ON_REF__github_core",
                        suite_uuid,
                        ref_uuid,
                        dims,
                        properties={
                            "before_sha": str(suite.get("before_sha") or ""),
                            "after_sha": str(suite.get("after_sha") or ""),
                        },
                    )
                )
            for rule in bypassed:
                if rule.get("ruleset_id") is None:
                    continue
                edges.append(
                    self._edge(
                        "BYPASSED_RULE__github_core",
                        suite_uuid,
                        ruleset_id(_owner_of(full_name), rule["ruleset_id"]),
                        dims,
                        properties={
                            "rule_type": str(rule.get("rule_type") or ""),
                            "enforcement": str(rule.get("enforcement") or ""),
                            "details": str(rule.get("details") or ""),
                        },
                    )
                )
        if suites:
            self.record_info(
                _SITE_RULE_SUITE_FOUND,
                "RULE_SUITES_BYPASS",
                f"{len(suites)} bypass event(s) on {full_name} in the last {_RULE_SUITE_WINDOW}.",
                message_data={
                    "repo": full_name,
                    "count": len(suites),
                    "window": _RULE_SUITE_WINDOW,
                },
            )

    def _bypassed_rules(
        self, client: GithubClient, full_name: str, suite: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """The rules a suite did not satisfy, from its detail. Degrades to [] with the list intact.

        The list endpoint says a bypass happened; only the detail says WHICH control was gone
        around, which is what turns the event from a log line into a finding.
        """
        try:
            detail = client.get(
                f"/repos/{full_name}/rulesets/rule-suites/{suite['id']}"
            )
        except GithubAPIError:
            return []
        out: list[dict[str, Any]] = []
        for evaluation in detail.get("rule_evaluations") or []:
            if evaluation.get("result") == "pass":
                continue
            source = evaluation.get("rule_source") or {}
            out.append(
                {
                    "rule_type": evaluation.get("rule_type"),
                    "enforcement": evaluation.get("enforcement"),
                    "result": evaluation.get("result"),
                    "ruleset_id": (
                        source.get("id") if source.get("type") == "ruleset" else None
                    ),
                    "ruleset_name": source.get("name"),
                    "details": evaluation.get("details"),
                }
            )
        return out

    # ---------- code scanning (req-github-core-code-scanning) ----------

    def _commits_seen(self) -> dict[str, Any]:
        """Run-wide index ``oid -> git_core__git_commit uuid`` of every commit emitted this run.

        Lazy for the same reason as `_walk_state`: the per-repo walk is driven directly by tests
        that never call `run()`. Filled by `_emit_commit`; read by any later surface that names a
        commit sha and may join to it ONLY when the commit is in the batch.
        """
        index = getattr(self, "_commit_uuid_by_oid", None)
        if index is None:
            self._commit_uuid_by_oid: dict[str, Any] = {}
            index = self._commit_uuid_by_oid
        return index

    def _collect_code_scanning(
        self,
        client: GithubClient,
        full_name: str,
        repo_uuid: Any,
        repo_envelope: dict[str, Any],
        dims: dict[str, str],
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
    ) -> None:
        """Collect the repository's code-scanning alerts and analyses; mint one finding per alert.

        Two REST listings, one permission (`security_events: read`). Every alert lands twice: as
        the GitHub detail (`github_core__code_scanning_alert`, everything the API said) and as the
        generic `compliance_core__compliance_finding` that the compliance substrate and its views
        already understand — the finding is the SUBJECT, the alert is the EVIDENCE, joined by
        `DETAILS_FINDING`. Each analysis (one SARIF upload) lands as
        `github_core__code_scanning_analysis`, so "did the scanner run on this commit" is a
        traversal rather than an inference from the absence of alerts.

        Four states on the repository node, because three would lie. `observed`: both listings
        answered 200, so zero alerts is a fact. `not_enabled`: GitHub said the feature is off —
        the 404 `no analysis found`, or a 403 naming Advanced Security on a private repository
        without it. `unobservable`: the credential was refused (a 403 without that phrase, or an
        unexplained 404) — no alert means nothing. `""`: never asked. If either listing was
        refused for credential reasons the repository is `unobservable`; otherwise if either said
        the feature is off it is `not_enabled`; otherwise `observed`.

        Alerts are walked to the end of the Link chain and the walk is checked; analyses are ONE
        page of the most recent hundred, and a pending next page is warned. Both truncations are
        recorded as non-evidence: absence of an alert or an analysis in this batch proves nothing.
        """
        alerts_state, alerts, alerts_complete, alerts_note = self._code_scanning_fetch(
            client, full_name, "alerts", walk=True
        )
        analyses_state, analyses, analyses_complete, analyses_note = self._code_scanning_fetch(
            client, full_name, "analyses", walk=False
        )
        states = {alerts_state, analyses_state}
        if _UNOBSERVABLE in states:
            state = _UNOBSERVABLE
        elif _NOT_ENABLED in states:
            state = _NOT_ENABLED
        else:
            state = _OBSERVED
        repo_envelope["node"]["code_scanning_observability"] = state
        notes = [n for n in (alerts_note, analyses_note) if n]
        if state == _UNOBSERVABLE:
            self.record_warn(
                _SITE_CODE_SCANNING_UNOBSERVABLE,
                "CODE_SCANNING_UNOBSERVABLE",
                f"code scanning NOT observed for {full_name}, which is not the same as no findings: "
                + "; ".join(notes),
                message_data={
                    "repo": full_name,
                    "alerts": alerts_state,
                    "analyses": analyses_state,
                    "notes": notes,
                },
            )
        elif state == _NOT_ENABLED:
            self.record_info(
                _SITE_CODE_SCANNING_NOT_ENABLED,
                "CODE_SCANNING_NOT_ENABLED",
                f"{full_name}: GitHub reports code scanning is not enabled for this repository "
                f"({'; '.join(notes)}). No findings because nothing scans it — a gap, not a clean bill.",
                message_data={"repo": full_name, "notes": notes},
            )

        workflow_by_path = self._walk_state()["by_path"]
        commits_seen = self._commits_seen()
        by_state: dict[str, int] = {}
        by_tool: dict[str, int] = {}
        workflow_linked = 0
        for alert in alerts:
            number = alert.get("number")
            if number is None:
                continue
            detail = self._code_scanning_alert_fields(full_name, alert)
            alert_uuid = code_scanning_alert_id(full_name, number)
            finding_uuid = code_scanning_finding_id(full_name, number)
            nodes.append(
                node_envelope(
                    entity_id=alert_uuid,
                    entity_type="github_core__code_scanning_alert",
                    name=f"#{number} {detail['tool_name']} {detail['rule_id']}".strip(),
                    dimensions=dims,
                    fields=detail,
                )
            )
            finding = self._code_scanning_finding_fields(detail)
            nodes.append(
                node_envelope(
                    entity_id=finding_uuid,
                    entity_type="compliance_core__compliance_finding",
                    name=finding["name"],
                    dimensions={**dims, "compliance": "finding"},
                    fields=finding,
                )
            )
            edges.append(
                self._edge(
                    "CARRIES_COMPLIANCE_FINDING__compliance_core", repo_uuid, finding_uuid, dims
                )
            )
            edges.append(
                self._edge("DETAILS_FINDING__github_core", alert_uuid, finding_uuid, dims)
            )
            # A finding IN a workflow file is a finding ON that workflow — the same edge type from
            # the workflow, when the path is one this run collected. A path we did not collect
            # (a deleted workflow, a non-workflow file) simply carries no second edge.
            wf_uuid = workflow_by_path.get((full_name, detail["location"]["path"]))
            if wf_uuid is not None:
                workflow_linked += 1
                edges.append(
                    self._edge(
                        "CARRIES_COMPLIANCE_FINDING__compliance_core", wf_uuid, finding_uuid, dims
                    )
                )
            by_state[detail["state"]] = by_state.get(detail["state"], 0) + 1
            by_tool[detail["tool_name"]] = by_tool.get(detail["tool_name"], 0) + 1

        analyses_by_tool: dict[str, int] = {}
        commit_linked = 0
        for analysis in analyses:
            analysis_id_int = analysis.get("id")
            if analysis_id_int is None:
                continue
            fields = self._code_scanning_analysis_fields(full_name, analysis)
            analysis_uuid = code_scanning_analysis_id(full_name, analysis_id_int)
            nodes.append(
                node_envelope(
                    entity_id=analysis_uuid,
                    entity_type="github_core__code_scanning_analysis",
                    name=(
                        f"{fields['tool_name']} {fields['category'] or fields['analysis_key']} "
                        f"@ {fields['commit_sha'][:12]}"
                    ).strip(),
                    dimensions=dims,
                    fields=fields,
                )
            )
            edges.append(
                self._edge("ANALYZES_REPOSITORY__github_core", analysis_uuid, repo_uuid, dims)
            )
            # Only when the commit is in this batch. The sha stays on the node either way; a
            # commit this run did not collect (a pull-request head past the ref window) is a
            # normal thing, not a warning.
            commit_uuid = commits_seen.get(fields["commit_sha"].lower())
            if commit_uuid is not None:
                commit_linked += 1
                edges.append(
                    self._edge("ANALYZES_COMMIT__github_core", analysis_uuid, commit_uuid, dims)
                )
            analyses_by_tool[fields["tool_name"]] = analyses_by_tool.get(fields["tool_name"], 0) + 1

        if alerts_state == _OBSERVED and not alerts_complete:
            self.record_warn(
                _SITE_CODE_SCANNING_ALERTS_TRUNCATED,
                "CODE_SCANNING_ALERTS_TRUNCATED",
                f"{full_name}: the alert walk stopped at the page cap with {len(alerts)} collected and "
                f"more pending. The alert set is INCOMPLETE; absence of an alert in this batch is not "
                f"evidence it is fixed or dismissed.",
                message_data={"repo": full_name, "collected": len(alerts)},
            )
        if analyses_state == _OBSERVED and not analyses_complete:
            self.record_warn(
                _SITE_CODE_SCANNING_ANALYSES_TRUNCATED,
                "CODE_SCANNING_ANALYSES_TRUNCATED",
                f"{full_name}: collected the {len(analyses)} most recent analyses; more exist. Absence of "
                f"an analysis in this batch is not evidence it did not run.",
                message_data={"repo": full_name, "collected": len(analyses)},
            )
        if state == _OBSERVED:
            self.record_info(
                _SITE_CODE_SCANNING_COLLECTED,
                "CODE_SCANNING_COLLECTED",
                f"{full_name}: {len(alerts)} code-scanning alert(s)"
                + (
                    " (" + ", ".join(f"{n} {s}" for s, n in sorted(by_state.items())) + ")"
                    if by_state
                    else ""
                )
                + (
                    " by " + ", ".join(f"{t} {n}" for t, n in sorted(by_tool.items()))
                    if by_tool
                    else ""
                )
                + f", {workflow_linked} in a collected workflow file; {len(analyses)} analysis(es)"
                + (
                    " by " + ", ".join(f"{t} {n}" for t, n in sorted(analyses_by_tool.items()))
                    if analyses_by_tool
                    else ""
                )
                + f", {commit_linked} on a commit in this batch.",
                message_data={
                    "repo": full_name,
                    "alerts": len(alerts),
                    "alerts_by_state": by_state,
                    "alerts_by_tool": by_tool,
                    "alerts_complete": alerts_complete,
                    "workflow_linked": workflow_linked,
                    "analyses": len(analyses),
                    "analyses_by_tool": analyses_by_tool,
                    "analyses_complete": analyses_complete,
                    "commit_linked": commit_linked,
                },
            )

    def _code_scanning_fetch(
        self,
        client: GithubClient,
        full_name: str,
        surface: str,
        *,
        walk: bool,
    ) -> tuple[str, list[dict[str, Any]], bool, str]:
        """One code-scanning listing: ``(state, items, walk_complete, note)``.

        `walk=True` follows the Link chain to its end (alerts); `walk=False` takes one page
        (analyses). Either way `walk_complete` is the client's own verdict on whether a next page
        was still pending, never inferred from the item count. A 403/404 is classified by its
        BODY into `not_enabled` (GitHub says the feature is off) or `unobservable` (the credential
        was refused); anything else re-raises like every sibling surface.
        """
        path = f"/repos/{full_name}/code-scanning/{surface}"
        try:
            items = client.get_paginated(
                path,
                params={"per_page": str(_CODE_SCANNING_PAGE_SIZE)},
                max_pages=100 if walk else 1,
            )
        except GithubAPIError as exc:
            if exc.status not in (403, 404):
                raise
            body = (exc.body or "").lower()
            refused_as = (
                _NOT_ENABLED
                if any(marker in body for marker in _CODE_SCANNING_NOT_ENABLED_MARKERS)
                else _UNOBSERVABLE
            )
            return refused_as, [], True, f"{surface} answered {exc.status}: {(exc.body or '')[:120]}"
        # A client that cannot say whether the walk finished has NOT proven completeness —
        # default to incomplete so the truncation warning fires rather than a silent "all".
        complete = bool(getattr(client, "last_walk_complete", False))
        return _OBSERVED, [item for item in items if isinstance(item, dict)], complete, ""

    @staticmethod
    def _code_scanning_alert_fields(full_name: str, alert: dict[str, Any]) -> dict[str, Any]:
        """The detail node's fields, flattened from GitHub's nested alert.

        Timestamps pass through as GitHub gave them (a string, or null = GitHub gave null);
        nested optional strings become `""` when null; the raw alert rides `configuration` so
        nothing the API said is lost to the flattening.
        """
        rule = alert.get("rule") or {}
        tool = alert.get("tool") or {}
        instance = alert.get("most_recent_instance") or {}
        location = instance.get("location") or {}
        dismissed_by = alert.get("dismissed_by") or {}
        return {
            "full_name": full_name,
            "number": alert.get("number"),
            "state": str(alert.get("state") or ""),
            "created_at": alert.get("created_at"),
            "updated_at": alert.get("updated_at"),
            "fixed_at": alert.get("fixed_at"),
            "dismissed_at": alert.get("dismissed_at"),
            "dismissed_reason": str(alert.get("dismissed_reason") or ""),
            "dismissed_comment": str(alert.get("dismissed_comment") or ""),
            "dismissed_by_login": str(dismissed_by.get("login") or ""),
            "html_url": str(alert.get("html_url") or ""),
            "rule_id": str(rule.get("id") or ""),
            "rule_name": str(rule.get("name") or ""),
            "rule_severity": str(rule.get("severity") or ""),
            "security_severity_level": str(rule.get("security_severity_level") or ""),
            "rule_description": str(rule.get("description") or ""),
            "rule_tags": list(rule.get("tags") or []),
            "tool_name": str(tool.get("name") or ""),
            "tool_version": str(tool.get("version") or ""),
            "tool_guid": str(tool.get("guid") or ""),
            "analysis_key": str(instance.get("analysis_key") or ""),
            "category": str(instance.get("category") or ""),
            "environment": str(instance.get("environment") or ""),
            "ref": str(instance.get("ref") or ""),
            "commit_sha": str(instance.get("commit_sha") or ""),
            "location": {
                "path": str(location.get("path") or ""),
                "start_line": int(location.get("start_line") or 0),
                "end_line": int(location.get("end_line") or 0),
                "start_column": int(location.get("start_column") or 0),
                "end_column": int(location.get("end_column") or 0),
            },
            "message": str((instance.get("message") or {}).get("text") or ""),
            "classifications": list(instance.get("classifications") or []),
            "instances_url": str(alert.get("instances_url") or ""),
            "configuration": alert,
            "tags": {},
        }

    @staticmethod
    def _code_scanning_finding_fields(detail: dict[str, Any]) -> dict[str, Any]:
        """Project the alert onto the compliance substrate's finding.

        `status` folds GitHub's three states into the substrate's two: `open` stays open,
        `dismissed` and `fixed` are both `resolved` — the substrate does not distinguish "went
        away" from "was waved through", and the true state lives on the detail node one edge
        away. The model has no `configuration`/`tags`, so none are emitted.

        `source` and `source_key` are the finding's IDENTITY, and they are the reason this
        projection is not optional (Issue# 8 - tap-plugin-compliance-core). compliance_core
        declares `NATURAL_KEY = ("source", "source_key")` on the model it owns, so those two
        values are what the importer's generated search filters when it resolves this node's
        ref. A projection that omitted them would not fail: the search would find a hole,
        answer "not found", and core would assign a FRESH id — one duplicate finding per alert
        per run, quietly. Both come from `identity.py`, which composes the key once so the
        value written here and the value the ref carries cannot drift apart.
        """
        name = f"{detail['tool_name']} {detail['rule_id']}".strip() or f"code scanning alert #{detail['number']}"
        summary = detail["rule_description"] or detail["rule_name"]
        location = detail["location"]
        parts = [detail["message"]] if detail["message"] else []
        if location["path"]:
            parts.append(f"{location['path']}:{location['start_line']}")
        return {
            "source": COMPLIANCE_FINDING_SOURCE,
            "source_key": code_scanning_finding_source_key(detail["full_name"], detail["number"]),
            "name": name[:255],
            "summary": summary[:500],
            "description": "\n\n".join(parts).strip(),
            "status": "open" if detail["state"] == _CODE_SCANNING_OPEN else "resolved",
        }

    @staticmethod
    def _code_scanning_analysis_fields(full_name: str, analysis: dict[str, Any]) -> dict[str, Any]:
        """The analysis node's fields; counts pass through as given (null = GitHub gave null)."""
        tool = analysis.get("tool") or {}
        return {
            "full_name": full_name,
            "analysis_id": analysis.get("id"),
            "ref": str(analysis.get("ref") or ""),
            "commit_sha": str(analysis.get("commit_sha") or ""),
            "analysis_key": str(analysis.get("analysis_key") or ""),
            "category": str(analysis.get("category") or ""),
            "environment": str(analysis.get("environment") or ""),
            "tool_name": str(tool.get("name") or ""),
            "tool_version": str(tool.get("version") or ""),
            "tool_guid": str(tool.get("guid") or ""),
            "created_at": analysis.get("created_at"),
            "results_count": analysis.get("results_count"),
            "rules_count": analysis.get("rules_count"),
            "sarif_id": str(analysis.get("sarif_id") or ""),
            "deletable": bool(analysis.get("deletable", False)),
            "warning": str(analysis.get("warning") or ""),
            "error": str(analysis.get("error") or ""),
            "url": str(analysis.get("url") or ""),
            "configuration": analysis,
            "tags": {},
        }

    def _collect_secrets(
        self,
        client: GithubClient,
        full_name: str,
        repo_uuid: Any,
        dims: dict[str, str],
        env_uuid_by_name: dict[str, Any],
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
    ) -> tuple[dict[str, list[Any]], list[str]]:
        """Collect this repository's Actions secret NAMES — repository scope and each environment.

        Never a value. GitHub's secrets API is names-and-timestamps only: the value is write-only
        and no credential can read it back, which is what makes this node safe to hold. The model
        and both edge declarations say the same thing.

        Returns ``(upper-cased name -> [uuid, ...], scopes fully enumerated)``.

        The value is a LIST because one name can exist at more than one scope, and those are
        different credentials. Collapsing them to one uuid meant at most one `REFERENCES_SECRET`
        edge per name and made which scope won depend on dict iteration order.

        The second element is the load-bearing one: a caller deciding that a workflow's
        `${{ secrets.X }}` reference resolves to nothing may only say so about the scopes it
        actually enumerated IN FULL. A 403 that silently produced an empty map would turn "the
        credential was refused" into "this repository has no secrets"; a listing that stopped at
        the page cap does the same thing more quietly, because the names it did return make it
        look like it worked.
        """
        scopes_read: list[str] = []
        out: dict[str, list[Any]] = {}

        listing = self._secret_rows(
            client,
            f"/repos/{full_name}/actions/secrets",
            _SITE_SECRETS_DEGRADED,
            "SECRETS_UNREADABLE",
            f"Repository secret names inaccessible for {full_name}",
            {"repo": full_name},
        )
        # The rows are emitted whichever way completeness went — a secret we SAW exists, and a
        # truncated page does not make the names before it imaginary. Only the claim "this scope
        # was enumerated" is withheld.
        for item in listing.rows:
            self._emit_secret(
                item,
                scope="repository",
                owner_login=full_name.split("/")[0],
                full_name=full_name,
                environment_name="",
                source_uuid=repo_uuid,
                dims=dims,
                nodes=nodes,
                edges=edges,
                out=out,
            )
        if listing.complete:
            scopes_read.append("repository")

        # Environment secrets. Without these, every `${{ secrets.X }}` a deployment job reads from
        # its environment would be reported as naming nothing — a false alarm on exactly the jobs
        # that hold the production credentials.
        env_complete = bool(env_uuid_by_name)
        for env_name, env_uuid in env_uuid_by_name.items():
            env_listing = self._secret_rows(
                client,
                f"/repos/{full_name}/environments/{quote(env_name, safe='')}/secrets",
                _SITE_ENV_SECRETS_DEGRADED,
                "ENVIRONMENT_SECRETS_UNREADABLE",
                f"Environment secret names inaccessible for {full_name} environment {env_name}",
                {"repo": full_name, "environment": env_name},
            )
            if not env_listing.complete:
                # One unreadable or truncated environment costs the whole ENVIRONMENT scope its
                # claim, because a reference resolves against the repository's environments as a
                # set and we can no longer say we have that set.
                env_complete = False
            for item in env_listing.rows:
                self._emit_secret(
                    item,
                    scope="environment",
                    owner_login=full_name.split("/")[0],
                    full_name=full_name,
                    environment_name=env_name,
                    source_uuid=env_uuid,
                    dims=dims,
                    nodes=nodes,
                    edges=edges,
                    out=out,
                )
        if env_complete:
            scopes_read.append("environment")
        return out, scopes_read

    def _collect_org_secrets(
        self,
        client: GithubClient,
        owner: str | None,
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
    ) -> tuple[dict[str, list[Any]], bool]:
        """Collect the ACCOUNT's Actions secret names, once per run.

        An account surface, like packages and custom properties: one organisation secret is
        readable by every repository it is shared with, and fetching it per repository would be
        one identical answer repeated twenty-four times.

        This is the scope that matters most for reference resolution. Measured on this estate,
        the two most-referenced names after the unresolved one (`OPENAI_API_KEY`, `XAI_API_KEY`,
        six workflows each) live at organisation scope and at NO repository — so a collector that
        read only repository scope would report twelve workflows as naming a secret that does not
        exist, and every one of those reports would be wrong.

        Returns ``(upper-cased name -> [uuid, ...], enumerated in full)``. False means the scope
        was not fully read, and a caller must not conclude anything from a name's absence.
        """
        if owner is None:
            self.record_info(
                _SITE_ORG_SECRETS_SKIPPED,
                "ORG_SECRETS_SKIPPED",
                "Organisation secrets are an account surface; a repos-only scope names no "
                "account, so they were not collected.",
            )
            return {}, False
        listing = self._secret_rows(
            client,
            f"/orgs/{owner}/actions/secrets",
            _SITE_ORG_SECRETS_DEGRADED,
            "ORG_SECRETS_UNREADABLE",
            f"Organisation secret names inaccessible for {owner}",
            {"owner": owner},
            # A user account has no organisation secrets endpoint at all. That 404 is "nothing to
            # ask", not "refused", and it must not be reported as a degradation.
            absent_statuses=(404,),
            absent_code="ORG_SECRETS_NOT_AN_ORGANISATION",
            absent_message=(
                f"{owner} answered 404 for organisation secrets — a user account has no such "
                f"surface. No organisation-scoped secret can exist, so references resolve "
                f"against repository and environment scope alone."
            ),
            absent_site=_SITE_ORG_SECRETS_SKIPPED,
        )
        account_uuid = account_id(owner)
        dims = {
            "git.host": _PLATFORM_HOST,
            "github.owner": owner,
            "github.surface": "secrets",
            "github.observation": "declaration",
        }
        out: dict[str, list[Any]] = {}
        for item in listing.rows:
            # Reach, derived now rather than left open. An organisation secret shared with
            # `selected` repositories does not reach the rest of the organisation, and a
            # workflow elsewhere naming it receives an empty string at runtime — the exact
            # silent failure this surface exists to catch, which resolution would otherwise
            # report as a working reference.
            self._org_secret_reach[str(item.get("name") or "").upper()] = self._reach_of(
                client, owner, item
            )
            self._emit_secret(
                item,
                scope="organization",
                owner_login=owner,
                full_name="",
                environment_name="",
                source_uuid=account_uuid,
                dims=dims,
                nodes=nodes,
                edges=edges,
                out=out,
            )
        return out, listing.complete

    def _reach_of(self, client: GithubClient, owner: str, item: dict[str, Any]) -> OrgSecretReach:
        """Resolve one organisation secret's sharing policy into a concrete reach.

        Only `selected` costs a request, and only one per such secret per RUN — not per
        repository. Estates that share everything with `all` pay nothing.
        """
        name = str(item.get("name") or "")
        visibility = str(item.get("visibility") or "")
        if visibility in ("all", "private"):
            return OrgSecretReach(visibility, frozenset())
        if visibility != "selected":
            # A policy GitHub has not documented to us. Say so rather than guess a default;
            # guessing `all` here would be the reassuring direction.
            self.record_warn(
                _SITE_ORG_SECRETS_DEGRADED,
                "ORG_SECRET_VISIBILITY_UNKNOWN",
                f"Organisation secret {name} reports visibility {visibility!r}, which this "
                f"collector does not know how to resolve; its reach is left undecided.",
                message_data={"owner": owner, "visibility": visibility},
            )
            return OrgSecretReach("unknown", frozenset())
        try:
            rows = client.get_paginated(
                f"/orgs/{owner}/actions/secrets/{quote(name, safe='')}/repositories",
                params={"per_page": "100"},
                item_path="repositories",
            )
        except GithubAPIError as exc:
            self.record_warn(
                _SITE_ORG_SECRETS_DEGRADED,
                f"ORG_SECRET_REPOS_UNREADABLE_{exc.status}",
                f"Selected-repository list for organisation secret {name} unreadable "
                f"({exc.status}); its reach is NOT observed, which is not the same as reaching "
                f"nothing.",
                message_data={"owner": owner, "secret": name, "status": exc.status},
            )
            return OrgSecretReach("unknown", frozenset())
        if not client.last_walk_complete:
            self.record_warn(
                _SITE_SECRET_SCOPE_INCOMPLETE,
                "ORG_SECRET_REPOS_INCOMPLETE",
                f"Selected-repository list for organisation secret {name} stopped at the page "
                f"cap; a repository missing from a PREFIX is not a repository out of reach.",
                message_data={"owner": owner, "secret": name},
            )
            return OrgSecretReach("unknown", frozenset())
        return OrgSecretReach(
            "selected",
            frozenset(str(r.get("full_name") or "") for r in rows if isinstance(r, dict)),
        )

    def _secret_rows(
        self,
        client: GithubClient,
        path: str,
        site: str,
        code: str,
        message: str,
        message_data: dict[str, Any],
        *,
        absent_statuses: tuple[int, ...] = (),
        absent_code: str = "",
        absent_message: str = "",
        absent_site: str = "",
    ) -> SecretListing:
        """Paginated secret listing as ``(rows, complete)``.

        THREE states, not two, which is the whole discipline of this surface:

        * ``([...], True)``  — asked, and this is the set. Only this may be called a read scope.
        * ``([], False)``    — could not ask (refused, or no such surface). Nothing is known.
        * ``([...], False)`` — asked and got a PREFIX: the walk hit the page cap with a `next`
          link still pending. The names returned are real, but their absence proves nothing.

        The third state is the one that hides. A refusal is loud and returns nothing; a truncated
        walk returns plausible names and looks like success, so a caller that only checked for
        emptiness would list the scope as read and then report every name on an unfetched page as
        naming nothing at all.

        A status in `absent_statuses` means the surface does not exist for this target rather
        than that it was refused — recorded as information rather than as a degradation, and
        still incomplete, so no caller treats a nonexistent scope as an observed-empty one.
        """
        try:
            rows = client.get_paginated(path, params={"per_page": "100"}, item_path="secrets")
        except GithubAPIError as exc:
            if exc.status in absent_statuses:
                self.record_info(absent_site or site, absent_code or code, absent_message or message)
                return SecretListing([], False)
            if exc.status in (401, 403, 404):
                self.record_warn(
                    site,
                    f"{code}_{exc.status}",
                    f"{message}: {exc.body[:120]}",
                    message_data={**message_data, "status": exc.status},
                )
                return SecretListing([], False)
            raise
        complete = bool(client.last_walk_complete)
        if not complete:
            self.record_warn(
                _SITE_SECRET_SCOPE_INCOMPLETE,
                "SECRET_LISTING_INCOMPLETE",
                f"Secret listing for {path} stopped before the end of the Link chain; the names "
                f"collected are a prefix, not the set, so this scope is NOT reported as read and "
                f"no reference may be called unresolved against it.",
                message_data=message_data,
            )
        return SecretListing([r for r in rows if isinstance(r, dict)], complete)

    def _emit_secret(
        self,
        item: dict[str, Any],
        *,
        scope: str,
        owner_login: str,
        full_name: str,
        environment_name: str,
        source_uuid: Any,
        dims: dict[str, str],
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
        out: dict[str, list[Any]],
    ) -> None:
        """One secret node plus the DEFINES_SECRET edge from whatever holds it.

        The node carries the name as GitHub returned it; the returned map is keyed upper-case,
        because that is the only form a reference can be matched on (GitHub secret names are not
        case-sensitive). It APPENDS rather than assigns: the same name at two scopes is two
        credentials and both belong in the resolution.
        """
        name = str(item.get("name") or "")
        if not name:
            return
        uuid_ = actions_secret_id(scope, owner_login, full_name, environment_name, name)
        out.setdefault(name.upper(), []).append(uuid_)
        nodes.append(
            node_envelope(
                entity_id=uuid_,
                entity_type="github_core__actions_secret",
                name=name,
                dimensions={**dims, "github.surface": "secrets"},
                fields={
                    "scope": scope,
                    "owner_login": owner_login,
                    "full_name": full_name,
                    "environment_name": environment_name,
                    # Canonical spelling is the identity; what GitHub said rides beside it.
                    "name": name.upper(),
                    "name_reported": name,
                    # Organisation secrets carry a sharing policy; repository and environment
                    # secrets have none, and "" says so rather than implying a default.
                    "visibility": str(item.get("visibility") or ""),
                    "created_at": item.get("created_at"),
                    "updated_at": item.get("updated_at"),
                    "configuration": {},
                    "tags": {},
                },
            )
        )
        edges.append(
            self._edge(
                "DEFINES_SECRET__github_core",
                source_uuid,
                uuid_,
                {**dims, "github.surface": "secrets"},
            )
        )

    def _collect_caches(
        self,
        client: GithubClient,
        full_name: str,
        repo_uuid: Any,
        dims: dict[str, str],
        ref_uuid_by_ref: dict[str, Any],
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
    ) -> None:
        """Collect stored cache entries and scope each to the ref that produced it.

        The `SCOPED_TO_REF` edge is emitted only when the entry's ref is one we observed. Its absence
        is usually the interesting case rather than a gap: an entry scoped to `refs/pull/42/merge`
        came from a pull request, and a cache written outside a branch and restored inside it is
        the shape five incidents share.
        """
        try:
            payload = client.get(
                f"/repos/{full_name}/actions/caches",
                params={"per_page": str(_CACHE_LIMIT_PER_REPO)},
            )
        except GithubAPIError as exc:
            if exc.status in (403, 404):
                self.record_warn(
                    _SITE_CACHE_DEGRADED,
                    f"CACHES_UNREADABLE_{exc.status}",
                    f"Cache list inaccessible for {full_name}: {exc.body[:120]}",
                    message_data={"repo": full_name, "status": exc.status},
                )
                return
            raise
        entries = payload.get("actions_caches") or []
        total = int(payload.get("total_count") or len(entries))
        for entry in entries:
            cache_uuid = actions_cache_id(full_name, entry["id"])
            ref = str(entry.get("ref") or "")
            nodes.append(
                node_envelope(
                    entity_id=cache_uuid,
                    entity_type="github_core__actions_cache",
                    name=str(entry.get("key") or entry["id"]),
                    dimensions=dims,
                    fields={
                        "full_name": full_name,
                        "cache_id": entry["id"],
                        "key": str(entry.get("key") or ""),
                        "version": str(entry.get("version") or ""),
                        "ref": ref,
                        "size_in_bytes": entry.get("size_in_bytes"),
                        "created_at": entry.get("created_at"),
                        "last_accessed_at": entry.get("last_accessed_at"),
                        "configuration": {},
                        "tags": {},
                    },
                )
            )
            edges.append(
                self._edge("STORES_CACHE__github_core", repo_uuid, cache_uuid, dims)
            )
            ref_uuid = ref_uuid_by_ref.get(ref)
            if ref_uuid is not None:
                edges.append(
                    self._edge("SCOPED_TO_REF__github_core", cache_uuid, ref_uuid, dims)
                )
        if total > len(entries):
            self.record_warn(
                _SITE_CACHES_TRUNCATED,
                "CACHES_TRUNCATED",
                f"{full_name}: collected {len(entries)} of {total} cache entries (most recently "
                f"accessed first). Absence of an entry in this batch is not evidence it is gone.",
                message_data={
                    "repo": full_name,
                    "collected": len(entries),
                    "total": total,
                },
            )

    # ---------- outputs (github-core#31): releases, artifacts, packages ----------

    def _collect_releases(
        self,
        full_name: str,
        repo_uuid: Any,
        dims: dict[str, str],
        ref_uuid_by_ref: dict[str, Any],
        run_index: list[dict[str, Any]],
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
        notes: dict[str, str],
    ) -> str:
        """Emit the repository's releases from the config layer already in hand.

        Returns the surface's observability state. A release is a product of execution riding
        the declaration transport (`req-github-core-releases`): it arrives in the same GraphQL
        response as rulesets and refs at no extra request, but it is stamped `execution` because
        it exists only because someone published it.

        Three edges. `PUBLISHES_RELEASE` is containment. `TARGETS_REF` joins the tag when we
        observed it — both ends carry the commit they resolved to, so a re-tag is a query. And
        `BUILDS_RELEASE` is DERIVED: GitHub records who published a release but never which run,
        so the run is inferred from its tag ref or its head commit and `match_kind` says which.
        """
        gql = self._config.get(full_name)
        if not gql or "releases" not in gql or gql.get("releases") is None:
            # A repos-only scope runs no config-layer query, and a degraded GraphQL field leaves
            # the key absent. Either way we did not look, and the node must say so.
            reason = (
                "the config-layer query did not answer the releases field for this repository"
                if gql
                else "a repos-only scope runs no config-layer query; releases are config-layer data"
            )
            notes["releases"] = reason
            self.record_warn(
                _SITE_RELEASES_UNOBSERVABLE,
                "RELEASES_UNOBSERVABLE",
                f"Releases NOT observed for {full_name} — {reason}. This is not the same as none existing.",
                message_data={"repo": full_name},
            )
            return _UNOBSERVABLE

        releases, missing = GithubGraphQLClient.releases(gql)
        for rel in releases:
            if rel.get("release_id") is None:
                continue
            rel_uuid = release_id(full_name, rel["release_id"])
            tag_name = str(rel.get("tag_name") or "")
            nodes.append(
                node_envelope(
                    entity_id=rel_uuid,
                    entity_type="github_core__github_release",
                    name=rel.get("name") or tag_name or str(rel["release_id"]),
                    dimensions=dims,
                    fields={
                        "release_id": rel["release_id"],
                        "full_name": full_name,
                        "tag_name": tag_name,
                        "name": str(rel.get("name") or ""),
                        "is_draft": rel.get("is_draft"),
                        "is_prerelease": rel.get("is_prerelease"),
                        "is_latest": rel.get("is_latest"),
                        "author_login": str(rel.get("author_login") or ""),
                        "target_sha": str(rel.get("target_sha") or ""),
                        "created_at": rel.get("created_at"),
                        "published_at": rel.get("published_at"),
                        "html_url": str(rel.get("html_url") or ""),
                        "asset_count": rel.get("asset_count"),
                        "assets": list(rel.get("assets") or []),
                        "configuration": {},
                        "tags": {},
                    },
                )
            )
            edges.append(
                self._edge("PUBLISHES_RELEASE__github_core", repo_uuid, rel_uuid, dims)
            )
            ref_uuid = (
                ref_uuid_by_ref.get(f"refs/tags/{tag_name}") if tag_name else None
            )
            if ref_uuid is not None:
                edges.append(
                    self._edge(
                        "TARGETS_REF__github_core",
                        rel_uuid,
                        ref_uuid,
                        dims,
                        properties={"tag_name": tag_name},
                    )
                )
            target_sha = str(rel.get("target_sha") or "")
            for run in run_index:
                match_kind = self._release_match_kind(run, tag_name, target_sha)
                if match_kind is None:
                    continue
                edges.append(
                    self._edge(
                        "BUILDS_RELEASE__github_core",
                        run["uuid"],
                        rel_uuid,
                        dims,
                        properties={
                            "match_kind": match_kind,
                            "head_sha": run["head_sha"],
                        },
                    )
                )
        if missing > 0:
            self.record_warn(
                _SITE_RELEASES_TRUNCATED,
                "RELEASES_TRUNCATED",
                f"{full_name}: collected {len(releases)} of {len(releases) + missing} releases (newest "
                f"first). Absence of a release in this batch is not evidence it was deleted.",
                message_data={
                    "repo": full_name,
                    "collected": len(releases),
                    "missing": missing,
                },
            )
        return _OBSERVED

    @staticmethod
    def _release_match_kind(
        run: dict[str, Any], tag_name: str, target_sha: str
    ) -> str | None:
        """How a run relates to a release as its producer, or ``None`` when it does not.

        `tag_ref` — the run's `head_branch` IS the tag: a tag-push build, the strongest signal
        GitHub offers. `same_commit` — the run built the commit the tag resolves to: co-location,
        which every workflow that ran on that push shares. A run triggered BY the release
        (`event: release`) consumed it and is never its producer.
        """
        if run["event"] == "release":
            return None
        if tag_name and run["head_branch"] == tag_name:
            return "tag_ref"
        if target_sha and run["head_sha"] == target_sha:
            return "same_commit"
        return None

    def _collect_artifacts(
        self,
        client: GithubClient,
        full_name: str,
        repo_uuid: Any,
        dims: dict[str, str],
        run_index: list[dict[str, Any]],
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
        notes: dict[str, str],
    ) -> str:
        """Collect the repository's artifacts and join each to the run that uploaded it.

        Returns the surface's observability state for the repository node (github-core#31:
        three states on the node the absence is about). REST-only (`req-github-core-artifacts`):
        GraphQL exposes no artifacts.

        The repository listing rather than the per-run endpoint: one call per page instead of
        one per run, and each item names its producing run, so `UPLOADS_ARTIFACT` is exact —
        GitHub's own attribution, which is why it is reported where `BUILDS_RELEASE` is derived.
        The edge is emitted only when that run is in this batch — the dangling-edge guard would
        otherwise drop it silently — and the rest are COUNTED, because an artifact of a run
        outside the collected window is a normal thing, not an error and not nothing. Every
        artifact hangs off the repository (`STORES_ARTIFACT`), so one whose run is outside the
        window stays reachable.

        Expired artifacts stay listed with `expired: true`, which is why expiry is a field and
        absence from the listing is never read as expiry (github-core#14, shape C).
        """
        try:
            payload = client.get(
                f"/repos/{full_name}/actions/artifacts",
                params={"per_page": str(_ARTIFACT_LIMIT_PER_REPO)},
            )
        except GithubAPIError as exc:
            if exc.status in (403, 404):
                notes["artifacts"] = f"the artifact listing answered {exc.status}"
                self.record_warn(
                    _SITE_ARTIFACTS_DEGRADED,
                    f"ARTIFACTS_UNREADABLE_{exc.status}",
                    f"Artifact list inaccessible for {full_name}: {exc.body[:120]}. An empty artifact set "
                    f"for this repository is NOT observable, not empty.",
                    message_data={"repo": full_name, "status": exc.status},
                )
                return _UNOBSERVABLE
            raise
        run_uuid_by_id = {run["run_id"]: run["uuid"] for run in run_index}
        entries = payload.get("artifacts") or []
        total = int(payload.get("total_count") or len(entries))
        linked = 0
        expired = 0
        for entry in entries:
            run_id_int = (entry.get("workflow_run") or {}).get("id")
            in_batch = run_id_int in run_uuid_by_id
            expired += int(bool(entry.get("expired", False)))
            nodes.append(self._artifact_node(full_name, entry, in_batch, dims))
            art_uuid = actions_artifact_id(full_name, entry["id"])
            edges.append(
                self._edge("STORES_ARTIFACT__github_core", repo_uuid, art_uuid, dims)
            )
            if in_batch:
                linked += 1
                edges.append(
                    self._edge(
                        "UPLOADS_ARTIFACT__github_core",
                        run_uuid_by_id[run_id_int],
                        art_uuid,
                        dims,
                    )
                )
        if entries:
            self.record_info(
                _SITE_ARTIFACTS_COLLECTED,
                "ARTIFACTS_COLLECTED",
                f"{full_name}: {len(entries)} artifact(s), {linked} linked to a run in this batch, "
                f"{len(entries) - linked} from runs outside the collected window, {expired} expired.",
                message_data={
                    "repo": full_name,
                    "collected": len(entries),
                    "linked": linked,
                    "unlinked": len(entries) - linked,
                    "expired": expired,
                },
            )
        if total > len(entries):
            self.record_warn(
                _SITE_ARTIFACTS_TRUNCATED,
                "ARTIFACTS_TRUNCATED",
                f"{full_name}: collected {len(entries)} of {total} artifacts (newest first). Absence of an "
                f"artifact in this batch is not evidence it is gone or expired.",
                message_data={
                    "repo": full_name,
                    "collected": len(entries),
                    "total": total,
                },
            )
        return _OBSERVED

    def _collect_packages(
        self,
        client: GithubClient,
        owner: str | None,
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
        *,
        repo_filtered: bool = False,
    ) -> tuple[str, str]:
        """Emit the account's packages and their versions; return ``(state, note)``.

        ``repo_filtered`` is true when the envelope names an explicit `repos` include-filter. The
        packages API is account-scoped, so the listing is still one call per type — but under a
        filter only packages GitHub links to a COLLECTED repository land, and the rest are counted
        in the note rather than inventoried. A repo-scoped envelope asked for those repositories'
        outputs, not the account's supply-chain inventory (PR #50 review).

        GitHub Packages is REST-only and, per GitHub's own OpenAPI description, its endpoints are
        `enabledForGitHubApps: false` (`req-github-core-packages`). Measured 2026-09-02 with an App
        installation token: `package_type=container` answers 400 while the org's ghcr.io images
        exist; `npm`/`maven`/`docker` answer 200 `[]`. So under an App credential an EMPTY listing
        proves nothing — the same asymmetry as bypass actors: a filtered answer cannot invent a
        package, so a non-empty one proves itself and an empty one is unobservable. The token,
        when placed, is routed here for exactly that reason.
        """
        if owner is None:
            return (
                _UNOBSERVABLE,
                "packages are an account surface; a repos-only scope names no account",
            )
        pat_client = self._pat_client
        listing_client = pat_client or client
        account_uuid = account_id(owner)
        dims = {
            "git.host": _PLATFORM_HOST,
            "github.owner": owner,
            "github.surface": "packages",
            "github.observation": "execution",
        }
        unobservable: dict[str, str] = {}
        collected = 0
        filtered_out = 0
        for package_type in _PACKAGE_TYPES:
            packages, outcome, scope = self._list_packages(
                listing_client, owner, package_type
            )
            if outcome:
                unobservable[package_type] = outcome
            elif not packages and pat_client is None:
                # 200 [] from a credential the description says cannot use the endpoint.
                unobservable[package_type] = (
                    "empty answer under an App credential, which GitHub does not enable for this endpoint"
                )
            for pkg in packages:
                linked = str((pkg.get("repository") or {}).get("full_name") or "")
                if repo_filtered and linked not in self._repo_envelopes:
                    filtered_out += 1
                    continue
                collected += 1
                self._emit_package(
                    listing_client,
                    owner,
                    scope,
                    account_uuid,
                    package_type,
                    pkg,
                    dims,
                    nodes,
                    edges,
                )
        if collected:
            self.record_info(
                _SITE_PACKAGES_COLLECTED,
                "PACKAGES_COLLECTED",
                f"{collected} package(s) under {owner}.",
                message_data={
                    "owner": owner,
                    "count": collected,
                    "unobservable_types": sorted(unobservable),
                },
            )
        note = self._packages_note(
            unobservable, filtered_out, app_only=pat_client is None
        )
        if not unobservable:
            return _OBSERVED, note
        self.record_warn(
            _SITE_PACKAGES_UNOBSERVABLE,
            "PACKAGES_UNOBSERVABLE",
            f"Packages NOT observed for {owner} on {len(unobservable)} of {len(_PACKAGE_TYPES)} package "
            f"type(s) — which is not the same as none published. {note}",
            message_data={
                "owner": owner,
                "unobservable": unobservable,
                "collected": collected,
            },
        )
        return _UNOBSERVABLE, note

    @staticmethod
    def _packages_note(
        unobservable: dict[str, str], filtered_out: int, *, app_only: bool
    ) -> str:
        """The operator-facing qualifier for the packages state: what was not seen, and why."""
        parts = [f"{t}: {why}" for t, why in unobservable.items()]
        if filtered_out:
            parts.append(
                f"{filtered_out} package(s) not linked to a collected repository were omitted under the repos filter"
            )
        note = "; ".join(parts)
        if unobservable and app_only:
            note += (
                ". GitHub's OpenAPI description marks the packages endpoints enabledForGitHubApps: false; "
                "a classic personal access token with read:packages is the credential GitHub documents"
            )
        return note

    def _list_packages(
        self, client: GithubClient, owner: str, package_type: str
    ) -> tuple[list[dict[str, Any]], str, str]:
        """One package-type listing: ``(items, reason, scope)``.

        ``reason`` is empty on an answer and names the refusal otherwise; ``scope`` is ``orgs`` or
        ``users`` — whichever path answered, so the versions call follows the same one. 400 is a
        refusal alongside 403/404 because it is what the endpoint returns an App installation
        token for `container` — measured, not assumed.
        """
        params = {
            "package_type": package_type,
            "per_page": str(_PACKAGE_LIMIT_PER_TYPE),
        }
        for scope in ("orgs", "users"):
            try:
                return (
                    client.get_paginated(
                        f"/{scope}/{owner}/packages", params=params, max_pages=1
                    ),
                    "",
                    scope,
                )
            except GithubAPIError as exc:
                if exc.status == 404 and scope == "orgs":
                    continue  # a user account: fall through to the user path
                if exc.status in (400, 403, 404):
                    self.record_warn(
                        _SITE_PACKAGES_UNREADABLE,
                        f"PACKAGES_UNREADABLE_{exc.status}",
                        f"Package listing ({package_type}) refused for {owner}: {exc.status} {exc.body[:120]}",
                        message_data={
                            "owner": owner,
                            "package_type": package_type,
                            "status": exc.status,
                        },
                    )
                    return [], f"listing answered {exc.status}", scope
                raise
        return (
            [],
            "listing answered 404 on both the organization and user paths",
            "users",
        )

    def _emit_package(
        self,
        client: GithubClient,
        owner: str,
        scope: str,
        account_uuid: Any,
        package_type: str,
        pkg: dict[str, Any],
        dims: dict[str, str],
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
    ) -> None:
        """One package node, its owner/repository edges, its versions, and the run joins."""
        name = str(pkg.get("name") or "")
        if not name:
            return
        pkg_uuid = package_id(owner, package_type, name)
        linked_repo = str((pkg.get("repository") or {}).get("full_name") or "")
        version_count = pkg.get("version_count")
        nodes.append(
            node_envelope(
                entity_id=pkg_uuid,
                entity_type="github_core__github_package",
                name=f"{owner}/{name}",
                dimensions=dims,
                fields={
                    "package_id": pkg.get("id"),
                    "owner_login": owner,
                    "package_type": package_type,
                    "name": name,
                    "purl": package_purl(package_type, owner, name),
                    "visibility": str(pkg.get("visibility") or ""),
                    "version_count": version_count,
                    "repository_full_name": linked_repo,
                    "html_url": str(pkg.get("html_url") or ""),
                    "created_at": pkg.get("created_at"),
                    "updated_at": pkg.get("updated_at"),
                    "configuration": {},
                    "tags": {},
                },
            )
        )
        edges.append(
            self._edge(
                "PUBLISHES_PACKAGE__github_core",
                account_uuid,
                pkg_uuid,
                dims,
                properties={"link_kind": "owner"},
            )
        )
        if linked_repo in self._repo_envelopes:
            edges.append(
                self._edge(
                    "PUBLISHES_PACKAGE__github_core",
                    repository_id(linked_repo),
                    pkg_uuid,
                    dims,
                    properties={"link_kind": "repository"},
                )
            )
        # Which runs a version may be matched against: ONLY the repository GitHub links the package
        # to. An unlinked package gets no `BUILDS_PACKAGE_VERSION` at all — a seven-hex prefix
        # searched across every collected repository's runs would let one repository's tag join
        # another repository's run, and a false producer edge hides exactly the shape the edge
        # exists to reveal (PR #50 review). Unlinked is recorded on the package, not guessed at.
        candidate_runs = self._run_index.get(linked_repo, []) if linked_repo else []
        try:
            versions = client.get_paginated(
                f"/{scope}/{owner}/packages/{package_type}/{name}/versions",
                params={"per_page": str(_PACKAGE_VERSION_LIMIT)},
                max_pages=1,
            )
        except GithubAPIError as exc:
            if exc.status in (400, 403, 404):
                self.record_warn(
                    _SITE_PACKAGE_VERSIONS_DEGRADED,
                    f"PACKAGE_VERSIONS_UNREADABLE_{exc.status}",
                    f"Versions of {owner}/{name} ({package_type}) refused: {exc.status} {exc.body[:120]}",
                    message_data={
                        "owner": owner,
                        "package": name,
                        "package_type": package_type,
                        "status": exc.status,
                    },
                )
                return
            raise
        for version in versions:
            self._emit_package_version(
                owner,
                package_type,
                name,
                pkg_uuid,
                version,
                candidate_runs,
                dims,
                nodes,
                edges,
            )
        if version_count is not None and int(version_count) > len(versions):
            self.record_warn(
                _SITE_PACKAGE_VERSIONS_TRUNCATED,
                "PACKAGE_VERSIONS_TRUNCATED",
                f"{owner}/{name}: collected {len(versions)} of {version_count} versions (newest first). "
                f"Absence of a version in this batch is not evidence it was deleted.",
                message_data={
                    "owner": owner,
                    "package": name,
                    "collected": len(versions),
                    "total": version_count,
                },
            )

    def _emit_package_version(
        self,
        owner: str,
        package_type: str,
        name: str,
        pkg_uuid: Any,
        version: dict[str, Any],
        candidate_runs: list[dict[str, Any]],
        dims: dict[str, str],
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
    ) -> None:
        """One version node, its containment edge, and — when a tag says so — the run that built it."""
        version_name = str(version.get("name") or "")
        ver_uuid = package_version_id(owner, package_type, name, version["id"])
        container_tags = list(
            ((version.get("metadata") or {}).get("container") or {}).get("tags") or []
        )
        nodes.append(
            node_envelope(
                entity_id=ver_uuid,
                entity_type="github_core__github_package_version",
                name=f"{name}@{version_name[:19] if version_name.startswith('sha256:') else version_name}",
                dimensions=dims,
                fields={
                    "version_id": version["id"],
                    "owner_login": owner,
                    "package_type": package_type,
                    "package_name": name,
                    "version": version_name,
                    "purl": package_purl(package_type, owner, name, version_name),
                    "container_tags": container_tags,
                    "html_url": str(version.get("html_url") or ""),
                    "created_at": version.get("created_at"),
                    "updated_at": version.get("updated_at"),
                    "configuration": {},
                    "tags": {},
                },
            )
        )
        edges.append(
            self._edge(
                "PUBLISHES_PACKAGE_VERSION__github_core", pkg_uuid, ver_uuid, dims
            )
        )
        # BUILDS_PACKAGE_VERSION, derived from the `sha-<short>` tag convention. Its ABSENCE is the
        # corpus's finding — but only once `match_kind` has been read, because a version tagged any
        # other way carries no edge for a reason that is a limit of this derivation, not evidence.
        # And its PRESENCE is a claim by whoever tagged the image, not by GitHub: anyone with push
        # to the registry can tag a digest `sha-<anything>`. The edge says `match_kind: tag_sha`
        # and `attested: null` so a reader knows that; an attestation surface is what upgrades it.
        shas = {
            tag[len(_CONTAINER_TAG_SHA_PREFIX) :].lower()
            for tag in container_tags
            if tag.startswith(_CONTAINER_TAG_SHA_PREFIX)
            and _CONTAINER_TAG_SHA_MIN_HEX
            <= len(tag) - len(_CONTAINER_TAG_SHA_PREFIX)
            <= 40
            and all(
                c in "0123456789abcdef"
                for c in tag[len(_CONTAINER_TAG_SHA_PREFIX) :].lower()
            )
        }
        if not shas:
            return
        for run in candidate_runs:
            head_sha = run["head_sha"].lower()
            if head_sha and any(head_sha.startswith(short) for short in shas):
                edges.append(
                    self._edge(
                        "BUILDS_PACKAGE_VERSION__github_core",
                        run["uuid"],
                        ver_uuid,
                        dims,
                        properties={"match_kind": "tag_sha", "attested": None},
                    )
                )

    @staticmethod
    def _artifact_node(
        full_name: str, entry: dict[str, Any], in_batch: bool, dims: dict[str, str]
    ) -> dict[str, Any]:
        """One artifact envelope from a listing item. `run_in_batch` says whether the
        UPLOADS_ARTIFACT edge exists or the join is by `run_id` against the grid."""
        run = entry.get("workflow_run") or {}
        return node_envelope(
            entity_id=actions_artifact_id(full_name, entry["id"]),
            entity_type="github_core__actions_artifact",
            name=str(entry.get("name") or entry["id"]),
            dimensions=dims,
            fields={
                "full_name": full_name,
                "artifact_id": entry["id"],
                "name": str(entry.get("name") or ""),
                "size_in_bytes": entry.get("size_in_bytes"),
                "digest": str(entry.get("digest") or ""),
                "expired": bool(entry.get("expired", False)),
                "expires_at": entry.get("expires_at"),
                "created_at": entry.get("created_at"),
                "updated_at": entry.get("updated_at"),
                "run_id": run.get("id"),
                "head_sha": str(run.get("head_sha") or ""),
                "head_branch": str(run.get("head_branch") or ""),
                "configuration": {"workflow_run": run, "run_in_batch": in_batch},
                "tags": {},
            },
        )

    def _collect_installation_selection(self, client: GithubClient) -> dict[str, Any]:
        """Record which repositories this run's credential may reach (github-core#141).

        Returns the selection it recorded — the same dict, so the `collection_scope` node carries
        it verbatim (derive a fact once; github-core#145).

        The tombstone candidate rule is *fan-out from the account, minus observed this run, minus
        outside the installation's selection*. The third term is a fact about THIS run's reach —
        an operation, perceived-true-at-a-time, because an org owner can narrow the selection in
        a settings page and nothing tells the collector — so it is recorded on the run rather
        than on the account, and placed verbatim on this run's ``collection_scope`` node
        (github-core#145).

        App: ``GET /installation/repositories`` answered by the installation token about itself,
        walked to the end and reconciled against ``total_count`` — a listed count that disagrees
        with the walked count is ``complete: false``, never a quietly shorter list. PAT, classic or fine-grained: ``unknown`` — a fine-grained grant is not introspectable through any
        API, and a classic token's scopes do not establish its effective reach — so a falsifier
        treats it as cannot-weigh-in (fail closed). The token value is inspected for its prefix
        only and never recorded.
        """
        if not self._auth.has_app:
            # A PAT's reach is UNKNOWN until measured, classic or fine-grained (Codex on PR #144):
            # a classic token may lack `repo`, be outside the org, or be SSO-blocked, so "all by
            # construction" was a claim about scopes, not about reach. Its scopes are in fact
            # introspectable — every response carries `X-OAuth-Scopes` — but this client returns
            # bodies only; reliability 1a's gather exposes headers, and that is where `all` can be
            # earned. Until then: unknown, and a falsifier treats unknown as cannot-weigh-in.
            token_kind = "fine_grained" if self._auth.token(prefer=PREFER_PAT).startswith("github_pat_") else "classic"
            selection: dict[str, Any] = {
                "credential": "pat",
                "token_kind": token_kind,
                "kind": "unknown",
                "repository_ids": None,
                "count": None,
                "total_count": None,
                "complete": False,
            }
            self.record_info(
                _SITE_INSTALLATION_SELECTION,
                "INSTALLATION_SELECTION",
                f"Personal access token only ({token_kind}): repository selection is unknown — "
                + (
                    "a fine-grained token's grant is not introspectable through any API"
                    if token_kind == "fine_grained"
                    else "a classic token's effective reach is not established by its scopes alone"
                )
                + "; absence cannot be weighed against it.",
                message_data=selection,
            )
            return selection
        declared = str((self._auth.installation or {}).get("repository_selection") or "")
        try:
            first = client.get("/installation/repositories", params={"per_page": "100"})
            rows = client.get_paginated(
                "/installation/repositories",
                params={"per_page": "100"},
                item_path="repositories",
            )
        except GithubAPIError as exc:
            # The full selection shape, with every observed-nothing field null and `complete`
            # false, so the node reads "declared X, members unobserved" rather than "no
            # selection" — a refused listing must never look like an empty one.
            selection = {
                "credential": "app",
                "kind": declared or "unknown",
                "repository_ids": None,
                "count": None,
                "total_count": None,
                "complete": False,
                "status": exc.status,
            }
            self.record_warn(
                _SITE_INSTALLATION_SELECTION_UNREADABLE,
                f"INSTALLATION_SELECTION_UNREADABLE_{exc.status}",
                f"Cannot list this installation's repositories ({exc.status}); the selection is "
                f"declared {declared or 'unknown'} but its members are unobserved this run — "
                f"absence cannot be weighed against it.",
                message_data=selection,
            )
            return selection
        total = first.get("total_count") if isinstance(first, dict) else None
        ids = [int(r["id"]) for r in rows if isinstance(r, dict) and r.get("id") is not None]
        walk_complete = bool(client.last_walk_complete)
        # Fail closed (Codex on PR #144): a response without `total_count` cannot be reconciled,
        # and an unreconciled selection is not one a tombstone pass may weigh absence against.
        complete = walk_complete and isinstance(total, int) and total == len(ids)
        selection = {
            "credential": "app",
            "kind": declared or "unknown",
            "repository_ids": ids,
            "count": len(ids),
            "total_count": total,
            "complete": complete,
        }
        self.record_info(
            _SITE_INSTALLATION_SELECTION,
            "INSTALLATION_SELECTION",
            f"Installation reaches {len(ids)} repositor{'y' if len(ids) == 1 else 'ies'} "
            f"(selection {declared or 'unknown'}; GitHub reports {total}; "
            f"{'complete' if complete else 'INCOMPLETE — absence cannot be weighed against it'}).",
            message_data=selection,
        )
        return selection

    def _collect_plan(self, client: GithubClient, owner: str | None) -> tuple[str, str]:
        """The account's plan and where it came from — a scope INPUT (the audit log is
        Enterprise-only), read from the organization detail this run fetches once and reuses
        when the account node is minted. `unknown` whenever it could not be read; the second
        value says why (`observed` / `public_only` / `unobservable` / `not_applicable` /
        `no_owner`) so unknown-because-refused and unknown-because-user-account never merge."""
        if owner is None:
            return "unknown", "no_owner"
        if not self._account_type:
            # Resolved once for the run; the Actions-policy read below reuses it. A user account
            # has no organization detail and must not be asked for one. A refusal here leaves
            # the kind unresolved for the later reads to handle as they always have — the scope
            # node still lands, with the plan honestly unknown.
            try:
                self._account_type = str(self._fetch_account(client, owner).get("type") or "")
            except GithubAPIError:
                return "unknown", _UNOBSERVABLE
        if self._account_type != "Organization":
            return "unknown", _NOT_APPLICABLE
        if self._org_detail_state == "":
            self._org_detail, self._org_detail_state = self._fetch_org_detail(client, owner)
        return plan_from_org_detail(self._org_detail), self._org_detail_state

    def _emit_collection_scope(
        self, client: GithubClient, owner: str | None, selection: dict[str, Any]
    ) -> None:
        """Land this run's `collection_scope` node before the walk (github-core#145).

        Its own batch, submitted now rather than with the main batch at the end of the run,
        because the node must EXIST while the run is in progress: reliability 1b (github-core#136)
        patches a tier verdict onto it at each tier's end, and a run that dies mid-way must leave
        the earlier verdicts behind. `SCOPES_RUN` targets the core `collection_job` entity, which
        `run_collection` created before this collector started, so the edge resolves against the
        grid under strict dangling-edge mode. The installation edge is NOT here: it lands with
        the main batch, beside the installation node the inventory mints — and not at all when
        that inventory could not be read, so it is never a guess.

        `visibility` and `tiers` are emitted EMPTY: they are declared, described seams for the
        visibility assessment (github-core#15) and reliability 1b, which write into them through
        the service layer.
        """
        installation = self._auth.installation if self._auth.has_app else None
        inst_id = (installation or {}).get("id")
        plan, plan_source = self._collect_plan(client, owner)
        manifest = load_collection_manifest()
        sources = manifest.get("sources")
        scope_uuid = collection_scope_id(self.config.collection_job_entity_id)
        observed_at = self._scope_observed_at
        node = node_envelope(
            entity_id=scope_uuid,
            entity_type="github_core__collection_scope",
            name=f"collection scope @ {observed_at:%Y-%m-%dT%H:%M:%SZ}",
            dimensions={**_PLATFORM_DIMENSIONS, "github.observation": "execution"},
            fields={
                "run_id": str(self.config.collection_job_entity_id),
                "observed_at": observed_at.isoformat().replace("+00:00", "Z"),
                "credential_kinds": list(self._auth.held),
                "installation_id": int(inst_id) if inst_id is not None else None,
                "selection": selection,
                "plan": plan,
                "visibility": {},
                "tiers": {},
                "configuration": {
                    "manifest": {
                        "version": str(manifest.get("manifest_version") or ""),
                        "sha256": collection_manifest_digest(),
                        "sources": len(sources) if isinstance(sources, list | dict) else 0,
                    },
                    "installation": (
                        {
                            "app_id": installation.get("app_id"),
                            "permissions": dict(installation.get("permissions") or {}),
                            "repository_selection": str(
                                installation.get("repository_selection") or ""
                            ),
                            "events": list(installation.get("events") or []),
                            "suspended": installation.get("suspended_at") is not None,
                        }
                        if installation is not None
                        else None
                    ),
                    "plan_source": plan_source,
                },
                "tags": {},
            },
        )
        job_uuid = self.config.collection_job_entity_id
        edge = edge_envelope(
            entity_id=edge_id("SCOPES_RUN__github_core", scope_uuid, job_uuid),
            edge_type="SCOPES_RUN__github_core",
            source_id=scope_uuid,
            target_id=job_uuid,
            dimensions={**_PLATFORM_DIMENSIONS, "github.observation": "execution"},
        )
        batch_dims = {"git.host": _PLATFORM_HOST}
        if owner is not None:
            batch_dims["github.owner"] = owner
        result = self.submit_grift(
            assemble_batch(
                batch_name=f"github_core collection scope: {owner or 'explicit repositories'}",
                description=(
                    "What this run's credential was allowed to weigh in on, established before "
                    "the walk (github-core#145)."
                ),
                nodes=[node],
                edges=[edge],
                batch_dimensions=batch_dims,
            )
        )
        # THE BATCH BOUNDARY (Issue# 162). The scope node rides its own batch and its ref dies
        # with it; the main batch, submitted at the end of the run, names the scope as the
        # source of `DERIVED_FROM_INSTALLATION`, and the reliability seam patches tier verdicts
        # onto it through the service layer. Both need the id core ASSIGNED, which the import
        # result is the one place to learn. A run whose batch did not import leaves this None,
        # and `_append_scope_installation_edge` already declines to guess on None.
        self._scope_uuid = self._assigned_id(result, scope_uuid)
        self.record_info(
            _SITE_COLLECTION_SCOPE,
            "COLLECTION_SCOPE_ESTABLISHED",
            f"Scope established for this run: credentials {', '.join(self._auth.held) or 'none'}; "
            f"selection {selection.get('kind')} "
            f"({'complete' if selection.get('complete') else 'incomplete'}); plan {plan}.",
            message_data={
                "scope_id": str(self._scope_uuid or scope_uuid),
                "installation_id": int(inst_id) if inst_id is not None else None,
                "selection_kind": selection.get("kind"),
                "complete": bool(selection.get("complete")),
                "plan": plan,
                "plan_source": plan_source,
            },
        )

    def _append_scope_installation_edge(self, edges: list[dict[str, Any]]) -> None:
        """`DERIVED_FROM_INSTALLATION` from this run's scope to the installation whose grant it
        read — only when that installation's node was minted this run, so the edge never dangles
        and never guesses (github-core#145). PAT-only runs have no installation to derive from."""
        if self._scope_uuid is None or not self._auth.has_app:
            return
        inst_id = (self._auth.installation or {}).get("id")
        if inst_id is None:
            return
        inst_uuid = app_installation_id(inst_id)
        if str(inst_uuid) not in self._emitted_installation_ids:
            return
        edges.append(
            edge_envelope(
                entity_id=edge_id("DERIVED_FROM_INSTALLATION__github_core", self._scope_uuid, inst_uuid),
                edge_type="DERIVED_FROM_INSTALLATION__github_core",
                source_id=self._scope_uuid,
                target_id=inst_uuid,
                dimensions={
                    **_PLATFORM_DIMENSIONS,
                    "github.surface": "apps",
                    "github.observation": "execution",
                },
            )
        )

    def _collect_app_installations(
        self,
        client: GithubClient,
        owner: str | None,
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
    ) -> None:
        """Emit the App inventory — application, installation, and the account it was granted on.

        **Which endpoint answers this matters more than it looks.** `/app/installations` answers
        "where is THIS App installed" — one row, about ourselves. `/orgs/{owner}/installations`
        answers "which Apps can reach this account's repositories", which is the question the
        product exists to ask, and it is App-only: a personal access token gets `404`. We ask the
        account first and fall back to our own installation, saying which we got, because an
        inventory of one is not an inventory.

        In PAT mode nothing is emitted and, crucially, nothing is CLAIMED: an empty inventory from
        a token means the surface was unreachable, not that no Apps are installed.
        """
        if not self._auth.has_app:
            self.record_info(
                _SITE_INSTALLATIONS_UNREACHABLE,
                "APP_INVENTORY_UNREACHABLE",
                "No App credential in the envelope: the installed-App inventory is an App-only "
                "surface and was not collected. This is not an observation that no Apps are "
                "installed — "
                + (self._auth.absent_note(PREFER_APP) or "add an App to see it")
                + ".",
                message_data={"held": self._auth.held},
            )
            return
        scope = "account"
        installations: list[dict[str, Any]] = []
        if owner is not None:
            try:
                installations = client.get_paginated(
                    f"/orgs/{owner}/installations", item_path="installations"
                )
            except GithubAPIError as exc:
                self.record_warn(
                    _SITE_INSTALLATIONS_UNREACHABLE,
                    f"APP_INVENTORY_PARTIAL_{exc.status}",
                    f"Cannot list the Apps installed on {owner} ({exc.status}) — this credential "
                    f"lacks organization administration read, so only THIS App's own installation "
                    f"is recorded. The absence of other Apps below is not evidence there are none.",
                    message_data={"owner": owner, "status": exc.status},
                )
                scope = "self_only"
        if not installations:
            try:
                installations = self._auth.installations()
                scope = (
                    "account" if scope == "account" and owner is None else "self_only"
                )
            except GithubAppAuthError as exc:
                self.record_warn(
                    _SITE_INSTALLATIONS_UNREACHABLE,
                    "APP_INVENTORY_FAILED",
                    f"Installed-App inventory unreadable: {exc}",
                )
                return
        apps_dims = {**_PLATFORM_DIMENSIONS, "github.surface": "apps"}
        for installation in installations:
            inst_id = installation.get("id")
            if inst_id is None:
                continue
            slug = str(installation.get("app_slug") or "")
            account = installation.get("account") or {}
            account_login = str(account.get("login") or "")
            inst_uuid = app_installation_id(inst_id)
            if str(inst_uuid) in self._emitted_installation_ids:
                continue
            self._emitted_installation_ids.add(str(inst_uuid))
            nodes.append(
                node_envelope(
                    entity_id=inst_uuid,
                    entity_type="github_core__app_installation",
                    name=(
                        f"{slug} @ {account_login}"
                        if slug and account_login
                        else str(inst_id)
                    ),
                    dimensions=apps_dims,
                    fields={
                        "installation_id": inst_id,
                        "app_id": installation.get("app_id"),
                        "app_slug": slug,
                        "account_login": account_login,
                        "target_type": str(installation.get("target_type") or ""),
                        "repository_selection": str(
                            installation.get("repository_selection") or ""
                        ),
                        "permissions": dict(installation.get("permissions") or {}),
                        "events": list(installation.get("events") or []),
                        "suspended": installation.get("suspended_at") is not None,
                        "installed_at": installation.get("created_at"),
                        "html_url": str(installation.get("html_url") or ""),
                        "configuration": {},
                        "tags": {},
                    },
                )
            )
            if slug:
                app_uuid = github_app_id(slug)
                if str(app_uuid) not in self._emitted_app_ids:
                    self._emitted_app_ids.add(str(app_uuid))
                    nodes.append(
                        node_envelope(
                            entity_id=app_uuid,
                            entity_type="github_core__github_app",
                            name=slug,
                            dimensions=apps_dims,
                            fields={
                                "slug": slug,
                                "name": slug,
                                "app_id": installation.get("app_id"),
                                "client_id": str(installation.get("client_id") or ""),
                                "html_url": f"https://github.com/apps/{slug}",
                                "description": "",
                                "configuration": {},
                                "tags": {},
                            },
                        )
                    )
                edges.append(
                    self._edge(
                        "REGISTERS_INSTALLATION__github_core",
                        app_uuid,
                        inst_uuid,
                        apps_dims,
                    )
                )
            if account_login:
                edges.append(
                    self._edge(
                        "INSTALLED_ON_ACCOUNT__github_core",
                        inst_uuid,
                        account_id(account_login),
                        apps_dims,
                    )
                )
        self.record_info(
            _SITE_INSTALLATIONS_COLLECTED,
            "APP_INVENTORY_COLLECTED",
            f"Collected {len(installations)} App installation(s)"
            + (
                " on this account."
                if scope == "account"
                else " — THIS App's own only; the account-wide inventory was unreadable."
            ),
            message_data={"installations": len(installations), "scope": scope},
        )

    def _collect_custom_properties(
        self,
        client: GithubClient,
        owner: str | None,
        nodes: list[dict[str, Any]],
    ) -> str:
        """Emit the organization's custom-property definitions and stamp every repository's values.

        Returns the surface's observability state, which is also written onto every collected
        repository envelope as `custom_properties_observability` beside its `custom_properties` map.

        Two endpoints, both organization-scoped and both at `organization:custom_properties:read`.
        The schema (`/orgs/{owner}/properties/schema`) is the DEFINITIONS — one node each — and it
        is what makes a repository's unset value a fact: the values map is built over the
        declared names first, so a property the organization declares and a repository never set
        lands as `null` (observed-unset), not as an absent key. The values listing
        (`/orgs/{owner}/properties/values`) then overlays what each repository carries.

        Custom properties exist only on organizations. A user account has no schema endpoint at
        all, so for one the surface is SKIPPED and every repository keeps `""` — never looked —
        rather than `unobservable`, which would say a credential was refused when there was
        nothing to ask. A refusal on an organization IS `unobservable`: an empty map after a 403
        is the most reassuring possible reading of a permission failure, and the state on the
        node is what stops a view rendering it as "nothing set" (the ruling of
        `github_ruleset.bypass_observability`, applied here).
        """
        if owner is None:
            self.record_info(
                _SITE_CUSTOM_PROPERTIES_SKIPPED,
                "CUSTOM_PROPERTIES_SKIPPED",
                "Custom properties are an account surface; a repos-only scope names no account, so "
                "they were not collected.",
            )
            return ""
        if self._account_type and self._account_type != "Organization":
            self.record_info(
                _SITE_CUSTOM_PROPERTIES_SKIPPED,
                "CUSTOM_PROPERTIES_SKIPPED",
                f"{owner} is a {self._account_type} account; custom properties exist only on "
                f"organizations, so the surface was not asked.",
                message_data={"owner": owner, "account_type": self._account_type},
            )
            return ""
        try:
            definitions = client.get_paginated(f"/orgs/{owner}/properties/schema")
        except GithubAPIError as exc:
            state = _UNOBSERVABLE
            self.record_warn(
                _SITE_CUSTOM_PROPERTIES_UNOBSERVABLE,
                f"CUSTOM_PROPERTIES_UNOBSERVABLE_{exc.status}",
                f"Custom-property definitions for {owner} unreadable ({exc.status}) — every "
                f"repository's properties are NOT observed, which is not the same as none being set. "
                f"The credential needs organization custom-properties read.",
                message_data={"owner": owner, "status": exc.status},
            )
            self._stamp_custom_properties(owner, state, {})
            return state
        try:
            rows = client.get_paginated(f"/orgs/{owner}/properties/values", params={"per_page": "100"})
        except GithubAPIError as exc:
            state = _UNOBSERVABLE
            self.record_warn(
                _SITE_CUSTOM_PROPERTIES_VALUES_UNOBSERVABLE,
                f"CUSTOM_PROPERTIES_VALUES_UNOBSERVABLE_{exc.status}",
                f"Custom-property VALUES for {owner} unreadable ({exc.status}) while the "
                f"definitions were; the definitions land, no repository's values do.",
                message_data={"owner": owner, "status": exc.status},
            )
            rows = []
        else:
            state = _OBSERVED
        dims = {**GithubCustomProperty.DEFAULT_DIMENSIONS, "github.owner": owner}
        names: list[str] = []
        for definition in definitions:
            name = str(definition.get("property_name") or "")
            if not name:
                continue
            names.append(name)
            nodes.append(
                node_envelope(
                    entity_id=custom_property_id(owner, name),
                    entity_type=GithubCustomProperty.ENTITY_TYPE,
                    name=name,
                    dimensions=dims,
                    fields={
                        "owner_login": owner,
                        "property_name": name,
                        "value_type": str(definition.get("value_type") or ""),
                        "required": bool(definition.get("required", False)),
                        "default_value": definition.get("default_value"),
                        "description": str(definition.get("description") or ""),
                        "allowed_values": list(definition.get("allowed_values") or []),
                        "values_editable_by": str(definition.get("values_editable_by") or ""),
                        "source_type": str(definition.get("source_type") or ""),
                        "url": str(definition.get("url") or ""),
                        "configuration": {
                            # Whether GitHub refuses a value outside `allowed_values` at write time.
                            "require_explicit_values": definition.get("require_explicit_values"),
                        },
                        "tags": {},
                    },
                )
            )
        # Built over the declared names FIRST: a declared property a repository never set is
        # observed-unset (null), which an overlay from the values listing alone could not say.
        values_by_repo: dict[str, dict[str, Any]] = {}
        if state == _OBSERVED:
            for row in rows:
                full_name = str(row.get("repository_full_name") or "")
                if not full_name:
                    continue
                values: dict[str, Any] = dict.fromkeys(names)
                for entry in row.get("properties") or []:
                    prop = str(entry.get("property_name") or "")
                    if prop:
                        values[prop] = entry.get("value")
                values_by_repo[full_name] = values
        self._stamp_custom_properties(owner, state, values_by_repo)
        stamped = [name for name in self._repo_envelopes if name in values_by_repo]
        unset = sum(1 for name in stamped for value in values_by_repo[name].values() if value is None)
        self.record_info(
            _SITE_CUSTOM_PROPERTIES_COLLECTED,
            "CUSTOM_PROPERTIES_COLLECTED",
            f"{len(names)} custom property definition(s) under {owner}; values observed on "
            f"{len(stamped)} of {len(self._repo_envelopes)} collected repositories, {unset} "
            f"declared-but-unset value(s)." + ("" if state == _OBSERVED else " Values were NOT observed."),
            message_data={
                "owner": owner,
                "definitions": names,
                "repositories_with_values": len(stamped),
                "unset_values": unset,
                "state": state,
            },
        )
        return state

    def _stamp_custom_properties(
        self,
        owner: str,
        state: str,
        values_by_repo: dict[str, dict[str, Any]],
    ) -> None:
        """Write the surface state and each repository's values map onto its envelope.

        A collected repository the values listing did not mention has values we did NOT observe.
        The listing omits what the credential cannot see there, and an omission is not "all
        unset" — so such a repository is stamped `unobservable` with an empty map and named in a
        warning, while the repositories the listing did report keep `observed` (Codex on PR #81:
        promoting an absent row to observed-unset would be an inference wearing a fact's clothes).
        """
        unlisted: list[str] = []
        for full_name, envelope in self._repo_envelopes.items():
            node = envelope["node"]
            values = values_by_repo.get(full_name) if state == _OBSERVED else None
            if state == _OBSERVED and values is None:
                unlisted.append(full_name)
            node["custom_properties_observability"] = _UNOBSERVABLE if values is None else state
            node["custom_properties"] = values or {}
        if unlisted:
            self.record_warn(
                _SITE_CUSTOM_PROPERTIES_REPOSITORY_UNLISTED,
                "CUSTOM_PROPERTIES_REPOSITORY_UNLISTED",
                f"{len(unlisted)} collected repositor{'y' if len(unlisted) == 1 else 'ies'} absent from "
                f"{owner}'s custom-property values listing — their values are NOT observed, which is not "
                f"the same as none being set: {', '.join(sorted(unlisted))}",
                message_data={"owner": owner, "repositories": sorted(unlisted)},
            )

    def _emit_github_app(
        self,
        app_meta: dict[str, str],
        full_name: str,
        repo_uuid: Any,
        repo_dims: dict[str, str],
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
    ) -> None:
        """Emit a github_app node (deduped, singleton by slug) + ENABLED_ON_REPOSITORY edge
        for a platform app detected enabled on ``full_name``."""
        apps_dims = {**repo_dims, "github.surface": "apps"}
        app_uuid = github_app_id(app_meta["slug"])
        owner = full_name.split("/", 1)[0]
        html_url = app_meta.get("html_url", "")
        if self._account_type == "Organization" and app_meta.get("org_html_url"):
            html_url = app_meta["org_html_url"].format(owner=owner)
        if str(app_uuid) not in self._emitted_app_ids:
            self._emitted_app_ids.add(str(app_uuid))
            nodes.append(
                node_envelope(
                    entity_id=app_uuid,
                    entity_type="github_core__github_app",
                    name=app_meta["name"],
                    dimensions=apps_dims,
                    fields={
                        "slug": app_meta["slug"],
                        "name": app_meta["name"],
                        "app_id": None,
                        "html_url": html_url,
                        "description": app_meta.get("description", ""),
                        "configuration": {},
                        "tags": {},
                    },
                )
            )
        edges.append(
            self._edge(
                "ENABLED_ON_REPOSITORY__github_core", app_uuid, repo_uuid, apps_dims
            )
        )
        self.record_info(
            _SITE_DEPENDABOT_APP,
            "GITHUB_APP_ENABLED",
            f"{app_meta['name']} app detected enabled on {full_name} "
            f"(reclassified from the synthetic Actions workflow entry).",
            message_data={"app_slug": app_meta["slug"], "repo": full_name},
        )

    def _edge(
        self,
        edge_type: str,
        source_uuid: Any,
        target_uuid: Any,
        dimensions: dict[str, str],
        properties: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """One edge envelope. `properties` defaults to empty, which every prior caller wanted."""
        return edge_envelope(
            entity_id=edge_id(edge_type, source_uuid, target_uuid),
            edge_type=edge_type,
            source_id=source_uuid,
            target_id=target_uuid,
            dimensions=dimensions,
            properties=properties or {},
        )

    def _fetch_account(self, client: GithubClient, owner: str) -> dict[str, Any]:
        try:
            return client.get(f"/users/{owner}")
        except GithubAPIError as exc:
            if exc.status == 404:
                # Maybe it's an org; let /orgs handle it (rare for user-owned repos).
                return client.get(f"/orgs/{owner}")
            raise

    # ---------- settings surfaces (req-github-core-settings) ----------

    def _account_configuration(
        self, client: GithubClient | None, account_payload: dict[str, Any]
    ) -> dict[str, Any]:
        """The organization's policy block, verbatim, plus how much of it the credential could see.

        `/users/{login}` answers for an organization too, but with the user-shaped public half
        only; the policy keys (2FA requirement, default repository permission, member privileges,
        security defaults for new repositories) live on `/orgs/{login}` and arrive only for an
        owner or an `organization:administration:read` App. So an organization gets one extra
        call, cached for the run, and `settings_observability` records which half came back:
        `observed` (policy present), `public_only` (answered, no policy key — the credential is
        not an administrator), `unobservable` (refused), `not_applicable` (a user account has
        no organization policy). Values are copied under GitHub's own key names, unrenamed.
        """
        login = str(account_payload.get("login") or "")
        account_type = str(account_payload.get("type") or "")
        if account_type != "Organization":
            return {"settings_observability": _NOT_APPLICABLE}
        if self._org_detail_state == "":
            self._org_detail, self._org_detail_state = self._fetch_org_detail(client, login)
        configuration: dict[str, Any] = {}
        detail = self._org_detail or {}
        for key in (*_ORG_SETTING_KEYS_PUBLIC, *_ORG_SETTING_KEYS_POLICY):
            if key in detail:
                configuration[key] = detail[key]
        configuration["settings_observability"] = self._org_detail_state
        # GitHub has TWO organization 2FA settings: "require two-factor for everyone" (the boolean
        # above) and "only allow secure two-factor methods" (blocks SMS for members and outside
        # collaborators). The second has no REST or GraphQL field at any tier (measured 2026-09-11:
        # 68 keys on /orgs/{org} with an owner App token, none about methods; tap#157 holds the full
        # measurement). It is written here as an explicit ceiling so no view can render the
        # requirement boolean as if it answered the method question: an organization can require
        # 2FA, permit SMS, and read `two_factor_requirement_enabled: true`.
        configuration["two_factor_secure_methods_required"] = None
        configuration["two_factor_methods_observability"] = _UNOBSERVABLE
        if self._org_actions_policy is not None:
            configuration["actions_policy"] = self._org_actions_policy
        configuration["actions_policy_observability"] = self._org_actions_policy_state
        return configuration

    def _fetch_org_detail(
        self, client: GithubClient | None, login: str
    ) -> tuple[dict[str, Any] | None, str]:
        if client is None or not login:
            return None, _UNOBSERVABLE
        try:
            detail = client.get(f"/orgs/{login}")
        except GithubAPIError as exc:
            self.record_warn(
                _SITE_ORG_SETTINGS_UNOBSERVABLE,
                f"ORG_SETTINGS_UNOBSERVABLE_{exc.status}",
                f"Organization settings for {login} unreadable ({exc.status}) — 2FA requirement, "
                f"default repository permission and member privileges are NOT observed, which is "
                f"not the same as any of them being off.",
                message_data={"owner": login, "status": exc.status},
            )
            return None, _UNOBSERVABLE
        if not any(key in detail for key in _ORG_SETTING_KEYS_POLICY):
            self.record_info(
                _SITE_ORG_SETTINGS_PUBLIC_ONLY,
                "ORG_SETTINGS_PUBLIC_ONLY",
                f"Organization settings for {login} answered without a single policy key: this "
                f"credential is not an owner and holds no organization administration read, so "
                f"2FA requirement, default repository permission and member privileges are NOT "
                f"observed. The public keys are recorded; nothing is defaulted.",
                message_data={"owner": login},
            )
            return detail, _PUBLIC_ONLY
        return detail, _OBSERVED

    def _collect_org_actions_policy(
        self, client: GithubClient | None, owner: str | None
    ) -> tuple[dict[str, Any] | None, str]:
        """`GET /orgs/{org}/actions/permissions` (+ `/selected-actions` when the policy is
        `selected`): which repositories may run Actions, which actions they may use, and whether
        SHA pinning is required. Admin-only — a member token is refused with 403, and that
        refusal is recorded, never read as "all actions allowed"."""
        if owner is None or client is None:
            return None, ""
        if not self._account_type:
            # This runs before the repository walk mints the account, so the kind is not yet known;
            # a user account has no organization Actions policy and must not be asked for one (a 404
            # would otherwise be recorded as a refusal).
            self._account_type = str(self._fetch_account(client, owner).get("type") or "")
        if self._account_type != "Organization":
            return None, _NOT_APPLICABLE
        try:
            policy = client.get(f"/orgs/{owner}/actions/permissions")
        except GithubAPIError as exc:
            self.record_warn(
                _SITE_ACTIONS_POLICY_UNOBSERVABLE,
                f"ACTIONS_POLICY_UNOBSERVABLE_{exc.status}",
                f"The Actions policy for {owner} is unreadable ({exc.status}) — which repositories "
                f"may run workflows, which actions are allowed and whether SHA pinning is required "
                f"are NOT observed. The credential needs organization administration read.",
                message_data={"owner": owner, "status": exc.status},
            )
            return None, _UNOBSERVABLE
        result: dict[str, Any] = {
            "enabled_repositories": policy.get("enabled_repositories"),
            "allowed_actions": policy.get("allowed_actions"),
            "sha_pinning_required": policy.get("sha_pinning_required"),
            "selected_actions": None,
        }
        if policy.get("allowed_actions") == "selected":
            try:
                result["selected_actions"] = client.get(
                    f"/orgs/{owner}/actions/permissions/selected-actions"
                )
            except GithubAPIError as exc:
                self.record_warn(
                    _SITE_ACTIONS_POLICY_UNOBSERVABLE,
                    f"ACTIONS_POLICY_SELECTED_UNOBSERVABLE_{exc.status}",
                    f"The Actions allow-list for {owner} is unreadable ({exc.status}) while the "
                    f"policy itself was; `selected_actions` stays null.",
                    message_data={"owner": owner, "status": exc.status},
                )
        return result, _OBSERVED

    def _fetch_repository_settings(
        self, client: GithubClient, full_name: str
    ) -> dict[str, Any] | None:
        try:
            return client.get(f"/repos/{full_name}")
        except GithubAPIError as exc:
            self.record_warn(
                _SITE_REPO_SETTINGS_UNOBSERVABLE,
                f"REPO_SETTINGS_UNOBSERVABLE_{exc.status}",
                f"Repository settings for {full_name} unreadable ({exc.status}) — forking, archive "
                f"state, merge policy and security settings are NOT observed for it.",
                message_data={"repo": full_name, "status": exc.status},
            )
            return None

    @staticmethod
    def _repository_configuration(payload: dict[str, Any] | None) -> dict[str, Any]:
        """Verbatim copy of the repository's settings keys, with two observability markers.

        `settings_observability` says whether the REST payload was read at all; the separate
        `security_settings_observability` exists because `security_and_analysis` is the one key
        GitHub omits for a non-admin caller — its absence from an otherwise complete payload
        means "not allowed to look", never "secret scanning is off".
        """
        if payload is None:
            return {"settings_observability": _UNOBSERVABLE}
        configuration: dict[str, Any] = {
            key: payload[key] for key in _REPO_SETTING_KEYS if key in payload
        }
        configuration["settings_observability"] = _OBSERVED
        configuration["security_settings_observability"] = (
            _OBSERVED if "security_and_analysis" in payload else _UNOBSERVABLE
        )
        return configuration

    @staticmethod
    def _fetch_environment_detail(
        client: GithubClient | None, full_name: str, name: str
    ) -> dict[str, Any] | int | None:
        """The REST environment: a payload, an HTTP status when refused, or None when no client."""
        if client is None:
            return None
        try:
            return client.get(f"/repos/{full_name}/environments/{quote(name, safe='')}")
        except GithubAPIError as exc:
            return exc.status

    @staticmethod
    def _environment_configuration(
        detail: dict[str, Any] | None, client: GithubClient | None
    ) -> dict[str, Any]:
        """Who gates the environment, lifted out of the REST protection rules.

        `required_reviewers` carries the principals (users and teams) and `prevent_self_review`;
        they are recorded here as data — the `GATED_BY` edges the vocabulary names for them wait
        for the people graph, which is what gives them a node to point at.
        """
        if detail is None:
            return {"detail_observability": _UNOBSERVABLE if client is not None else ""}
        reviewers: list[dict[str, Any]] = []
        prevent_self_review: bool | None = None
        wait_timer: int | None = None
        for rule in detail.get("protection_rules") or []:
            kind = rule.get("type")
            if kind == "required_reviewers":
                prevent_self_review = rule.get("prevent_self_review")
                for entry in rule.get("reviewers") or []:
                    principal = entry.get("reviewer") or {}
                    reviewers.append(
                        {
                            "type": entry.get("type"),
                            "login": principal.get("login") or principal.get("slug"),
                            "id": principal.get("id"),
                        }
                    )
            elif kind == "wait_timer":
                wait_timer = rule.get("wait_timer")
        return {
            "detail_observability": _OBSERVED,
            "required_reviewers": reviewers,
            "prevent_self_review": prevent_self_review,
            "wait_timer": wait_timer,
        }

    def _fetch_run_window(
        self, client: GithubClient, full_name: str, run_limit: int
    ) -> list[dict[str, Any]]:
        """Run-list fetch per req-github-core-collector-3.

        First population (no on-grid runs): the latest `run_limit` runs.
        Later populations: every run created since the latest on-grid
        `run_started_at` for this repo, scoped via GitHub's `?created=>=ISO`
        filter. The first-fetch cap is `run_limit`; later fetches are
        unbounded but typically small (only new runs since last collection).
        """
        from django.db.models import Max
        from tap_plugin.github_core.models import GithubActionsRun

        max_ts = GithubActionsRun.objects.filter(full_name=full_name).aggregate(
            Max("run_started_at")
        )["run_started_at__max"]
        if max_ts is None:
            # First population — cap at run_limit, one page is enough.
            return client.get_paginated(
                f"/repos/{full_name}/actions/runs",
                params={"per_page": str(min(run_limit, 100))},
                item_path="workflow_runs",
                max_pages=1,
            )[:run_limit]

        # Incremental — fetch everything strictly newer. GitHub's `created`
        # filter accepts ISO 8601 with comparison operators. We use `>` not
        # `>=` to avoid re-fetching the boundary run we already have.
        iso = max_ts.astimezone().strftime("%Y-%m-%dT%H:%M:%SZ")
        self.record_info(
            _SITE_INCREMENTAL_WINDOW,
            "INCREMENTAL_WINDOW",
            f"{full_name}: incremental run fetch since {iso}.",
        )
        return client.get_paginated(
            f"/repos/{full_name}/actions/runs",
            params={"created": f">{iso}", "per_page": "100"},
            item_path="workflow_runs",
        )

    def _fetch_non_terminal_refresh(
        self,
        client: GithubClient,
        full_name: str,
        already_fetched_run_ids: set[int],
    ) -> list[dict[str, Any]]:
        """Re-fetch on-grid runs whose status is non-terminal per
        req-github-core-collector-4.

        Each run is fetched via the single-run endpoint
        `/repos/{owner}/{repo}/actions/runs/{run_id}`. A 404 on that endpoint
        (real, body-bearing — the empty-body retry in api_client already
        absorbed the intermittent ones) records a structured warn and the
        run is skipped from this refresh; mirrors the per-run /jobs degrade
        in `_fetch_run_jobs`.
        """
        from tap_plugin.github_core.models import GithubActionsRun

        non_terminal_ids = list(
            GithubActionsRun.objects.filter(full_name=full_name)
            .exclude(status__in=list(_TERMINAL_RUN_STATUSES))
            .exclude(run_id__in=list(already_fetched_run_ids))
            .values_list("run_id", flat=True)
        )
        if not non_terminal_ids:
            return []
        self.record_info(
            _SITE_NON_TERMINAL_REFRESH,
            "NON_TERMINAL_REFRESH",
            f"{full_name}: refreshing {len(non_terminal_ids)} non-terminal run(s).",
        )
        refreshed: list[dict[str, Any]] = []
        for rid in non_terminal_ids:
            try:
                payload = client.get(f"/repos/{full_name}/actions/runs/{rid}")
            except GithubAPIError as exc:
                if exc.status == 404:
                    self.record_warn(
                        _SITE_RUN_NOT_FOUND,
                        "RUN_NOT_FOUND",
                        f"{full_name} run {rid}: single-run endpoint 404 "
                        f"({exc.body[:120] or '(empty)'}). "
                        f"Skipping refresh for this run.",
                    )
                    continue
                raise
            refreshed.append(payload)
        return refreshed

    def _fetch_run_jobs(
        self, client: GithubClient, full_name: str, run_id_int: int
    ) -> list[dict[str, Any]] | None:
        """Fetch the jobs list for a specific run, or `None` when it was not observable.

        Per GitHub docs the endpoint documents only `200 - OK`; no 404
        condition is documented. The HTTP client retries empty-body 404s
        (undocumented intermittent quirk; see api_client module docstring).
        Real 404s — a JSON body with `{"message": "..."}` — still propagate
        and we graceful-degrade per-run to avoid aborting the whole collection
        on a single quirky run (`req-github-core-collector-5` discipline).

        `None` on that degrade, not `[]`: a run with no jobs (skipped) and a run
        whose jobs could not be read are different observations, and the run's
        end time is derived from the jobs (`_run_completed_at`), so the caller
        has to be able to tell them apart.
        """
        try:
            return client.get_paginated(
                f"/repos/{full_name}/actions/runs/{run_id_int}/jobs", item_path="jobs"
            )
        except GithubAPIError as exc:
            if exc.status == 404:
                self.record_warn(
                    _SITE_RUN_JOBS_MISSING,
                    "RUN_JOBS_MISSING",
                    f"{full_name} run {run_id_int} jobs endpoint returned 404 "
                    f"with body: {exc.body[:120] or '(empty)'}. "
                    f"Skipping job collection for this run.",
                )
                return None
            raise

    def _fetch_workflow_config(
        self, client: GithubClient, full_name: str, path: str
    ) -> tuple[str, dict[str, Any]]:
        """Fetch workflow YAML via Contents API; return (raw, parsed configuration)."""
        if not path:
            return "", parse_workflow_yaml("")
        try:
            payload = client.get(f"/repos/{full_name}/contents/{path}")
        except GithubAPIError as exc:
            if exc.status == 404:
                self.record_warn(
                    _SITE_WORKFLOW_YAML_MISSING,
                    "WORKFLOW_YAML_MISSING",
                    f"{full_name} workflow file not found: {path}",
                )
                return "", parse_workflow_yaml("")
            raise
        encoded = payload.get("content", "")
        raw_yaml = base64.b64decode(encoded).decode("utf-8") if encoded else ""
        return raw_yaml, parse_workflow_yaml(raw_yaml)

    def _record_enrichment_summary(self, enrichment: Any) -> None:
        emitted = sum(1 for r in enrichment.resolutions if r.emitted_edge)
        zero = sum(1 for r in enrichment.resolutions if r.candidate_count == 0)
        multi = sum(1 for r in enrichment.resolutions if r.candidate_count > 1)
        near = len(enrichment.near_matches)
        skipped = len(enrichment.skipped_rules)
        self.record_info(
            _SITE_ENRICHMENT_SUMMARY,
            "ENRICHMENT_SUMMARY",
            f"Link resolution: {emitted} edge(s) emitted, "
            f"{zero} zero-candidate, {multi} multi-candidate, "
            f"{near} near-match warning(s), {skipped} rule(s) skipped (target vocabulary not installed).",
        )
        for rule in enrichment.skipped_rules:
            self.record_warn(
                _SITE_LINK_RULE_SKIPPED,
                "LINK_RULE_SKIPPED",
                f"Link rule {rule.rule_name!r} skipped: type {rule.missing_entity_type!r} is not "
                f"installed in this composition (req-github-core-grid-links-8).",
                message_data={
                    "rule": rule.rule_name,
                    "missing_entity_type": rule.missing_entity_type,
                },
            )
        # Multi-candidate failures are warnings per req-github-core-grid-links-3.
        for res in enrichment.resolutions:
            if res.candidate_count > 1:
                self.record_warn(
                    "3812",
                    "LINK_AMBIGUOUS",
                    f"Rule {res.rule_name} on {res.source_entity_type}: value "
                    f"{res.source_value!r} matched {res.candidate_count} candidates; no edge emitted.",
                )
        # Near-match warnings surface "almost looks right but not quite" rows
        # (GHES tenant URLs, typos, alternate audiences) so the operator can
        # investigate instead of silently missing the link.
        for nm in enrichment.near_matches:
            self.record_warn(
                "db00",
                "LINK_NEAR_MATCH",
                f"Rule {nm.rule_name}: no exact match for {nm.expected_value!r} on "
                f"{nm.target_entity_type}.{nm.expected_value}, but a near-match exists: "
                f"{nm.target_value!r}. Not linking — investigate whether the rule should "
                f"be extended or the target is misconfigured.",
            )


def _readiness_summary(
    *,
    repo_access_ok: bool,
    owner_walk_failed: bool = False,
    explicit_repos: int,
    owner: str | None,
    enumerated: int | None,
    enumeration_complete: bool,
) -> str:
    """The one-line readiness summary, stating what this run actually proved.

    The count used to come from ``len(repos)`` — the length of the EXPLICIT repo filter, which is
    empty for an ordinary owner-scoped credential. So a credential that had just enumerated an
    entire organisation reported "0 repo(s) accessible": a number that reads as a dead credential
    while the run beside it proved the opposite. The count now comes from whichever scope the run
    actually walked, and a genuinely empty scope says so in words rather than rendering as a zero.
    """
    if owner_walk_failed:
        # Named separately because the generic repo message below would blame "configured repos"
        # for an account-scope failure, and an owner-scoped credential has none configured.
        return (
            f"GitHub Core collector cannot enumerate repositories under {owner}; the credential's "
            "account scope is unreadable."
        )
    if not repo_access_ok:
        return "GitHub Core collector credential cannot access one or more configured repos."
    if explicit_repos:
        return (
            f"GitHub Core collector is ready; {explicit_repos} explicitly configured repo(s) "
            "accessible."
        )
    if enumerated is not None:
        incomplete = "" if enumeration_complete else " (walk INCOMPLETE — page cap hit)"
        return (
            f"GitHub Core collector is ready; {enumerated} repo(s) enumerated under "
            f"{owner}{incomplete}."
        )
    return (
        "GitHub Core collector reached GitHub, but nothing is in scope: no owner and no explicit "
        "repos are configured, so a collection would observe nothing."
    )
