"""Batch-local REFS for github_core nodes, and the UUIDv5 ids edges still keep.

Spec: plugins/github_core/specs/spec-github-core-v0.md
(req-github-core-models-4 Identity). The natural-key table in the spec is the
source of truth for each entity type's identity inputs.

**Node ids are no longer derived here** (Issue# 162 - git-serious / tap-plugin-github-core).
github_core is core's first adopter of assigned identity: every function below that used to
mint a node's UUIDv5 now returns a batch-local :class:`Ref` — a namespaced key STRING the
GRIFT importer resolves against the model's ``NATURAL_KEY`` declaration, finding the live row
if there is one and assigning a fresh UUIDv7 if there is not. The id a node ends up with is
core's to assign; the recipe here only has to name the same source object the same way twice.

The recipes are unchanged: a ref is exactly the string the old ``_id`` hashed, so every
docstring below still describes the identity inputs and the reasoning behind them.

What deliberately stays derived:

- **Edge ids.** The importer never substitutes an edge envelope's id (edges are ``KEYLESS``
  and keep their assignment), so :func:`edge_id` remains the plugin's cross-run edge
  idempotency: the same fact re-observed keeps one edge instead of accumulating one per run.
  Its endpoints are hashed through :func:`_endpoint_token`, which reproduces the node id each
  ref used to derive as, so every edge id is UNCHANGED by this adoption and an existing grid
  gains no duplicates. Edge identity under assigned nodes is Issue# 690 - tap.
- **Nothing else.** The held-back set is EMPTY as of 2026-09-20: every node type this module
  names is a ref. The last three were released one at a time, each by making the declared
  search able to filter the same value the ref composes — ``commit_observation`` gained a
  ``host`` field (Issue# 164 - github-core), ``actions_secret`` stored the canonical
  upper-cased spelling (Issue# 165 - github-core), and ``code_scanning_finding`` waited on the
  plugin that OWNS the type to declare (Issue# 8 - tap-plugin-compliance-core), because a
  declaration lives on the owning model and no amount of work here could substitute for it.

  Every ``git_core__*`` and ``identity_core__*`` node this collector emits still keeps the id
  its own plugin's identity module derives — those are ids this module never named.
"""

from __future__ import annotations

from uuid import NAMESPACE_DNS, UUID, uuid5

# A stable, github_core-specific namespace derived from the canonical DNS
# namespace. Using a fixed UUID here keeps the derived EDGE ids (and the one
# remaining derived node id) reproducible across environments without depending
# on a runtime random seed.
GITHUB_CORE_NAMESPACE: UUID = uuid5(NAMESPACE_DNS, "github_core.tap")


class Ref(str):
    """A batch-local GRIFT ref: ``<entity_type>:<natural key>``.

    A ``str`` subclass on purpose. Every call site that used to hold a minted ``UUID`` used it
    as an ENVELOPE IDENTITY and, in a handful of places, as a set member, a dict key or a
    ``str()`` for a log line — all of which a string does unchanged. ``batch.node_envelope`` /
    ``batch.edge_envelope`` check for this type to decide between ``entity_id`` and ``ref`` /
    ``from_ref`` / ``to_ref``, so the collector's 60-odd call sites did not have to change.

    Refs are batch-local and must be unique within a batch: the ``<entity_type>:`` prefix
    namespaces them per type, and the collector collapses repeated envelopes by ref before
    submitting (the same node seen from several repositories is one observation, not a
    duplicate-ref error).
    """

    __slots__ = ()


def _id(entity_type: str, natural_key: str) -> Ref:
    return Ref(f"{entity_type}:{natural_key}")


def _uuid5_id(entity_type: str, natural_key: str) -> UUID:
    """The pre-assignment derivation, kept only for the types still addressed explicitly."""
    return uuid5(GITHUB_CORE_NAMESPACE, f"{entity_type}:{natural_key}")


def platform_id(host: str) -> Ref:
    # Natural key is the host ("github.com"); a GHES tenant gets its own id.
    return _id("github_core__github_platform", host)


def account_id(login: str) -> Ref:
    return _id("github_core__github_account", login)


def repository_id(full_name: str) -> Ref:
    return _id("github_core__github_repository", full_name)


def workflow_id(full_name: str, workflow_id_int: int | str) -> Ref:
    return _id("github_core__github_workflow", f"{full_name}#{workflow_id_int}")


def github_app_id(slug: str) -> Ref:
    # Natural key is the app slug ("dependabot"); one app node is shared across
    # every repo that enables it (ENABLED_ON_REPOSITORY edges fan in).
    return _id("github_core__github_app", slug)


def workflow_job_id(full_name: str, workflow_id_int: int | str, job_key: str) -> Ref:
    """A DECLARED job: the workflow it is written in, plus its YAML key.

    Keyed on the workflow id rather than the file path so a renamed file keeps the same job
    nodes, and on the job key rather than the display name because `name:` is free text an
    author changes without changing what the job is.
    """
    return _id("github_core__workflow_job", f"{full_name}#{workflow_id_int}#{job_key}")


def commit_observation_id(
    host: str, repository_github_id: int | str, hash_algorithm: str, oid: str
) -> Ref:
    """GitHub's OBSERVATION of a commit in one repository (ruling 0.2, github-core#76).

    Keyed on the host, the repository's STABLE id (never `owner/repo`, which renames) and the
    commit identity. The commit itself is the neutral `git_core__git_commit`, minted by
    `tap_plugin.git_core.identity.git_commit_id`; this record is the forge's half — resolved
    logins and the signature verdict — persisted per repository network, so it is per
    repository by construction and can never merge two networks' verdicts. The cross-fork join
    on the network root is a follow-on once `Repository.parent` is collected.
    """
    return _id(
        "github_core__commit_observation",
        f"{host}#{repository_github_id}#{hash_algorithm}:{oid.lower()}",
    )


def ruleset_id(owner: str, ruleset_id_int: int | str) -> Ref:
    """A ruleset, keyed on owner + GitHub's ruleset id.

    Not repo-scoped: one organization ruleset applies to many repositories and must be ONE node
    that many repositories point at, or the question "what does this ruleset protect" becomes a
    string comparison across duplicates. Measured on the fixture org: 3 organization rulesets
    reported by 19 repositories = 57 attachments over 3 nodes.

    The owner prefix is belt-and-braces. GitHub's ruleset `databaseId` was measured to be
    PLATFORM-global rather than per-account — org- and repo-sourced ids interleave when
    sorted, id order is exactly creation order, and an org owning six rulesets holds ids near
    20.6 million rather than 1-6 — so the bare id would also have keyed correctly. Recorded so
    nobody re-derives it: the prefix costs nothing and a natural key cannot be changed once
    nodes exist.
    """
    return _id("github_core__github_ruleset", f"{owner}#{ruleset_id_int}")


def pull_request_id(full_name: str, number: int | str) -> Ref:
    """A pull request, keyed on the repository it is opened against plus its number.

    The number is GitHub's own identity for a pull request within a repository and is what every
    URL, commit message and review comment names it by; `databaseId` is carried as a field for
    continuity across a repository transfer, not as the key. Scoped to the BASE repository: a
    fork's pull request is a fact about the repository it targets, and the head repository is a
    field on the node.
    """
    return _id("github_core__pull_request", f"{full_name}#{number}")


def custom_property_id(owner: str, property_name: str) -> Ref:
    """A custom-property DEFINITION, keyed on the owner and the property name.

    Owner-scoped like `ruleset_id`: one organization declares the property once and every
    repository's value is read against that one declaration. The name is the key because it is
    the only identity GitHub gives a definition — the schema endpoint returns no numeric id —
    and it is stored exactly as reported (hyphens, case) because it is also the key of every
    repository's `custom_properties` map; normalizing it here would break the join by name.
    An enterprise-sourced definition inherited by the organization keys under the organization
    that reports it, which is where its values live.
    """
    return _id("github_core__github_custom_property", f"{owner}#{property_name}")


def status_check_id(owner: str, context: str) -> Ref:
    """A required check context, keyed on the owner and the context string.

    Owner-scoped like `ruleset_id`: an organization ruleset requires the same context across
    every repository it protects, and one node with fan-in is the whole point. The context is
    kept exactly as written — check names are case-sensitive on GitHub.
    """
    return _id("github_core__status_check", f"{owner}#{context}")


def rule_suite_id(suite_id_int: int | str) -> Ref:
    """A rule suite, keyed on GitHub's own suite id — unique across the platform.

    Not scoped by repository: the id is assigned by GitHub and the suite carries its own
    `repository_name`, so scoping would add nothing and would break the join if the same
    suite were ever reached from another path.
    """
    return _id("github_core__rule_suite", str(suite_id_int))


def code_scanning_alert_id(full_name: str, number: int | str) -> Ref:
    """A code-scanning alert, keyed on the repository plus GitHub's alert number.

    The number is how every URL and every dismissal names the alert within its repository, and
    it is stable across re-analysis: a new analysis that finds the same result updates the alert
    rather than opening a new one. Repository-scoped because numbers restart per repository.
    """
    return _id("github_core__code_scanning_alert", f"{full_name}#{number}")


def dependabot_alert_id(full_name: str, number: int | str) -> Ref:
    """A Dependabot alert, keyed on the repository plus GitHub's alert number.

    The number is how every URL and every dismissal names the alert within its repository, and
    it is stable across re-scans. Repository-scoped because numbers restart per repository.
    """
    return _id("github_core__dependabot_alert", f"{full_name}#{number}")


def code_scanning_analysis_id(full_name: str, analysis_id_int: int | str) -> Ref:
    """One analysis (one SARIF upload), keyed on the repository plus GitHub's analysis id.

    The id is platform-global like runs and artifacts; the repository prefix is belt-and-braces
    in the same way `actions_artifact_id`'s is, recorded rather than re-derived.
    """
    return _id("github_core__code_scanning_analysis", f"{full_name}#{analysis_id_int}")


#: The value a `compliance_core__compliance_finding` this collector mints carries in its
#: `source` column: the slug of the plugin that asserted it. compliance_core's declared key
#: is ``("source", "source_key")``, and `source` is the namespace half — it is what keeps
#: github_core's `acme/app#7` and another producer's `acme/app#7` two different findings.
COMPLIANCE_FINDING_SOURCE = "github_core"


def code_scanning_finding_source_key(full_name: str, number: int | str) -> str:
    """What github_core calls one code-scanning finding, verbatim — composed HERE, once.

    This string is BOTH halves of the contract: the collector writes it into the finding's
    `source_key` column, and :func:`code_scanning_finding_id` names the ref with it. Composing
    it in one function is what keeps the value the declared search filters and the value the
    ref carries from drifting apart (the lesson of `actions_secret_id`, PR# 163 - github-core).

    The middle segment names the GitHub security surface the finding came from, so the same
    repository's Dependabot alert number 7 (``#dependabot#7``) and code-scanning alert number 7
    can never collide; a future secret-scanning finding takes ``#secret_scanning#``.
    """
    return f"{full_name}#code_scanning#{number}"


def code_scanning_finding_id(full_name: str, number: int | str) -> Ref:
    """The generic `compliance_core__compliance_finding` github_core mints for a code-scanning alert.

    A REF since compliance_core declared (Issue# 8 - tap-plugin-compliance-core). It was the
    last type this collector held back, and for the only reason this repository could not
    settle alone: the declaration lives on the owning model, so a ref to a type whose plugin
    had not declared was refused outright — *undeclared is never keyless*.

    What changed is the DIRECTION, not the recipe. Under derived ids github_core decided this
    type's identity because somebody had to compute an identifier and only the producer held
    the values; that docstring line ("the finding's identity is github_core's to derive") is
    now false. compliance_core decides the key — ``("source", "source_key")`` — and github_core
    owes the VALUES: :meth:`GithubCollector._code_scanning_finding_fields` writes
    :data:`COMPLIANCE_FINDING_SOURCE` and :func:`code_scanning_finding_source_key` onto the
    node. That is the data contract, and it is not optional in the way an API is: a producer
    that wrote neither field would get a hole, a search that answers "not found", and a FRESH
    node every run — duplicates, not an error.

    The ref string is unchanged from the string the uuid5 hashed, which is what keeps every
    edge id byte-identical through :func:`_endpoint_token`.

    Every ``git_core__*`` and ``identity_core__*`` node this collector emits still keeps the id
    its own plugin's identity module derives.
    """
    return _id("compliance_core__compliance_finding", code_scanning_finding_source_key(full_name, number))


def dependabot_finding_source_key(full_name: str, number: int | str) -> str:
    """What github_core calls one Dependabot finding, verbatim — composed HERE, once.

    Same contract as :func:`code_scanning_finding_source_key`: the collector writes this string
    into the finding's `source_key` column and :func:`dependabot_finding_id` names the ref with it.
    The `#dependabot#` segment is what keeps repository `acme/app`'s Dependabot alert 7 and its
    code-scanning alert 7 two findings.
    """
    return f"{full_name}#dependabot#{number}"


def dependabot_finding_id(full_name: str, number: int | str) -> Ref:
    """The generic `compliance_core__compliance_finding` github_core mints for a Dependabot alert.

    A REF on compliance_core's declared key ``("source", "source_key")`` exactly as
    :func:`code_scanning_finding_id` is; the collector owes the VALUES
    (:data:`COMPLIANCE_FINDING_SOURCE` and :func:`dependabot_finding_source_key`) on the node.
    """
    return _id("compliance_core__compliance_finding", dependabot_finding_source_key(full_name, number))


def environment_id(full_name: str, name: str) -> Ref:
    return _id("github_core__github_environment", f"{full_name}#{name}")


def actions_secret_id(
    scope: str, owner_login: str, full_name: str, environment_name: str, name: str
) -> Ref:
    """One ref per (scope, owner, repository, environment, name), with the name case-folded.

    Scope is in the key because an organisation secret and a repository secret can share a name
    and are different credentials — collapsing them would make an org secret look like it lives
    in whichever repository was collected last.

    Takes the four holder fields rather than one pre-joined ``owner/repo/environment`` string
    (Grok on PR# 163 - github-core). The caller was composing that string from the same fields
    the payload already carries, so the ref and the declared search were derived twice from one
    fact and could drift apart with nothing to notice; the composition now happens HERE, once,
    over exactly the fields ``ActionsSecret.NATURAL_KEY`` names. The string it produces is
    byte-identical to the one this function has always produced, so no secret's ref — and
    therefore no ``DEFINES_SECRET`` edge id — changes.

    The name is upper-cased because GitHub secret names are NOT case-sensitive: a workflow
    writing ``${{ secrets.harness_pat }}`` and one writing ``${{ secrets.HARNESS_PAT }}`` read
    the same credential, and two nodes here would say they are two. Observed on this estate —
    two of the nine referenced names are written lower-case.

    The fold now agrees with the stored field: `ActionsSecret.name` holds the canonical
    spelling and `name_reported` keeps what GitHub returned, so the declared search filters the
    same value this key composes (Issue# 165, ruled 2026-09-20).
    """
    if environment_name:
        holder = f"{full_name}/{environment_name}"
    elif full_name:
        holder = full_name
    else:
        holder = owner_login
    return _id("github_core__actions_secret", f"{scope}#{holder}#{name.upper()}")


def actions_cache_id(full_name: str, cache_id_int: int | str) -> Ref:
    return _id("github_core__actions_cache", f"{full_name}#{cache_id_int}")


def actions_artifact_id(full_name: str, artifact_id_int: int | str) -> Ref:
    """An artifact, keyed on the repository plus GitHub's artifact id.

    The id is platform-global (the same generator as runs and caches), so the repository
    prefix is belt-and-braces in the same way `ruleset_id`'s owner prefix is — and a natural
    key cannot change once nodes exist, so it is recorded rather than re-derived.
    """
    return _id("github_core__actions_artifact", f"{full_name}#{artifact_id_int}")


def app_installation_id(installation_id_int: int | str) -> Ref:
    """An installation, keyed on GitHub's installation id — unique across the platform."""
    return _id("github_core__app_installation", str(installation_id_int))


def collection_scope_id(run_id: UUID | str) -> Ref:
    """The scope statement about one collection run, keyed on the `collection_job` entity id.

    Natural key: the run. One scope per run by construction — a re-run is a new job and so a new
    scope, which is what makes "when did we stop being able to see X" answerable from history
    (github-core#145).
    """
    return _id("github_core__collection_scope", str(run_id))


def run_id(full_name: str, run_id_int: int | str) -> Ref:
    # v0 natural key is owner/repo + run_id (run_attempt deferred — see
    # req-github-core-backlog-run-attempts).
    return _id("github_core__github_actions_run", f"{full_name}#{run_id_int}")


def job_id(full_name: str, job_id_int: int | str) -> Ref:
    return _id("github_core__github_actions_job", f"{full_name}#{job_id_int}")


def runner_id(full_name: str, runner_id_int: int | str) -> Ref:
    return _id("github_core__github_runner", f"{full_name}#{runner_id_int}")


def release_id(full_name: str, release_id_int: int | str) -> Ref:
    """A release, keyed on `owner/repo` + GitHub's release id (github-core#31).

    The id rather than the tag name: a release can be deleted and re-cut on the same tag, and
    a tag can be moved under a release, and both must read as what they are — a different
    object, or the same object whose `target_sha` changed — rather than being folded together.
    """
    return _id("github_core__github_release", f"{full_name}#{release_id_int}")


def package_id(owner: str, package_type: str, name: str) -> Ref:
    """A package, keyed on owner + type + name — GitHub's own path to it.

    Not on the numeric id: the REST path `/orgs/{owner}/packages/{type}/{name}` is how every
    later surface reaches the package, and a deleted-and-republished package of the same name
    IS the same thing to every consumer that pulls it by name.
    """
    return _id("github_core__github_package", f"{owner}#{package_type}#{name}")


def package_version_id(
    owner: str, package_type: str, name: str, version_id_int: int | str
) -> Ref:
    """A version, scoped under its package and keyed on GitHub's version id.

    GitHub's id rather than the version name: for a container the name is a digest, which is
    content-addressed and would key correctly, but for npm/maven a version string can be
    unpublished and re-published as different bytes, and the id is what tells them apart.
    """
    return _id(
        "github_core__github_package_version",
        f"{owner}#{package_type}#{name}#{version_id_int}",
    )


#: GitHub Packages registry host per package type — the `repository_url` a purl needs to say
#: that this npm package lives on GitHub's registry rather than npmjs.org.
_REGISTRY_HOST_BY_TYPE = {
    "npm": "npm.pkg.github.com",
    "maven": "maven.pkg.github.com",
    "rubygems": "rubygems.pkg.github.com",
    "nuget": "nuget.pkg.github.com",
}
#: purl type per GitHub package type where the purl spec has one of its own.
_PURL_TYPE_BY_TYPE = {
    "npm": "npm",
    "maven": "maven",
    "rubygems": "gem",
    "nuget": "nuget",
}


def package_purl(package_type: str, owner: str, name: str, version: str = "") -> str:
    """Package-URL for a GitHub Packages package, per the purl spec's type registry.

    The vocabulary corpus (decision 4) keys `package` / `package_version` on a purl and homes them
    in a future `supply_chain_core`. This is the seam: github_core mints the purl from what the
    GitHub surface knows, so the substrate can claim these nodes by identity later.

    * `container` (ghcr.io) -> `pkg:docker/ghcr.io/<owner>/<name>@<digest>` — the purl spec's
      docker type with the registry in the namespace, as its own examples do for gcr.io.
    * `docker` (the retired docker.pkg.github.com registry) -> `pkg:docker/docker.pkg.github.com/...`.
    * npm / maven / rubygems / nuget -> that ecosystem's purl type with
      `?repository_url=<host>.pkg.github.com`, because the bare purl would name the public registry.
    * anything else -> `pkg:github/<owner>/<name>@<version>`, the spec's GitHub-hosted type.

    Owner and name are lowercased for the docker forms only — OCI references are case-sensitive
    and always lowercase, and GitHub lowercases them on push. Every other form keeps the case
    GitHub returned.
    """
    ptype = package_type.lower()
    at = f"@{version}" if version else ""
    if ptype == "container":
        return f"pkg:docker/ghcr.io/{owner.lower()}/{name.lower()}{at}"
    if ptype == "docker":
        return f"pkg:docker/docker.pkg.github.com/{owner.lower()}/{name.lower()}{at}"
    purl_type = _PURL_TYPE_BY_TYPE.get(ptype)
    if purl_type is not None:
        host = _REGISTRY_HOST_BY_TYPE[ptype]
        if ptype == "npm":
            # GitHub-hosted npm packages are always scoped by owner: `@owner/name`. The purl spec
            # percent-encodes the `@` of a scope in the namespace.
            return f"pkg:npm/%40{owner}/{name}{at}?repository_url={host}"
        if ptype == "maven":
            # GitHub reports a Maven package as `group.artifact` in one string; the last dotted
            # segment is the artifact and the rest the group, which is the spec's namespace.
            group, _, artifact = name.rpartition(".")
            return f"pkg:maven/{group or owner}/{artifact}{at}?repository_url={host}"
        return f"pkg:{purl_type}/{name}{at}?repository_url={host}"
    return f"pkg:github/{owner}/{name}{at}"


def github_action_id(action_path: str) -> Ref:
    """An action, keyed on the `uses:` path with the ref stripped.

    Platform-global rather than repository-scoped, like `github_app`: `actions/checkout` is
    ONE node every job on every repository points at, or "which jobs use an unpinned checkout"
    becomes a string comparison across duplicates. The ref is deliberately NOT here — the same
    action is pinned differently by different jobs, and the pin belongs to the edge.
    """
    return _id("github_core__github_action", action_path)


def _endpoint_token(value: UUID | Ref) -> UUID | Ref:
    """What an edge id hashes for one endpoint: the node id the endpoint USED to be derived as.

    Edge ids are not substituted by the importer, so this derivation is what keeps one edge per
    fact across runs — and it is also what an ALREADY-POPULATED grid's existing edges were
    minted from. Hashing the ref string directly would have been just as deterministic going
    forward and would have changed every edge id exactly once, which on a populated grid means
    a second live edge for every fact that already has one: the importer finds an edge by the
    ``entity_id`` the envelope supplies and by nothing else, so it would create rather than
    replace (Codex on PR# 163 - github-core, verified against
    ``tap_grid/grift/importer.py``'s ``edge_exists`` branch).

    Since a ref is exactly the string the old node derivation hashed, re-hashing it here
    reproduces that node id byte for byte, and every edge id is unchanged by the adoption. The
    node ids themselves are equally safe: ``find_existing`` matches the existing typed rows on
    their declared fields, so they are found rather than minted. The whole change is therefore
    data-neutral on a grid collected before it.

    Deliberately transitional. It exists to make adoption a no-op for existing edges, not
    because an edge's identity should be a function of its endpoints' former ids; that is the
    question Issue# 690 - tap owns. An endpoint that is already a real id (another batch's
    entity, another plugin's node) passes straight through, as it always did.
    """
    if isinstance(value, Ref):
        return _uuid5_id(*str(value).split(":", 1))
    return value


def uses_action_edge_id(job_uuid: UUID | Ref, action_uuid: UUID | Ref, declared_ref: str) -> UUID:
    """A `USES_ACTION` edge, keyed on the job, the action AND the ref as written.

    Not the generic `edge_id` (type, source, target): a job that calls the same action at two
    refs — `actions/checkout@v4` in one step and `actions/checkout@<sha>` in another — is two
    facts, and an id that ignored the ref would keep only the last one after envelope collapse.
    """
    return uuid5(
        GITHUB_CORE_NAMESPACE,
        f"edge:USES_ACTION__github_core:{_endpoint_token(job_uuid)}:"
        f"{_endpoint_token(action_uuid)}:{declared_ref}",
    )


def edge_id(edge_type: str, source: UUID | Ref, target: UUID | Ref) -> UUID:
    """Deterministic UUIDv5 for an edge by (type, source, target).

    Endpoints are hashed through :func:`_endpoint_token`, so an edge id is unchanged by the move
    to assigned node identity — see that function for why that matters on a populated grid.
    """
    return uuid5(
        GITHUB_CORE_NAMESPACE,
        f"edge:{edge_type}:{_endpoint_token(source)}:{_endpoint_token(target)}",
    )
