"""Per-type falsifiers for the git-provable and enumerable shapes (github-core#151, phase 3).

A retirement candidate (``tap_grid.candidates``) is a child the grid holds under a parent
whose listing this run read completely and did not name it. Nothing is retired on that
alone: a **falsifier** — one per entity type, declared in ``[falsifiers]`` of
``tap-plugin.toml`` — probes GitHub for each candidate and hands what it found to
``tap_grid.falsifiers.verdict_from_probe``, which derives the verdict. HTTP success is not a
verdict; the identity and the owner are compared, never the status line
(``req-grid-reconcile-falsifier``). Authority stays off: the verdicts are recorded on the
run's lifecycle batch and the reconcile verb (tap#652) is what would act on them.

Which types get one follows the shape table in github-core#14:

- **Shape A, git-provable** — ``github_workflow`` and ``workflow_job``. The workflow is a file
  under ``.github/workflows/`` at HEAD; its removal is a commit. The probe reads the file at
  HEAD (``GET /repos/{owner}/{repo}/contents/{path}``) and, when it is there, resolves the
  Actions workflow record behind it (``GET /repos/{owner}/{repo}/actions/workflows/{file}``)
  so a file re-created at the same path with a new workflow id reads as REIDENTIFIED rather
  than as the old one. A declared job is falsified at the same granularity: the job key is
  looked for in that file.
- **Shape B, enumerable** — ``github_repository`` and ``github_environment``. ``GET
  /repos/{owner}/{repo}`` and ``GET /repos/{owner}/{repo}/environments/{name}``: 404 is
  ``not_found``, 401/403 is ``forbidden`` (GitHub answers 404 for a private repository the
  credential may not see, so a repository ``not_found`` still means "gone from this
  credential's view", which is all the listing ever claimed), and a found object is compared
  by its stable numeric id and — for a repository — by its owner login, so a transfer ends
  the ownership edge rather than retiring the repository.
- **Shape B, no stable id** — ``actions_secret`` (github-core#866, the deletion-detection half
  of the duplication fix). ``GET .../actions/secrets/{name}`` at whichever of the three URL
  shapes ``row.scope`` names (organization / repository / environment): 404 is ``not_found``,
  routed through the same reach-gated ``_absence_verdict`` as every other type here. GitHub's
  secrets API returns only a name and timestamps — no numeric id, nothing independent of the
  name the URL already asked for — so a ``found`` probe's own identity claim IS the name it
  was given, never an id the source reports back. ``REIDENTIFIED`` and ``RELOCATED`` are
  therefore structurally unreachable for this type: there is nothing beyond "found" or "not
  found" for the probe to compare. Only the repository scope is a retirement candidate today
  (``GithubRepository.CONTAINMENT_EDGES``); organization and environment scope remain
  references (``GithubAccount``, ``GithubEnvironment``), so ``ActionsSecretFalsifier`` judges
  all three shapes correctly but is only ever called with repository-scoped candidates until
  that widens.
- **Shape C, immutable events** — ``github_actions_run`` and ``github_actions_job`` get NO
  falsifier on purpose: no containment edge reaches them, so they are never candidates, and
  a run does not stop having happened when GitHub ages it out.

  ``pull_request``, ``code_scanning_alert`` and ``status_check`` join this shape (github-core#194;
  an earlier audit flagged all three as "arguably event-like, no clear docstring stance" — this
  is that stance, with the reasoning on each model). A PR or an alert never leaves GitHub's API
  on close/merge or dismiss/fix — only ``state`` changes, which the collector already re-observes
  — and neither has any edge targeting it that a model could declare as containment, so both are
  structurally unreachable by ``tap_grid.candidates`` regardless. ``status_check`` is further out:
  it names no GitHub resource at all, only a context string two declarations (``REQUIRES_CHECK``,
  ``PRODUCES_CHECK``) happen to agree on, so a falsifier would have nothing to probe — its
  freshness is the edges', re-derived every run. See ``PullRequest``, ``CodeScanningAlert`` and
  ``StatusCheck``'s own docstrings for the full reasoning per type.

  ``github_release``, ``github_package`` and ``github_package_version`` join it too
  (github-core#197): each has an existing, explicit "reference, not containment" ruling on its
  parent's docstring (``github_repository.py`` for releases, ``github_account.py`` for packages),
  and each listing is either page-capped (releases, ``first: 50``) or credential-shaped enough
  (packages, ``enabledForGitHubApps: false``) that ``enumeration_complete`` could rarely be
  honestly asserted for it. ``github_runner`` is a related but DIFFERENT gap: no edge reaches it
  from its repository at all today (not even a reference one), so there is no parent to declare
  containment on without first adding one — deferred as a follow-on, not ruled out on the merits
  (see the model's own docstring).

- **App installation, a fourth shape** — ``app_installation`` gets a falsifier
  (``AppInstallationFalsifier``, github-core#197) that fits none of A/B/C. The probe is
  ``GET /app/installations/{id}`` under the App's own JWT (``GithubAuth.app_jwt()``), never the
  installation token a repository-scoped probe would use. That is the whole reason it needs no
  reach gate (github-core#157): the JWT is not asking "can this grant still see it" — it is the
  App asking about its OWN installation, globally, so a 404 is unambiguous. A PAT-only credential
  cannot mint a JWT at all and answers ``UNDETERMINED(scope_unknown)`` for every candidate rather
  than attempting a call it structurally cannot make. Containment is declared on ``GithubApp``
  (``REGISTERS_INSTALLATION``): see both models' docstrings for why the security-relevant absence
  here is the installation, never the application.

``Expected.owner`` is the parent's source identity read off the candidate's ``parent``
(Option A, tap#650): the account login for a repository, the repository full name for a
workflow or an environment, the workflow id for a declared job. Where the grid holds no
parent, the owner is ``None`` and the probe's owner is not compared — a comparison the grid
never asked for cannot yield a transfer.

**A 404 is judged against the credential's reach, never taken at face value** (github-core#157,
ruling D on github-core#155). GitHub answers 404 both for an object that is gone and for one
this credential may not see, so ``not_found`` is only allowed to become
``DROPPED_FROM_OBSERVATION`` when the object's repository is provably inside the reach
``tap_plugin.github_core.reach`` resolved for this run. Outside it, or where the reach could not
be read at all, the verdict is ``UNDETERMINED(scope_unknown)`` — a credential that could not
prove it could look never reads as gone. For an object INSIDE a repository the tie-breaker is one
probe of that repository, cached per run: parent answers → the child's absence is the child's;
parent 404 → the child says nothing.

Every probe is a single-object read of the source under this plugin's own credential
(``github_core:collector``, resolved here, never taken from the run context); no response
body is recorded — ``Probe.detail`` carries an HTTP status or an error class only.
"""

from __future__ import annotations

import base64
import logging
import posixpath
from collections import OrderedDict
from collections.abc import Callable, Sequence
from datetime import datetime
from typing import Any
from urllib.parse import quote

from tap_plugin.github_core.collectors.github_collector.api_client import GithubAPIError, GithubClient
from tap_plugin.github_core.collectors.github_collector.app_jwt import GithubAppAuthError
from tap_plugin.github_core.collectors.github_collector.auth import GithubAuth
from tap_plugin.github_core.collectors.github_collector.parser import parse_workflow_yaml
from tap_plugin.github_core.collectors.github_collector.secret import api_base_url, resolve_github_secret

from tap_grid.falsifiers import (
    DROPPED_FROM_OBSERVATION,
    UNDETERMINED,
    Candidate,
    Expected,
    Falsifier,
    FalsifyContext,
    Probe,
    Verdict,
    verdict_from_probe,
)
from tap_plugin.github_core.reach import Reach, resolve_reach, unobservable

from tap_grid.falsifiers import UNDETERMINED_REASONS
from tap_grid.services import get_node

logger = logging.getLogger(__name__)

#: What a probe needs of the client: one authenticated GET that raises ``GithubAPIError``.
ProbeClient = Any


def _default_session() -> tuple[GithubClient, GithubAuth]:
    """The collector's own credential, resolved from the secret store (consumer-scoped).

    Both halves are returned because the reach statement (github-core#157) is read off the
    AUTH — the installation record the token was minted for — while the probes go through the
    client. Resolving them together mints one installation token for the run rather than one
    per question.
    """
    secret = resolve_github_secret()
    data = dict(secret.data)
    auth = GithubAuth(kind=secret.kind, data=data, api_base_url=api_base_url(data))
    client = GithubClient(token=auth.token(), api_base_url=api_base_url(data), retry_empty_404=False)
    return client, auth


def _default_client() -> GithubClient:
    """The client half of the default session, for a caller that needs no reach."""
    return _default_session()[0]


def _default_app_session() -> tuple[GithubClient, GithubAuth]:
    """The App's own JWT-authenticated session — the credential ``/app/installations/{id}``
    requires (github-core#197). An installation token, which every other falsifier's default
    session mints, cannot call this endpoint at all; only the App's JWT identifies the caller as
    the application itself.

    Raises ``GithubAppAuthError`` when the envelope carries no App credential — a PAT-only
    envelope cannot mint a JWT, and ``AppInstallationFalsifier`` turns that into
    ``UNDETERMINED(scope_unknown)`` for every candidate rather than attempting a call it
    structurally cannot make.
    """
    secret = resolve_github_secret()
    data = dict(secret.data)
    auth = GithubAuth(kind=secret.kind, data=data, api_base_url=api_base_url(data))
    if not auth.has_app:
        raise GithubAppAuthError("no App credential in the envelope: /app/installations/{id} is App-only")
    client = GithubClient(token=auth.app_jwt(), api_base_url=api_base_url(data), retry_empty_404=False)
    return client, auth


def probe_status_of(exc: GithubAPIError) -> str:
    """The closed probe status an API failure maps to. 404 is the only ``not_found``; a
    credential refusal is ``forbidden``; a rate limit is named as such; everything else
    (network, 5xx, 0) is ``errored`` — the probe could not answer."""
    if exc.status == 404:
        return "not_found"
    if exc.status == 429:
        return "rate_limited"
    if exc.status == 403 and "rate limit" in exc.body.lower():
        return "rate_limited"
    if exc.status in (401, 403):
        return "forbidden"
    return "errored"


#: What a 404 from GitHub does and does not say, stated on the record itself: GitHub answers 404
#: both for an object that is gone and for a private one this credential may not see.
#:
#: This wording is kept for the human reading a verdict; the JUDGEMENT no longer rests on it. A
#: ``not_found`` only becomes a retirement inside the credential's provable reach, and for a
#: repository the reach is read again after the probe (``_reach_after_probe``).
#:
#: An earlier version of this note said the residual — access narrowed between the listing and the
#: probe — was the reconcile verb's freshness fence to hold. That was checked against
#: ``tap_grid/reconcile.py`` and is FALSE: the verb rejects a verdict whose target was RE-OBSERVED since the candidate record
#: was derived, and a repository that left the credential's reach is precisely the one this run
#: cannot observe, so nothing re-observes it and the fence never fires. The residual is held here,
#: not there.
NOT_FOUND_DETAIL = "HTTP 404 (GitHub also answers 404 for a private object this credential may not see)"


#: Parent probes already made, per run (keyed by the lifecycle batch id) and per repository.
#: A 404 on an object inside a repository is judged against ONE probe of that repository, and
#: every child candidate of that repository — of every type — reuses the answer
#: (github-core#157: one call per parent, cached per run). Bounded rather than unbounded: a
#: process serving many runs would otherwise hold every run's probes forever.
_PARENT_PROBES: "OrderedDict[str, dict[str, Probe]]" = OrderedDict()
_PARENT_PROBE_RUNS = 8

#: The note on a verdict that refused to let a 404 stand because the reach could not be read.
_REACH_UNOBSERVED_NOTE = "a 404 cannot mean gone here: "
#: The note when the reach WAS read and does not contain the object's repository.
_OUT_OF_REACH_NOTE = (
    "the containing repository is not in this credential's reach, so a 404 is what a credential "
    "that may not look receives, not evidence the object is gone"
)


def _parent_probe(client: ProbeClient, batch_id: str, full_name: str) -> Probe:
    """Probe the containing repository once per run, and remember the answer.

    The tie-breaker for an in-repository 404: the same credential asking for the parent. Parent
    answers → the child's absence is the child's. Parent 404 or refused → the credential's view
    of the whole repository changed, and the child says nothing.
    """
    runs = _PARENT_PROBES.get(batch_id)
    if runs is None:
        runs = _PARENT_PROBES[batch_id] = {}
        while len(_PARENT_PROBES) > _PARENT_PROBE_RUNS:
            _PARENT_PROBES.popitem(last=False)
    _PARENT_PROBES.move_to_end(batch_id)
    if full_name not in runs:
        result = _GithubFalsifier._probe_get(client, f"/repos/{full_name}")
        runs[full_name] = result if isinstance(result, Probe) else Probe(status="found", detail="HTTP 200")
    return runs[full_name]


def _failed_probe(exc: GithubAPIError) -> Probe:
    """A probe that did not find, or could not answer. ``detail`` is the status line only:
    never the body (``Probe.detail`` contract)."""
    status = probe_status_of(exc)
    detail = NOT_FOUND_DETAIL if status == "not_found" else f"HTTP {exc.status}"
    return Probe(status=status, detail=detail)  # type: ignore[arg-type]


def _created_at(payload: dict[str, Any]) -> datetime | None:
    value = payload.get("created_at")
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _undetermined(candidate: Candidate, reason: str, note: str) -> Verdict:
    return Verdict(
        entity_id=candidate.entity_id, verdict=UNDETERMINED, reason=reason, surface=candidate.surface, note=note
    )


def _row_of(entity_id: Any) -> Any | None:
    """The typed grid row behind an entity id through the service read, or None when it
    cannot be read (unknown id, unknown type, an edge)."""
    if entity_id is None:
        return None
    try:
        return get_node(entity_id)
    except Exception:  # noqa: BLE001 — a candidate the grid cannot show is answered, not raised
        logger.warning("[82e7] falsifier could not read grid row %s", entity_id)
        return None


def _decode_file(payload: dict[str, Any]) -> str:
    """The text of a Contents API payload (base64) or "" when it carries none."""
    encoded = payload.get("content") or ""
    if not isinstance(encoded, str) or not encoded:
        return ""
    try:
        return base64.b64decode(encoded).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return ""


class _GithubFalsifier(Falsifier):
    """The shared shape: one client per batch, one verdict per candidate, fail closed.

    ``client`` is injected by tests (``tests/fake_github.py``); at runtime it is resolved from
    the collector's secret on the first batch. A credential that cannot be resolved answers
    ``UNDETERMINED(errored)`` for every candidate rather than raising — core would record the
    same verdict, but this way the note says why.
    """

    def __init__(
        self,
        client: ProbeClient | None = None,
        client_factory: Callable[[], ProbeClient] | None = None,
        reach: Reach | None = None,
        session_factory: Callable[[], tuple[ProbeClient, Any]] | None = None,
    ) -> None:
        self._client = client
        self._auth: Any = None
        self._client_factory = client_factory
        self._session_factory = session_factory or _default_session
        #: True when this falsifier builds its own credential, which is the production case and
        #: the only one where it may throw the session away and mint a fresh one per run.
        self._owns_session = client is None and client_factory is None
        #: A reach handed in by a caller (tests) pins the answer and is never re-resolved.
        self._injected_reach = reach
        #: A reach RESOLVED from the credential is scoped to the run it was resolved for: an
        #: installation can be narrowed between runs, and a falsifier instance that outlived the
        #: first run would otherwise carry the old selection into the second and authorize
        #: exactly the retirement this gate exists to refuse.
        self._resolved_reach: Reach | None = None
        self._resolved_for = ""
        #: A SECOND reading of the reach, taken after a probe and before a repository retirement
        #: is allowed to stand. One per run, on that path only.
        self._confirmed_reach: Reach | None = None
        self._confirmed_for = ""
        self._batch_id = ""

    def _resolve_client(self) -> ProbeClient:
        if self._client is None:
            if self._client_factory is not None:
                self._client = self._client_factory()
            else:
                self._client, self._auth = self._session_factory()
        return self._client

    def _resolve_reach(self, client: ProbeClient) -> Reach:
        """This RUN's reach. An injected client with no credential behind it has no reach to
        read, and says so rather than assuming one — which is what keeps an injected client from
        silently licensing retirements.

        Resolved once per run, not once per instance: the cache is keyed on the lifecycle batch
        id exactly as the parent-probe cache is, so a falsifier instance reused across runs
        re-reads the installation rather than carrying a stale selection forward.
        """
        if self._injected_reach is not None:
            return self._injected_reach
        if self._resolved_reach is None or self._resolved_for != self._batch_id:
            if self._auth is not None:
                self._resolved_reach = resolve_reach(self._auth, client)
            else:
                self._resolved_reach = unobservable(
                    "none", "this falsifier was given a client but no credential whose reach could be read"
                )
            self._resolved_for = self._batch_id
        return self._resolved_reach

    def batch_falsify(self, candidates: Sequence[Candidate], context: FalsifyContext) -> list[Verdict]:
        self._begin_run(context.batch_id)
        try:
            client = self._resolve_client()
        except Exception as exc:  # noqa: BLE001 — a missing credential is an answer, not a crash
            note = f"credential unavailable: {type(exc).__name__}"
            logger.warning("[dffc] %s: %s", type(self).__name__, note)
            return [_undetermined(c, "errored", note) for c in candidates]
        self._resolve_reach(client)
        ordered = list(candidates)
        return self.confirm_retirements(client, ordered, self.judge_all(client, ordered))

    def _begin_run(self, batch_id: str) -> None:
        """Start a new run: the batch id keys the per-run parent-probe cache, and a session this
        falsifier owns is thrown away so the next probe mints a fresh one.

        Re-resolving the reach was not enough on its own. ``GithubAuth`` records the installation
        once, when the token is minted, and never re-reads it — so an ``all`` selection would be
        re-derived from a frozen record and a narrowed installation would keep authorizing
        retirements. Nothing here touches an injected client: a
        caller that supplied one owns its lifetime, and a test's pinned credential must stay
        pinned.
        """
        if batch_id == self._batch_id:
            return
        self._batch_id = batch_id
        if self._owns_session:
            self._client = None
            self._auth = None
        self._resolved_reach = None
        self._resolved_for = ""
        self._confirmed_reach = None
        self._confirmed_for = ""

    def _reach_after_probe(self, client: ProbeClient) -> Reach:
        """The reach read AGAIN, after the probe, for the one case that has no other freshness
        check.

        A child's 404 is confirmed by a probe of its parent made at judgement time, so it is
        already judged against something fresh. A REPOSITORY has no parent to probe: its only
        gate is the reach, and that was read once near the start of the run. An installation
        narrowed in between would leave a stale `all` authorizing a retirement.

        Core's reconcile verb rejects a verdict whose target was RE-OBSERVED since the candidate
        record was derived, which does not help here: a repository that left the reach is exactly
        the one this run cannot observe. So the second reading happens here.

        It mints its own session, because ``GithubAuth`` records the installation once and a
        second read against the same credential would return the same frozen answer. One extra
        mint per run, on the path where something is about to be retired, and never for an
        injected credential whose lifetime belongs to its caller.
        """
        if self._injected_reach is not None:
            return self._injected_reach
        if self._confirmed_reach is not None and self._confirmed_for == self._batch_id:
            return self._confirmed_reach
        confirmed: Reach
        if self._owns_session:
            try:
                fresh_client, fresh_auth = self._session_factory()
                confirmed = resolve_reach(fresh_auth, fresh_client)
            except Exception:  # noqa: BLE001 — an unreadable reach is an answer, not a crash
                logger.warning("[5d41] the reach could not be re-read after the probe; refusing to retire")
                confirmed = unobservable("none", "the reach could not be re-read after the probe")
        else:
            confirmed = self._resolve_reach(client)
        self._confirmed_reach = confirmed
        self._confirmed_for = self._batch_id
        return confirmed

    def _absence_verdict(
        self,
        client: ProbeClient,
        candidate: Candidate,
        expected: Expected,
        probe: Probe,
        *,
        full_name: str,
        github_id: Any = None,
        parent_probe: bool,
    ) -> Verdict:
        """A ``not_found`` is only allowed to mean GONE inside the credential's provable reach.

        Three refusals, each with its own note, because they are three different facts: the
        reach could not be read at all; the reach was read and does not hold this repository;
        the repository is in reach but did not answer the parent probe. Outside them the probe
        stands and core derives ``DROPPED_FROM_OBSERVATION`` as before (github-core#157,
        ruling D on github-core#155).
        """
        reach = self._resolve_reach(client)
        held = reach.holds_repository(full_name=full_name, github_id=github_id)
        if held is None:
            return _undetermined(candidate, "scope_unknown", f"{_REACH_UNOBSERVED_NOTE}{reach.note}")
        if held is False:
            return _undetermined(candidate, "scope_unknown", _OUT_OF_REACH_NOTE)
        if parent_probe:
            # KNOWN GAP (github-core#160, a precondition for arming): a repository that answers
            # does not prove this credential may read what is INSIDE it. An installation can keep
            # `metadata` and lose `actions`, and where GitHub conceals that with a 404 the parent
            # answers 200 while the child answers 404. The permission axis closes it; until then
            # this gate covers the repository set only, and the spec says so.
            parent = _parent_probe(client, self._batch_id, full_name)
            if parent.status != "found":
                reason = parent.status if parent.status in UNDETERMINED_REASONS else "scope_unknown"
                return _undetermined(
                    candidate,
                    reason,
                    f"the containing repository {full_name} did not answer the probe ({parent.detail}), so a "
                    "404 on the object inside it says nothing about the object",
                )
        # A candidate with no parent to probe is confirmed against a reach read after EVERY probe
        # of the run — see `confirm_retirements`, which runs once the judgements are in.
        return verdict_from_probe(candidate, expected, probe)

    def judge_all(self, client: ProbeClient, candidates: list[Candidate]) -> list[Verdict]:
        return [self.judge(client, c) for c in candidates]

    def _locator_of(self, candidate: Candidate) -> tuple[str, Any]:
        """The repository this candidate lives in, as ``(full_name, github_id)``.

        The default is the in-repository shape: the containing repository's name, and no id,
        because a workflow or an environment carries its parent's name but not its parent's
        numeric id. A repository overrides it to add its own.
        """
        row = _row_of(candidate.entity_id)
        if row is None:
            return "", None
        return str(getattr(row, "full_name", "") or ""), None

    def confirm_retirements(
        self, client: ProbeClient, candidates: list[Candidate], verdicts: list[Verdict]
    ) -> list[Verdict]:
        """Downgrade every retirement this run would make if the reach moved underneath it.

        Every type takes this, for two different reasons that end in the same place. A
        repository has no parent to probe, so the reach is its only gate. An object inside one
        does have a parent probe, but that probe is cached for the run, so a membership
        narrowing after it would let a later 404 through. One reading covers both.

        The other half of the child case — a permission narrowing while the repository stays
        readable — is github-core#160 and is a precondition for arming, not closed here.

        The reading is taken AFTER every probe of the run, which is what makes it complete: a
        narrowing that could have caused any of these 404s necessarily happened before this read,
        so it is caught for all of them rather than only for the ones probed after it. Reading at
        the first absence and caching — the earlier shape — left every later candidate judged
        against a snapshot that predated its own probe.

        Conservative on purpose. A narrowing downgrades every retirement in the run, including
        ones that may genuinely be gone, because after the reach moves there is no longer evidence
        that separates them.
        """
        if not any(v.verdict == DROPPED_FROM_OBSERVATION for v in verdicts):
            return verdicts
        after = self._reach_after_probe(client)
        out: list[Verdict] = []
        for candidate, verdict in zip(candidates, verdicts, strict=True):
            if verdict.verdict != DROPPED_FROM_OBSERVATION:
                out.append(verdict)
                continue
            full_name, github_id = self._locator_of(candidate)
            if after.holds_repository(full_name=full_name, github_id=github_id) is True:
                out.append(verdict)
                continue
            out.append(
                _undetermined(
                    candidate,
                    "scope_unknown",
                    "the reach was read again after every probe of this run and no longer holds this "
                    f"repository, so the 404 is attributable to the change in reach ({after.note})",
                )
            )
        return out

    def judge(self, client: ProbeClient, candidate: Candidate) -> Verdict:
        raise NotImplementedError

    @staticmethod
    def _probe_get(client: ProbeClient, path: str) -> dict[str, Any] | Probe:
        """A single GET: the payload, or the failed probe it maps to."""
        try:
            payload = client.get(path)
        except GithubAPIError as exc:
            return _failed_probe(exc)
        return payload if isinstance(payload, dict) else {}


class RepositoryFalsifier(_GithubFalsifier):
    """Shape B: ``GET /repos/{owner}/{repo}``; compare GitHub's numeric id and the owner login.

    A repository has four causes for one listing absence (deleted, made private, transferred,
    access narrowed). The probe separates them: ``not_found`` is dropped from this credential's
    view; ``forbidden`` is undetermined; a found object under another login is a transfer
    (RELOCATED, ends the ownership edge, retires nothing); a found object with a different id
    at the same name is REIDENTIFIED.
    """

    def _locator_of(self, candidate: Candidate) -> tuple[str, Any]:
        """A repository names itself, and carries a stable id to compare a selected list by."""
        row = _row_of(candidate.entity_id)
        if row is None:
            return "", None
        return str(getattr(row, "full_name", "") or ""), getattr(row, "github_id", None)

    def judge(self, client: ProbeClient, candidate: Candidate) -> Verdict:
        row = _row_of(candidate.entity_id)
        if row is None:
            return _undetermined(candidate, "errored", "the grid row could not be read")
        if getattr(row, "github_id", None) is None:
            return _undetermined(
                candidate, "scope_unknown", "the grid holds no stable id (github_id) for this repository"
            )
        full_name = str(getattr(row, "full_name", "") or "")
        if "/" not in full_name:
            return _undetermined(candidate, "scope_unknown", "the grid holds no owner/repo locator for this repository")
        parent = _row_of(candidate.parent)
        owner = str(getattr(parent, "login", "") or "") or None if parent is not None else None
        expected = Expected(source_id=str(row.github_id), owner=owner, name=full_name)
        result = self._probe_get(client, f"/repos/{full_name}")
        if isinstance(result, Probe):
            if result.status == "not_found":
                # No parent probe: the repository IS the parent. Under an installation that
                # follows the account (`all`) the grant cannot narrow per repository, so a 404
                # there is the repository leaving the account; under `selected` the membership
                # test is the whole question.
                return self._absence_verdict(
                    client, candidate, expected, result, full_name=full_name, github_id=row.github_id,
                    parent_probe=False,
                )
            return verdict_from_probe(candidate, expected, result)
        found_owner = str((result.get("owner") or {}).get("login") or "") or None
        probe = Probe(
            status="found",
            source_id=str(result.get("id")) if result.get("id") is not None else None,
            # Compared only when the grid holds an owner (Option A): with no parent on record
            # there is no ownership relation for a transfer to end.
            owner=found_owner if owner is not None else None,
            name=str(result.get("full_name") or "") or None,
            created_at=_created_at(result),
            detail="HTTP 200",
        )
        return verdict_from_probe(candidate, expected, probe)


class EnvironmentFalsifier(_GithubFalsifier):
    """Shape B: ``GET /repos/{owner}/{repo}/environments/{name}``; compare the numeric id."""

    def judge(self, client: ProbeClient, candidate: Candidate) -> Verdict:
        row = _row_of(candidate.entity_id)
        if row is None:
            return _undetermined(candidate, "errored", "the grid row could not be read")
        if getattr(row, "environment_id", None) is None:
            return _undetermined(
                candidate, "scope_unknown", "the grid holds no stable id (environment_id) for this environment"
            )
        full_name, name = str(getattr(row, "full_name", "") or ""), str(getattr(row, "name", "") or "")
        if "/" not in full_name or not name:
            return _undetermined(
                candidate, "scope_unknown", "the grid holds no repository locator or name for this environment"
            )
        parent = _row_of(candidate.parent)
        owner = str(getattr(parent, "full_name", "") or "") or None if parent is not None else None
        expected = Expected(source_id=str(row.environment_id), owner=owner, name=name)
        result = self._probe_get(client, f"/repos/{full_name}/environments/{quote(name, safe='')}")
        if isinstance(result, Probe):
            if result.status == "not_found":
                return self._absence_verdict(
                    client, candidate, expected, result, full_name=full_name, parent_probe=True
                )
            return verdict_from_probe(candidate, expected, result)
        probe = Probe(
            status="found",
            source_id=str(result.get("id")) if result.get("id") is not None else None,
            # The environment endpoint is addressed by repository, so the owner it answers under
            # is the repository asked; compared only when the grid holds one.
            owner=full_name if owner is not None else None,
            name=str(result.get("name") or "") or None,
            created_at=_created_at(result),
            detail="HTTP 200",
        )
        return verdict_from_probe(candidate, expected, probe)


class ActionsSecretFalsifier(_GithubFalsifier):
    """Shape B with no stable id: ``GET`` a single secret at whichever of three URL shapes
    ``row.scope`` names, and compare presence only (github-core#866).

    GitHub's secrets API returns ``{name, created_at, updated_at, visibility (org only)}`` —
    never a numeric id, and never anything about the object that was not already in the URL
    used to ask for it. Every other falsifier in this module compares a source-reported id
    (or, for a job, a workflow id GitHub's Actions record carries independently of the file
    path used to reach it) against what the grid holds; a secret offers nothing like that.

    So ``Expected.source_id`` and a found ``Probe.source_id`` are both set to the row's own
    canonical (upper-cased) name — the same value the URL was built from, never an
    independently-reported one — which makes them equal by construction whenever anything is
    found. ``owner`` and ``name`` are left uncompared (``None`` on both sides): the address a
    secret is probed at already encodes its full location (scope, owner/repository, and for an
    environment secret, the environment), so there is no separate "owner" or "name" the source
    could report that would mean a transfer or a rename. Concretely, this means
    **``REIDENTIFIED`` and ``RELOCATED`` can never be the verdict for this type** — a ``found``
    probe is always ``PRESENT_AT_PROBE``, and the only other reachable verdicts are
    ``DROPPED_FROM_OBSERVATION`` (via the same reach-gated ``_absence_verdict`` every other
    type here uses) and ``UNDETERMINED``.

    ``row.scope`` selects the path: ``organization`` (``GET
    /orgs/{owner}/actions/secrets/{name}``), ``repository`` (``GET
    /repos/{owner}/{repo}/actions/secrets/{name}``), or ``environment`` (``GET
    /repos/{owner}/{repo}/environments/{environment}/secrets/{name}``). The repository and
    environment shapes live inside a repository, so a 404 there is judged against a probe of
    that repository (``parent_probe=True``, exactly like ``EnvironmentFalsifier``); an
    organization secret has no containing repository to probe or to check reach against, so
    it is judged with ``parent_probe=False`` and an empty ``full_name`` — which, correctly,
    means ``Reach.holds_repository`` can never say yes for it, so an organization secret's
    absence is always ``UNDETERMINED(scope_unknown)`` until the reach model grows an
    account-level notion of reach.
    """

    def judge(self, client: ProbeClient, candidate: Candidate) -> Verdict:
        row = _row_of(candidate.entity_id)
        if row is None:
            return _undetermined(candidate, "errored", "the grid row could not be read")
        name = str(getattr(row, "name", "") or "")
        scope = str(getattr(row, "scope", "") or "")
        if not name or scope not in ("organization", "repository", "environment"):
            return _undetermined(
                candidate, "scope_unknown", "the grid holds no name or a recognised scope for this secret"
            )
        owner_login = str(getattr(row, "owner_login", "") or "")
        full_name = str(getattr(row, "full_name", "") or "")
        environment_name = str(getattr(row, "environment_name", "") or "")
        if scope == "organization":
            if not owner_login:
                return _undetermined(
                    candidate, "scope_unknown", "the grid holds no owner login for this organisation secret"
                )
            path = f"/orgs/{owner_login}/actions/secrets/{quote(name, safe='')}"
            parent_probe = False
        elif scope == "repository":
            if "/" not in full_name:
                return _undetermined(
                    candidate, "scope_unknown", "the grid holds no repository locator for this secret"
                )
            path = f"/repos/{full_name}/actions/secrets/{quote(name, safe='')}"
            parent_probe = True
        else:
            if "/" not in full_name or not environment_name:
                return _undetermined(
                    candidate,
                    "scope_unknown",
                    "the grid holds no repository locator or environment name for this secret",
                )
            path = (
                f"/repos/{full_name}/environments/{quote(environment_name, safe='')}/secrets/"
                f"{quote(name, safe='')}"
            )
            parent_probe = True
        # No owner, no name: the address already IS the full location, so there is nothing left
        # for a found probe to disagree with the grid about besides existence.
        expected = Expected(source_id=name, owner=None, name=None)
        result = self._probe_get(client, path)
        if isinstance(result, Probe):
            if result.status == "not_found":
                return self._absence_verdict(
                    client, candidate, expected, result, full_name=full_name, parent_probe=parent_probe
                )
            return verdict_from_probe(candidate, expected, result)
        probe = Probe(
            status="found",
            source_id=name,
            owner=None,
            name=None,
            created_at=_created_at(result),
            detail="HTTP 200",
        )
        return verdict_from_probe(candidate, expected, probe)


class AppInstallationFalsifier(_GithubFalsifier):
    """A fourth shape (github-core#197): ``GET /app/installations/{id}`` under the App's own JWT.

    Every other falsifier in this module probes with the collector's installation-scoped
    credential and gates a 404 against that credential's REACH (github-core#157) — a repository
    the installation was never granted answers 404 for a reason that has nothing to do with the
    object's existence. This falsifier's question is different in kind: the App is asking about
    its OWN installation, and its JWT can name any installation of itself regardless of what that
    installation was ever granted. A 404 here is unambiguous — this installation id is no longer
    associated with the App — so no reach gate applies and ``_absence_verdict`` is never used.

    The credential itself is the one thing that CAN be absent: a PAT-only envelope cannot mint a
    JWT at all (``GithubAuth.has_app`` is ``False``), which ``_default_app_session`` raises on and
    this falsifier turns into ``UNDETERMINED(scope_unknown)`` for every candidate, never a crash
    and never a silent "found nothing".
    """

    def __init__(
        self,
        client: ProbeClient | None = None,
        client_factory: Callable[[], ProbeClient] | None = None,
        session_factory: Callable[[], tuple[ProbeClient, Any]] | None = None,
    ) -> None:
        super().__init__(
            client=client,
            client_factory=client_factory,
            session_factory=session_factory or _default_app_session,
        )

    def batch_falsify(self, candidates: Sequence[Candidate], context: FalsifyContext) -> list[Verdict]:
        # Overridden rather than reusing the base class's flow: that flow resolves a REPOSITORY
        # reach (`_resolve_reach`) which this falsifier's JWT-authenticated client cannot answer
        # (`/installation/repositories` requires an installation token) and does not need — the
        # JWT probe is self-authoritative, per the class docstring.
        self._begin_run(context.batch_id)
        try:
            client = self._resolve_client()
        except GithubAppAuthError as exc:
            note = f"no App credential: {exc}"
            logger.info("[a9f1] AppInstallationFalsifier: %s", note)
            return [_undetermined(c, "scope_unknown", note) for c in list(candidates)]
        except Exception as exc:  # noqa: BLE001 — a missing credential is an answer, not a crash
            note = f"credential unavailable: {type(exc).__name__}"
            logger.warning("[a9f2] AppInstallationFalsifier: %s: %s", note, exc)
            return [_undetermined(c, "errored", note) for c in list(candidates)]
        return self.judge_all(client, list(candidates))

    def judge(self, client: ProbeClient, candidate: Candidate) -> Verdict:
        row = _row_of(candidate.entity_id)
        if row is None:
            return _undetermined(candidate, "errored", "the grid row could not be read")
        installation_id = getattr(row, "installation_id", None)
        if installation_id is None:
            return _undetermined(
                candidate, "scope_unknown", "the grid holds no stable id (installation_id) for this installation"
            )
        app_slug = str(getattr(row, "app_slug", "") or "") or None
        parent = _row_of(candidate.parent)
        owner = str(getattr(parent, "slug", "") or "") or None if parent is not None else None
        expected = Expected(source_id=str(installation_id), owner=owner, name=app_slug)
        result = self._probe_get(client, f"/app/installations/{installation_id}")
        if isinstance(result, Probe):
            # No reach gate and no parent probe: see the class docstring. The App JWT already
            # answers "does this exist" directly; there is no ambiguous 404 left to disambiguate.
            return verdict_from_probe(candidate, expected, result)
        found_slug = str(result.get("app_slug") or "") or None
        probe = Probe(
            status="found",
            source_id=str(result.get("id")) if result.get("id") is not None else None,
            owner=found_slug if owner is not None else None,
            name=found_slug,
            created_at=_created_at(result),
            detail="HTTP 200",
        )
        return verdict_from_probe(candidate, expected, probe)


#: The probe recorded when a file read yields neither a record nor a failure — unreachable by
#: construction (``_workflow_file_at_head`` always returns one of the two), kept so the fail-closed
#: branch needs no assertion that a production build would strip.
_NO_ANSWER = Probe(status="errored", detail="the file read returned no answer")


def _workflow_file_at_head(
    client: ProbeClient, full_name: str, path: str
) -> tuple[dict[str, Any] | None, Probe | None]:
    """The file at HEAD (shape A's proof) and, when present, the Actions workflow record behind
    it. Returns ``(record, failed_probe)``: a record with ``id``/``name``/``path``/``text`` when
    the file is there and Actions knows it; otherwise the probe that explains why not."""
    contents = _GithubFalsifier._probe_get(client, f"/repos/{full_name}/contents/{path}")
    if isinstance(contents, Probe):
        return None, contents
    record = _GithubFalsifier._probe_get(
        client, f"/repos/{full_name}/actions/workflows/{quote(posixpath.basename(path), safe='')}"
    )
    if isinstance(record, Probe):
        if record.status == "not_found":
            # The file is at HEAD but Actions has no workflow record for it: not a workflow the
            # grid's row can be compared against. Not answered, rather than retired.
            return None, Probe(status="errored", detail="file present at HEAD; no Actions workflow record (HTTP 404)")
        return None, record
    return {**record, "text": _decode_file(contents)}, None


class WorkflowFalsifier(_GithubFalsifier):
    """Shape A: the file at HEAD, then the Actions workflow id behind it.

    The grid's identity is GitHub's workflow id; the file path is the locator. A missing file
    is ``not_found`` (a commit removed it — positive evidence); a present file whose Actions
    record carries a different id is REIDENTIFIED; the same id is PRESENT_AT_PROBE. The owner
    is the repository the file is asked in, so a transfer of the repository shows on the
    repository's own candidate, never here.
    """

    def judge(self, client: ProbeClient, candidate: Candidate) -> Verdict:
        row = _row_of(candidate.entity_id)
        if row is None:
            return _undetermined(candidate, "errored", "the grid row could not be read")
        workflow_id, path = getattr(row, "workflow_id", None), str(getattr(row, "path", "") or "")
        full_name = str(getattr(row, "full_name", "") or "")
        if workflow_id is None or not path or "/" not in full_name:
            return _undetermined(
                candidate,
                "scope_unknown",
                "the grid holds no workflow id, path or repository locator for this workflow",
            )
        parent = _row_of(candidate.parent)
        owner = str(getattr(parent, "full_name", "") or "") or None if parent is not None else None
        expected = Expected(source_id=str(workflow_id), owner=owner, name=str(getattr(row, "name", "") or "") or None)
        record, failed = _workflow_file_at_head(client, full_name, path)
        if record is None:
            answer = failed or _NO_ANSWER
            if answer.status == "not_found":
                return self._absence_verdict(
                    client, candidate, expected, answer, full_name=full_name, parent_probe=True
                )
            return verdict_from_probe(candidate, expected, answer)
        probe = Probe(
            status="found",
            source_id=str(record.get("id")) if record.get("id") is not None else None,
            owner=full_name if owner is not None else None,
            name=str(record.get("name") or "") or None,
            created_at=_created_at(record),
            detail="HTTP 200",
        )
        return verdict_from_probe(candidate, expected, probe)


class WorkflowJobFalsifier(_GithubFalsifier):
    """Shape A at the job's granularity: the job key inside the workflow file at HEAD.

    Identity is ``<workflow id>#<job key>`` — a job re-declared under the same key in a
    re-created file (new workflow id) is a different declaration, REIDENTIFIED. The owner is
    the parent workflow's id. One file fetch per (repository, path) serves every job candidate
    of that file.
    """

    def judge_all(self, client: ProbeClient, candidates: list[Candidate]) -> list[Verdict]:
        files: dict[tuple[str, str], tuple[dict[str, Any] | None, Probe | None]] = {}
        out: list[Verdict] = []
        for candidate in candidates:
            row = _row_of(candidate.entity_id)
            if row is None:
                out.append(_undetermined(candidate, "errored", "the grid row could not be read"))
                continue
            workflow_id, path = getattr(row, "workflow_id", None), str(getattr(row, "workflow_path", "") or "")
            full_name, job_key = str(getattr(row, "full_name", "") or ""), str(getattr(row, "job_key", "") or "")
            if workflow_id is None or not path or not job_key or "/" not in full_name:
                out.append(
                    _undetermined(
                        candidate,
                        "scope_unknown",
                        "the grid holds no workflow id, path, job key or repository locator for this job",
                    )
                )
                continue
            parent = _row_of(candidate.parent)
            parent_id = getattr(parent, "workflow_id", None) if parent is not None else None
            owner = str(parent_id) if parent_id is not None else None
            expected = Expected(
                source_id=f"{workflow_id}#{job_key}", owner=owner, name=str(getattr(row, "name", "") or "") or None
            )
            key = (full_name, path)
            if key not in files:
                files[key] = _workflow_file_at_head(client, full_name, path)
            record, failed = files[key]
            if record is None:
                answer = failed or _NO_ANSWER
                if answer.status == "not_found":
                    out.append(
                        self._absence_verdict(
                            client, candidate, expected, answer, full_name=full_name, parent_probe=True
                        )
                    )
                else:
                    out.append(verdict_from_probe(candidate, expected, answer))
                continue
            jobs = {
                str(j.get("id") or ""): j for j in (parse_workflow_yaml(record.get("text") or "").get("jobs") or [])
            }
            job = jobs.get(job_key)
            if job is None:
                # Deliberately NOT routed through the reach judgement: this absence rests on a
                # file this credential just READ, so the question "could it look" is already
                # answered yes by the read itself. The reach gate exists for a 404, which is the
                # status that cannot tell gone from unreadable (github-core#157).
                out.append(
                    verdict_from_probe(
                        candidate, expected, Probe(status="not_found", detail="job key absent from the file at HEAD")
                    )
                )
                continue
            found_id = record.get("id")
            probe = Probe(
                status="found",
                source_id=f"{found_id}#{job_key}" if found_id is not None else None,
                owner=str(found_id) if owner is not None and found_id is not None else None,
                name=str(job.get("name") or job_key),
                detail="HTTP 200",
            )
            out.append(verdict_from_probe(candidate, expected, probe))
        return out

    def judge(self, client: ProbeClient, candidate: Candidate) -> Verdict:
        return self.judge_all(client, [candidate])[0]


__all__ = [
    "ActionsSecretFalsifier",
    "AppInstallationFalsifier",
    "EnvironmentFalsifier",
    "RepositoryFalsifier",
    "WorkflowFalsifier",
    "WorkflowJobFalsifier",
    "probe_status_of",
]
