"""The collector's auth seam: one object holding both credentials, asked per source.

**Neither credential dominates, so the collector holds both and picks per call.** This is measured,
not assumed:

* Only a **GitHub App** sees the account's installed-App inventory and its fine-grained PAT grants
  — both answer `404` to any token. The App is its own principal with its own declared permissions.
* Only an **owner-minted PAT** sees a ruleset's `bypass_actors`, because GitHub discloses that list
  solely to a caller with write access to the ruleset, which a read-only App is never given.

An either/or design would therefore condemn every deployment to one permanent blind spot. So a
caller names the credential that answers ITS question best — `auth.token(prefer=PREFER_PAT)` for
the ruleset detail, `auth.app_jwt()` for the App-only inventory — and where the better credential
is absent, `auth.absent_note(prefer=...)` says which one would have shown more, so a gap becomes
an instruction rather than a dead end.

A caller that does not care asks for `auth.token()` and gets whichever is present.

Spec: plugins/github_core/specs/spec-github-core-v0.md (req-github-core-app-auth)
"""

from __future__ import annotations

import logging
from typing import Any

from .app_jwt import GithubAppAuthError, exchange_installation_token, list_installations, mint_jwt
from .secret import normalize_credentials

logger = logging.getLogger(__name__)

#: What a caller asks for when one credential genuinely answers better than the other.
#:
#: There is deliberately NO `mode` property. Under a combined envelope "which mode am I in" has no
#: correct answer, and any default it were given would leave every existing call site compiling
#: while quietly changing meaning — the failure is invisible because the type never changes.
#: Capability predicates (`has_app` / `has_pat`) force each call site to say what it actually
#: needs, and migrating them was loud, which is the point.
PREFER_APP = "app"
PREFER_PAT = "pat"

#: Why each preference exists, in the operator's terms. Used to explain a gap rather than to
#: choose — the sentence an operator reads when a column is blank because the better credential
#: was not placed.
_ABSENT_NOTE: dict[str, str] = {
    PREFER_PAT: (
        "GitHub discloses a ruleset's bypass actors only to a caller with write access to the "
        "ruleset, which a read-only App is never given; an owner-minted fine-grained token would "
        "show them"
    ),
    PREFER_APP: (
        "the installed-App inventory and the organization's fine-grained PAT grants answer 404 to "
        "any personal access token; a GitHub App would show them"
    ),
}


class GithubAuth:
    """Resolved credential → bearer token, plus the App-only facts a PAT cannot reach.

    Installation tokens are held on the INSTANCE, never at module or class scope. Two collections
    running against two accounts in one process would otherwise be one shared mutable token away
    from cross-account leakage — a failure that produces plausible results rather than an error,
    which is the worst kind (`req-github-core-app-auth-7`).
    """

    def __init__(self, *, kind: str, data: dict[str, Any], api_base_url: str) -> None:
        self._data = normalize_credentials(kind, data)
        self._app = self._data.get("app") or {}
        self._pat = self._data.get("pat") or {}
        self._api_base_url = api_base_url
        self._installation_token: str | None = None
        self._installation: dict[str, Any] | None = None
        self._installations: list[dict[str, Any]] | None = None

    @property
    def has_app(self) -> bool:
        """Whether an App credential is present."""
        return bool(self._app.get("private_key"))

    @property
    def app_id(self) -> int | str | None:
        """This envelope's own App id — the identity a `GET /app/installations/{id}` probe under
        this JWT is actually scoped to. The endpoint answers `404` both for a revoked installation
        and for one that belongs to a DIFFERENT App this JWT was never issued for, and the two
        must not be told apart by status code alone (github-core#197). `None` when the envelope
        carries no App credential.
        """
        return self._app.get("app_id") if self.has_app else None

    @property
    def has_pat(self) -> bool:
        """Whether a personal access token is present."""
        return bool(self._pat.get("token"))

    @property
    def held(self) -> list[str]:
        """Which credentials this envelope carries, for reporting only — never for dispatch."""
        return [name for name, present in ((PREFER_APP, self.has_app), (PREFER_PAT, self.has_pat)) if present]

    def absent_note(self, prefer: str) -> str:
        """Why a gap exists, when the credential that would close it is not present.

        Empty when the preferred credential IS present — there is then nothing to explain, and a
        note that fires anyway would train a reader to ignore it.
        """
        if (prefer == PREFER_APP and self.has_app) or (prefer == PREFER_PAT and self.has_pat):
            return ""
        return _ABSENT_NOTE.get(prefer, "")

    @property
    def installation(self) -> dict[str, Any] | None:
        """The installation whose token is in use, once an App token has been minted."""
        return self._installation

    def token(self, prefer: str | None = None) -> str:
        """A bearer token for repository-scoped calls.

        `prefer` names the credential that answers the CALLER's question best; when it is absent
        the other is used rather than failing, because a partial answer beats none — the caller
        pairs this with `absent_note` to say what the partial answer is missing.

        The App's installation token is minted once and reused for the run: GitHub's installation
        tokens last about an hour, comfortably longer than a collection, and re-minting per call
        would burn rate limit to no purpose.
        """
        if prefer == PREFER_PAT and self.has_pat:
            return str(self._pat["token"])
        if prefer == PREFER_APP and not self.has_app and self.has_pat:
            return str(self._pat["token"])
        if self.has_app:
            if self._installation_token is None:
                self._installation_token = self._mint_installation_token()
            return self._installation_token
        return str(self._pat["token"])

    def app_jwt(self) -> str:
        """The App-level JWT. Requires an App credential — a token cannot produce one."""
        if not self.has_app:
            raise GithubAppAuthError("app_jwt() requires an App credential in the envelope")
        return mint_jwt(self._app["app_id"], self._app["private_key"])

    def installations(self) -> list[dict[str, Any]]:
        """Every installation of this App, or an empty list when the envelope carries no App.

        Empty means *nothing observed*, and the caller must not render it as *nothing installed*:
        without an App the surface is unreachable, not empty. The collector records which it was.
        """
        if not self.has_app:
            return []
        if self._installations is None:
            self._installations = list_installations(self._api_base_url, self.app_jwt())
        return self._installations

    def _mint_installation_token(self) -> str:
        """Pick this account's installation and trade the JWT for its token.

        The envelope's `owner` selects the installation rather than "the first one": an App
        installed into several accounts would otherwise collect one account's repositories under
        another account's name, silently and plausibly.
        """
        installations = self.installations()
        if not installations:
            raise GithubAppAuthError("App has no installations — nothing to collect as")
        owner = str(self._data.get("owner") or "")
        chosen: dict[str, Any] | None = None
        if owner:
            chosen = next(
                (i for i in installations if str((i.get("account") or {}).get("login", "")).lower() == owner.lower()),
                None,
            )
            if chosen is None:
                available = ", ".join(sorted(str((i.get("account") or {}).get("login", "?")) for i in installations))
                raise GithubAppAuthError(
                    f"App is not installed on {owner!r} (installed on: {available or 'nothing'})"
                )
        else:
            # A repos-only envelope names no account. One installation is unambiguous; several are
            # not, and guessing would attribute one account's data to another.
            if len(installations) > 1:
                raise GithubAppAuthError(
                    "App has several installations and the envelope names no `owner` to choose between them"
                )
            chosen = installations[0]
        self._installation = chosen
        token, expires_at = exchange_installation_token(self._api_base_url, self.app_jwt(), chosen["id"])
        # nosec B105 — the message NAMES the act of minting; the token itself is never an
        # argument here, and must never become one.
        logger.info(
            "[17b1] minted installation token for %s (installation %s), expires %s",  # nosec B105
            (chosen.get("account") or {}).get("login", "?"),
            chosen.get("id"),
            expires_at or "unknown",
        )
        return token
