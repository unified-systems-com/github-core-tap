"""The verification seam: who checks the signature chain (req-github-core-sbom-attestations-3).

``AttestationVerifier.verify`` returns what a successful ``gh attestation verify --format json`` returns for one
trusted signer: a list of entries, each with the bundle and ``verificationResult``. Nothing is trusted yet when
it comes back; ``attestations.check_item`` holds each entry to the trust list again.

Two implementations sit behind the seam, chosen by the collector config's ``verifier`` key:

* ``SigstoreCoreVerifier`` (the default) lists the subject's attestations through the plugin's own GitHub client
  and verifies each bundle in process with ``sigstore_core.verify.verify_dsse_bundle``: certificate chain to the
  public-good Fulcio root, Rekor inclusion proof, and the DSSE signature, under a policy built from the trust-list
  entry. ``sigstore_core`` owns the ``sigstore`` dependency; this plugin never imports ``sigstore.*``.
* ``GhCliVerifier`` runs the same command, with the same flags, that tap's own workflow
  (``sbom-vulnerability-evidence.yml``) runs per trust-list entry, and is the only code in this plugin that
  starts a process. The token reaches the child process through its environment only and is scrubbed from
  anything recorded. It stays as the alternative for a host where the in-process verifier cannot run.

Both return the shape ``gh attestation verify --format json`` prints, so ``attestations.check_item`` holds either
one to the trust list the same way.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess  # nosec B404 - the one place a process is started; arguments are a list, never a shell string
import tempfile
from collections import Counter
from collections.abc import Callable, Mapping
from typing import Any, NamedTuple, Protocol

from ..github_collector.api_client import GithubAPIError, GithubClient
from .attestations import OIDC_ISSUER, PREDICATE_TYPE
from .config import Subject, TrustedSigner
from .errors import VerifierUnavailable

_NOTE_MAX = 300


class VerifyResult(NamedTuple):
    items: list[Any]
    """The verified entries; empty when nothing verified for this signer."""
    note: str = ""
    """Why the list is empty, when the verifier can say (first line of its error, token scrubbed)."""


class AttestationVerifier(Protocol):
    def verify(self, subject: Subject, signer: TrustedSigner) -> VerifyResult:  # pragma: no cover - protocol
        ...


class GhCliVerifier:
    """``gh attestation verify oci://<image>@<digest> --owner <o> --cert-identity <signer> ... --format json``."""

    def __init__(self, *, token: str, executable: str | None = None, timeout: float = 180.0) -> None:
        found = executable or shutil.which("gh")
        if not found:
            raise VerifierUnavailable("the gh CLI is not on PATH, so no attestation can be verified")
        if not token:
            raise VerifierUnavailable("no GitHub token to give gh")
        self._gh = os.path.abspath(found)
        self._token = token
        self._timeout = timeout
        self._home = tempfile.TemporaryDirectory(prefix="gh-sbom-verify-")

    def close(self) -> None:
        self._home.cleanup()

    def argv(self, subject: Subject, signer: TrustedSigner) -> list[str]:
        """The command, exactly as tap's evidence workflow builds it (no token in it)."""
        args = [
            self._gh,
            "attestation",
            "verify",
            subject.oci,
            "--owner",
            subject.owner,
            "--predicate-type",
            PREDICATE_TYPE,
            "--cert-identity",
            signer.identity,
            "--cert-oidc-issuer",
            OIDC_ISSUER,
            "--format",
            "json",
        ]
        if signer.signer_digest is not None:
            args += ["--signer-digest", signer.signer_digest]
        return args

    def verify(self, subject: Subject, signer: TrustedSigner) -> VerifyResult:
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": self._home.name,
            "GH_TOKEN": self._token,
            "GH_PROMPT_DISABLED": "1",
            "GH_NO_UPDATE_NOTIFIER": "1",
            "NO_COLOR": "1",
        }
        try:
            command = self.argv(subject, signer)
            # argv[0] is a literal "gh"; the resolved binary travels as `executable`, so the program name is never
            # a variable. No shell; every other element is validated config or a constant. B607 (partial path) does not
            # apply: `executable` is the absolute path __init__ resolved, the literal is only argv[0] as the program sees it.
            done = subprocess.run(  # nosec B603 B607
                ["gh", *command[1:]],
                executable=command[0],
                capture_output=True,
                env=env,
                timeout=self._timeout,
                check=False,
                stdin=subprocess.DEVNULL,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise VerifierUnavailable(f"gh could not be run for {signer.id}: {type(exc).__name__}") from exc
        if done.returncode != 0:
            err = done.stderr.decode("utf-8", errors="replace").replace(self._token, "***").strip()
            first = err.splitlines()[0] if err else f"exit {done.returncode}"
            return VerifyResult([], f"exit {done.returncode}: {first}"[:_NOTE_MAX])
        try:
            parsed = json.loads(done.stdout)
        except ValueError as exc:
            raise VerifierUnavailable(f"gh printed output that is not JSON for {signer.id}: {exc}") from exc
        if not isinstance(parsed, list):
            raise VerifierUnavailable(f"gh printed JSON that is not a list for {signer.id}")
        return VerifyResult(parsed)


class BundleListing(NamedTuple):
    bundles: list[Mapping[str, Any]]
    """Sigstore bundles GitHub holds for the subject (unverified; nothing here is trusted yet)."""
    note: str = ""
    """Why the list is empty or short, when GitHub could not say more."""


class AttestationFetcher(Protocol):
    def bundles(self, subject: Subject) -> BundleListing:  # pragma: no cover - protocol
        ...


class GithubAttestationFetcher:
    """``GET /orgs/{owner}/attestations/{subject_digest}`` (``/users/...`` for a user): the bundles, not the verdicts.

    The endpoint is the one the lister counts; each row carries the Sigstore bundle inline. Rows are cached per
    digest because ``verify`` is called once per trust-list entry. Nothing fetched is trusted: every bundle goes
    through the verifier before ``check_item`` sees it.
    """

    def __init__(self, client: GithubClient) -> None:
        self._client = client
        self._cache: dict[str, BundleListing] = {}

    def bundles(self, subject: Subject) -> BundleListing:
        cached = self._cache.get(subject.digest)
        if cached is not None:
            return cached
        params = {"predicate_type": PREDICATE_TYPE, "per_page": "100"}
        last: GithubAPIError | None = None
        for kind in ("orgs", "users"):
            path = f"/{kind}/{subject.owner}/attestations/{subject.digest}"
            try:
                rows: list[Any] = self._client.get_paginated(path, params=params, item_path="attestations")
            except GithubAPIError as exc:
                last = exc
                if exc.status == 404:
                    continue
                break
            bundles = [r["bundle"] for r in rows if isinstance(r, Mapping) and isinstance(r.get("bundle"), Mapping)]
            note = ""
            if len(bundles) != len(rows):
                note = f"{len(rows) - len(bundles)} listed attestation(s) carried no inline bundle and were not read"
            if not self._client.last_walk_complete:
                note = (note + "; " if note else "") + "the attestation listing was cut short"
            result = BundleListing(bundles, note)
            self._cache[subject.digest] = result
            return result
        # Not cached: a refused or failed listing may succeed on the next call.
        return BundleListing([], f"GitHub answered {last.status if last else '?'} when asked for the attestations of {subject.digest}")


def load_sigstore_core() -> tuple[Callable[..., Any], Callable[..., Any], Callable[..., Any]]:
    """(verify_dsse_bundle, extract_predicate, GitHubWorkflowPolicy) from sigstore_core, or ``VerifierUnavailable``.

    Imported on demand so the gh-backed path and the pure modules do not need sigstore_core installed.
    """
    try:
        from tap_plugin.sigstore_core.statement import extract_predicate
        from tap_plugin.sigstore_core.verify import GitHubWorkflowPolicy, verify_dsse_bundle
    except ImportError as exc:
        raise VerifierUnavailable(
            "sigstore_core with DSSE verification is not installed; install a sigstore-core-tap release that "
            f"carries verify_dsse_bundle, or set the config's verifier to 'gh' ({exc})"
        ) from exc
    return verify_dsse_bundle, extract_predicate, GitHubWorkflowPolicy


class SigstoreCoreVerifier:
    """Verify each listed bundle in process with ``sigstore_core`` and return it in ``gh``'s result shape.

    The policy is built from the trust-list entry, never from the bundle: the entry's exact signer identity
    (``TrustedSigner.identity``) is the certificate SAN, the issuer is GitHub Actions, the repository is the
    entry's, and a pinned ``signer_digest`` is the Fulcio *Build Signer Digest* (the commit of the signing
    workflow file). It is deliberately not the certificate's workflow SHA: for a reusable workflow that is the
    calling repository's commit, a different value. The ref is not pinned separately; the exact identity URI
    already ends in it.

    ``verify`` is called once per trust-list entry, so a bundle signed by another entry fails this entry's
    policy (``policy_mismatch``) and is dropped without comment, exactly as ``gh --cert-identity`` drops it. A bundle that
    matches the identity but fails anything else (signature, chain, Rekor proof) is dropped too and counted in
    the note, so it is visible in the refusal text. Only a verifier that could not run at all
    (``failure_code == "unexpected"``: trust root unreachable, library error) raises ``VerifierUnavailable``.
    """

    def __init__(
        self,
        fetcher: AttestationFetcher,
        *,
        verify_dsse: Callable[..., Any] | None = None,
        extract_predicate: Callable[..., Any] | None = None,
        policy_factory: Callable[..., Any] | None = None,
    ) -> None:
        if verify_dsse is None or extract_predicate is None or policy_factory is None:
            loaded_verify, loaded_extract, loaded_policy = load_sigstore_core()
            verify_dsse = verify_dsse or loaded_verify
            extract_predicate = extract_predicate or loaded_extract
            policy_factory = policy_factory or loaded_policy
        self._fetcher = fetcher
        self._verify_dsse = verify_dsse
        self._extract = extract_predicate
        self._policy = policy_factory

    def policy_for(self, signer: TrustedSigner) -> Any:
        """The sigstore_core policy a trust-list entry means."""
        return self._policy(
            oidc_issuer=OIDC_ISSUER,
            github_repository=signer.repository,
            workflow_identity_uri=signer.identity,
            build_signer_digest=signer.signer_digest,
        )

    def verify(self, subject: Subject, signer: TrustedSigner) -> VerifyResult:
        listing = self._fetcher.bundles(subject)
        policy = self.policy_for(signer)
        items: list[Any] = []
        dropped: Counter[str] = Counter()
        for bundle in listing.bundles:
            outcome = self._verify_dsse(json.dumps(bundle).encode("utf-8"), policy=policy)
            if outcome.signature_verified is not True:
                code = outcome.failure_code or "unverified"
                if code == "unexpected":
                    raise VerifierUnavailable(
                        f"the in-process verifier could not run for {signer.id}: {outcome.failure_detail[:_NOTE_MAX]}"
                    )
                dropped[code] += 1
                continue
            statement = self._extract(
                outcome.payload,
                expected_subject_sha256=subject.digest,
                expected_predicate_type=PREDICATE_TYPE,
            )
            if not statement.ok:
                dropped[statement.failure_code] += 1
                continue
            items.append(
                {
                    "attestation": {"bundle": bundle},
                    "verificationResult": {
                        "signature": {
                            "certificate": {
                                "subjectAlternativeName": outcome.signed_by,
                                "issuer": outcome.signing_issuer,
                                "buildSignerDigest": outcome.build_signer_digest,
                            }
                        },
                        "statement": {"predicateType": PREDICATE_TYPE, "predicate": json.loads(statement.predicate)},
                    },
                }
            )
        if items:
            return VerifyResult(items)
        why = ", ".join(f"{n} {code}" for code, n in sorted(dropped.items()))
        parts = [f"{len(listing.bundles)} bundle(s) listed" + (f", none verified for this signer ({why})" if why else "")]
        if listing.note:
            parts.append(listing.note)
        return VerifyResult([], "; ".join(parts)[:_NOTE_MAX])
