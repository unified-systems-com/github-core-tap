"""The verification seam: who checks the signature chain (req-github-core-sbom-attestations-3).

``AttestationVerifier.verify`` returns what a successful ``gh attestation verify --format json`` returns for one
trusted signer: a list of entries, each with the bundle and ``verificationResult``. Nothing is trusted yet when
it comes back; ``attestations.check_item`` holds each entry to the trust list again.

``GhCliVerifier`` is the production implementation. It runs the same command, with the same flags, that tap's
own workflow (``sbom-vulnerability-evidence.yml``) runs per trust-list entry, and it is the only code in this
plugin that starts a process. No Python Sigstore verifier is a dependency of TAP and adding one needs an
approval, so the certificate chain, the transparency-log inclusion and the DSSE signature are checked by the
tool that GitHub ships for exactly that. The token reaches the child process through its environment only and
is scrubbed from anything recorded.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess  # nosec B404 - the one place a process is started; arguments are a list, never a shell string
import tempfile
from typing import Any, NamedTuple, Protocol

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
        self._gh = found
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
            done = subprocess.run(  # nosec B603 - list argv, no shell; every element is validated config or a constant
                self.argv(subject, signer),
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
