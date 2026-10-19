"""SbomAttestationCollector: CI-signed CycloneDX SBOMs, verified against the trust list, mapped to findings.

Spec: specs/spec-github-core-v0.md (req-github-core-sbom-attestations). One run reads every subject the
operator's config names, verifies its attestations (``verifier.py``), keeps the highest revision per serial as
current and the earlier ones as superseded, maps them through computing_core's verified parser and this
plugin's ``sbom_vulnerability_grift``, and submits the result through ``CollectorBase.submit_grift`` with the
default abort on rejection.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar

from tap_cares.collectors import (
    CollectorDocRef,
    CollectorReadinessStatus,
    CollectorSelfTestResult,
    check_fail,
    check_pass,
)
from tap_cares.collectors.base import CollectorBase
from tap_cares.exceptions import SecretError

from ..github_collector.api_client import GithubClient
from ..github_collector.auth import GithubAuth
from ..github_collector.secret import GITHUB_SECRET_REF, api_base_url, resolve_github_secret
from .config import CONFIG_FILENAME, SbomAttestationConfig, TrustedSigner, load_config, load_trusted_signers
from .errors import SbomAttestationError
from .lister import AttestationLister, GithubAttestationLister
from .pipeline import PipelineResult, run_pipeline
from .verifier import (
    AttestationVerifier,
    GhCliVerifier,
    GithubAttestationFetcher,
    SigstoreCoreVerifier,
    load_sigstore_core,
)

# Log site tokens for the recorder. Minted via scripts/log-site-id.
_SITE_RUN_STARTED = "e6af"
_SITE_ABORT_CONFIG = "e328"
_SITE_ABORT_CREDENTIAL = "f748"
_SITE_ABORT_VERIFY = "e756"
_SITE_SUBJECT = "7d4e"
_SITE_UNVERIFIED = "2680"
_SITE_UNLISTED = "a575"
_SITE_UNSCANNED = "0511"
_SITE_NOTHING_TO_SUBMIT = "d962"
_SITE_SUBMITTED = "6349"

_DOCS = (
    CollectorDocRef(
        plugin="github_core",
        doc="collector",
        section="sbom-attestations",
        label="GitHub Core SBOM attestation collector",
    ),
)


class SbomAttestationCollector(CollectorBase):
    """Fetch, verify and feed signed SBOM attestations to the SBOM vulnerability mapping."""

    #: Tests replace these to run offline (req-github-core-sbom-attestations-8). Production builds the
    #: `gh`-backed verifier and the REST lister from the collector credential.
    verifier: ClassVar[AttestationVerifier | None] = None
    lister: ClassVar[AttestationLister | None] = None
    #: Where the operator's config is read from; tests point it at a temporary file.
    config_path: ClassVar[Path | None] = None

    @classmethod
    def _config_path(cls) -> Path:
        if cls.config_path is not None:
            return cls.config_path
        from django.conf import settings  # local: the pure modules never import Django

        return Path(settings.TAP_SECRETS_ROOT) / GITHUB_SECRET_REF.scope / CONFIG_FILENAME

    @classmethod
    def self_test(cls) -> CollectorSelfTestResult:
        """Config valid, trust list valid, credential placed, and `gh` present when no verifier is injected."""
        checks: list[Any] = []

        def stop(summary: str) -> CollectorSelfTestResult:
            return CollectorSelfTestResult.from_checks(checks, summary=summary, docs=_DOCS)

        try:
            config = load_config(cls._config_path())
            signers = load_trusted_signers(config.trusted_signers_path)
        except SbomAttestationError as exc:
            checks.append(
                check_fail("SBOM_CONFIG_VALID", str(exc), readiness_status=CollectorReadinessStatus.UNCONFIGURED, docs=_DOCS)
            )
            return stop("The SBOM attestation config or trust list is unusable.")
        checks.append(
            check_pass(
                "SBOM_CONFIG_VALID",
                f"{len(config.subjects)} subject(s); {len(signers)} trusted signer(s).",
                context={"subjects": len(config.subjects), "signers": len(signers)},
                docs=_DOCS,
            )
        )
        try:
            resolve_github_secret(GITHUB_SECRET_REF)
        except SecretError as exc:
            checks.append(
                check_fail("GITHUB_SECRET_VALID", f"Collector credential is unusable: {exc}", readiness_status=CollectorReadinessStatus.UNCONFIGURED, docs=_DOCS)
            )
            return stop("No usable collector credential.")
        checks.append(check_pass("GITHUB_SECRET_VALID", "Collector credential resolves.", docs=_DOCS))
        if cls.verifier is None and config.verifier == "gh":
            import shutil

            if shutil.which("gh") is None:
                checks.append(
                    check_fail(
                        "GH_CLI_PRESENT",
                        "The gh CLI is not on PATH; attestations cannot be verified.",
                        readiness_status=CollectorReadinessStatus.MISCONFIGURED,
                        docs=_DOCS,
                    )
                )
                return stop("The gh CLI that verifies attestations is missing.")
            checks.append(check_pass("GH_CLI_PRESENT", "The gh CLI is on PATH.", docs=_DOCS))
        elif cls.verifier is None:
            try:
                load_sigstore_core()
            except SbomAttestationError as exc:
                checks.append(
                    check_fail("SIGSTORE_CORE_PRESENT", str(exc), readiness_status=CollectorReadinessStatus.MISCONFIGURED, docs=_DOCS)
                )
                return stop("The sigstore_core verifier is unavailable.")
            checks.append(check_pass("SIGSTORE_CORE_PRESENT", "sigstore_core DSSE verification is installed.", docs=_DOCS))
        return stop("SBOM attestation collector is ready.")

    def _abort(self, site: str, code: str, message: str) -> None:
        self.record_error(site, code, message)
        raise SbomAttestationError(message)

    def run(self) -> None:
        self.record_info(_SITE_RUN_STARTED, "RUN_STARTED", "SBOM attestation collection started.")
        try:
            config: SbomAttestationConfig = load_config(self._config_path())
            signers: tuple[TrustedSigner, ...] = load_trusted_signers(config.trusted_signers_path)
        except SbomAttestationError as exc:
            self._abort(_SITE_ABORT_CONFIG, "CONFIG_UNUSABLE", f"Collector config or trust list unusable: {exc}")
            return
        verifier = type(self).verifier
        lister = type(self).lister
        owned_verifier: GhCliVerifier | None = None
        if verifier is None or lister is None:
            try:
                secret = resolve_github_secret(GITHUB_SECRET_REF)
                data = dict(secret.data)
                auth = GithubAuth(kind=secret.kind, data=data, api_base_url=api_base_url(data))
                token = auth.token()
            except Exception as exc:  # noqa: BLE001 - any credential failure stops the run, loudly
                self._abort(_SITE_ABORT_CREDENTIAL, "SECRET_UNUSABLE", f"GitHub credential unusable: {type(exc).__name__}: {exc}")
                return
            client = GithubClient(token=token, api_base_url=api_base_url(data))
            if verifier is None:
                try:
                    if config.verifier == "gh":
                        owned_verifier = verifier = GhCliVerifier(token=token)
                    else:
                        verifier = SigstoreCoreVerifier(GithubAttestationFetcher(client))
                except SbomAttestationError as exc:
                    self._abort(_SITE_ABORT_VERIFY, "VERIFIER_UNAVAILABLE", str(exc))
                    return
            if lister is None:
                lister = GithubAttestationLister(client)
        try:
            result = run_pipeline(config, signers, verifier, lister)
        except SbomAttestationError as exc:
            self._abort(_SITE_ABORT_VERIFY, "ATTESTATION_REFUSED", f"Nothing was submitted: {exc}")
            return
        finally:
            if owned_verifier is not None:
                owned_verifier.close()
        self._report(result)

        if result.grift is None:
            self.record_warn(
                _SITE_NOTHING_TO_SUBMIT,
                "NOTHING_TO_SUBMIT",
                "No subject has a scanned current revision, so there are no findings to state or resolve.",
            )
            self.summary = f"Verified {len(result.subjects)} subject(s); none carried vulnerabilities[]; nothing submitted."
            return
        self.submit_grift(result.grift.document)
        counts = result.grift
        self.record_info(
            _SITE_SUBMITTED,
            "SBOM_BATCH_SUBMITTED",
            f"Submitted {counts.findings_open} open and {counts.findings_resolved} resolved finding(s), "
            f"{counts.vulnerabilities} vulnerabilit(ies), {counts.scanners} scanner(s).",
            message_data={"components": len(counts.components), "notes": list(counts.notes)},
        )
        self.summary = (
            f"{len(result.subjects)} subject(s): {counts.findings_open} open, {counts.findings_resolved} resolved "
            f"finding(s), {counts.vulnerabilities} vulnerabilit(ies)."
        )

    def _report(self, result: PipelineResult) -> None:
        for s in result.subjects:
            self.record_info(
                _SITE_SUBJECT,
                "SUBJECT_VERIFIED",
                f"{s.image}@{s.digest[:19]}: revision {s.current_version} ({s.status}) signed by {s.current_signer}; "
                f"{len(s.superseded_versions)} earlier revision(s), {s.superseded_unscanned} without vulnerabilities[].",
                message_data={
                    "image": s.image,
                    "digest": s.digest,
                    "status": s.status,
                    "current_version": s.current_version,
                    "superseded_versions": list(s.superseded_versions),
                    "verified": s.verified,
                    "listed": s.listed,
                },
            )
            if s.unverified:
                self.record_warn(
                    _SITE_UNVERIFIED,
                    "ATTESTATIONS_NOT_ON_TRUST_LIST",
                    f"{s.image}@{s.digest[:19]}: GitHub lists {s.listed} CycloneDX attestation(s) but {s.verified} verified "
                    f"against the trust list. The other {s.unverified} were not read.",
                    message_data={"image": s.image, "digest": s.digest, "listed": s.listed, "verified": s.verified},
                )
            if s.listed is None:
                self.record_warn(
                    _SITE_UNLISTED,
                    "ATTESTATION_LISTING_UNOBSERVED",
                    f"{s.image}@{s.digest[:19]}: GitHub's attestation listing could not be read, so attestations "
                    f"outside the trust list are unobserved (not zero).",
                    message_data={"image": s.image, "digest": s.digest, "notes": list(s.notes)},
                )
            if s.status == "unscanned":
                self.record_warn(
                    _SITE_UNSCANNED,
                    "CURRENT_REVISION_UNSCANNED",
                    f"{s.image}@{s.digest[:19]}: the newest verified revision ({s.current_version}) was never scanned; "
                    f"it states and resolves nothing.",
                    message_data={"image": s.image, "digest": s.digest, "current_version": s.current_version},
                )
