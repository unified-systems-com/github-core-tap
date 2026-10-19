"""Refusals of the SBOM attestation collector (req-github-core-sbom-attestations-4)."""

from __future__ import annotations


class SbomAttestationError(Exception):
    """Base of every refusal here: the run stops and submits nothing."""


class ConfigError(SbomAttestationError):
    """The collector config, or the trust list it names, is unreadable or invalid (default deny)."""


class AttestationRefused(SbomAttestationError):
    """A verified-looking attestation does not satisfy the trust list, or is not what it claims to be."""


class VerifierUnavailable(SbomAttestationError):
    """The verifier could not run at all (no ``gh``, no token): distinct from "nothing verified"."""
