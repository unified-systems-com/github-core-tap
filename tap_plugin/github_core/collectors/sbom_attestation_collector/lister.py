"""The listing seam: how many CycloneDX attestations GitHub holds for a subject (req-github-core-sbom-attestations-6).

Listing is not trusted and is not read. It exists so that an attestation no trusted signer verified is
*visible*: ``gh attestation verify`` per signer only ever shows what verified, so without a count of what
exists, an attestation signed by an unlisted identity would vanish without a word. The count comes from the
documented REST endpoint ``GET /orgs/{owner}/attestations/{subject_digest}`` (``/users/{owner}/...`` when the
owner is not an organisation) through the plugin's own GitHub client and credential.
"""

from __future__ import annotations

from typing import Any, NamedTuple, Protocol

from ..github_collector.api_client import GithubAPIError, GithubClient
from .attestations import PREDICATE_TYPE
from .config import Subject


class Listing(NamedTuple):
    total: int | None
    """Attestations listed, or ``None`` when GitHub could not be asked (null is unobserved, never 0)."""
    note: str = ""
    complete: bool = True
    """False when the walk stopped before the end of the pages: ``total`` is then a floor."""


class AttestationLister(Protocol):
    def count(self, subject: Subject) -> Listing:  # pragma: no cover - protocol
        ...


class GithubAttestationLister:
    def __init__(self, client: GithubClient) -> None:
        self._client = client

    def count(self, subject: Subject) -> Listing:
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
            return Listing(len(rows), complete=self._client.last_walk_complete)
        return Listing(None, f"GitHub answered {last.status if last else '?'} when asked for the attestations of {subject.digest}")
