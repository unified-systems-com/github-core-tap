"""GRIFT envelope + batch assembly for the github_core collector.

Spec: plugins/github_core/specs/spec-github-core-v0.md
(req-github-core-collector). THREE batches per run, and the boundaries between
them matter because refs are batch-local (Issue# 162):

1. the collection-scope batch, submitted before the walk so the node exists while the run is
   in progress. Its `SCOPES_RUN` edge targets the core `collection_job`, which is a real id
   from another batch entirely, so that endpoint is an `entity_id` while the scope node is a
   ref. The collector reads the scope's ASSIGNED id back off the import result.
2. the GitHub batch (nodes + spine edges), where almost every github_core node is a ref;
3. the enrichment batch (REFERENCES_RESOURCE / FEDERATES_VIA_PROVIDER edges only), whose
   endpoints are real ids READ BACK OFF THE GRID after batch 2 committed — never refs.

Document shape per `tap_grid/schemas/grift-document.schema.json`:
  {metadata: {grift_version, spine_version, type_versions}, _reserved: {}, batches: [GriftBatchContainer]}

The header is GRIFT format "1", and it is core's to write: :func:`with_header` sets it from
`tap_grid.grift.upgrade.build_header`, which reads the spine version and every carried type's
version off the grid. That needs Django and a database, and `assemble_batch` is also called by the
Django-free `sbom_vulnerability_grift` (req-github-core-sbom-vulnerabilities-1), so assembly leaves
``metadata`` empty and each collector's `submit_grift` stamps the header on the finished document.
An unstamped document fails the schema (``grift_version`` is required) instead of importing as
format "0", which core 0.5.0 refuses by default.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid7

from .identity import Ref

COLLECTION_FORMAT = "tap.github_core.collection-v0"


def with_header(document: dict[str, Any]) -> dict[str, Any]:
    """Set ``document["metadata"]`` to core's format "1" header for it, and return the document.

    Call it once the document's batches are complete: the header names every type they carry.
    Needs Django and the database, so the import is local and the pure assembly path never runs it.
    """
    from tap_grid.grift.upgrade import build_header

    document["metadata"] = build_header(document)
    return document


def _addressed(value: UUID | Ref | str) -> dict[str, str]:
    """``{"ref": …}`` for a batch-local ref, ``{"entity_id": …}`` for a real id.

    The one place the choice is made (Issue# 162). Exactly one of the two is permitted per
    envelope — the GRIFT document schema enforces the XOR — and which one it is follows from
    the type of the value the caller already had: :class:`~.identity.Ref` for a github_core
    type that has declared its ``NATURAL_KEY`` and lets core assign the id, a ``UUID`` for
    everything still addressed explicitly (other plugins' types, and the entities this run did
    not create, such as the core ``collection_job``).
    """
    if isinstance(value, Ref):
        return {"ref": str(value)}
    return {"entity_id": str(value)}


def node_envelope(
    *,
    entity_id: UUID | Ref,
    entity_type: str,
    name: str,
    dimensions: dict[str, str],
    fields: dict[str, Any],
) -> dict[str, Any]:
    return {
        "entity": {
            **_addressed(entity_id),
            "entity_type": entity_type,
            "name": name,
            "dimensions": dimensions,
        },
        "node": fields,
    }


def edge_envelope(
    *,
    entity_id: UUID,
    edge_type: str,
    source_id: UUID | Ref,
    target_id: UUID | Ref,
    dimensions: dict[str, str],
    properties: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """One edge envelope; each endpoint independently names a ref or an id.

    Mixed endpoints are normal and the schema allows them: a `HOSTS_REPOSITORY` edge runs from
    a github_core repository ref to a git_core repository still addressed by a derived id. The
    edge's OWN id stays a real UUID — the importer never substitutes an edge envelope's id
    (edges are ``KEYLESS`` and keep their assignment), so the plugin's derivation is what keeps
    one edge per fact across runs.
    """
    endpoints = {
        f"from_{k}": v for k, v in _addressed(source_id).items()
    } | {f"to_{k}": v for k, v in _addressed(target_id).items()}
    return {
        "entity": {
            "entity_id": str(entity_id),
            "entity_type": "edge",
            "name": edge_type,
            "dimensions": dimensions,
        },
        "edge": {
            **endpoints,
            "edge_type": edge_type,
            "properties": properties or {},
        },
    }


def envelope_key(envelope: dict[str, Any]) -> str | None:
    """How this envelope names itself — its ``ref`` or its ``entity_id``, whichever it carries."""
    entity = envelope.get("entity") or {}
    value = entity.get("ref", entity.get("entity_id"))
    return None if value is None else str(value)


def endpoint_keys(envelope: dict[str, Any]) -> tuple[str, str]:
    """An edge's two endpoints as the keys its own batch's nodes are named by."""
    edge = envelope.get("edge") or {}
    return (
        str(edge.get("from_ref", edge.get("from_entity_id"))),
        str(edge.get("to_ref", edge.get("to_entity_id"))),
    )


def assemble_batch(
    *,
    batch_name: str,
    description: str,
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    batch_dimensions: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Wrap nodes + edges into a single-batch GRIFT document, its header left for :func:`with_header`."""
    moment = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    batch = {
        "batch_entity": {
            "entity_id": str(uuid7()),
            "entity_type": "batch",
            "name": batch_name,
            "dimensions": batch_dimensions or {"git.host": "github.com"},
        },
        "batch_node": {
            "source": "github_core",
            "name": batch_name,
            "description": description,
            "description_json": {
                "format": COLLECTION_FORMAT,
                "collected_at": moment,
                "counts": {"nodes": len(nodes), "edges": len(edges)},
            },
        },
        "nodes": nodes,
        "edges": edges,
    }
    return {
        "metadata": {},
        "_reserved": {},
        "batches": [batch],
    }
