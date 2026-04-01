"""
routes/stix.py — STIX 2.1 export and indicator statistics.

Converts Cerberus investigation graphs into STIX 2.1 JSON bundles so analysts
can share findings with other threat-intel platforms (MISP, OpenCTI, etc.) via
the standard TAXII interchange format.

Endpoints:
  GET /api/stix/bundle?entity=X&type=Y  — full STIX 2.1 bundle for an entity
  GET /api/stix/indicator-count          — aggregate indicator counts by type
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Query

import neo4j_client as db
from models import EntityType

router = APIRouter(prefix="/api/stix")


# ── STIX type mapping ────────────────────────────────────────────────────────
# Maps Neo4j node labels to their corresponding STIX 2.1 SDO/SCO type and the
# property used to carry the node's identifier (name, value, account_login, etc.).

_NODE_TYPE_TO_STIX: dict[str, dict[str, str]] = {
    "Package":      {"stix_type": "software",      "id_prop": "name"},
    "IP":           {"stix_type": "ipv4-addr",      "id_prop": "value"},
    "Domain":       {"stix_type": "domain-name",    "id_prop": "value"},
    "CVE":          {"stix_type": "vulnerability",  "id_prop": "name"},
    "ThreatActor":  {"stix_type": "threat-actor",   "id_prop": "name"},
    "Technique":    {"stix_type": "attack-pattern", "id_prop": "name"},
    "Account":      {"stix_type": "user-account",   "id_prop": "account_login"},
    "FraudSignal":  {"stix_type": "note",           "id_prop": "abstract"},
}


def _make_stix_object(node: dict[str, Any], now_iso: str) -> dict[str, Any] | None:
    """
    Convert a single Cerberus graph node (from get_graph()) into a STIX 2.1
    domain/cyber-observable object.  Returns None for unmapped node types.
    """
    node_type = node.get("type", "")
    node_id = node.get("id", "")
    mapping = _NODE_TYPE_TO_STIX.get(node_type)
    if not mapping:
        return None

    stix_type = mapping["stix_type"]
    stix_id = f"{stix_type}--{uuid.uuid4()}"

    obj: dict[str, Any] = {
        "type": stix_type,
        "spec_version": "2.1",
        "id": stix_id,
        "created": now_iso,
        "modified": now_iso,
    }

    # Populate the type-specific property that carries the node identifier
    id_prop = mapping["id_prop"]
    if stix_type == "note":
        obj["abstract"] = f"Fraud signal: {node_id}"
    elif stix_type == "vulnerability":
        obj["name"] = node_id
        obj["external_references"] = [
            {"source_name": "cve", "external_id": node_id}
        ]
    else:
        obj[id_prop] = node_id

    return obj


def _make_relationship(
    link: dict[str, Any],
    node_stix_ids: dict[str, str],
    now_iso: str,
) -> dict[str, Any] | None:
    """
    Convert a Cerberus graph link into a STIX 2.1 relationship SRO.
    node_stix_ids maps the original node id → assigned STIX id.
    """
    source_ref = node_stix_ids.get(link.get("source", ""))
    target_ref = node_stix_ids.get(link.get("target", ""))
    if not source_ref or not target_ref:
        return None

    rel_type = (link.get("type") or "related-to").lower().replace("_", "-")

    return {
        "type": "relationship",
        "spec_version": "2.1",
        "id": f"relationship--{uuid.uuid4()}",
        "created": now_iso,
        "modified": now_iso,
        "relationship_type": rel_type,
        "source_ref": source_ref,
        "target_ref": target_ref,
    }


# ── GET /api/stix/bundle ─────────────────────────────────────────────────────

@router.get("/bundle")
async def stix_bundle(
    entity: str = Query(..., description="Entity to export (e.g. 'ua-parser-js')"),
    type: EntityType = Query(EntityType.package, description="Entity type"),
):
    """
    Export the investigation graph for *entity* as a STIX 2.1 JSON bundle.

    1. Traverses the Neo4j graph to gather raw paths
    2. Fetches the force-graph representation (nodes + links)
    3. Maps every node to the appropriate STIX SDO/SCO
    4. Maps every link to a STIX relationship SRO
    5. Wraps everything in a STIX bundle envelope
    """
    entity_type = type.value

    traversal, graph = await asyncio.gather(
        asyncio.to_thread(db.traverse, entity, entity_type),
        asyncio.to_thread(db.get_graph, entity, entity_type),
    )

    nodes = graph.get("nodes", [])
    links = graph.get("links", [])

    if not nodes:
        raise HTTPException(
            status_code=404,
            detail=f"No graph data found for entity '{entity}' (type={entity_type})",
        )

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    # Build STIX objects from nodes, tracking original-id → stix-id for relationships
    stix_objects: list[dict[str, Any]] = []
    node_stix_ids: dict[str, str] = {}

    for node in nodes:
        stix_obj = _make_stix_object(node, now_iso)
        if stix_obj:
            node_stix_ids[node["id"]] = stix_obj["id"]
            stix_objects.append(stix_obj)

    # Build STIX relationships from links
    for link in links:
        rel = _make_relationship(link, node_stix_ids, now_iso)
        if rel:
            stix_objects.append(rel)

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": stix_objects,
    }

    return bundle


# ── GET /api/stix/indicator-count ─────────────────────────────────────────────

@router.get("/indicator-count")
async def indicator_count():
    """
    Return total indicator count and a breakdown by STIX type.
    Queries Neo4j for node counts per label, then maps each label to its STIX
    type so consumers can gauge the breadth of intelligence in the graph.
    """
    schema = await asyncio.to_thread(db.get_schema)
    counts_raw: list[dict[str, Any]] = schema.get("counts", [])

    by_type: dict[str, int] = {}
    total = 0

    for entry in counts_raw:
        label = entry.get("label", "")
        count = entry.get("count", 0)
        mapping = _NODE_TYPE_TO_STIX.get(label)
        if mapping:
            stix_type = mapping["stix_type"]
            by_type[stix_type] = by_type.get(stix_type, 0) + count
            total += count

    return {"total_indicators": total, "by_type": by_type}
