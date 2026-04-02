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

_TLP_DEFINITIONS: dict[str, dict[str, str]] = {
    "clear": {
        "display_name": "TLP:CLEAR",
        "stix_name": "TLP:WHITE",
        "stix_tlp": "white",
        "id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    },
    "green": {
        "display_name": "TLP:GREEN",
        "stix_name": "TLP:GREEN",
        "stix_tlp": "green",
        "id": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    },
    "amber": {
        "display_name": "TLP:AMBER",
        "stix_name": "TLP:AMBER",
        "stix_tlp": "amber",
        "id": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    },
    "red": {
        "display_name": "TLP:RED",
        "stix_name": "TLP:RED",
        "stix_tlp": "red",
        "id": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
    },
}


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


def _normalize_tlp(tlp: str) -> str:
    value = (tlp or "amber").strip().lower()
    if value not in {"clear", "green", "amber", "amber+strict", "red"}:
        raise HTTPException(status_code=400, detail=f"Unsupported TLP level '{tlp}'")
    return value


def _build_marking_definitions(tlp: str, now_iso: str) -> tuple[list[dict[str, Any]], list[str], str]:
    normalized = _normalize_tlp(tlp)
    base_key = "amber" if normalized == "amber+strict" else normalized
    base = _TLP_DEFINITIONS[base_key]

    markings: list[dict[str, Any]] = [
        {
            "type": "marking-definition",
            "spec_version": "2.1",
            "id": base["id"],
            "created": "2017-01-20T00:00:00.000Z",
            "definition_type": "tlp",
            "name": base["stix_name"],
            "definition": {"tlp": base["stix_tlp"]},
        }
    ]
    refs = [base["id"]]

    if normalized == "amber+strict":
        strict_id = f"marking-definition--{uuid.uuid5(uuid.NAMESPACE_URL, 'cerberus:tlp:amber+strict')}"
        markings.append(
            {
                "type": "marking-definition",
                "spec_version": "2.1",
                "id": strict_id,
                "created": now_iso,
                "definition_type": "statement",
                "definition": {
                    "statement": (
                        "TLP:AMBER+STRICT handling: share only within the recipient organization "
                        "on a need-to-know basis."
                    )
                },
            }
        )
        refs.append(strict_id)

    return markings, refs, normalized


def _make_stix_object(
    node: dict[str, Any],
    now_iso: str,
    object_marking_refs: list[str] | None = None,
) -> dict[str, Any] | None:
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
    if object_marking_refs:
        obj["object_marking_refs"] = object_marking_refs

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
    object_marking_refs: list[str] | None = None,
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

    relationship = {
        "type": "relationship",
        "spec_version": "2.1",
        "id": f"relationship--{uuid.uuid4()}",
        "created": now_iso,
        "modified": now_iso,
        "relationship_type": rel_type,
        "source_ref": source_ref,
        "target_ref": target_ref,
    }
    if object_marking_refs:
        relationship["object_marking_refs"] = object_marking_refs
    return relationship


# ── GET /api/stix/bundle ─────────────────────────────────────────────────────

@router.get("/bundle")
async def stix_bundle(
    entity: str = Query(..., description="Entity to export (e.g. 'ua-parser-js')"),
    type: EntityType = Query(EntityType.package, description="Entity type"),
    tlp: str = Query("amber", description="TLP marking to apply to export"),
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
    marking_objects, marking_refs, normalized_tlp = _build_marking_definitions(tlp, now_iso)

    # Build STIX objects from nodes, tracking original-id → stix-id for relationships
    stix_objects: list[dict[str, Any]] = [*marking_objects]
    node_stix_ids: dict[str, str] = {}

    for node in nodes:
        stix_obj = _make_stix_object(node, now_iso, object_marking_refs=marking_refs)
        if stix_obj:
            node_stix_ids[node["id"]] = stix_obj["id"]
            stix_objects.append(stix_obj)

    # Build STIX relationships from links
    for link in links:
        rel = _make_relationship(link, node_stix_ids, now_iso, object_marking_refs=marking_refs)
        if rel:
            stix_objects.append(rel)

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "x_cerberus_tlp": normalized_tlp,
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
