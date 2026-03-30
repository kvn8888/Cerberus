"""
routes/demo.py

Demo-focused APIs that make the judging flow stronger without changing the
core investigation model:
  - natural-language entity extraction
  - lightweight multi-entity comparison
  - synthetic live feed events with optional ingestion
  - geographic IP map points
  - report payload generation for frontend PDF export
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

import neo4j_client as db
from models import EntityType

router = APIRouter(prefix="/api/demo")


class NaturalLanguageRequest(BaseModel):
    message: str


class CompareQuery(BaseModel):
    entity: str
    type: EntityType


class CompareRequest(BaseModel):
    queries: list[CompareQuery] = Field(min_length=2, max_length=4)


class FeedIngestRequest(BaseModel):
    juspay_id: str
    fraud_type: str
    amount: float
    currency: str = "USD"
    ip_address: str
    merchant_id: str | None = None


@router.post("/natural")
async def parse_natural(req: NaturalLanguageRequest):
    message = req.message.strip()
    if not message:
        raise HTTPException(status_code=400, detail="message must not be empty")

    entities = _extract_entities(message)
    if not entities:
        raise HTTPException(status_code=400, detail="no recognizable entities found")

    primary = entities[0]
    return {
        "message": message,
        "primary_entity": primary,
        "entities": entities,
    }


@router.post("/compare")
async def compare_queries(req: CompareRequest):
    results = []
    for query in req.queries:
        entity = query.entity.strip()
        entity_type = query.type.value
        cached = await asyncio.to_thread(db.cache_check, entity, entity_type)
        if cached:
            narrative = _extract_cached_narrative(cached) or "Confirmed threat pattern cached."
            results.append(
                {
                    "entity": entity,
                    "entity_type": entity_type,
                    "from_cache": True,
                    "paths_found": len(cached),
                    "risk_level": _infer_risk_level(narrative),
                    "summary": narrative[:240],
                }
            )
            continue

        traversal = await asyncio.to_thread(db.traverse, entity, entity_type)
        results.append(
            {
                "entity": entity,
                "entity_type": entity_type,
                "from_cache": False,
                "paths_found": traversal["paths_found"],
                "risk_level": _risk_from_paths(traversal["paths_found"]),
                "summary": _build_compare_summary(entity, traversal),
                "cross_domain_count": len(traversal.get("cross_domain", [])),
            }
        )

    return {"results": results}


@router.get("/feed")
async def demo_feed(limit: int = 6):
    if limit < 1 or limit > 20:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 20")

    events = []
    now_ms = int(time.time() * 1000)
    for index, signal in enumerate(_DEMO_FEED_EVENTS[:limit]):
        event = signal.copy()
        event["timestamp"] = now_ms - index * 90_000
        events.append(event)
    return {"events": events}


@router.post("/feed/ingest")
async def ingest_feed_event(req: FeedIngestRequest):
    signal = {
        "juspay_id": req.juspay_id,
        "fraud_type": req.fraud_type,
        "amount": req.amount,
        "currency": req.currency,
        "ip_address": req.ip_address,
        "merchant_id": req.merchant_id,
        "timestamp": int(time.time() * 1000),
        "source": "demo_feed",
        "synthetic": True,
    }
    result = await asyncio.to_thread(db.ingest_fraud_signals, [signal])
    return {"success": True, **result}


@router.get("/map")
async def geo_map(entity: str, type: EntityType = EntityType.package):
    entity = entity.strip()
    if not entity:
        raise HTTPException(status_code=400, detail="entity must not be empty")
    points = await asyncio.to_thread(db.get_geo_points, entity, type.value)
    return {"entity": entity, "entity_type": type.value, "points": points}


@router.get("/report")
async def report(entity: str, type: EntityType = EntityType.package):
    entity = entity.strip()
    if not entity:
        raise HTTPException(status_code=400, detail="entity must not be empty")

    entity_type = type.value
    cached = await asyncio.to_thread(db.cache_check, entity, entity_type)
    traversal = await asyncio.to_thread(db.traverse, entity, entity_type)
    graph = await asyncio.to_thread(db.get_graph, entity, entity_type)
    juspay = await asyncio.to_thread(db.get_juspay_summary, 5)

    narrative = ""
    from_cache = False
    if cached:
        from_cache = True
        narrative = _extract_cached_narrative(cached) or "Confirmed threat pattern cached."

    return {
        "entity": entity,
        "entity_type": entity_type,
        "generated_at": int(time.time() * 1000),
        "from_cache": from_cache,
        "paths_found": traversal["paths_found"],
        "cross_domain": traversal.get("cross_domain", []),
        "graph": graph,
        "juspay_summary": juspay,
        "narrative": narrative,
        "summary": _build_compare_summary(entity, traversal),
    }


def _extract_entities(message: str) -> list[dict[str, str]]:
    entities: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(entity_type: str, value: str):
        key = (entity_type, value)
        if key not in seen:
            entities.append({"type": entity_type, "value": value})
            seen.add(key)

    cve_matches = re.findall(r"\bCVE-\d{4}-\d{4,7}\b", message, flags=re.IGNORECASE)
    for match in cve_matches:
        add("cve", match.upper())

    ip_matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", message)
    for match in ip_matches:
        add("ip", match)

    domain_matches = re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", message)
    for match in domain_matches:
        if not match.upper().startswith("CVE-"):
            add("domain", match.lower())

    actor_matches = re.findall(
        r"\b(?:APT\d{1,3}|APT-\d{1,3}|Lazarus Group|APT41|APT29|APT28|Cl0p|HAFNIUM|Sandworm Team)\b",
        message,
        flags=re.IGNORECASE,
    )
    for match in actor_matches:
        normalized = match.replace("-", "")
        add("threatactor", normalized if normalized.upper().startswith("APT") else match)

    token_matches = re.findall(r"\b[a-zA-Z0-9][a-zA-Z0-9._/-]{2,}\b", message)
    for token in token_matches:
        lowered = token.lower()
        if lowered in {"analyze", "investigate", "compare", "show", "with", "and", "against", "from"}:
            continue
        if token.upper().startswith("CVE-") or re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", token):
            continue
        if "." in token and token.lower().split(".")[-1].isalpha() and len(token.split(".")[-1]) >= 2:
            continue
        add("package", token)

    return entities


def _build_compare_summary(entity: str, traversal: dict[str, Any]) -> str:
    paths_found = traversal.get("paths_found", 0)
    cross_domain = traversal.get("cross_domain", [])
    if paths_found == 0:
        return f"No known threat paths found for {entity} in the current graph."
    if cross_domain:
        return (
            f"{entity} has {paths_found} threat path(s) and {len(cross_domain)} "
            f"cross-domain connection(s) spanning software, infrastructure, or fraud signals."
        )
    return f"{entity} has {paths_found} graph path(s) into the threat-intelligence network."


def _risk_from_paths(paths_found: int) -> str:
    if paths_found >= 5:
        return "CRITICAL"
    if paths_found >= 3:
        return "HIGH"
    if paths_found >= 1:
        return "MEDIUM"
    return "LOW"


def _infer_risk_level(narrative: str) -> str:
    upper = narrative.upper()
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if level in upper:
            return level
    return "MEDIUM"


def _extract_cached_narrative(cached: list[dict]) -> str | None:
    for record in cached:
        narrative = record.get("narrative")
        if isinstance(narrative, str) and narrative:
            return narrative
    return None


_DEMO_FEED_EVENTS = [
    {
        "juspay_id": "JS-LIVE-1001",
        "fraud_type": "account_takeover",
        "amount": 3800,
        "currency": "USD",
        "ip_address": "203.0.113.42",
        "merchant_id": "demo-merchant-a",
    },
    {
        "juspay_id": "JS-LIVE-1002",
        "fraud_type": "card_not_present",
        "amount": 1250,
        "currency": "USD",
        "ip_address": "185.220.101.47",
        "merchant_id": "demo-merchant-b",
    },
    {
        "juspay_id": "JS-LIVE-1003",
        "fraud_type": "credential_stuffing",
        "amount": 410,
        "currency": "USD",
        "ip_address": "46.101.116.100",
        "merchant_id": "demo-merchant-c",
    },
    {
        "juspay_id": "JS-LIVE-1004",
        "fraud_type": "synthetic_identity",
        "amount": 8700,
        "currency": "USD",
        "ip_address": "175.45.176.0",
        "merchant_id": "demo-merchant-d",
    },
]
