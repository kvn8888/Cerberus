"""
routes/demo.py

Demo-focused APIs that make the judging flow stronger without changing the
core investigation model:
  - natural-language entity extraction
  - lightweight multi-entity comparison
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

_TLP_LEVELS = {"clear", "green", "amber", "amber+strict", "red"}


def _normalize_tlp(tlp: str) -> str:
    value = (tlp or "amber").strip().lower()
    if value not in _TLP_LEVELS:
        raise HTTPException(status_code=400, detail=f"Unsupported TLP level '{tlp}'")
    return value


class NaturalLanguageRequest(BaseModel):
    message: str


class CompareQuery(BaseModel):
    entity: str
    type: EntityType


class CompareRequest(BaseModel):
    queries: list[CompareQuery] = Field(min_length=2, max_length=4)



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



@router.get("/map")
async def geo_map(entity: str, type: EntityType = EntityType.package):
    entity = entity.strip()
    if not entity:
        raise HTTPException(status_code=400, detail="entity must not be empty")
    points = await asyncio.to_thread(db.get_geo_points, entity, type.value)
    return {"entity": entity, "entity_type": type.value, "points": points}


@router.get("/report")
async def report(
    entity: str,
    type: EntityType = EntityType.package,
    tlp: str = "amber",
):
    entity = entity.strip()
    if not entity:
        raise HTTPException(status_code=400, detail="entity must not be empty")

    entity_type = type.value
    normalized_tlp = _normalize_tlp(tlp)
    # Run all DB lookups concurrently — these are independent queries
    cached, traversal, graph, juspay = await asyncio.gather(
        asyncio.to_thread(db.cache_check, entity, entity_type),
        asyncio.to_thread(db.traverse, entity, entity_type),
        asyncio.to_thread(db.get_graph, entity, entity_type),
        asyncio.to_thread(db.get_juspay_summary, 5),
    )

    narrative = ""
    from_cache = False
    if cached:
        from_cache = True
        narrative = _extract_cached_narrative(cached) or "Confirmed threat pattern cached."

    return {
        "entity": entity,
        "entity_type": entity_type,
        "tlp": normalized_tlp,
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


