"""
routes/intelligence.py — Advanced graph intelligence endpoints

Provides four analytical endpoints that leverage Neo4j graph structure to
surface threat context beyond simple traversal:

GET /api/threat-score?entity=X&type=Y     — 0-100 risk score with factors
GET /api/blast-radius?entity=X&type=Y     — count of reachable entities (4 hops)
GET /api/shortest-path?from_entity=X&from_type=Y&to_entity=A&to_type=B
                                          — shortest graph path between two entities
GET /api/suggestions?entity=X&type=Y      — top 5 neighbors to investigate next
"""

from __future__ import annotations

import asyncio

from fastapi import APIRouter

import neo4j_client as db
from models import EntityType

router = APIRouter(prefix="/api")


@router.get("/threat-score")
async def threat_score(entity: str, type: EntityType = EntityType.package):
    """Compute a 0-100 threat score based on graph connectivity."""
    return await asyncio.to_thread(db.threat_score, entity.strip(), type.value)


@router.get("/blast-radius")
async def blast_radius(entity: str, type: EntityType = EntityType.package):
    """Count distinct entities reachable within 4 hops."""
    return await asyncio.to_thread(db.blast_radius, entity.strip(), type.value)


@router.get("/shortest-path")
async def shortest_path(
    from_entity: str,
    from_type: EntityType,
    to_entity: str,
    to_type: EntityType,
):
    """Find the shortest path between any two entities in the graph."""
    return await asyncio.to_thread(
        db.shortest_path,
        from_entity.strip(), from_type.value,
        to_entity.strip(), to_type.value,
    )


@router.get("/suggestions")
async def suggestions(entity: str, type: EntityType = EntityType.package):
    """Suggest the top 5 most-connected unconfirmed neighbors to investigate."""
    return await asyncio.to_thread(db.suggest_next, entity.strip(), type.value)
