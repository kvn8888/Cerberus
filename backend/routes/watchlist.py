"""
routes/watchlist.py — Entity watchlist with change detection.

Analysts can "watch" entities to be notified when new graph connections
appear. The watchlist is stored as Neo4j (:Watchlist) nodes. A /check
endpoint scans watched entities for connections added after the last
check timestamp, surfacing new threat intelligence automatically.

Endpoints:
  GET    /api/watchlist              — list all watched entities
  POST   /api/watchlist              — add entity to watchlist
  DELETE /api/watchlist/{entity}     — remove entity from watchlist
  GET    /api/watchlist/check        — check all watched entities for new connections
"""

from __future__ import annotations

import time

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

import neo4j_client as db

router = APIRouter(prefix="/api/watchlist")


class WatchRequest(BaseModel):
    """Payload for adding an entity to the watchlist."""
    entity: str = Field(..., min_length=1)
    entity_type: str = Field(default="package")


class WatchedEntity(BaseModel):
    """Shape returned by list/create endpoints."""
    entity: str
    entity_type: str
    added_at: int
    last_checked: int


@router.get("")
async def list_watchlist():
    """Return all entities on the watchlist."""
    query = """
    MATCH (w:Watchlist)
    RETURN w.entity AS entity, w.entity_type AS entity_type,
           w.added_at AS added_at, w.last_checked AS last_checked
    ORDER BY w.added_at DESC
    """
    records = db.run_query(query)
    return [
        WatchedEntity(
            entity=r["entity"],
            entity_type=r["entity_type"] or "package",
            added_at=r["added_at"] or 0,
            last_checked=r["last_checked"] or 0,
        )
        for r in records
    ]


@router.post("", status_code=201)
async def add_to_watchlist(req: WatchRequest):
    """Add an entity to the watchlist (idempotent via MERGE)."""
    now = int(time.time() * 1000)
    query = """
    MERGE (w:Watchlist {entity: $entity})
    ON CREATE SET w.entity_type = $entity_type,
                  w.added_at = $now,
                  w.last_checked = $now
    ON MATCH SET  w.entity_type = $entity_type
    RETURN w.entity AS entity, w.entity_type AS entity_type,
           w.added_at AS added_at, w.last_checked AS last_checked
    """
    records = db.run_query(query, {
        "entity": req.entity.strip(),
        "entity_type": req.entity_type,
        "now": now,
    })
    if not records:
        raise HTTPException(status_code=500, detail="Failed to add to watchlist")
    r = records[0]
    return WatchedEntity(
        entity=r["entity"],
        entity_type=r["entity_type"],
        added_at=r["added_at"],
        last_checked=r["last_checked"],
    )


@router.delete("/{entity}")
async def remove_from_watchlist(entity: str):
    """Remove an entity from the watchlist."""
    query = """
    MATCH (w:Watchlist {entity: $entity})
    DELETE w
    RETURN count(w) AS deleted
    """
    records = db.run_query(query, {"entity": entity})
    deleted = records[0]["deleted"] if records else 0
    if deleted == 0:
        raise HTTPException(status_code=404, detail="Entity not on watchlist")
    return {"deleted": True}


@router.get("/check")
async def check_watchlist(since: int | None = Query(default=None)):
    """Check all watched entities for new connections since last check.

    For each watched entity, counts relationships on matching nodes
    that were created (have a created_at or confirmed_at timestamp)
    after the watchlist's last_checked time. Updates last_checked
    after scanning.
    """
    now = int(time.time() * 1000)

    # Get all watched entities
    watched = db.run_query("""
        MATCH (w:Watchlist)
        RETURN w.entity AS entity, w.entity_type AS entity_type,
               w.last_checked AS last_checked
    """)

    alerts = []
    for w in watched:
        entity = w["entity"]
        last_checked = w["last_checked"] or 0
        effective_since = max(last_checked, since or 0)

        # Count new relationships since last check
        new_connections = db.run_query("""
            MATCH (e)-[r]-(neighbor)
                        WHERE coalesce(e.name, e.id, e.address, e.juspay_id, e.username, e.mitre_id) = $entity
              AND (r.created_at > $since OR r.confirmed_at > $since)
            RETURN count(r) AS new_count,
                   collect(DISTINCT labels(neighbor)[0])[..5] AS neighbor_types
                """, {"entity": entity, "since": effective_since})

        new_count = new_connections[0]["new_count"] if new_connections else 0
        neighbor_types = new_connections[0].get("neighbor_types", []) if new_connections else []

        if new_count > 0:
            alerts.append({
                "entity": entity,
                "entity_type": w["entity_type"],
                "new_connections": new_count,
                "neighbor_types": neighbor_types,
                "since": effective_since,
            })

    # Update last_checked for all watched entities
    db.run_query("""
        MATCH (w:Watchlist)
        SET w.last_checked = $now
    """, {"now": now})

    return {
        "digest_since": since,
        "checked_at": now,
        "watched_count": len(watched),
        "alerts": alerts,
    }
