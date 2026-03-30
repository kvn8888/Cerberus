"""
routes/confirm.py

POST /api/confirm
  Body:    { "entity": "ua-parser-js", "type": "package" }
  Returns: { "success": true, "entity": str, "entity_type": str }

Marks all relationships on the threat path as confirmed=true and tags
nodes with :ConfirmedThreat, enabling the cache-hit path on next query.
This is the self-improvement write-back triggered by analyst validation.
"""

import asyncio

from fastapi import APIRouter, HTTPException

import neo4j_client as db
from models import ConfirmRequest

router = APIRouter(prefix="/api/confirm")


@router.post("")
async def confirm(req: ConfirmRequest):
    entity      = req.entity.strip()
    entity_type = req.type.value

    if not entity:
        raise HTTPException(status_code=400, detail="entity must not be empty")

    result = await asyncio.to_thread(db.confirm, entity, entity_type)
    rel_count = result.get("count", 0)

    return {
        "success":                  True,
        "entity":                   entity,
        "entity_type":              entity_type,
        "relationships_confirmed":  rel_count,
        "message": (
            f"Marked {rel_count} relationship(s) as confirmed for {entity}. "
            f"Future queries will skip the LLM and return instantly from cache."
        ) if rel_count > 0 else (
            f"No confirmed threat path found for {entity}. "
            f"Run an investigation first, then confirm."
        ),
    }
