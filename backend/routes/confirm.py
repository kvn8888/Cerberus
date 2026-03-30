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
from pydantic import BaseModel

import neo4j_client as db

router = APIRouter(prefix="/api/confirm")


class ConfirmRequest(BaseModel):
    entity: str
    type:   str = "package"


@router.post("")
async def confirm(req: ConfirmRequest):
    entity      = req.entity.strip()
    entity_type = req.type.strip().lower()

    if not entity:
        raise HTTPException(status_code=400, detail="entity must not be empty")

    await asyncio.to_thread(db.confirm, entity, entity_type)

    return {
        "success":     True,
        "entity":      entity,
        "entity_type": entity_type,
    }
