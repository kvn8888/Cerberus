"""
routes/query.py

POST /api/query
  Body:  { "entity": "ua-parser-js", "type": "package" }
  Returns: {
      "entity":       str,
      "entity_type":  str,
      "paths_found":  int,
      "from_cache":   bool,
      "llm_called":   bool,
      "narrative":    str,
      "cross_domain": list,
  }

GET /api/query/stream?entity=ua-parser-js&type=package
  Server-Sent Events stream of the LLM narrative for the frontend.
  Each event: data: <text chunk>
  Final event: data: [DONE]
"""

from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

import neo4j_client as db
import llm

router = APIRouter(prefix="/api/query")


class QueryRequest(BaseModel):
    entity: str
    type:   str = "package"


@router.post("")
async def query(req: QueryRequest):
    entity      = req.entity.strip()
    entity_type = req.type.strip().lower()

    if not entity:
        raise HTTPException(status_code=400, detail="entity must not be empty")

    # ── 1. Cache check ────────────────────────────────────────────────────────
    cached = await asyncio.to_thread(db.cache_check, entity, entity_type)
    if cached:
        # Return cached path without calling LLM.
        # Narrative is stored on the ThreatActor node after first confirm.
        narrative = _extract_cached_narrative(cached) or (
            f"[CACHED] Confirmed threat path exists for {entity}. "
            f"No LLM call needed — pattern was previously analyst-confirmed."
        )
        return {
            "entity":       entity,
            "entity_type":  entity_type,
            "paths_found":  len(cached),
            "from_cache":   True,
            "llm_called":   False,
            "narrative":    narrative,
            "cross_domain": [],
        }

    # ── 2. Graph traversal ────────────────────────────────────────────────────
    traversal = await asyncio.to_thread(db.traverse, entity, entity_type)
    paths_found = traversal["paths_found"]

    # ── 3. LLM narrative ──────────────────────────────────────────────────────
    if paths_found == 0:
        narrative = (
            f"No threat paths found for {entity} in the current graph. "
            f"The entity may not yet be ingested or has no known connections."
        )
        llm_called = False
    else:
        narrative  = await asyncio.to_thread(
            llm.generate_narrative, entity, entity_type, traversal
        )
        llm_called = True

        # ── 4. Write-back: tag paths with analysis timestamp ─────────────────
        await asyncio.to_thread(db.write_back, entity, entity_type)

    return {
        "entity":       entity,
        "entity_type":  entity_type,
        "paths_found":  paths_found,
        "from_cache":   False,
        "llm_called":   llm_called,
        "narrative":    narrative,
        "cross_domain": traversal.get("cross_domain", []),
    }


@router.get("/stream")
async def query_stream(entity: str, type: str = "package"):
    """SSE endpoint for the React frontend."""
    entity      = entity.strip()
    entity_type = type.strip().lower()

    if not entity:
        raise HTTPException(status_code=400, detail="entity must not be empty")

    async def event_generator():
        # Cache check
        cached = await asyncio.to_thread(db.cache_check, entity, entity_type)
        if cached:
            narrative = _extract_cached_narrative(cached) or (
                f"[CACHED] Confirmed threat path for {entity}. LLM skipped."
            )
            yield f"data: {json.dumps({'from_cache': True})}\n\n"
            for chunk in _chunk_string(narrative, 80):
                yield f"data: {json.dumps({'text': chunk})}\n\n"
            yield "data: [DONE]\n\n"
            return

        # Traversal
        traversal = await asyncio.to_thread(db.traverse, entity, entity_type)

        if traversal["paths_found"] == 0:
            yield f"data: {json.dumps({'text': f'No threat paths found for {entity}.'})}\n\n"
            yield "data: [DONE]\n\n"
            return

        yield f"data: {json.dumps({'paths_found': traversal['paths_found'], 'from_cache': False})}\n\n"

        # Stream LLM narrative
        loop = asyncio.get_event_loop()
        gen  = llm.generate_narrative_stream(entity, entity_type, traversal)

        for chunk in gen:
            yield f"data: {json.dumps({'text': chunk})}\n\n"
            await asyncio.sleep(0)   # yield control to event loop

        # Write-back
        await asyncio.to_thread(db.write_back, entity, entity_type)
        yield "data: [DONE]\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":  "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_cached_narrative(cached: list[dict]) -> str | None:
    """Pull a stored narrative from cached path nodes if present."""
    for record in cached:
        for _key, node in (record.get("path") or {}).items():
            if isinstance(node, dict) and "narrative" in node:
                return node["narrative"]
    return None


def _chunk_string(s: str, size: int):
    for i in range(0, len(s), size):
        yield s[i : i + size]
