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

import neo4j_client as db
import llm
import rocketride
from models import EntityType, QueryRequest

router = APIRouter(prefix="/api/query")


@router.post("")
async def query(req: QueryRequest):
    entity      = req.entity.strip()
    entity_type = req.type.value

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

    # ── 3. LLM narrative (via RocketRide or direct Anthropic fallback) ───────
    # rocketride.generate_narrative_or_fallback() tries RocketRide first.
    # On any failure it silently falls back to direct llm.py calls.
    if paths_found == 0:
        narrative = (
            f"No threat paths found for {entity} in the current graph. "
            f"The entity may not yet be ingested or has no known connections."
        )
        llm_called = False
    else:
        try:
            narrative  = await rocketride.generate_narrative_or_fallback(
                entity, entity_type, traversal
            )
            llm_called = bool(narrative)
        except Exception as exc:
            cross_domain = traversal.get("cross_domain", [])
            cross_summary = f"{len(cross_domain)} cross-domain link(s) found" if cross_domain else "no cross-domain links"
            narrative = (
                f"[LLM unavailable: {type(exc).__name__}] "
                f"Graph traversal found {paths_found} threat path(s) for {entity}. "
                f"{cross_summary}. "
                f"Review the raw graph data for full detail."
            )
            llm_called = False

        if llm_called:
            # ── 4. Write-back: tag paths with analysis timestamp ─────────────
            await asyncio.to_thread(db.write_back, entity, entity_type, narrative)

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
async def query_stream(entity: str, type: EntityType = EntityType.package):
    """SSE endpoint for the React frontend."""
    entity      = entity.strip()
    entity_type = type.value

    if not entity:
        raise HTTPException(status_code=400, detail="entity must not be empty")

    async def event_generator():
        # ── Stage: input ─────────────────────────────────────────────────────
        yield f"data: {json.dumps({'stage': 'input'})}\n\n"
        await asyncio.sleep(0)

        # ── Stage: ner + classify (cache check counts as routing) ────────────
        yield f"data: {json.dumps({'stage': 'ner'})}\n\n"
        await asyncio.sleep(0)
        yield f"data: {json.dumps({'stage': 'classify'})}\n\n"
        await asyncio.sleep(0)

        # Cache check
        yield f"data: {json.dumps({'stage': 'route'})}\n\n"
        cached = await asyncio.to_thread(db.cache_check, entity, entity_type)
        if cached:
            narrative = _extract_cached_narrative(cached) or (
                f"[CACHED] Confirmed threat path for {entity}. LLM skipped."
            )
            yield f"data: {json.dumps({'from_cache': True, 'paths_found': len(cached)})}\n\n"
            yield f"data: {json.dumps({'stage': 'narrate'})}\n\n"
            for chunk in _chunk_string(narrative, 80):
                yield f"data: {json.dumps({'text': chunk})}\n\n"
            yield "data: [DONE]\n\n"
            return

        # ── Stage: traverse ───────────────────────────────────────────────────
        yield f"data: {json.dumps({'stage': 'traverse'})}\n\n"
        traversal = await asyncio.to_thread(db.traverse, entity, entity_type)

        if traversal["paths_found"] == 0:
            yield f"data: {json.dumps({'paths_found': 0, 'from_cache': False})}\n\n"
            yield f"data: {json.dumps({'text': f'No threat paths found for {entity}.'})}\n\n"
            yield "data: [DONE]\n\n"
            return

        yield f"data: {json.dumps({'paths_found': traversal['paths_found'], 'from_cache': False})}\n\n"

        # ── Stage: analyze → narrate (via RocketRide or direct LLM fallback) ──
        # rocketride.stream_via_rocketride_or_fallback() tries RocketRide first.
        # If RocketRide is not running or returns an error, it silently falls
        # back to direct Anthropic calls. Either way it emits the same SSE
        # contract: {"stage":...}, {"text":...} chunks, then returns.
        narrative_chunks: list[str] = []
        try:
            async for sse_line in rocketride.stream_via_rocketride_or_fallback(
                entity, entity_type, traversal
            ):
                # Collect text chunks for write-back, then forward to client
                if sse_line.startswith("data: ") and not sse_line.startswith("data: ["):
                    try:
                        chunk = json.loads(sse_line[6:].strip())
                        if "text" in chunk:
                            narrative_chunks.append(chunk["text"])
                    except json.JSONDecodeError:
                        pass
                yield sse_line
        except Exception as exc:
            # Absolute last-resort fallback if the abstraction itself errors
            fallback = (
                f"[LLM unavailable: {type(exc).__name__}] "
                f"Graph traversal found {traversal['paths_found']} threat path(s) for {entity}. "
                f"Review the raw graph data for full detail."
            )
            yield f"data: {json.dumps({'text': fallback})}\n\n"
            yield "data: [DONE]\n\n"
            return

        # ── Write-back ────────────────────────────────────────────────────────
        if narrative_chunks:
            await asyncio.to_thread(
                db.write_back,
                entity,
                entity_type,
                "".join(narrative_chunks),
            )
        yield "data: [DONE]\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":  "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/graph")
async def query_graph(entity: str, type: EntityType = EntityType.package):
    """
    Return the graph traversal result as nodes + links for the frontend
    force-directed visualization. Separate from the narrative endpoints
    so the frontend can fetch graph data independently.
    """
    entity = entity.strip()
    entity_type = type.value

    if not entity:
        raise HTTPException(status_code=400, detail="entity must not be empty")

    graph = await asyncio.to_thread(db.get_graph, entity, entity_type)
    return graph


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_cached_narrative(cached: list[dict]) -> str | None:
    """Pull a stored narrative from cached path nodes if present."""
    for record in cached:
        narrative = record.get("narrative")
        if isinstance(narrative, str) and narrative:
            return narrative
    return None


def _chunk_string(s: str, size: int):
    for i in range(0, len(s), size):
        yield s[i : i + size]
