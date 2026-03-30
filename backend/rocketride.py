"""
rocketride.py — RocketRide AI pipeline integration with direct-LLM fallback.

When RocketRide is running (ROCKETRIDE_URL is reachable), the query stream
is routed through the cerberus-query pipeline so judges see the full agent
flow: NER → Classify → Cache check → Graph traversal → LLM narrative → SSE.

When RocketRide is unavailable (no API key, not running, or network error),
the backend falls back to calling Anthropic directly via llm.py. This fallback
ensures the app keeps working during development and as a safety net at demo.

Usage in routes/query.py:
    from rocketride import stream_via_rocketride_or_fallback

    async for chunk in stream_via_rocketride_or_fallback(entity, entity_type, traversal):
        yield chunk

RocketRide pipeline invocation (cerberus-query pipeline):
    POST {ROCKETRIDE_URL}/api/pipelines/cerberus-query/run
    Content-Type: application/json
    Body: {"message": "analyze {entity}", "entity": entity, "entity_type": entity_type}

    Response: SSE stream of events:
        data: {"stage": "ner"}
        data: {"stage": "traverse"}
        data: {"text": "narrative chunk..."}
        data: [DONE]

If RocketRide's SSE event format differs from the above contract, update
_normalize_rocketride_chunk() below to translate before yielding to the frontend.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, AsyncIterator

import httpx

import config
import llm

logger = logging.getLogger(__name__)

# RocketRide pipeline endpoint path — cerberus-query uses ChatSource with endpoint:/query
_PIPELINE_RUN_PATH = "/query"
# Health check path — used to detect if RocketRide is reachable
_HEALTH_PATH = "/health"
# Request timeout for checking availability (seconds)
_HEALTH_TIMEOUT = 2.0
# Stream timeout — how long to wait for narrative to complete (seconds)
_STREAM_TIMEOUT = 60.0


async def is_available() -> bool:
    """
    Check if RocketRide is reachable. Returns False (never raises) so callers
    can safely fall through to the direct-LLM path.
    """
    url = config.get("ROCKETRIDE_URL", "http://127.0.0.1:3000")
    try:
        async with httpx.AsyncClient(timeout=_HEALTH_TIMEOUT) as client:
            resp = await client.get(f"{url}{_HEALTH_PATH}")
            return resp.status_code < 500
    except Exception:
        return False


async def generate_narrative_or_fallback(
    entity: str,
    entity_type: str,
    traversal: dict[str, Any],
) -> str:
    """
    Collect the full narrative string (non-streaming).
    Used by the sync POST /api/query endpoint.
    Tries RocketRide first; falls back to direct Anthropic call.
    """
    chunks: list[str] = []
    async for sse_line in stream_via_rocketride_or_fallback(entity, entity_type, traversal):
        if sse_line.startswith("data: ") and not sse_line.startswith("data: ["):
            try:
                event = json.loads(sse_line[6:].strip())
                if "text" in event:
                    chunks.append(event["text"])
            except json.JSONDecodeError:
                pass
    return "".join(chunks)


async def stream_via_rocketride_or_fallback(
    entity: str,
    entity_type: str,
    traversal: dict[str, Any],
) -> AsyncIterator[str]:
    """
    Yield SSE-formatted data strings for the narrative stream.

    Tries RocketRide first. On any failure (not running, bad response,
    timeout, missing keys) silently falls back to direct Anthropic calls.

    Each yielded string is already formatted as "data: {...}\\n\\n" or
    "data: [DONE]\\n\\n" — ready to be yielded directly from the FastAPI
    StreamingResponse generator.
    """
    rocketride_url = config.get("ROCKETRIDE_URL", "http://127.0.0.1:3000")
    rocketride_key = config.get("ROCKETRIDE_API_KEY")  # optional

    if await is_available():
        logger.info("RocketRide is available — routing through pipeline")
        try:
            async for chunk in _stream_rocketride(
                rocketride_url, rocketride_key, entity, entity_type, traversal
            ):
                yield chunk
            return
        except Exception as exc:
            logger.warning(
                "RocketRide stream failed (%s: %s) — falling back to direct LLM",
                type(exc).__name__,
                exc,
            )
            # Signal frontend that we switched to fallback
            yield f"data: {json.dumps({'rocketride_fallback': True})}\n\n"

    # Direct Anthropic fallback
    logger.info("Using direct Anthropic LLM (RocketRide not available)")
    yield f"data: {json.dumps({'stage': 'analyze'})}\n\n"
    yield f"data: {json.dumps({'stage': 'narrate'})}\n\n"
    await asyncio.sleep(0)

    try:
        gen = llm.generate_narrative_stream(entity, entity_type, traversal)
        for text_chunk in gen:
            yield f"data: {json.dumps({'text': text_chunk})}\n\n"
            await asyncio.sleep(0)
    except Exception as exc:
        fallback_text = (
            f"[LLM unavailable: {type(exc).__name__}] "
            f"Graph traversal found {traversal.get('paths_found', 0)} threat path(s) for {entity}. "
            f"Review the raw graph data for detail."
        )
        yield f"data: {json.dumps({'text': fallback_text})}\n\n"


async def _stream_rocketride(
    base_url: str,
    api_key: str | None,
    entity: str,
    entity_type: str,
    traversal: dict[str, Any],
) -> AsyncIterator[str]:
    """
    POST to the cerberus-query RocketRide pipeline and proxy its SSE output.
    Normalizes RocketRide event format to the Cerberus SSE contract.
    """
    headers = {"Content-Type": "application/json", "Accept": "text/event-stream"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    # RocketRide ChatSource expects natural language in "message".
    # The NERNode inside the pipeline extracts entity + type from it.
    payload = {
        "message": f"analyze {entity}",
    }

    url = f"{base_url}{_PIPELINE_RUN_PATH}"
    async with httpx.AsyncClient(timeout=_STREAM_TIMEOUT) as client:
        async with client.stream("POST", url, json=payload, headers=headers) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if not line.startswith("data: "):
                    continue
                raw = line[6:].strip()
                # Handle both "[DONE]" string and {"done": true} JSON terminal
                if raw == "[DONE]":
                    return  # caller emits [DONE] after write-back
                try:
                    event = json.loads(raw)
                    # RocketRide terminal event — emit metadata then stop
                    if event.get("done") is True:
                        normalized = _normalize_rocketride_chunk(event)
                        if normalized:
                            yield f"data: {json.dumps(normalized)}\n\n"
                        return
                    normalized = _normalize_rocketride_chunk(event)
                    if normalized is not None:
                        yield f"data: {json.dumps(normalized)}\n\n"
                except json.JSONDecodeError:
                    pass  # skip non-JSON lines


def _normalize_rocketride_chunk(event: dict) -> dict | None:
    """
    Translate a RocketRide SSE event into the Cerberus SSE contract.

    Confirmed RocketRide SSE format (from pipeline YAML analysis):
        Mid-stream:  {"chunk": "text fragment", "done": false}
        Terminal:    {"done": true, "paths_found": int, "from_cache": bool}

    Cerberus contract (what the frontend expects):
        {"stage": str}                          — pipeline stage transition
        {"text": str}                           — narrative chunk
        {"paths_found": int, "from_cache": bool}  — metadata (terminal)
        "[DONE]"                                — handled separately in caller

    Note: {"done": true} is handled by the caller (_stream_rocketride checks
    for it to stop iteration). This function only maps non-terminal chunks.
    """
    # RocketRide confirmed format: {"chunk": "...", "done": false}
    if "chunk" in event and not event.get("done", False):
        return {"text": event["chunk"]}

    # RocketRide terminal metadata: {"done": true, "paths_found": N, "from_cache": bool}
    # The "done" signal itself is handled by caller; emit the metadata here.
    if event.get("done") is True:
        result: dict = {}
        if "paths_found" in event:
            result["paths_found"] = event["paths_found"]
        if "from_cache" in event:
            result["from_cache"] = event["from_cache"]
        return result if result else None

    # Already in Cerberus contract format (stage events, etc.)
    if "stage" in event or "text" in event or "paths_found" in event:
        return event

    # Alternative field names seen in other orchestrators — keep as fallback
    if "content" in event:
        return {"text": event["content"]}
    if "node" in event:
        return {"stage": event["node"]}
    if "step" in event:
        return {"stage": event["step"]}

    # Unknown event — pass through for debugging
    return event
