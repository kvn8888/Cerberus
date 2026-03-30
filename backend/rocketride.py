"""
rocketride.py — RocketRide AI pipeline integration with direct-LLM fallback.

Uses the RocketRide Python SDK (pip install rocketride) to orchestrate
the cerberus-query pipeline. The pipeline runs on the RocketRide server
(ROCKETRIDE_URI from .env) and uses Claude Sonnet 4.6 to generate the
threat narrative.

Flow:
1. Backend does Neo4j graph traversal (in neo4j_client.py)
2. Traversal data + entity info are passed as context to RocketRide
3. RocketRide runs: chat → prompt (threat analyst) → llm_anthropic → response_answers
4. Answer is streamed back to the frontend as SSE chunks

When RocketRide is unavailable (server not running, SDK import error, timeout),
the backend falls back to calling Anthropic directly via llm.py.

Usage in routes/query.py:
    from rocketride import stream_via_rocketride_or_fallback

    async for chunk in stream_via_rocketride_or_fallback(entity, entity_type, traversal):
        yield chunk
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any, AsyncIterator

import config
import llm

logger = logging.getLogger(__name__)

# Path to the cerberus-query pipeline definition
_PIPELINE_PATH = str(Path(__file__).parent.parent / "pipelines" / "cerberus-query.pipe")

# Cached pipeline token — reused across requests to avoid reloading the pipeline
_pipeline_token: str | None = None
_rocketride_client = None


def _get_client():
    """
    Lazily import and initialize the RocketRide client.
    Returns None if the rocketride package is not installed.
    """
    global _rocketride_client
    if _rocketride_client is not None:
        return _rocketride_client
    try:
        from rocketride import RocketRideClient  # type: ignore
        uri = config.get("ROCKETRIDE_URI", "http://localhost:5565")
        apikey = config.get("ROCKETRIDE_APIKEY", "")
        _rocketride_client = RocketRideClient(uri=uri, auth=apikey)
        return _rocketride_client
    except ImportError:
        logger.warning("rocketride package not installed — will use direct LLM fallback")
        return None


async def is_available() -> bool:
    """
    Check if the RocketRide server is reachable and the SDK is installed.
    Returns False (never raises) so callers can fall through to direct LLM.
    """
    client = _get_client()
    if client is None:
        return False
    try:
        await client.connect()
        await client.ping()
        return True
    except Exception as exc:
        logger.debug("RocketRide not available: %s", exc)
        return False


async def _get_pipeline_token(client) -> str:
    """
    Load the cerberus-query pipeline into RocketRide and return its token.
    Token is cached after first load to avoid reloading on every request.
    """
    global _pipeline_token
    if _pipeline_token is not None:
        return _pipeline_token
    result = await client.use(filepath=_PIPELINE_PATH)
    _pipeline_token = result["token"]
    logger.info("cerberus-query pipeline loaded, token=%s", _pipeline_token)
    return _pipeline_token


async def generate_narrative_or_fallback(
    entity: str,
    entity_type: str,
    traversal: dict[str, Any],
) -> str:
    """
    Collect the full narrative string (non-streaming).
    Used by the sync POST /api/query endpoint.
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

    Tries RocketRide first. On any failure silently falls back to direct
    Anthropic calls via llm.py.

    Each yielded string is already formatted as "data: {...}\\n\\n" or
    "data: [DONE]\\n\\n" — ready to be yielded directly from the FastAPI
    StreamingResponse generator.
    """
    if await is_available():
        logger.info("RocketRide is available — routing through pipeline")
        try:
            async for chunk in _stream_via_sdk(entity, entity_type, traversal):
                yield chunk
            return
        except Exception as exc:
            logger.warning(
                "RocketRide stream failed (%s: %s) — falling back to direct LLM",
                type(exc).__name__,
                exc,
            )
            # Reset cached token so next request reloads the pipeline
            global _pipeline_token
            _pipeline_token = None
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


async def _stream_via_sdk(
    entity: str,
    entity_type: str,
    traversal: dict[str, Any],
) -> AsyncIterator[str]:
    """
    Use the RocketRide SDK to run the cerberus-query pipeline and stream
    the answer back as SSE chunks.

    The SDK's client.chat() returns a complete response (not streaming),
    so we yield stage events first, then stream the answer word-by-word
    to keep the frontend's streaming animation alive.
    """
    from rocketride.schema import Question  # type: ignore

    client = _get_client()
    await client.connect()

    token = await _get_pipeline_token(client)

    # Signal pipeline stages to the frontend
    yield f"data: {json.dumps({'stage': 'ner'})}\n\n"
    await asyncio.sleep(0)
    yield f"data: {json.dumps({'stage': 'classify'})}\n\n"
    await asyncio.sleep(0)
    yield f"data: {json.dumps({'stage': 'traverse'})}\n\n"
    await asyncio.sleep(0)

    # Emit paths_found metadata
    paths_found = traversal.get("paths_found", 0)
    yield f"data: {json.dumps({'paths_found': paths_found})}\n\n"
    await asyncio.sleep(0)

    yield f"data: {json.dumps({'stage': 'analyze'})}\n\n"
    await asyncio.sleep(0)

    # Build the question with graph context
    question = Question()
    question.addContext(
        f"Entity to investigate: {entity} (type: {entity_type})\n\n"
        f"Graph traversal result:\n{json.dumps(traversal, indent=2)}"
    )
    question.addQuestion(
        f"Analyze the threat entity '{entity}' ({entity_type}) using the graph traversal data above. "
        f"Generate a threat intelligence narrative."
    )

    # Call RocketRide — this blocks until the full answer is ready
    response = await client.chat(token=token, question=question)

    yield f"data: {json.dumps({'stage': 'narrate'})}\n\n"
    await asyncio.sleep(0)

    # Extract the answer text
    answers = response.get("answers", [])
    narrative = answers[0] if answers else ""

    if not narrative:
        raise ValueError("RocketRide returned empty answer")

    # Stream the narrative word-by-word for live animation effect
    words = narrative.split(" ")
    chunk_size = 5  # words per SSE chunk
    for i in range(0, len(words), chunk_size):
        chunk = " ".join(words[i : i + chunk_size])
        if i + chunk_size < len(words):
            chunk += " "
        yield f"data: {json.dumps({'text': chunk})}\n\n"
        await asyncio.sleep(0.02)  # small delay for streaming effect
