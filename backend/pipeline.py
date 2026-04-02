"""
pipeline.py — RocketRide AI pipeline integration with direct-LLM fallback.

Architecture:
  The cerberus-threat-agent pipeline runs a RocketRide native wave-planning
  agent inside RocketRide that autonomously explores the Neo4j threat graph
  via an MCP Client node connected to our neo4j-mcp server.  The agent uses
  Claude Sonnet 4.6 for reasoning, keyed memory for cross-investigation
  context, and generates the threat narrative.

  Pipeline shape (cerberus-threat-agent.pipe):
    chat → agent_rocketride → [invoke] → mcp_client (neo4j-mcp)
                             → [invoke] → llm_anthropic (Claude Sonnet 4.6)
                             → [invoke] → memory_internal
             ↓
        response_answers

  Fallback pipeline (cerberus-query.pipe):
    chat → prompt → llm_anthropic (Claude Sonnet 4.6) → response_answers

Flow:
  1. Backend sends the entity name + type to RocketRide via SDK chat()
  2. RocketRide's wave-planning agent queries Neo4j via MCP tools (get-neo4j-schema,
     read-neo4j-cypher) — it explores the graph autonomously in parallel waves
  3. Agent stores key findings in keyed memory across investigation waves
  4. Agent generates a cross-domain threat intelligence narrative
  5. Answer is returned to the backend and streamed to the frontend as SSE

  The backend still runs db.traverse() in parallel for the GraphPanel
  visualization — the agent's graph exploration is independent.

When RocketRide is unavailable (server not running, SDK import error, timeout),
the backend falls back to calling Anthropic directly via llm.py.

Usage in routes/query.py:
    from pipeline import stream_via_rocketride_or_fallback

    async for chunk in stream_via_rocketride_or_fallback(entity, entity_type, traversal):
        yield chunk
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any, AsyncIterator

import config
import llm

logger = logging.getLogger(__name__)

# ── Pipeline paths ────────────────────────────────────────────────────────────
# Primary: agent-based pipeline with MCP Client → neo4j-mcp
_AGENT_PIPELINE_PATH = str(
    Path(__file__).parent.parent / "pipelines" / "cerberus-threat-agent.pipe"
)
# Fallback: simple prompt → LLM pipeline (no MCP, uses pre-fetched traversal)
_QUERY_PIPELINE_PATH = str(
    Path(__file__).parent.parent / "pipelines" / "cerberus-query.pipe"
)

# Cached pipeline token — reused across requests to avoid reloading
_pipeline_token: str | None = None
# Which pipeline was loaded (so we know which send strategy to use)
_active_pipeline: str | None = None
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
    Times out after 3 seconds so slow/missing RocketRide doesn't block queries.
    """
    client = _get_client()
    if client is None:
        return False
    try:
        await asyncio.wait_for(client.connect(), timeout=3.0)
        await asyncio.wait_for(client.ping(), timeout=3.0)
        return True
    except Exception as exc:
        logger.debug("RocketRide not available: %s", exc)
        return False


async def _load_pipeline(client) -> str:
    """
    Load the best available pipeline and return its token.

    Tries the agent pipeline first (cerberus-threat-agent.pipe) which uses
    the MCP Client for autonomous Neo4j exploration.  Falls back to the
    simple query pipeline (cerberus-query.pipe) if the agent pipeline fails.

    Token is cached after first successful load.
    """
    global _pipeline_token, _active_pipeline

    if _pipeline_token is not None:
        return _pipeline_token

    # Try agent pipeline first (MCP Client → neo4j-mcp)
    try:
        result = await client.use(filepath=_AGENT_PIPELINE_PATH)
        _pipeline_token = result["token"]
        _active_pipeline = "agent"
        logger.info(
            "cerberus-threat-agent pipeline loaded (MCP+agent), token=%s",
            _pipeline_token,
        )
        return _pipeline_token
    except Exception as exc:
        logger.warning(
            "Agent pipeline failed to load (%s: %s) — trying query pipeline",
            type(exc).__name__,
            exc,
        )

    # Fallback: simple prompt → LLM pipeline
    result = await client.use(filepath=_QUERY_PIPELINE_PATH)
    _pipeline_token = result["token"]
    _active_pipeline = "query"
    logger.info(
        "cerberus-query pipeline loaded (simple LLM), token=%s",
        _pipeline_token,
    )
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

    Tries RocketRide first (agent pipeline, then query pipeline).
    On any failure silently falls back to direct Anthropic calls via llm.py.

    Each yielded string is already formatted as "data: {...}\\n\\n" —
    ready to be yielded directly from the FastAPI StreamingResponse.
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
            global _pipeline_token, _active_pipeline
            _pipeline_token = None
            _active_pipeline = None
            yield f"data: {json.dumps({'rocketride_fallback': True})}\n\n"

    # Direct Anthropic fallback — no RocketRide needed
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
            f"Graph traversal found {traversal.get('paths_found', 0)} threat path(s) "
            f"for {entity}. Review the raw graph data for detail."
        )
        yield f"data: {json.dumps({'text': fallback_text})}\n\n"


async def _stream_via_sdk(
    entity: str,
    entity_type: str,
    traversal: dict[str, Any],
) -> AsyncIterator[str]:
    """
    Send a query to the loaded RocketRide pipeline and stream the answer.

    Both pipelines use a ``chat`` source, so we use the SDK ``chat()`` method
    with a ``Question`` object.

    If the agent pipeline is active, we send just the entity name — the
    agent will autonomously explore Neo4j via MCP tools.

    If the simple query pipeline is active (fallback), we send the full
    traversal data as context, same as before.
    """
    # Lazy import — only needed when RocketRide is actually reachable
    from rocketride.schema import Question  # type: ignore

    client = _get_client()
    await asyncio.wait_for(client.connect(), timeout=3.0)
    token = await _load_pipeline(client)

    # Signal pipeline stages to the frontend
    yield f"data: {json.dumps({'stage': 'ner'})}\n\n"
    await asyncio.sleep(0)
    yield f"data: {json.dumps({'stage': 'classify'})}\n\n"
    await asyncio.sleep(0)
    yield f"data: {json.dumps({'stage': 'traverse'})}\n\n"
    await asyncio.sleep(0)

    # Emit paths_found from the backend's own traversal (used by GraphPanel)
    paths_found = traversal.get("paths_found", 0)
    yield f"data: {json.dumps({'paths_found': paths_found})}\n\n"
    await asyncio.sleep(0)

    yield f"data: {json.dumps({'stage': 'analyze'})}\n\n"
    await asyncio.sleep(0)

    # ── Build and send the question via SDK chat() ────────────────────────
    question = Question()

    if _active_pipeline == "agent":
        # Agent pipeline: send just the entity name — the CrewAI agent
        # will use MCP tools to query Neo4j and explore the graph itself.
        question.addQuestion(
            f"Investigate the threat entity '{entity}' (type: {entity_type}). "
            f"Use your Neo4j MCP tools to explore the graph and generate "
            f"a cross-domain threat intelligence narrative."
        )
    else:
        # Simple query pipeline: send the full traversal data as context
        # because this pipeline has no MCP access.
        question.addContext(
            f"Graph traversal result:\n{json.dumps(traversal, indent=2)}"
        )
        question.addQuestion(
            f"Investigate the threat entity '{entity}' (type: {entity_type}). "
            f"Analyze it using the graph traversal data above. "
            f"Generate a cross-domain threat intelligence narrative."
        )

    # Both pipelines use a chat source → use chat() method
    response = await client.chat(token=token, question=question)

    yield f"data: {json.dumps({'stage': 'narrate'})}\n\n"
    await asyncio.sleep(0)

    # ── Extract the answer from the response ──────────────────────────────
    # chat() response format: {"answers": ["..."]}
    narrative = _extract_narrative(response)

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
        await asyncio.sleep(0.02)  # small delay for streaming animation


def _extract_narrative(response: dict[str, Any]) -> str:
    """
    Pull the narrative text out of a RocketRide pipeline response.

    Primary format from chat():  {"answers": ["text..."]}
    Fallback format from send(): {"data": {"objects": {"<uuid>": {"text": "..."}}}}
    """
    # Try answers format first (from chat())
    answers = response.get("answers", [])
    if answers:
        return answers[0] if isinstance(answers[0], str) else str(answers[0])

    # Try data.objects format (from send() / webhook)
    data = response.get("data", {})
    objects = data.get("objects", {})
    for obj in objects.values():
        if isinstance(obj, dict) and "text" in obj:
            return obj["text"]

    # Last resort: stringify the whole response
    logger.warning("Unexpected RocketRide response format: %s", list(response.keys()))
    return json.dumps(response, indent=2)
