"""
routes/ingest.py

Webhook-based threat intelligence ingestion via RocketRide.

The cerberus-ingest pipeline handles everything behind the scenes:
  webhook → parse → ocr (images) → prompt → llm_anthropic (haiku) → extract_data → response

The extract_data component produces structured tabular output with columns:
  type, value, threat_domain, confidence, context

Supports:
  - POST /api/ingest/file   — upload a file (PDF, image, doc) for entity extraction
  - POST /api/ingest/text   — submit raw text/paste for entity extraction
  - GET  /api/ingest/status — check if the ingest pipeline is loaded and ready

Extracted entities are returned as JSON and optionally written to the graph.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import anthropic
from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from pydantic import BaseModel

import config
import neo4j_client as db

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/ingest")

# Path to the ingest pipeline
_PIPELINE_PATH = str(Path(__file__).parent.parent.parent / "pipelines" / "cerberus-ingest.pipe")

# Cached pipeline token
_ingest_token: str | None = None
_ingest_client = None


def _parse_extraction_response(response: dict) -> list[dict[str, Any]]:
    """
    Parse the RocketRide pipeline response into a list of entity dicts.

    Handles two formats:
    1. Structured tabular output from extract_data — already a list of row dicts
       in 'entities' or 'answers' key
    2. Legacy raw text (JSON string) from the LLM — needs JSON parsing with
       markdown fence stripping
    """
    # Try 'entities' first (our laneName), then 'answers'
    data = response.get("entities", response.get("answers", []))

    # If data is already a list of dicts (structured extract_data output), return it
    if isinstance(data, list) and data and isinstance(data[0], dict):
        return data

    # Otherwise treat as raw text from LLM and parse JSON
    raw = data[0] if isinstance(data, list) and data else str(data) if data else "[]"
    try:
        clean = raw.strip()
        if clean.startswith("```"):
            clean = "\n".join(clean.split("\n")[1:])
        if clean.endswith("```"):
            clean = "\n".join(clean.split("\n")[:-1])
        return json.loads(clean.strip())
    except (json.JSONDecodeError, AttributeError):
        return []


def _get_client():
    """Lazily initialize the RocketRide client. Returns None if SDK not available."""
    global _ingest_client
    if _ingest_client is not None:
        return _ingest_client
    try:
        from rocketride import RocketRideClient  # type: ignore
        uri = config.get("ROCKETRIDE_URI", "http://localhost:5565")
        apikey = config.get("ROCKETRIDE_APIKEY", "")
        _ingest_client = RocketRideClient(uri=uri, auth=apikey)
        return _ingest_client
    except ImportError:
        return None


# ── Direct-LLM fallback extraction ──────────────────────────────────────
# Used when RocketRide is unavailable (pipeline already running, SDK missing, etc.)
# Calls Claude Haiku directly to extract entities from text.

_EXTRACT_SYSTEM = """\
You are a threat intelligence entity extractor. Given raw text, extract all \
cyber threat entities and return ONLY a JSON array. Each element must have:
  type: one of "Package", "IP", "Domain", "CVE", "ThreatActor", "Technique"
  value: the exact entity string
  threat_domain: one of "supply_chain", "infrastructure", "financial", "unknown"
  confidence: "high", "medium", or "low"
  context: a short phrase explaining where/how this entity appears
Return only the JSON array, no markdown fences, no extra text.\
"""


def _extract_entities_via_llm(text: str) -> list[dict[str, Any]]:
    """
    Direct Anthropic API fallback for entity extraction.
    Uses Claude Haiku to extract entities when RocketRide pipeline is unavailable.
    """
    try:
        api_key = config.get("ANTHROPIC_API_KEY") or config.get("ROCKETRIDE_ANTHROPIC_KEY")
        if not api_key:
            logger.warning("No Anthropic API key for direct extraction fallback")
            return []

        client = anthropic.Anthropic(api_key=api_key)
        message = client.messages.create(
            model="claude-haiku-4-5",
            max_tokens=2048,
            system=_EXTRACT_SYSTEM,
            messages=[{"role": "user", "content": text}],
        )

        raw = message.content[0].text.strip()
        # Strip markdown fences if present
        if raw.startswith("```"):
            raw = "\n".join(raw.split("\n")[1:])
        if raw.endswith("```"):
            raw = "\n".join(raw.split("\n")[:-1])
        return json.loads(raw.strip())
    except Exception as exc:
        logger.error("Direct LLM extraction failed: %s", exc)
        return []


async def _get_ingest_token(client) -> str:
    """Load the cerberus-ingest pipeline and cache its token."""
    global _ingest_token
    if _ingest_token is not None:
        return _ingest_token
    result = await client.use(filepath=_PIPELINE_PATH)
    _ingest_token = result["token"]
    logger.info("cerberus-ingest pipeline loaded, token=%s", _ingest_token)
    return _ingest_token


class TextIngestRequest(BaseModel):
    text: str
    write_to_graph: bool = True


@router.get("/status")
async def ingest_status():
    """Check if the RocketRide ingest pipeline is ready."""
    client = _get_client()
    if client is None:
        return {"ready": False, "reason": "rocketride SDK not installed"}
    try:
        await client.connect()
        await client.ping()
        token = await _get_ingest_token(client)
        return {"ready": True, "pipeline": "cerberus-ingest", "token": token}
    except Exception as exc:
        return {"ready": False, "reason": str(exc)}


@router.post("/text")
async def ingest_text(req: TextIngestRequest):
    """
    Submit raw text for threat entity extraction.
    Tries RocketRide ingest pipeline first; falls back to direct Claude Haiku
    if the pipeline is unavailable (already running, SDK missing, etc.).
    """
    pipeline_name = "direct-llm (Claude Haiku)"
    entities: list[dict[str, Any]] = []

    # ── Try RocketRide pipeline first ────────────────────────────────
    client = _get_client()
    if client is not None:
        try:
            from rocketride.schema import Question  # type: ignore
            await client.connect()
            token = await _get_ingest_token(client)

            question = Question()
            question.addContext(req.text)
            question.addQuestion(
                "Extract all threat intelligence entities from the above content. "
                "Return a JSON array of entities with type, value, threat_domain, confidence, and context."
            )

            response = await client.chat(token=token, question=question)
            entities = _parse_extraction_response(response)
            pipeline_name = "cerberus-ingest (RocketRide)"
        except Exception as exc:
            logger.warning("RocketRide ingest failed (%s), falling back to direct LLM", exc)

    # ── Fallback: extract entities via direct Anthropic API ──────────
    if not entities:
        entities = _extract_entities_via_llm(req.text)

    if not entities:
        raise HTTPException(status_code=500, detail="No entities extracted — both pipeline and LLM fallback failed")

    # ── Optionally write to graph ────────────────────────────────────
    written = 0
    if req.write_to_graph and entities:
        written = _write_entities_to_graph(entities)

    return {
        "entities_found": len(entities),
        "entities": entities,
        "written_to_graph": written,
        "pipeline": pipeline_name,
    }


@router.post("/file")
async def ingest_file(
    file: UploadFile = File(...),
    write_to_graph: bool = Form(default=True),
):
    """
    Upload a file (PDF, image, text) for threat entity extraction.
    Tries RocketRide pipeline (with OCR support) first; for text-based files,
    falls back to direct Claude Haiku extraction if pipeline is unavailable.
    """
    content = await file.read()
    if len(content) > 10 * 1024 * 1024:  # 10MB limit
        raise HTTPException(status_code=413, detail="File too large (max 10MB)")

    pipeline_name = "direct-llm (Claude Haiku)"
    entities: list[dict[str, Any]] = []

    # ── Try RocketRide pipeline first (supports OCR for images/PDFs) ──
    client = _get_client()
    if client is not None:
        try:
            await client.connect()
            token = await _get_ingest_token(client)

            result = await client.send_files(
                token=token,
                files=[{"name": file.filename, "content": content, "mime_type": file.content_type}],
            )
            entities = _parse_extraction_response(result)
            pipeline_name = "cerberus-ingest (RocketRide webhook + OCR)"
        except Exception as exc:
            logger.warning("RocketRide file ingest failed (%s), trying direct LLM fallback", exc)

    # ── Fallback: try to decode file as text and run through direct LLM ──
    if not entities:
        try:
            text_content = content.decode("utf-8", errors="ignore")
            if text_content.strip():
                entities = _extract_entities_via_llm(text_content)
        except Exception as exc:
            logger.warning("Direct LLM file fallback failed: %s", exc)

    if not entities:
        raise HTTPException(
            status_code=500,
            detail="No entities extracted — file may be binary (PDF/image) and requires the RocketRide OCR pipeline",
        )

    written = 0
    if write_to_graph and entities:
        written = _write_entities_to_graph(entities)

    return {
        "filename": file.filename,
        "entities_found": len(entities),
        "entities": entities,
        "written_to_graph": written,
        "pipeline": pipeline_name,
    }


def _write_entities_to_graph(entities: list[dict[str, Any]]) -> int:
    """
    Write extracted entities to Neo4j. Returns count of nodes written.
    Uses MERGE so duplicate entities are safely skipped.
    """
    written = 0
    for entity in entities:
        try:
            etype = entity.get("type", "").strip()
            value = entity.get("value", "").strip()
            if not etype or not value:
                continue

            if etype == "Package":
                db.driver.execute_query(
                    "MERGE (p:Package {name: $name}) SET p.source = 'ingest', p.confidence = $conf",
                    name=value, conf=entity.get("confidence", "medium"),
                )
            elif etype == "IP":
                db.driver.execute_query(
                    "MERGE (i:IP {address: $addr}) SET i.source = 'ingest', i.confidence = $conf",
                    addr=value, conf=entity.get("confidence", "medium"),
                )
            elif etype == "Domain":
                db.driver.execute_query(
                    "MERGE (d:Domain {name: $name}) SET d.source = 'ingest', d.confidence = $conf",
                    name=value, conf=entity.get("confidence", "medium"),
                )
            elif etype == "CVE":
                db.driver.execute_query(
                    "MERGE (c:CVE {id: $id}) SET c.source = 'ingest', c.confidence = $conf",
                    id=value, conf=entity.get("confidence", "medium"),
                )
            elif etype == "ThreatActor":
                db.driver.execute_query(
                    "MERGE (t:ThreatActor {name: $name}) SET t.source = 'ingest', t.confidence = $conf",
                    name=value, conf=entity.get("confidence", "medium"),
                )
            written += 1
        except Exception as exc:
            logger.warning("Failed to write entity %s to graph: %s", entity, exc)

    return written
