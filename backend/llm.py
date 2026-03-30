"""
llm.py — Anthropic LLM node for threat narrative generation.

Called only when the cache-check misses (new or unconfirmed path).
"""

from __future__ import annotations

import json
from typing import Any

import anthropic

import config

_client: anthropic.Anthropic | None = None

SYSTEM_PROMPT = """\
You are a senior threat intelligence analyst working in a security operations center.

You receive the output of a Neo4j graph traversal that traces cross-domain attack chains
across three domains:
  1. Software supply-chain  (Package, CVE, Account nodes)
  2. Infrastructure         (IP, Domain nodes)
  3. Financial fraud        (FraudSignal nodes)

Your task:
- Explain the cross-domain attack chain in plain language, step by step.
- Explicitly highlight each point where the chain crosses a domain boundary
  (e.g., software->infrastructure, infrastructure->financial).
- Name every node and relationship type you reference — be specific.
- Identify which ThreatActor is likely responsible, if the graph shows attribution.
- Rate the overall threat level: CRITICAL / HIGH / MEDIUM / LOW.
- Keep the narrative under 400 words. Lead with the threat level rating.\
"""


def _get_client() -> anthropic.Anthropic:
    global _client
    if _client is None:
        _client = anthropic.Anthropic(api_key=config.require("ANTHROPIC_API_KEY"))
    return _client


def generate_narrative(
    entity: str,
    entity_type: str,
    traversal_result: dict[str, Any],
) -> str:
    """
    Generate a threat narrative from a graph traversal result.
    Returns the narrative string.
    """
    user_content = (
        f"Entity: {entity} (type: {entity_type})\n\n"
        f"Graph traversal result:\n"
        f"{json.dumps(traversal_result, indent=2, default=str)}"
    )

    message = _get_client().messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=600,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_content}],
    )

    return message.content[0].text


def generate_narrative_stream(
    entity: str,
    entity_type: str,
    traversal_result: dict[str, Any],
):
    """
    Streaming version — yields text chunks as they arrive.
    Intended for the SSE endpoint.
    """
    user_content = (
        f"Entity: {entity} (type: {entity_type})\n\n"
        f"Graph traversal result:\n"
        f"{json.dumps(traversal_result, indent=2, default=str)}"
    )

    with _get_client().messages.stream(
        model="claude-sonnet-4-20250514",
        max_tokens=600,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_content}],
    ) as stream:
        for text in stream.text_stream:
            yield text


_CLEAN_ASSESSMENT_PROMPT = """\
You are a senior threat intelligence analyst. A security analyst queried an entity
and the system found NO threat paths, NO known vulnerabilities, and NO connections
to threat actors in the cross-domain knowledge graph.

Your task:
- Briefly explain what the entity is (if recognizable).
- State clearly that no threat intelligence was found.
- Explain WHY this is likely benign — e.g. it's a well-known legitimate service,
  not present in any threat feed, no CVEs linked, etc.
- If the entity type is a domain or IP, mention whether it belongs to a known
  legitimate organization.
- Recommend any follow-up steps if relevant (e.g. "monitor for future advisories").
- Keep it under 150 words. Be direct and professional.\
"""


def generate_clean_assessment(entity: str, entity_type: str) -> str:
    """
    Generate a brief explanation for why an entity has no threats.
    Called when traversal returns 0 paths.
    """
    user_content = f"Entity: {entity}\nType: {entity_type}\nThreat paths found: 0"

    message = _get_client().messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=200,
        system=_CLEAN_ASSESSMENT_PROMPT,
        messages=[{"role": "user", "content": user_content}],
    )
    return message.content[0].text


def generate_clean_assessment_stream(entity: str, entity_type: str):
    """Streaming version of clean assessment for the SSE endpoint."""
    user_content = f"Entity: {entity}\nType: {entity_type}\nThreat paths found: 0"

    with _get_client().messages.stream(
        model="claude-sonnet-4-20250514",
        max_tokens=200,
        system=_CLEAN_ASSESSMENT_PROMPT,
        messages=[{"role": "user", "content": user_content}],
    ) as stream:
        for text in stream.text_stream:
            yield text
