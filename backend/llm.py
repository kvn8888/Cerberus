"""
llm.py — Anthropic LLM node for threat narrative generation.

Called only when the cache-check misses (new or unconfirmed path).
"""

from __future__ import annotations

import json
from typing import Any

import anthropic

import config

_client = anthropic.Anthropic(api_key=config.ANTHROPIC_KEY)

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

    message = _client.messages.create(
        model="claude-opus-4-6",
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

    with _client.messages.stream(
        model="claude-opus-4-6",
        max_tokens=600,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_content}],
    ) as stream:
        for text in stream.text_stream:
            yield text
