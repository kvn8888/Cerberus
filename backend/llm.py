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
        model="claude-sonnet-4-6",
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
        model="claude-sonnet-4-6",
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
- Briefly explain what the entity is (if recognizable). If the entity is a CVE,
  note whether the ID format is valid and within a plausible allocation range.
- State clearly that no threat intelligence was found in the current knowledge graph.
- Do NOT assume the entity is benign or safe. Absence of evidence is not evidence
  of absence — the entity may be newly disclosed, reserved but unpublished,
  tracked in sources outside our feeds, or simply not yet ingested.
- For CVEs: note that the ID may be reserved, recently assigned, or from a CNA
  not yet reflected in our data. Never call an unknown CVE "fictitious" or "invalid"
  unless the numeric range is provably unallocated.
- For IPs/domains: note that lack of threat data does not confirm legitimacy.
- Recommend concrete follow-up steps: check NVD/MITRE directly, query additional
  threat feeds, set up monitoring alerts, or revisit after data refresh.
- Keep it under 200 words. Be direct, professional, and cautious.\
"""


def generate_clean_assessment(entity: str, entity_type: str) -> str:
    """
    Generate a cautious assessment when no threat paths are found.
    Called when traversal returns 0 paths — does NOT assume the entity is safe.
    """
    user_content = f"Entity: {entity}\nType: {entity_type}\nThreat paths found: 0"

    message = _get_client().messages.create(
        model="claude-sonnet-4-6",
        max_tokens=400,
        system=_CLEAN_ASSESSMENT_PROMPT,
        messages=[{"role": "user", "content": user_content}],
    )
    return message.content[0].text


def generate_clean_assessment_stream(entity: str, entity_type: str):
    """Streaming version of cautious assessment when no threat paths found."""
    user_content = f"Entity: {entity}\nType: {entity_type}\nThreat paths found: 0"

    with _get_client().messages.stream(
        model="claude-sonnet-4-6",
        max_tokens=400,
        system=_CLEAN_ASSESSMENT_PROMPT,
        messages=[{"role": "user", "content": user_content}],
    ) as stream:
        for text in stream.text_stream:
            yield text


_DETECTION_RULES_PROMPT = """\
You are a senior detection engineer supporting a SOC analyst.

Generate analyst-ready drafts, not perfect production rules.
- Use the provided IOCs and MITRE techniques only.
- Output strict JSON with keys: sigma, yara, notes.
- sigma: a single Sigma rule string inside plain text.
- yara: a single YARA rule string inside plain text.
- notes: a JSON array of short caveats or tuning notes.
- Keep rules conservative and clearly labeled as drafts.
- If evidence is sparse, still provide useful sketches and explain the gaps in notes.
"""


def _parse_json_response(raw: str) -> dict[str, Any]:
    text = raw.strip()
    if text.startswith("```"):
        text = "\n".join(text.splitlines()[1:-1]).strip()
    return json.loads(text)


def generate_detection_rules(
    entity: str,
    entity_type: str,
    iocs: list[dict[str, str]],
    techniques: list[str],
    narrative: str,
    tlp: str,
) -> dict[str, Any]:
    """Generate Sigma and YARA draft rules from an investigation context."""
    user_content = json.dumps(
        {
            "entity": entity,
            "entity_type": entity_type,
            "tlp": tlp,
            "iocs": iocs,
            "mitre_techniques": techniques,
            "narrative": narrative[:2500],
        },
        indent=2,
    )

    message = _get_client().messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1800,
        system=_DETECTION_RULES_PROMPT,
        messages=[{"role": "user", "content": user_content}],
    )
    raw = message.content[0].text
    try:
        parsed = _parse_json_response(raw)
    except Exception:
        parsed = {
            "sigma": raw.strip(),
            "yara": "rule cerberus_placeholder {\n  condition:\n    false\n}",
            "notes": ["The model response could not be parsed as structured JSON; review manually."],
        }

    return {
        "sigma": str(parsed.get("sigma", "")).strip(),
        "yara": str(parsed.get("yara", "")).strip(),
        "notes": [str(note).strip() for note in parsed.get("notes", []) if str(note).strip()],
        "tlp": tlp,
    }
