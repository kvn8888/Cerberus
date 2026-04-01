"""
routes/threatmap.py

AI-generated threat map SVG via Anthropic Claude.

POST /api/threatmap  — generate a visual threat intelligence SVG for an entity
"""

from __future__ import annotations

import logging
import re

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

import config

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api")


class ThreatMapRequest(BaseModel):
    entity: str
    entity_type: str
    narrative: str = ""  # optional context from the investigation


@router.post("/threatmap")
async def generate_threatmap(req: ThreatMapRequest):
    """
    Generate a threat intelligence visualization as an SVG using Claude.
    Returns the raw SVG string for inline rendering.
    """
    api_key = config.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise HTTPException(status_code=503, detail="ANTHROPIC_API_KEY not configured")

    # Import here to avoid top-level dependency issues
    import anthropic

    client = anthropic.Anthropic(api_key=api_key)

    summary = req.narrative[:500] if req.narrative else f"{req.entity_type} threat entity"

    prompt = f"""Generate a complete, standalone SVG image (1000x600 viewBox) visualizing a cybersecurity threat intelligence graph.

Entity: {req.entity} (type: {req.entity_type})
Context: {summary}

Requirements:
- Dark background (#0a0e1a)
- Central node for "{req.entity}" glowing in red with a label
- Surrounding connected nodes representing: ThreatActors (purple #a855f7), IPs (orange #f97316), CVEs (red #ef4444), Domains (cyan #06b6d4), Packages (blue #3b82f6), FraudSignals (yellow #eab308)
- Create 6-10 connected nodes based on the context, using real entity names from the narrative if available
- Neon glowing edges (use SVG filters for glow effects)
- Each node: circle with glow + text label below
- Edges: curved paths with gradient strokes
- Include a title bar at top: "CERBERUS THREAT MAP — {req.entity}"
- Include a small legend in the bottom-right corner
- Style: dark SOC terminal aesthetic, cyberpunk feel
- Add subtle grid lines in the background
- Use SVG animations: pulsing nodes (animate r), dashed-stroke moving edges (animate stroke-dashoffset)

Return ONLY the SVG code, starting with <svg and ending with </svg>. No markdown, no explanation."""

    try:
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=4000,
            messages=[{"role": "user", "content": prompt}],
        )

        svg_text = response.content[0].text.strip()

        # Extract SVG if wrapped in markdown code blocks
        md_match = re.search(r"```(?:svg|xml)?\s*(.*?)```", svg_text, re.DOTALL)
        if md_match:
            svg_text = md_match.group(1).strip()

        # Validate it looks like SVG
        if not svg_text.startswith("<svg"):
            raise ValueError("Response did not contain valid SVG")

        return {
            "entity": req.entity,
            "entity_type": req.entity_type,
            "svg": svg_text,
            "provider": "Anthropic Claude",
        }
    except Exception as exc:
        logger.error("Threat map generation failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Image generation failed: {exc}")
