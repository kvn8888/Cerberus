"""
routes/threatmap.py

AI-generated threat map image via GMI Cloud (gpt-image-1.5).

POST /api/threatmap  — generate a visual threat intelligence image for an entity
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from openai import OpenAI

import config

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api")


class ThreatMapRequest(BaseModel):
    entity: str
    entity_type: str
    narrative: str = ""  # optional — uses short summary if provided


@router.post("/threatmap")
async def generate_threatmap(req: ThreatMapRequest):
    """
    Generate a threat intelligence visualization image using GMI's gpt-image-1.5.
    Returns a URL to the generated image.
    """
    gmi_key = config.get("GMI_API_KEY")
    gmi_url = config.get("GMI_BASE_URL", "https://api.gmi-serving.com/v1")

    if not gmi_key:
        raise HTTPException(status_code=503, detail="GMI_API_KEY not configured")

    client = OpenAI(api_key=gmi_key, base_url=gmi_url)

    # Build a prompt that creates a compelling threat intel visualization
    summary = req.narrative[:300] if req.narrative else f"{req.entity_type} threat entity"
    prompt = (
        f"A dark cyberpunk threat intelligence map visualization. "
        f"Central node labeled '{req.entity}' ({req.entity_type}) glowing red, "
        f"connected by neon lines to surrounding threat nodes: ThreatActors in purple, "
        f"malicious IPs in orange, CVEs in red, Domains in cyan, FraudSignals in yellow. "
        f"Force-directed graph layout on a deep black background with subtle grid lines. "
        f"Style: dark terminal aesthetic, security operations center display. "
        f"Context: {summary}"
    )

    try:
        response = client.images.generate(
            model="gpt-image-1.5",
            prompt=prompt,
            n=1,
            size="1024x1024",
        )
        image_url = response.data[0].url
        return {
            "entity": req.entity,
            "entity_type": req.entity_type,
            "image_url": image_url,
            "provider": "GMI Cloud / gpt-image-1.5",
        }
    except Exception as exc:
        logger.error("GMI image generation failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Image generation failed: {exc}")
