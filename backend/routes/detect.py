"""
routes/detect.py — Detection-rule drafting endpoints.

Turns an investigation context into analyst-tunable Sigma and YARA sketches
so teams can operationalize findings without starting from a blank page.
"""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

import llm

router = APIRouter(prefix="/api/detect")


class DetectionIoc(BaseModel):
    """Single IOC item forwarded from the frontend investigation context."""

    type: str = Field(..., min_length=1)
    value: str = Field(..., min_length=1)


class DetectionRuleRequest(BaseModel):
    """Payload used to draft detection content for an investigation."""

    entity: str = Field(..., min_length=1)
    entityType: str = Field(..., min_length=1)
    iocs: list[DetectionIoc] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    narrative: str = ""
    tlp: str = "amber"


@router.post("/rules")
async def generate_rules(req: DetectionRuleRequest):
    """Generate draft Sigma and YARA content from the current investigation."""
    if not req.entity.strip():
        raise HTTPException(status_code=400, detail="entity must not be empty")

    result = await asyncio.to_thread(
        llm.generate_detection_rules,
        req.entity.strip(),
        req.entityType.strip(),
        [ioc.model_dump() if hasattr(ioc, "model_dump") else ioc.dict() for ioc in req.iocs],
        [tech.strip() for tech in req.techniques if tech.strip()],
        req.narrative,
        req.tlp,
    )
    return result