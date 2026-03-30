"""
routes/juspay.py

POST /api/juspay/ingest
  Body: single Juspay-style alert, list of alerts, or {"signals": [...]}
  Returns: normalized ingest summary

GET /api/juspay/signals
  Returns: summary of the fraud-signal layer currently stored in Neo4j
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from fastapi import APIRouter, HTTPException

import neo4j_client as db

router = APIRouter(prefix="/api/juspay")


@router.post("/ingest")
async def ingest_juspay(payload: dict[str, Any] | list[dict[str, Any]]):
    signals = _normalize_payload(payload)
    if not signals:
        raise HTTPException(
            status_code=400,
            detail="payload did not contain any valid Juspay fraud signals",
        )

    result = await asyncio.to_thread(db.ingest_fraud_signals, signals)
    return {
        "success": True,
        "ingested": result["ingested"],
        "linked_ips": result["linked_ips"],
        "signal_ids": result["signal_ids"],
    }


@router.get("/signals")
async def juspay_signals(limit: int = 10):
    if limit < 1 or limit > 100:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 100")
    return await asyncio.to_thread(db.get_juspay_summary, limit)


def _normalize_payload(payload: dict[str, Any] | list[dict[str, Any]]) -> list[dict[str, Any]]:
    raw_signals: list[dict[str, Any]]
    if isinstance(payload, list):
        raw_signals = payload
    else:
        maybe_signals = payload.get("signals")
        if isinstance(maybe_signals, list):
            raw_signals = maybe_signals
        else:
            raw_signals = [payload]

    normalized: list[dict[str, Any]] = []
    for raw in raw_signals:
        signal = _normalize_signal(raw)
        if signal is not None:
            normalized.append(signal)
    return normalized


def _normalize_signal(raw: dict[str, Any]) -> dict[str, Any] | None:
    juspay_id = _pick_first(raw, "juspay_id", "id", "transaction_id", "juspay_transaction_id")
    fraud_type = _pick_first(raw, "fraud_type", "signal_type", "alert_type", "type")
    amount = _pick_first(raw, "amount", "transaction_amount")
    ip_address = _pick_first(raw, "ip_address", "ip", "customer_ip", "device_ip")

    if not juspay_id or not fraud_type or amount is None or not ip_address:
        return None

    timestamp = _pick_first(raw, "timestamp", "created_at", "event_time")
    try:
        normalized_amount = float(amount)
    except (TypeError, ValueError):
        return None

    return {
        "juspay_id": str(juspay_id),
        "fraud_type": str(fraud_type),
        "amount": normalized_amount,
        "currency": str(_pick_first(raw, "currency", "currency_code") or "USD"),
        "ip_address": str(ip_address),
        "timestamp": _normalize_timestamp(timestamp),
        "merchant_id": _pick_first(raw, "merchant_id", "mid"),
        "source": str(raw.get("source") or "juspay"),
        "synthetic": bool(raw.get("synthetic", False)),
    }


def _pick_first(raw: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = raw.get(key)
        if value is not None and value != "":
            return value
    return None


def _normalize_timestamp(value: Any) -> int:
    if value is None:
        return int(time.time() * 1000)
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return int(time.time() * 1000)
