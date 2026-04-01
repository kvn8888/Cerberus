"""
apikeys.py — API key creation, listing, and revocation for Cerberus.

In-memory store — keys survive only as long as the process runs, which is
fine for a hackathon demo.  Pre-seeded with two demo keys on module load.

Prefix: /api/keys
"""

import secrets
import uuid
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from auth import require_role

router = APIRouter(prefix="/api/keys", tags=["api-keys"])

# ── In-memory key store ──────────────────────────────────────────────────────
# Keyed by a UUID id; each value holds the full key, metadata, and permissions.

_API_KEYS: dict[str, dict] = {}


def _add_key(name: str, permissions: list[str], key_override: str | None = None) -> dict:
    """Insert a new API key into the store and return the record."""
    key_id = str(uuid.uuid4())
    raw_key = key_override or f"cerb_live_{secrets.token_hex(12)}"
    record = {
        "id": key_id,
        "name": name,
        "key": raw_key,
        "permissions": permissions,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _API_KEYS[key_id] = record
    return record


# Pre-seed two demo keys so the UI is never empty on first load.
_add_key("Demo Analyst Key", ["read", "investigate"], key_override="cerb_live_demo_analyst_key")
_add_key(
    "Demo Admin Key",
    ["read", "investigate", "confirm", "admin"],
    key_override="cerb_live_demo_admin_key",
)

# ── Request / response models ────────────────────────────────────────────────


class CreateKeyRequest(BaseModel):
    name: str
    permissions: List[str]


class CreateKeyResponse(BaseModel):
    key: str
    name: str
    created_at: str


class KeyPreview(BaseModel):
    id: str
    name: str
    key_preview: str
    permissions: List[str]
    created_at: str


# ── Routes ────────────────────────────────────────────────────────────────────


@router.post("/create", response_model=CreateKeyResponse)
async def create_key(body: CreateKeyRequest, user: dict = Depends(require_role("admin"))):
    """Generate a new API key.  Only admins may create keys."""
    record = _add_key(body.name, body.permissions)
    return CreateKeyResponse(
        key=record["key"],
        name=record["name"],
        created_at=record["created_at"],
    )


@router.get("", response_model=List[KeyPreview])
async def list_keys(user: dict = Depends(require_role("admin"))):
    """List all API keys with masked previews (last 4 chars visible)."""
    return [
        KeyPreview(
            id=rec["id"],
            name=rec["name"],
            key_preview=f"****{rec['key'][-4:]}",
            permissions=rec["permissions"],
            created_at=rec["created_at"],
        )
        for rec in _API_KEYS.values()
    ]


@router.delete("/{key_id}")
async def delete_key(key_id: str, user: dict = Depends(require_role("admin"))):
    """Revoke an API key by its id."""
    if key_id not in _API_KEYS:
        raise HTTPException(status_code=404, detail="API key not found")
    del _API_KEYS[key_id]
    return {"status": "deleted", "id": key_id}
