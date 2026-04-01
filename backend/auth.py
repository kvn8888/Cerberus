"""
auth.py — Lightweight JWT authentication and RBAC for Cerberus.

Provides token creation/verification, role-based access control via FastAPI
dependencies, and hardcoded demo users (no DB required).  Designed for
hackathon demos — impressive UX, not production hardening.
"""

import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import Depends, HTTPException, Request

# ── Config ────────────────────────────────────────────────────────────────────

JWT_SECRET = os.environ.get("JWT_SECRET", "cerberus-demo-secret-2024")
JWT_ALGORITHM = "HS256"
TOKEN_EXPIRY_HOURS = 24

# ── Roles ─────────────────────────────────────────────────────────────────────

ROLES = {"admin", "analyst", "viewer"}

# ── Demo Users (in-memory, no DB) ────────────────────────────────────────────

DEMO_USERS = {
    "admin@cerberus.io": {
        "password": "admin123",
        "role": "admin",
        "name": "Admin User",
    },
    "analyst@cerberus.io": {
        "password": "analyst123",
        "role": "analyst",
        "name": "Threat Analyst",
    },
    "viewer@cerberus.io": {
        "password": "viewer123",
        "role": "viewer",
        "name": "SOC Viewer",
    },
}

# ── Token helpers ─────────────────────────────────────────────────────────────


def create_token(user_id: str, role: str, email: str) -> str:
    """Create a signed JWT containing user identity and role, valid for 24 h."""
    payload = {
        "sub": user_id,
        "role": role,
        "email": email,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRY_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_token(token: str) -> dict:
    """Decode and validate a JWT.  Raises jwt.PyJWTError on failure."""
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])


# ── FastAPI dependency factory ────────────────────────────────────────────────


def _extract_bearer_token(request: Request) -> Optional[str]:
    """Pull the raw token string from an ``Authorization: Bearer <tok>`` header."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return None


def require_role(*roles: str):
    """Return a FastAPI Dependency that enforces JWT auth + role membership.

    Usage::

        @router.get("/admin-only", dependencies=[Depends(require_role("admin"))])
        def admin_only(user=Depends(require_role("admin"))):
            ...

    The dependency extracts the Bearer token, verifies it, checks the role,
    and returns the decoded user payload dict.
    """

    async def _dependency(request: Request) -> dict:
        token = _extract_bearer_token(request)
        if token is None:
            raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

        try:
            payload = verify_token(token)
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token has expired")
        except jwt.PyJWTError:
            raise HTTPException(status_code=401, detail="Invalid token")

        user_role = payload.get("role", "")
        if roles and user_role not in roles:
            raise HTTPException(
                status_code=403,
                detail=f"Role '{user_role}' is not authorized. Required: {', '.join(roles)}",
            )

        return payload

    return _dependency
