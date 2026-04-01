"""
auth_routes.py — Login, session, and user-listing endpoints for Cerberus.

Prefix: /api/auth
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from auth import DEMO_USERS, create_token, require_role

router = APIRouter(prefix="/api/auth", tags=["auth"])

# ── Request / response models ─────────────────────────────────────────────────


class LoginRequest(BaseModel):
    email: str
    password: str


class UserInfo(BaseModel):
    email: str
    name: str
    role: str


class LoginResponse(BaseModel):
    token: str
    user: UserInfo


# ── Routes ────────────────────────────────────────────────────────────────────


@router.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest):
    """Authenticate with email + password, receive a signed JWT."""
    user = DEMO_USERS.get(body.email)
    if user is None or user["password"] != body.password:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_token(
        user_id=body.email,
        role=user["role"],
        email=body.email,
    )

    return LoginResponse(
        token=token,
        user=UserInfo(email=body.email, name=user["name"], role=user["role"]),
    )


@router.get("/me", response_model=UserInfo)
async def me(user: dict = Depends(require_role("admin", "analyst", "viewer"))):
    """Return the current authenticated user's profile from the JWT."""
    return UserInfo(
        email=user["email"],
        name=DEMO_USERS.get(user["email"], {}).get("name", user["email"]),
        role=user["role"],
    )


@router.get("/users")
async def list_users(user: dict = Depends(require_role("admin"))):
    """Admin-only: list all demo users (passwords redacted)."""
    return [
        {"email": email, "name": info["name"], "role": info["role"]}
        for email, info in DEMO_USERS.items()
    ]
