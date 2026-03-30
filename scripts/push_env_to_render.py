#!/usr/bin/env python3
"""
push_env_to_render.py — Upload local .env to Render production service.

Reads the local .env file, filters out local-only variables that have no
meaning in a cloud container, and uploads the remaining variables to Render
via the Render API. Then triggers a redeploy.

Usage:
    RENDER_API_KEY=rnd_xxxx python scripts/push_env_to_render.py

Or pass the key explicitly:
    python scripts/push_env_to_render.py --api-key rnd_xxxx

Generate your Render API key at:
    https://dashboard.render.com/u/settings#api-keys
"""

import argparse
import json
import os
import sys
from pathlib import Path

import httpx

# ── Configuration ─────────────────────────────────────────────────────────────

# Render API base URL
RENDER_API = "https://api.render.com/v1"

# Service name as it appears in Render dashboard (from the URL slug)
SERVICE_NAME = "cerberus-backend"

# Variables that are local-only and should NOT be pushed to production.
# These reference localhost/127.0.0.1 or are macOS-specific paths.
LOCAL_ONLY_VARS = {
    "SSL_CERT_FILE",         # macOS Python cert path — not needed in Linux container
    "NEO4J_MCP_URL",         # Local neo4j-mcp service URL
    "ROCKETRIDE_URL",        # Local RocketRide dashboard URL
    "CERBERUS_API",          # Local backend URL
    "NEO4J_MCP_ENDPOINT",    # Local MCP endpoint (only needed if RocketRide is cloud-accessible)
    "ROCKETRIDE_NEO4J_BASIC_AUTH",  # Only needed when RocketRide can reach neo4j-mcp
    "ROCKETRIDE_URI",        # Local RocketRide server — production value differs
    "ROCKETRIDE_APIKEY",     # Placeholder value — must be set manually in Render dashboard
}


def load_dotenv(env_path: Path) -> dict[str, str]:
    """
    Parse a .env file into a dict of key->value pairs.
    Handles quoted values and ignores comments/blank lines.
    """
    env: dict[str, str] = {}
    for line in env_path.read_text().splitlines():
        line = line.strip()
        # Skip comments and blank lines
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        # Strip surrounding quotes if present
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        env[key] = value
    return env


def get_service_id(client: httpx.Client, service_name: str) -> str:
    """
    Look up the Render service ID by name.
    Returns the serviceId string (e.g. 'srv-xxxxx').
    """
    # List services — Render returns paginated results
    cursor: str | None = None
    while True:
        params: dict = {"limit": 100}
        if cursor:
            params["cursor"] = cursor

        resp = client.get(f"{RENDER_API}/services", params=params)
        resp.raise_for_status()
        data = resp.json()

        for item in data:
            svc = item.get("service", {})
            # Match on the service name or slug
            if svc.get("name", "").lower() == service_name.lower():
                return svc["id"]
            # Also check if the service name contains our target (partial match)
            if service_name.lower() in svc.get("name", "").lower():
                print(f"  Matched service: {svc['name']} → {svc['id']}")
                return svc["id"]

        # Check for next page
        if len(data) < 100:
            break
        cursor = data[-1].get("cursor")
        if not cursor:
            break

    raise SystemExit(
        f"Service '{service_name}' not found in your Render account.\n"
        f"Check the service name in the Render dashboard and update SERVICE_NAME in this script."
    )


def push_env_vars(client: httpx.Client, service_id: str, env: dict[str, str]) -> None:
    """
    Replace all environment variables on the Render service with the provided dict.

    IMPORTANT: The Render PUT /env-vars endpoint is a full replacement — any vars
    not included in this call will be DELETED from the service. This script sends
    all production-relevant vars from the local .env.
    """
    payload = [{"key": k, "value": v} for k, v in env.items()]

    print(f"\nUploading {len(payload)} environment variables to service {service_id}...")
    for item in payload:
        print(f"  {item['key']}={'*' * min(len(item['value']), 8)}...")

    resp = client.put(
        f"{RENDER_API}/services/{service_id}/env-vars",
        json=payload,
    )

    if resp.status_code != 200:
        print(f"\nError {resp.status_code}: {resp.text}", file=sys.stderr)
        resp.raise_for_status()

    print("\nEnvironment variables updated successfully.")


def trigger_deploy(client: httpx.Client, service_id: str) -> None:
    """
    Trigger a new deploy on the Render service so the updated env vars take effect.
    Render does NOT automatically redeploy after env var updates.
    """
    resp = client.post(
        f"{RENDER_API}/services/{service_id}/deploys",
        json={"clearCache": "do_not_clear"},
    )

    if resp.status_code not in (200, 201):
        print(f"\nWarning: Deploy trigger failed ({resp.status_code}): {resp.text}", file=sys.stderr)
        print("You may need to manually trigger a redeploy in the Render dashboard.")
        return

    deploy = resp.json()
    deploy_id = deploy.get("id", "unknown")
    print(f"\nDeploy triggered: {deploy_id}")
    print("Track progress at: https://dashboard.render.com/")


def main() -> None:
    # ── Parse arguments ───────────────────────────────────────────────────────
    parser = argparse.ArgumentParser(description="Push local .env to Render production")
    parser.add_argument(
        "--api-key",
        default=os.environ.get("RENDER_API_KEY"),
        help="Render API key (or set RENDER_API_KEY env var)",
    )
    parser.add_argument(
        "--service",
        default=SERVICE_NAME,
        help=f"Render service name to target (default: {SERVICE_NAME})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be uploaded without actually pushing",
    )
    args = parser.parse_args()

    if not args.api_key:
        print(
            "Error: Render API key required.\n"
            "Set RENDER_API_KEY env var or pass --api-key.\n"
            "Generate one at: https://dashboard.render.com/u/settings#api-keys",
            file=sys.stderr,
        )
        sys.exit(1)

    # ── Load .env ─────────────────────────────────────────────────────────────
    env_path = Path(__file__).parent.parent / ".env"
    if not env_path.exists():
        print(f"Error: .env not found at {env_path}", file=sys.stderr)
        sys.exit(1)

    all_vars = load_dotenv(env_path)
    print(f"Loaded {len(all_vars)} variables from {env_path}")

    # Filter out local-only variables
    prod_vars = {k: v for k, v in all_vars.items() if k not in LOCAL_ONLY_VARS}
    skipped = {k for k in all_vars if k in LOCAL_ONLY_VARS}
    if skipped:
        print(f"Skipping local-only vars: {', '.join(sorted(skipped))}")

    if args.dry_run:
        print("\nDry run — would upload these variables:")
        for k, v in prod_vars.items():
            masked = v[:4] + "*" * max(0, len(v) - 4) if len(v) > 4 else "****"
            print(f"  {k}={masked}")
        return

    # ── Render API client ─────────────────────────────────────────────────────
    headers = {
        "Authorization": f"Bearer {args.api_key}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    with httpx.Client(headers=headers, timeout=30) as client:
        # Find service
        print(f"\nFinding service '{args.service}' in Render...")
        service_id = get_service_id(client, args.service)
        print(f"Found service: {service_id}")

        # Push vars
        push_env_vars(client, service_id, prod_vars)

        # Trigger deploy
        trigger_deploy(client, service_id)

    print("\nDone! Your service will redeploy with the updated environment variables.")
    print("The Neo4j auth error should be gone once the deploy completes (~1-2 minutes).")


if __name__ == "__main__":
    main()
