"""
routes/enrichment.py — External threat intelligence enrichment endpoints.

Provides three endpoints that query VirusTotal and Have I Been Pwned (HIBP)
to enrich investigations with real-world threat data:

GET /api/enrich/virustotal?entity=X&type=Y  — IP/domain/hash reputation via VT v3
GET /api/enrich/hibp?email=X                — Breach history for an email via HIBP v3
GET /api/enrich/summary?entity=X&type=Y     — Unified enrichment summary with highlights

When API keys are missing, endpoints return realistic simulated data (marked
simulated=True) so the platform always works for demos.
"""

from __future__ import annotations

import logging
import os
import re

import httpx
from fastapi import APIRouter, Query

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/enrich")

_VT_BASE = "https://www.virustotal.com/api/v3"
_HIBP_BASE = "https://haveibeenpwned.com/api/v3"
_TIMEOUT = 10.0

# Regex for common hash formats (MD5, SHA-1, SHA-256)
_HASH_RE = re.compile(r"^[0-9a-fA-F]{32,64}$")


# ── VirusTotal ──────────────────────────────────────────────────────────────


def _vt_api_key() -> str:
    return os.environ.get("VIRUSTOTAL_API_KEY", "")


def _simulate_virustotal(entity: str, entity_type: str) -> dict:
    """Generate realistic-looking VirusTotal data for demo purposes."""
    base_stats = {
        "malicious": 7,
        "suspicious": 3,
        "harmless": 62,
        "undetected": 12,
    }

    if entity_type == "ip":
        return {
            "country": "RU",
            "as_owner": "SELECTEL-MSK",
            "last_analysis_stats": base_stats,
            "reputation": -15,
            "network": "185.220.101.0/24",
        }
    elif entity_type == "domain":
        return {
            "registrar": "Namecheap, Inc.",
            "creation_date": "2019-03-14",
            "last_analysis_stats": {**base_stats, "malicious": 4, "harmless": 68},
            "reputation": -8,
            "categories": {
                "Forcepoint ThreatSeeker": "malicious sources",
                "sophos": "malware callhome",
            },
        }
    else:
        return {
            "meaningful_name": f"{entity[:12]}...malware.exe",
            "type_description": "Win32 EXE",
            "last_analysis_stats": {**base_stats, "malicious": 48, "suspicious": 5, "harmless": 8},
            "reputation": -72,
            "sha256": entity if len(entity) == 64 else "e3b0c44298fc1c149afbf4c8996fb924"
                      "27ae41e4649b934ca495991b7852b855",
        }


async def _fetch_virustotal(entity: str, entity_type: str) -> dict:
    """
    Hit the VirusTotal v3 API for the given entity.

    Routes to the appropriate VT endpoint based on entity_type:
      - ip     → /ip_addresses/{ip}
      - domain → /domains/{domain}
      - hash   → /files/{hash}

    Returns the parsed data dict, or falls back to simulated data on any error.
    """
    api_key = _vt_api_key()
    if not api_key:
        logger.info("No VIRUSTOTAL_API_KEY set — returning simulated data")
        return {"simulated": True, "data": _simulate_virustotal(entity, entity_type)}

    # Pick the right VT v3 endpoint
    if entity_type == "ip":
        url = f"{_VT_BASE}/ip_addresses/{entity}"
    elif entity_type == "domain":
        url = f"{_VT_BASE}/domains/{entity}"
    else:
        url = f"{_VT_BASE}/files/{entity}"

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(url, headers={"x-apikey": api_key})
            resp.raise_for_status()
            raw = resp.json().get("data", {}).get("attributes", {})
    except Exception as exc:
        logger.warning("VirusTotal request failed for %s — falling back to simulated: %s", entity, exc)
        return {"simulated": True, "data": _simulate_virustotal(entity, entity_type)}

    # Extract the fields we care about per entity type
    if entity_type == "ip":
        extracted = {
            "country": raw.get("country", "unknown"),
            "as_owner": raw.get("as_owner", "unknown"),
            "last_analysis_stats": raw.get("last_analysis_stats", {}),
            "reputation": raw.get("reputation", 0),
            "network": raw.get("network", ""),
        }
    elif entity_type == "domain":
        extracted = {
            "registrar": raw.get("registrar", "unknown"),
            "creation_date": str(raw.get("creation_date", "unknown")),
            "last_analysis_stats": raw.get("last_analysis_stats", {}),
            "reputation": raw.get("reputation", 0),
            "categories": raw.get("categories", {}),
        }
    else:
        extracted = {
            "meaningful_name": raw.get("meaningful_name", "unknown"),
            "type_description": raw.get("type_description", "unknown"),
            "last_analysis_stats": raw.get("last_analysis_stats", {}),
            "reputation": raw.get("reputation", 0),
        }

    return {"simulated": False, "data": extracted}


@router.get("/virustotal")
async def enrich_virustotal(
    entity: str = Query(..., description="IP address, domain, or file hash to look up"),
    type: str = Query("ip", description="Entity type: ip, domain, or hash"),
):
    """
    Look up an entity on VirusTotal and return analysis stats.

    If no VIRUSTOTAL_API_KEY is configured, returns convincing simulated data
    so the endpoint always works for demos and development.
    """
    entity = entity.strip()

    # Auto-detect hashes so callers can pass type="file" or just a raw hash
    entity_type = type.lower()
    if entity_type in ("hash", "file") or _HASH_RE.match(entity):
        entity_type = "hash"
    elif entity_type not in ("ip", "domain"):
        entity_type = "ip"

    result = await _fetch_virustotal(entity, entity_type)

    return {
        "entity": entity,
        "source": "virustotal",
        "simulated": result["simulated"],
        "data": result["data"],
    }


# ── Have I Been Pwned ───────────────────────────────────────────────────────


SIMULATED_BREACHES = [
    {
        "Name": "LinkedIn",
        "Domain": "linkedin.com",
        "BreachDate": "2021-06-22",
        "DataClasses": ["Email addresses", "Passwords"],
        "IsVerified": True,
        "PwnCount": 700_000_000,
    },
    {
        "Name": "Adobe",
        "Domain": "adobe.com",
        "BreachDate": "2013-10-04",
        "DataClasses": ["Email addresses", "Password hints", "Passwords", "Usernames"],
        "IsVerified": True,
        "PwnCount": 153_000_000,
    },
    {
        "Name": "Dropbox",
        "Domain": "dropbox.com",
        "BreachDate": "2012-07-01",
        "DataClasses": ["Email addresses", "Passwords"],
        "IsVerified": True,
        "PwnCount": 68_648_009,
    },
]


def _hibp_api_key() -> str:
    return os.environ.get("HIBP_API_KEY", "")


async def _fetch_hibp(email: str) -> dict:
    """
    Query the HIBP v3 API for breach records associated with an email address.

    Returns a dict with simulated flag and breach list. Falls back to
    simulated data when no API key is set or the request fails.
    """
    api_key = _hibp_api_key()
    if not api_key:
        logger.info("No HIBP_API_KEY set — returning simulated breach data")
        return {"simulated": True, "breaches": SIMULATED_BREACHES}

    url = f"{_HIBP_BASE}/breachedaccount/{email}"
    headers = {
        "hibp-api-key": api_key,
        "user-agent": "Cerberus-ThreatIntel",
    }

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                url,
                headers=headers,
                params={"truncateResponse": "false"},
            )

            # 404 means the email has no breaches — that's a valid result
            if resp.status_code == 404:
                return {"simulated": False, "breaches": []}

            resp.raise_for_status()
            raw_breaches = resp.json()
    except Exception as exc:
        logger.warning("HIBP request failed for %s — falling back to simulated: %s", email, exc)
        return {"simulated": True, "breaches": SIMULATED_BREACHES}

    # Extract the fields we care about from each breach record
    breaches = [
        {
            "Name": b.get("Name", "Unknown"),
            "Domain": b.get("Domain", ""),
            "BreachDate": b.get("BreachDate", ""),
            "DataClasses": b.get("DataClasses", []),
            "IsVerified": b.get("IsVerified", False),
            "PwnCount": b.get("PwnCount", 0),
        }
        for b in raw_breaches
    ]

    return {"simulated": False, "breaches": breaches}


@router.get("/hibp")
async def enrich_hibp(
    email: str = Query(..., description="Email address to check for data breaches"),
):
    """
    Check whether an email address appears in known data breaches via HIBP.

    If no HIBP_API_KEY is configured, returns realistic simulated breach data
    (LinkedIn, Adobe, Dropbox) for demo purposes.
    """
    email = email.strip().lower()
    result = await _fetch_hibp(email)

    return {
        "email": email,
        "source": "hibp",
        "simulated": result["simulated"],
        "breaches": result["breaches"],
        "total_breaches": len(result["breaches"]),
    }


# ── Combined enrichment summary ────────────────────────────────────────────


def _vt_highlights(data: dict, entity_type: str) -> list[str]:
    """Distill VirusTotal results into 3-5 human-readable highlight strings."""
    highlights: list[str] = []
    stats = data.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values()) if stats else 0

    if total:
        highlights.append(f"{malicious}/{total} engines flagged as malicious")
    if suspicious:
        highlights.append(f"{suspicious} engines flagged as suspicious")

    rep = data.get("reputation", 0)
    if rep < 0:
        highlights.append(f"Reputation score: {rep} (negative = bad)")

    if entity_type == "ip":
        owner = data.get("as_owner")
        country = data.get("country")
        if owner:
            highlights.append(f"AS owner: {owner} ({country or '??'})")
    elif entity_type == "domain":
        cats = data.get("categories", {})
        if cats:
            cat_str = ", ".join(cats.values())
            highlights.append(f"Categorized as: {cat_str}")
    else:
        name = data.get("meaningful_name")
        if name:
            highlights.append(f"File: {name}")

    return highlights[:5]


def _hibp_highlights(breaches: list[dict]) -> list[str]:
    """Distill HIBP results into 3-5 human-readable highlight strings."""
    if not breaches:
        return ["No known breaches found"]

    highlights = [f"Found in {len(breaches)} known data breach(es)"]

    # Show the largest breach by PwnCount
    biggest = max(breaches, key=lambda b: b.get("PwnCount", 0))
    highlights.append(
        f"Largest: {biggest['Name']} ({biggest.get('PwnCount', 0):,} accounts, "
        f"{biggest.get('BreachDate', 'unknown date')})"
    )

    # Unique exposed data classes across all breaches
    all_classes: set[str] = set()
    for b in breaches:
        all_classes.update(b.get("DataClasses", []))
    if all_classes:
        highlights.append(f"Exposed data types: {', '.join(sorted(all_classes)[:6])}")

    # Most recent breach
    sorted_by_date = sorted(breaches, key=lambda b: b.get("BreachDate", ""), reverse=True)
    if sorted_by_date:
        recent = sorted_by_date[0]
        highlights.append(f"Most recent: {recent['Name']} ({recent.get('BreachDate', '?')})")

    return highlights[:5]


@router.get("/summary")
async def enrich_summary(
    entity: str = Query(..., description="Entity to enrich (IP, domain, email, or hash)"),
    type: str = Query("auto", description="Entity type: ip, domain, email, hash, or auto"),
):
    """
    Unified enrichment summary that routes to the right source based on
    entity type and returns the top highlights as plain-English strings.

    Auto-detection logic:
      - Contains '@' → treated as email → calls HIBP
      - Matches hex hash pattern → calls VirusTotal (file lookup)
      - Otherwise uses the explicit type parameter for VirusTotal
    """
    entity = entity.strip()
    entity_type = type.lower()

    # Auto-detect entity type when set to "auto"
    if entity_type == "auto":
        if "@" in entity:
            entity_type = "email"
        elif _HASH_RE.match(entity):
            entity_type = "hash"
        elif re.match(r"^\d{1,3}(\.\d{1,3}){3}$", entity):
            entity_type = "ip"
        else:
            entity_type = "domain"

    enrichments: list[dict] = []

    if entity_type == "email" or "@" in entity:
        result = await _fetch_hibp(entity)
        enrichments.append({
            "source": "hibp",
            "simulated": result["simulated"],
            "highlights": _hibp_highlights(result["breaches"]),
        })
    else:
        # IPs, domains, and hashes all go through VirusTotal
        vt_type = entity_type if entity_type in ("ip", "domain") else "hash"
        result = await _fetch_virustotal(entity, vt_type)
        enrichments.append({
            "source": "virustotal",
            "simulated": result["simulated"],
            "highlights": _vt_highlights(result["data"], vt_type),
        })

    return {
        "entity": entity,
        "enrichments": enrichments,
    }
