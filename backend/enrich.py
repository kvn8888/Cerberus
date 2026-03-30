"""
enrich.py — Real-time threat intelligence enrichment from public APIs.

When a user queries an entity that doesn't exist in the Neo4j graph,
this module checks external threat intel APIs and ingests any findings
into Neo4j on-the-fly. The entity then persists for future queries.

Supported sources:
  - OSV.dev   — Open Source Vulnerability database (packages + CVEs)
  - NVD       — NIST National Vulnerability Database (CVE details)
  - Abuse.ch  — Feodo Tracker (IPs) + URLhaus (domains)

Flow (called from routes/query.py):
  1. db.traverse() returns paths_found == 0
  2. enrich.try_enrich(entity, entity_type) is called
  3. Module queries external APIs based on entity_type
  4. Any findings are written as new nodes/edges in Neo4j
  5. Returns True if new data was ingested (caller should re-traverse)

All API calls use generous timeouts and catch exceptions — enrichment
is best-effort and never blocks the query flow on failure.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx
from neo4j import GraphDatabase

import config

logger = logging.getLogger(__name__)

# Timeout for external API calls (seconds)
_API_TIMEOUT = 10.0

# ── Neo4j driver (reuses config from neo4j_client.py) ────────────────────────

_driver = None


def _get_driver():
    """Get or create the Neo4j driver singleton."""
    global _driver
    if _driver is None:
        _driver = GraphDatabase.driver(
            config.require("NEO4J_URI"),
            auth=(
                config.require("NEO4J_USERNAME"),
                config.require("NEO4J_PASSWORD"),
            ),
        )
    return _driver


# ── Public entry point ────────────────────────────────────────────────────────


async def try_enrich(entity: str, entity_type: str) -> bool:
    """
    Try to enrich the graph with external threat intel for the given entity.

    Returns True if new data was ingested (caller should re-run traversal).
    Returns False if no data found or enrichment failed.
    Never raises — all errors are caught and logged.
    """
    etype = entity_type.lower()

    try:
        if etype == "package":
            return await _enrich_package(entity)
        elif etype == "cve":
            return await _enrich_cve(entity)
        elif etype == "ip":
            return await _enrich_ip(entity)
        elif etype == "domain":
            return await _enrich_domain(entity)
        else:
            logger.debug("No enrichment source for entity_type=%s", etype)
            return False
    except Exception as exc:
        logger.warning(
            "Enrichment failed for %s/%s: %s: %s",
            entity_type, entity, type(exc).__name__, exc,
        )
        return False


# ── Package enrichment (OSV.dev) ──────────────────────────────────────────────


async def _enrich_package(package_name: str) -> bool:
    """
    Query OSV.dev for known vulnerabilities in the given package.
    Creates Package and CVE nodes with HAS_VULNERABILITY edges.

    OSV.dev API: https://api.osv.dev/v1/query
    No authentication required, no rate limits published.
    """
    logger.info("Enriching package '%s' from OSV.dev", package_name)

    # OSV.dev supports multiple ecosystems; try npm first, then PyPI
    vulns: list[dict] = []
    for ecosystem in ["npm", "PyPI"]:
        found = await _query_osv(package_name, ecosystem)
        if found:
            vulns.extend(found)
            break  # stop after first ecosystem match

    if not vulns:
        logger.info("OSV.dev: no vulnerabilities found for '%s'", package_name)
        return False

    # Write Package node + CVE nodes + edges into Neo4j
    ingested = _ingest_package_vulns(package_name, vulns)
    logger.info(
        "Enriched '%s': %d CVEs ingested from OSV.dev",
        package_name, ingested,
    )
    return ingested > 0


async def _query_osv(package_name: str, ecosystem: str) -> list[dict]:
    """
    Call the OSV.dev API to find vulnerabilities for a package.
    Returns a list of vulnerability dicts (OSV format).
    """
    async with httpx.AsyncClient(timeout=_API_TIMEOUT) as client:
        resp = await client.post(
            "https://api.osv.dev/v1/query",
            json={"package": {"name": package_name, "ecosystem": ecosystem}},
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("vulns", [])


def _ingest_package_vulns(package_name: str, vulns: list[dict]) -> int:
    """
    Write Package + CVE nodes and HAS_VULNERABILITY edges into Neo4j.
    Returns the count of new CVE nodes created.
    """
    # Cypher: MERGE the Package, then for each CVE, MERGE + link
    cypher = """
    MERGE (pkg:Package {name: $pkg_name})
    ON CREATE SET pkg.source = 'osv_enrichment',
                  pkg.enriched_at = timestamp()
    WITH pkg
    UNWIND $vulns AS v
    MERGE (cve:CVE {id: v.cve_id})
    ON CREATE SET cve.description = v.description,
                  cve.severity    = v.severity,
                  cve.cvss        = v.cvss,
                  cve.source      = 'osv_enrichment',
                  cve.enriched_at = timestamp()
    MERGE (pkg)-[:HAS_VULNERABILITY]->(cve)
    RETURN count(cve) AS cnt
    """

    # Transform OSV format into our schema
    vuln_rows = []
    for v in vulns[:20]:  # cap at 20 CVEs per package to avoid bloat
        cve_id = _extract_cve_id(v)
        if not cve_id:
            continue
        severity, cvss = _extract_severity(v)
        vuln_rows.append({
            "cve_id":      cve_id,
            "description": (v.get("summary") or v.get("details", ""))[:500],
            "severity":    severity,
            "cvss":        cvss,
        })

    if not vuln_rows:
        return 0

    with _get_driver().session() as s:
        result = s.run(cypher, pkg_name=package_name, vulns=vuln_rows)
        return result.single()["cnt"]


# ── CVE enrichment (NVD API) ─────────────────────────────────────────────────


async def _enrich_cve(cve_id: str) -> bool:
    """
    Query NVD for details on a specific CVE.
    Creates the CVE node if it doesn't exist.

    NVD API: https://services.nvd.nist.gov/rest/json/cves/2.0
    Rate limit: 5 requests per 30 seconds (no API key).
    """
    logger.info("Enriching CVE '%s' from NVD", cve_id)

    # Normalize CVE ID format (e.g., "cve-2021-44228" → "CVE-2021-44228")
    cve_id_upper = cve_id.upper()
    if not cve_id_upper.startswith("CVE-"):
        cve_id_upper = f"CVE-{cve_id_upper}"

    async with httpx.AsyncClient(timeout=_API_TIMEOUT) as client:
        resp = await client.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": cve_id_upper},
        )
        resp.raise_for_status()
        data = resp.json()

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        logger.info("NVD: CVE '%s' not found", cve_id_upper)
        return False

    # Extract CVE details from the NVD response
    cve_data = vulns[0].get("cve", {})
    description = ""
    for desc in cve_data.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break

    severity, cvss = _extract_nvd_severity(cve_data)

    # Write CVE node into Neo4j
    cypher = """
    MERGE (cve:CVE {id: $cve_id})
    ON CREATE SET cve.description = $description,
                  cve.severity    = $severity,
                  cve.cvss        = $cvss,
                  cve.source      = 'nvd_enrichment',
                  cve.enriched_at = timestamp()
    ON MATCH SET  cve.description = CASE WHEN cve.description IS NULL
                                         THEN $description
                                         ELSE cve.description END
    RETURN cve.id AS id
    """

    with _get_driver().session() as s:
        s.run(
            cypher,
            cve_id=cve_id_upper,
            description=description[:500],
            severity=severity,
            cvss=cvss,
        )

    logger.info("Enriched CVE '%s' (severity=%s, cvss=%s)", cve_id_upper, severity, cvss)
    return True


# ── IP enrichment (Abuse.ch Feodo Tracker) ────────────────────────────────────


async def _enrich_ip(ip_address: str) -> bool:
    """
    Check Abuse.ch Feodo Tracker for a known malicious IP.
    Creates IP node with threat metadata if found.

    Feodo Tracker API: https://feodotracker.abuse.ch/downloads/ipblocklist.json
    Public feed, no auth, updated every 5 minutes.
    """
    logger.info("Enriching IP '%s' from Abuse.ch Feodo Tracker", ip_address)

    async with httpx.AsyncClient(timeout=_API_TIMEOUT) as client:
        resp = await client.get(
            "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
        )
        resp.raise_for_status()
        data = resp.json()

    # Search for the IP in the blocklist
    found = None
    for entry in data:
        if entry.get("ip_address") == ip_address:
            found = entry
            break

    if not found:
        # Also try URLhaus for IP-based lookups
        return await _check_urlhaus_ip(ip_address)

    # Write IP node into Neo4j with threat intel metadata
    cypher = """
    MERGE (ip:IP {address: $address})
    ON CREATE SET ip.source       = 'feodo_tracker',
                  ip.enriched_at  = timestamp(),
                  ip.malware      = $malware,
                  ip.first_seen   = $first_seen,
                  ip.last_online  = $last_online,
                  ip.status       = $status
    RETURN ip.address AS addr
    """

    with _get_driver().session() as s:
        s.run(
            cypher,
            address=ip_address,
            malware=found.get("malware", "unknown"),
            first_seen=found.get("first_seen", ""),
            last_online=found.get("last_online", ""),
            status=found.get("status", ""),
        )

    logger.info("Enriched IP '%s' (malware=%s)", ip_address, found.get("malware"))
    return True


async def _check_urlhaus_ip(ip_address: str) -> bool:
    """
    Check URLhaus for URLs hosted on the given IP.
    Creates IP + Domain nodes if malicious URLs are found.

    URLhaus API: https://urlhaus-api.abuse.ch/v1/host/
    """
    async with httpx.AsyncClient(timeout=_API_TIMEOUT) as client:
        resp = await client.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": ip_address},
        )
        resp.raise_for_status()
        data = resp.json()

    if data.get("query_status") != "ok" or not data.get("urls"):
        return False

    # Write IP node + associated URLs/domains
    cypher = """
    MERGE (ip:IP {address: $address})
    ON CREATE SET ip.source       = 'urlhaus',
                  ip.enriched_at  = timestamp(),
                  ip.url_count    = $url_count
    RETURN ip.address AS addr
    """

    url_count = len(data.get("urls", []))
    with _get_driver().session() as s:
        s.run(cypher, address=ip_address, url_count=url_count)

    logger.info("Enriched IP '%s' from URLhaus (%d URLs)", ip_address, url_count)
    return True


# ── Domain enrichment (Abuse.ch URLhaus) ──────────────────────────────────────


async def _enrich_domain(domain_name: str) -> bool:
    """
    Check URLhaus for known malicious URLs on the given domain.
    Creates Domain node with threat metadata if found.

    URLhaus API: https://urlhaus-api.abuse.ch/v1/host/
    """
    logger.info("Enriching domain '%s' from URLhaus", domain_name)

    async with httpx.AsyncClient(timeout=_API_TIMEOUT) as client:
        resp = await client.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": domain_name},
        )
        resp.raise_for_status()
        data = resp.json()

    if data.get("query_status") != "ok" or not data.get("urls"):
        logger.info("URLhaus: domain '%s' not found", domain_name)
        return False

    urls = data.get("urls", [])

    # Write Domain node into Neo4j
    cypher = """
    MERGE (d:Domain {name: $name})
    ON CREATE SET d.source       = 'urlhaus',
                  d.enriched_at  = timestamp(),
                  d.url_count    = $url_count,
                  d.threat_types = $threat_types
    RETURN d.name AS name
    """

    # Collect unique threat types from the URLs
    threat_types = list({u.get("threat", "unknown") for u in urls if u.get("threat")})

    with _get_driver().session() as s:
        s.run(
            cypher,
            name=domain_name,
            url_count=len(urls),
            threat_types=threat_types,
        )

    logger.info(
        "Enriched domain '%s' from URLhaus (%d URLs, threats=%s)",
        domain_name, len(urls), threat_types,
    )
    return True


# ── Helper functions ──────────────────────────────────────────────────────────


def _extract_cve_id(osv_vuln: dict) -> str | None:
    """Extract CVE ID from an OSV vulnerability entry."""
    # Check aliases for a CVE ID
    for alias in osv_vuln.get("aliases", []):
        if alias.startswith("CVE-"):
            return alias
    # Some OSV entries use the ID field directly
    vuln_id = osv_vuln.get("id", "")
    if vuln_id.startswith("CVE-"):
        return vuln_id
    return None


def _extract_severity(osv_vuln: dict) -> tuple[str, float]:
    """Extract severity rating and CVSS score from an OSV entry."""
    severity_list = osv_vuln.get("severity", [])
    for sev in severity_list:
        if sev.get("type") == "CVSS_V3":
            score_str = sev.get("score", "")
            # CVSS vector string — extract base score if present
            try:
                # Try to parse as a float directly
                return _cvss_to_rating(float(score_str)), float(score_str)
            except (ValueError, TypeError):
                pass

    # Fallback: check database_specific for severity
    db_specific = osv_vuln.get("database_specific", {})
    severity = db_specific.get("severity", "UNKNOWN")
    return severity.upper(), 0.0


def _cvss_to_rating(score: float) -> str:
    """Convert a CVSS 3.x score to a severity rating string."""
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0.0:
        return "LOW"
    return "UNKNOWN"


def _extract_nvd_severity(cve_data: dict) -> tuple[str, float]:
    """Extract severity and CVSS score from NVD CVE response."""
    metrics = cve_data.get("metrics", {})

    # Try CVSS v3.1 first, then v3.0, then v2.0
    for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        metric_list = metrics.get(version_key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            score = cvss_data.get("baseScore", 0.0)
            severity = cvss_data.get("baseSeverity", _cvss_to_rating(score))
            return severity.upper(), score

    return "UNKNOWN", 0.0
