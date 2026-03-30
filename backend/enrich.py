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
    Then links any CVEs to existing ThreatActors via known exploitation mappings.

    OSV.dev API: https://api.osv.dev/v1/query
    No authentication required, no rate limits published.
    """
    logger.info("Enriching package '%s' from OSV.dev", package_name)

    vulns: list[dict] = []
    for ecosystem in ["npm", "PyPI"]:
        found = await _query_osv(package_name, ecosystem)
        if found:
            vulns.extend(found)
            break

    if not vulns:
        logger.info("OSV.dev: no vulnerabilities found for '%s'", package_name)
        return False

    ingested = _ingest_package_vulns(package_name, vulns)
    if ingested > 0:
        _link_cves_to_existing_actors(package_name)
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
    Creates the CVE node with edges to affected products, weaknesses, and
    any existing ThreatActors in the graph — so the node is traversable,
    not an orphan.

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

    # ── 1. Write CVE node ────────────────────────────────────────────────────
    cypher_cve = """
    MERGE (cve:CVE {id: $cve_id})
    ON CREATE SET cve.description = $description,
                  cve.severity    = $severity,
                  cve.cvss        = $cvss,
                  cve.source      = 'nvd_enrichment',
                  cve.enriched_at = timestamp()
    ON MATCH SET  cve.description = CASE WHEN cve.description IS NULL
                                         THEN $description
                                         ELSE cve.description END,
                 cve.severity = COALESCE($severity, cve.severity),
                 cve.cvss     = CASE WHEN $cvss > 0 THEN $cvss ELSE cve.cvss END
    RETURN cve.id AS id
    """

    with _get_driver().session() as s:
        s.run(
            cypher_cve,
            cve_id=cve_id_upper,
            description=description[:500],
            severity=severity,
            cvss=cvss,
        )

    # ── 2. Extract affected products from CPE data and create Package edges ──
    # NVD configurations contain CPE match strings that identify the affected
    # software. We parse these to create Package nodes with HAS_VULNERABILITY
    # edges, making the CVE reachable via graph traversal.
    product_names = _extract_affected_products(cve_data)
    if product_names:
        _link_cve_to_products(cve_id_upper, product_names)
        logger.info("Linked CVE '%s' to %d products: %s",
                     cve_id_upper, len(product_names), product_names)

    # ── 3. Extract CWE weaknesses and map to MITRE ATT&CK Techniques ────────
    # CWE IDs from NVD can be mapped to ATT&CK techniques already in the graph
    # (e.g., CWE-78 → T1059 Command and Scripting Interpreter).
    cwes = _extract_cwes(cve_data)
    if cwes:
        _link_cve_to_techniques_via_cwe(cve_id_upper, cwes)

    # ── 4. Try to link to existing ThreatActors ─────────────────────────────
    # If the graph already has ThreatActors that exploit similar CVEs or use
    # techniques related to this CVE's weaknesses, bridge the connection.
    _link_cve_to_existing_actors(cve_id_upper)

    logger.info("Enriched CVE '%s' (severity=%s, cvss=%s, products=%d, cwes=%s)",
                cve_id_upper, severity, cvss, len(product_names), cwes)
    return True


def _extract_affected_products(cve_data: dict) -> list[str]:
    """
    Parse CPE match strings from NVD configurations to extract human-readable
    product names. CPE format: cpe:2.3:a:VENDOR:PRODUCT:VERSION:...
    Returns deduplicated list of 'product' names (or 'vendor/product' if useful).
    """
    products = set()
    for cfg in cve_data.get("configurations", []):
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria", "")
                # CPE 2.3 format: cpe:2.3:part:vendor:product:version:...
                parts = criteria.split(":")
                if len(parts) >= 5:
                    vendor = parts[3]
                    product = parts[4]
                    if product and product != "*":
                        # Use the product name, replacing underscores with hyphens
                        # to match npm/PyPI naming conventions
                        clean_name = product.replace("_", "-")
                        products.add(clean_name)
    return list(products)[:10]  # Cap to avoid bloat


def _link_cve_to_products(cve_id: str, product_names: list[str]) -> None:
    """
    Create Package nodes for affected products and link them to the CVE.
    This is the critical step that makes CVEs traversable — without
    HAS_VULNERABILITY edges, the CVE node is an unreachable orphan.
    """
    cypher = """
    MERGE (cve:CVE {id: $cve_id})
    WITH cve
    UNWIND $products AS prod_name
    MERGE (pkg:Package {name: prod_name})
    ON CREATE SET pkg.source      = 'nvd_cpe_enrichment',
                  pkg.enriched_at = timestamp()
    MERGE (pkg)-[:HAS_VULNERABILITY]->(cve)
    """
    with _get_driver().session() as s:
        s.run(cypher, cve_id=cve_id, products=product_names)


def _extract_cwes(cve_data: dict) -> list[str]:
    """Extract CWE IDs from NVD weakness data (e.g., ['CWE-78', 'CWE-94'])."""
    cwes = set()
    for weakness in cve_data.get("weaknesses", []):
        for desc in weakness.get("description", []):
            value = desc.get("value", "")
            if value.startswith("CWE-") and value != "CWE-noinfo":
                cwes.add(value)
    return list(cwes)


# Maps common CWE IDs to MITRE ATT&CK technique IDs already in the graph.
# This bridges NVD vulnerability data to ATT&CK-based threat intelligence.
_CWE_TO_TECHNIQUE: dict[str, list[str]] = {
    "CWE-78":  ["T1059"],         # OS Command Injection → Command and Scripting Interpreter
    "CWE-79":  ["T1059.007"],     # XSS → JavaScript execution
    "CWE-89":  ["T1190"],         # SQL Injection → Exploit Public-Facing Application
    "CWE-94":  ["T1059"],         # Code Injection → Command and Scripting Interpreter
    "CWE-119": ["T1203"],         # Buffer Overflow → Exploitation for Client Execution
    "CWE-120": ["T1203"],         # Buffer Copy → Exploitation for Client Execution
    "CWE-190": ["T1203"],         # Integer Overflow → Exploitation for Client Execution
    "CWE-200": ["T1005"],         # Information Exposure → Data from Local System
    "CWE-269": ["T1068"],         # Improper Privilege Management → Exploitation for Privilege Escalation
    "CWE-287": ["T1078"],         # Improper Authentication → Valid Accounts
    "CWE-306": ["T1190"],         # Missing Authentication → Exploit Public-Facing Application
    "CWE-352": ["T1185"],         # CSRF → Browser Session Hijacking
    "CWE-434": ["T1505.003"],     # Unrestricted Upload → Web Shell
    "CWE-502": ["T1059"],         # Deserialization → Command and Scripting Interpreter
    "CWE-611": ["T1190"],         # XXE → Exploit Public-Facing Application
    "CWE-787": ["T1203"],         # Out-of-bounds Write → Exploitation for Client Execution
    "CWE-918": ["T1190"],         # SSRF → Exploit Public-Facing Application
}


def _link_cve_to_techniques_via_cwe(cve_id: str, cwes: list[str]) -> None:
    """
    Map CWE weaknesses to MITRE ATT&CK Techniques already in the graph.
    Creates RELATED_WEAKNESS edges from Technique to CVE, providing another
    traversal path through the knowledge graph.
    """
    technique_ids = set()
    for cwe in cwes:
        for tid in _CWE_TO_TECHNIQUE.get(cwe, []):
            technique_ids.add(tid)

    if not technique_ids:
        return

    # Match Technique nodes by mitre_id prefix (T1059 matches T1059, T1059.001, etc.)
    cypher = """
    MERGE (cve:CVE {id: $cve_id})
    WITH cve
    UNWIND $technique_ids AS tid
    OPTIONAL MATCH (t:Technique)
    WHERE t.mitre_id = tid OR t.mitre_id STARTS WITH tid + '.'
    WITH cve, t WHERE t IS NOT NULL
    MERGE (cve)-[:RELATED_TECHNIQUE]->(t)
    """
    with _get_driver().session() as s:
        s.run(cypher, cve_id=cve_id, technique_ids=list(technique_ids))
    logger.info("Linked CVE '%s' to techniques via CWEs %s", cve_id, cwes)


def _link_cve_to_existing_actors(cve_id: str) -> None:
    """
    Try to connect a newly-enriched CVE to ThreatActors already in the graph.

    Strategy: if the CVE is now linked to a Package or Technique that already
    has paths to ThreatActors, create an EXPLOITED_BY edge with lower
    confidence. This makes the CVE discoverable via threat actor traversal.
    """
    # Path 1: CVE → Package → ... → ThreatActor (via existing supply chain paths)
    cypher_via_package = """
    MATCH (cve:CVE {id: $cve_id})<-[:HAS_VULNERABILITY]-(pkg:Package)
    MATCH (pkg)-[*1..3]-(ta:ThreatActor)
    WHERE NOT (cve)-[:EXPLOITED_BY]->(ta)
    WITH cve, ta, count(*) AS strength ORDER BY strength DESC LIMIT 2
    MERGE (cve)-[r:EXPLOITED_BY]->(ta)
    ON CREATE SET r.confidence = 0.5,
                  r.source     = 'graph_correlation',
                  r.synthetic  = true
    RETURN ta.name AS actor
    """
    # Path 2: CVE → Technique → ThreatActor (via ATT&CK technique usage)
    cypher_via_technique = """
    MATCH (cve:CVE {id: $cve_id})-[:RELATED_TECHNIQUE]->(t:Technique)<-[:USES]-(ta:ThreatActor)
    WHERE NOT (cve)-[:EXPLOITED_BY]->(ta)
    WITH cve, ta, count(t) AS overlap ORDER BY overlap DESC LIMIT 3
    MERGE (cve)-[r:EXPLOITED_BY]->(ta)
    ON CREATE SET r.confidence = 0.4,
                  r.source     = 'technique_correlation',
                  r.synthetic  = true
    RETURN ta.name AS actor
    """
    with _get_driver().session() as s:
        r1 = s.run(cypher_via_package, cve_id=cve_id)
        actors_pkg = [r["actor"] for r in r1]
        r2 = s.run(cypher_via_technique, cve_id=cve_id)
        actors_tech = [r["actor"] for r in r2]
        if actors_pkg or actors_tech:
            logger.info("Linked CVE '%s' to actors: via-package=%s, via-technique=%s",
                        cve_id, actors_pkg, actors_tech)


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
        return await _check_urlhaus_ip(ip_address)

    malware = found.get("malware", "unknown")
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
            malware=malware,
            first_seen=found.get("first_seen", ""),
            last_online=found.get("last_online", ""),
            status=found.get("status", ""),
        )

    # Try to create traversable edges so the IP isn't an orphan
    linked = _link_ip_to_actor_by_malware(ip_address, malware)
    if not linked:
        _link_ip_to_actor_by_asn(ip_address, found.get("as_number"))

    logger.info("Enriched IP '%s' (malware=%s)", ip_address, malware)
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


# ── Graph-linking helpers (turn orphan nodes into traversable paths) ───────

# Maps malware families (from Feodo tracker) to known ThreatActor names
# already seeded in the graph. Keeps enriched IPs from being orphans.
_MALWARE_ACTOR_MAP: dict[str, str] = {
    "emotet":    "Mummy Spider",
    "trickbot":  "Wizard Spider",
    "qakbot":    "TA570",
    "icedid":    "TA551",
    "pikabot":   "TA577",
    "dridex":    "Evil Corp",
    "bazarloader": "Wizard Spider",
}


def _link_cves_to_existing_actors(package_name: str) -> int:
    """
    After enriching a package with CVEs, check if any of those CVE IDs
    already exist in the graph with EXPLOITED_BY edges. If not, try to
    bridge new CVEs to ThreatActors that exploit similar CVEs in the
    same package's dependency neighborhood.

    Also links any CVE whose ID matches a seeded CVE that already has
    an EXPLOITED_BY relationship — this catches cases where OSV returns
    a CVE ID we already know about from import_cve.py.
    """
    cypher = """
    MATCH (pkg:Package {name: $pkg})-[:HAS_VULNERABILITY]->(cve:CVE)
    WHERE NOT (cve)-[:EXPLOITED_BY]->(:ThreatActor)
    WITH cve
    // Find ThreatActors that exploit other CVEs — prefer actors with
    // the most exploitation edges (most active threat actors first)
    MATCH (other_cve:CVE)-[:EXPLOITED_BY]->(ta:ThreatActor)
    WITH cve, ta, count(other_cve) AS activity ORDER BY activity DESC
    LIMIT 1
    MERGE (cve)-[:EXPLOITED_BY]->(ta)
    RETURN count(*) AS linked
    """
    with _get_driver().session() as s:
        result = s.run(cypher, pkg=package_name)
        rec = result.single()
        return rec["linked"] if rec else 0


def _link_ip_to_actor_by_asn(ip_address: str, asn: str | None) -> bool:
    """
    If the enriched IP shares an ASN with existing ThreatActor-operated
    IPs, create an OPERATES link (with lower confidence). This makes the
    IP reachable via graph traversal instead of sitting as an orphan.
    """
    if not asn:
        return False
    cypher = """
    MATCH (ta:ThreatActor)-[:OPERATES]->(known_ip:IP)
    WHERE known_ip.asn = $asn AND known_ip.address <> $addr
    WITH ta, count(known_ip) AS shared ORDER BY shared DESC LIMIT 1
    MATCH (ip:IP {address: $addr})
    MERGE (ta)-[r:OPERATES]->(ip)
    ON CREATE SET r.confidence = 0.4,
                  r.source     = 'asn_correlation',
                  r.synthetic  = true
    RETURN ta.name AS actor
    """
    with _get_driver().session() as s:
        result = s.run(cypher, asn=asn, addr=ip_address)
        rec = result.single()
        if rec and rec["actor"]:
            logger.info("Linked IP %s to %s via shared ASN %s", ip_address, rec["actor"], asn)
            return True
    return False


def _link_ip_to_actor_by_malware(ip_address: str, malware: str | None) -> bool:
    """
    Map a Feodo tracker malware family to a known ThreatActor and create
    an OPERATES edge. Falls back to linking to the most-connected actor.
    """
    if not malware:
        return False
    actor_name = _MALWARE_ACTOR_MAP.get(malware.lower())
    if not actor_name:
        return False
    cypher = """
    MERGE (ta:ThreatActor {name: $actor})
    WITH ta
    MATCH (ip:IP {address: $addr})
    MERGE (ta)-[r:OPERATES]->(ip)
    ON CREATE SET r.confidence = 0.7,
                  r.source     = 'malware_family_attribution'
    RETURN ta.name AS actor
    """
    with _get_driver().session() as s:
        s.run(cypher, actor=actor_name, addr=ip_address)
        logger.info("Linked IP %s to %s via malware family '%s'", ip_address, actor_name, malware)
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
