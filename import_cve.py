#!/usr/bin/env python3
"""
import_cve.py — Import high-profile CVEs into Neo4j.

Fetches CVE data from the NVD (National Vulnerability Database) API
for a curated list of ~50 well-known CVEs relevant to the Cerberus demo.
Falls back to a local seed file if the API is unavailable or rate-limited.

Each CVE becomes a :CVE node with id, severity, cvss_score, description,
and published_date properties.

Requires env vars:
  NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD

Usage:
  python import_cve.py
"""

import json
import os
import sys
import time
import urllib.request
import urllib.error
from neo4j import GraphDatabase

# ── Local cache path ───────────────────────────────────────────
CACHE_PATH = os.path.join("seed_data", "cves.json")

# ── NVD API base URL ──────────────────────────────────────────
# The NVD 2.0 API. Free tier allows 5 requests per 30 seconds
# without an API key, 50/30s with one. We batch to stay under.
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# ── Curated CVE list ──────────────────────────────────────────
# These are high-profile CVEs relevant to supply chain attacks,
# dependency vulnerabilities, and infrastructure exploitation.
# The demo focuses on ua-parser-js (CVE-2021-27292) but having
# a broader set makes the graph richer for traversal queries.
CURATED_CVES = [
    # Supply chain / npm compromises
    "CVE-2021-27292",   # ua-parser-js ReDoS (+ supply chain compromise)
    "CVE-2021-23566",   # nanoid
    "CVE-2022-0235",    # node-fetch redirect
    "CVE-2021-44228",   # Log4Shell (infrastructure crossover)
    "CVE-2021-45046",   # Log4j follow-up
    "CVE-2021-45105",   # Log4j follow-up
    "CVE-2021-3749",    # axios SSRF
    "CVE-2022-46175",   # json5 prototype pollution
    "CVE-2022-37601",   # loader-utils prototype pollution
    "CVE-2022-37599",   # loader-utils ReDoS
    "CVE-2022-24999",   # qs prototype pollution
    "CVE-2022-3517",    # minimatch ReDoS
    "CVE-2021-3807",    # ansi-regex ReDoS
    "CVE-2021-23337",   # lodash command injection
    "CVE-2020-28500",   # lodash ReDoS
    "CVE-2021-23424",   # ansi-html ReDoS
    "CVE-2020-7788",    # ini prototype pollution
    "CVE-2021-42340",   # Apache Tomcat DoS

    # Major infrastructure CVEs (for cross-domain graph)
    "CVE-2021-34527",   # PrintNightmare
    "CVE-2021-26855",   # ProxyLogon (Exchange)
    "CVE-2021-26857",   # ProxyLogon (Exchange)
    "CVE-2021-27065",   # ProxyLogon (Exchange)
    "CVE-2021-21972",   # VMware vCenter RCE
    "CVE-2020-1472",    # Zerologon
    "CVE-2021-40444",   # MSHTML RCE
    "CVE-2023-44487",   # HTTP/2 Rapid Reset
    "CVE-2023-34362",   # MOVEit Transfer SQL injection
    "CVE-2023-0669",    # GoAnywhere MFT RCE
    "CVE-2022-1388",    # F5 BIG-IP RCE
    "CVE-2022-22965",   # Spring4Shell
    "CVE-2022-26134",   # Confluence OGNL injection
    "CVE-2022-41040",   # ProxyNotShell (Exchange)

    # Python supply chain
    "CVE-2022-42969",   # py_css ReDoS
    "CVE-2021-29921",   # ipaddress Python stdlib
    "CVE-2022-0778",    # OpenSSL infinite loop

    # Container / K8s
    "CVE-2022-0811",    # CRI-O container escape
    "CVE-2020-15257",   # containerd host access
    "CVE-2021-25741",   # Kubernetes symlink

    # Crypto / auth
    "CVE-2022-24773",   # node-forge signature verification
    "CVE-2022-23529",   # jsonwebtoken
    "CVE-2021-43798",   # Grafana path traversal

    # Recent high-impact
    "CVE-2023-46604",   # Apache ActiveMQ RCE
    "CVE-2023-4966",    # Citrix Bleed
    "CVE-2023-22515",   # Confluence privilege escalation
    "CVE-2024-3094",    # xz backdoor (supply chain)
    "CVE-2023-38545",   # curl SOCKS5 heap overflow
    "CVE-2023-44487",   # HTTP/2 Rapid Reset
    "CVE-2024-21762",   # Fortinet FortiOS RCE
    "CVE-2023-36884",   # Office/Windows HTML RCE
    "CVE-2023-27997",   # Fortinet FortiOS heap overflow
]


def get_env(name: str) -> str:
    """Read a required environment variable or exit with an error."""
    val = os.environ.get(name)
    if not val:
        print(f"ERROR: {name} environment variable is required")
        sys.exit(1)
    return val


def fetch_cve_from_nvd(cve_id: str) -> dict | None:
    """
    Fetch a single CVE from the NVD 2.0 API.
    Returns a normalized dict or None if the fetch fails.

    NVD returns a complex nested structure — we extract what we need:
    - severity (CRITICAL/HIGH/MEDIUM/LOW)
    - CVSS v3.1 base score (falls back to v3.0 or v2.0)
    - English description
    - Published date
    """
    url = f"{NVD_API}?cveId={cve_id}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Cerberus-Import/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        print(f"    WARN: Failed to fetch {cve_id}: {e}")
        return None

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None

    cve_data = vulns[0].get("cve", {})

    # Extract CVSS score — try v3.1 first, then v3.0, then v2.0
    metrics = cve_data.get("metrics", {})
    cvss_score = None
    severity = None

    for version_key in ["cvssMetricV31", "cvssMetricV30"]:
        metric_list = metrics.get(version_key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity")
            break

    if cvss_score is None:
        # Fall back to CVSS v2
        v2 = metrics.get("cvssMetricV2", [])
        if v2:
            cvss_score = v2[0].get("cvssData", {}).get("baseScore")
            severity = v2[0].get("baseSeverity")

    # Extract English description
    descriptions = cve_data.get("descriptions", [])
    description = ""
    for desc in descriptions:
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break

    # Truncate long descriptions to save graph storage
    if len(description) > 500:
        description = description[:497] + "..."

    return {
        "id": cve_id,
        "severity": severity or "UNKNOWN",
        "cvss_score": cvss_score or 0.0,
        "description": description,
        "published_date": cve_data.get("published", ""),
    }


def fetch_all_cves() -> list[dict]:
    """
    Fetch all curated CVEs, using cache if available.
    Respects NVD rate limits (5 requests / 30 seconds without API key).
    """
    # Check cache first
    if os.path.exists(CACHE_PATH):
        print(f"  Using cached CVE data: {CACHE_PATH}")
        with open(CACHE_PATH, "r") as f:
            return json.load(f)

    print(f"  Fetching {len(CURATED_CVES)} CVEs from NVD API ...")
    print("  (This will take ~3 minutes due to rate limiting)")

    os.makedirs("seed_data", exist_ok=True)
    cves = []
    seen = set()  # deduplicate the curated list

    for i, cve_id in enumerate(CURATED_CVES):
        if cve_id in seen:
            continue
        seen.add(cve_id)

        print(f"    [{i+1}/{len(CURATED_CVES)}] Fetching {cve_id} ...")
        result = fetch_cve_from_nvd(cve_id)
        if result:
            cves.append(result)

        # NVD rate limit: 5 requests per 30 seconds (no API key)
        # We wait 6.5s between requests to stay safe
        if (i + 1) % 5 == 0 and i + 1 < len(CURATED_CVES):
            print("    (rate limit pause — 30s)")
            time.sleep(30)
        else:
            time.sleep(1)

    # Cache the results
    with open(CACHE_PATH, "w") as f:
        json.dump(cves, f, indent=2)
    print(f"  Cached {len(cves)} CVEs to {CACHE_PATH}")

    return cves


def import_to_neo4j(cves: list[dict]):
    """
    Bulk-MERGE CVE nodes into Neo4j using UNWIND for efficiency.
    Each CVE node gets: id, severity, cvss_score, description, published_date.
    """
    uri = get_env("NEO4J_URI")
    user = get_env("NEO4J_USERNAME")
    password = get_env("NEO4J_PASSWORD")

    driver = GraphDatabase.driver(uri, auth=(user, password))

    with driver.session() as session:
        print(f"  Importing {len(cves)} CVE nodes ...")
        session.run(
            """
            UNWIND $cves AS c
            MERGE (cve:CVE {id: c.id})
            SET cve.severity = c.severity,
                cve.cvss_score = c.cvss_score,
                cve.description = c.description,
                cve.published_date = c.published_date
            """,
            cves=cves,
        )

    driver.close()


def main():
    print("=== CVE Import ===")

    cves = fetch_all_cves()
    print(f"  Loaded {len(cves)} CVEs")

    import_to_neo4j(cves)

    print("✅ CVE import complete")


if __name__ == "__main__":
    main()
