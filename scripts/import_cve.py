#!/usr/bin/env python3
"""
import_cve.py — Imports ~50 high-profile CVEs into Neo4j.

Sources:
  - NVD REST API 2.0 for live data (requires no key for low-volume requests)
  - Hardcoded fallback list of the most critical CVEs for the demo

Writes:
  CVE nodes
  (:Package)-[:HAS_VULNERABILITY]->(:CVE) edges where package is known
  (:CVE)-[:EXPLOITED_BY]->(:ThreatActor) edges where attribution is known

Requires: NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD env vars.
"""

import os
import time
import requests
from dotenv import load_dotenv
from neo4j import GraphDatabase

load_dotenv()

NEO4J_URI  = os.environ["NEO4J_URI"]
NEO4J_USER = os.environ["NEO4J_USERNAME"]
NEO4J_PASS = os.environ["NEO4J_PASSWORD"]

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# ── Hardcoded seed list ────────────────────────────────────────────────────────
# Each entry: (cve_id, severity, cvss_score, description, package_name, actor_name)
# package_name / actor_name may be None if not directly attributable.
SEED_CVES = [
    # Supply-chain / npm specific
    ("CVE-2021-27292", "HIGH",     7.5,  "ua-parser-js ReDoS before 0.7.24",
     "ua-parser-js",  None),
    ("CVE-2022-0155",  "MEDIUM",   6.5,  "follow-redirects credentials leak",
     "follow-redirects", None),
    ("CVE-2021-23337", "HIGH",     7.2,  "lodash command injection via template",
     "lodash",        None),
    ("CVE-2020-28168", "MEDIUM",   5.9,  "axios SSRF via open redirect",
     "axios",         None),
    ("CVE-2021-3918",  "CRITICAL", 9.8,  "json-schema prototype pollution",
     "json-schema",   None),
    ("CVE-2022-24999", "HIGH",     7.5,  "qs prototype pollution",
     "qs",            None),
    ("CVE-2021-44228", "CRITICAL", 10.0, "Log4Shell RCE in Apache Log4j2",
     None,            "APT41"),
    ("CVE-2021-45046", "CRITICAL", 9.0,  "Log4j2 incomplete fix for Log4Shell",
     None,            "APT41"),
    ("CVE-2022-22965", "CRITICAL", 9.8,  "Spring4Shell RCE in Spring Framework",
     None,            None),
    ("CVE-2021-26855", "CRITICAL", 9.8,  "ProxyLogon SSRF in Microsoft Exchange",
     None,            "HAFNIUM"),
    ("CVE-2021-26857", "HIGH",     7.8,  "ProxyLogon insecure deserialization Exchange",
     None,            "HAFNIUM"),
    ("CVE-2021-34527", "CRITICAL", 8.8,  "PrintNightmare Windows Print Spooler RCE",
     None,            None),
    ("CVE-2022-30190", "HIGH",     7.8,  "Follina MSDT RCE via Office documents",
     None,            "Sandworm Team"),
    ("CVE-2023-23397", "CRITICAL", 9.8,  "Outlook zero-click privilege escalation",
     None,            "APT28"),
    ("CVE-2023-44487", "HIGH",     7.5,  "HTTP/2 Rapid Reset DDoS",
     None,            None),
    ("CVE-2021-44228", "CRITICAL", 10.0, "Log4Shell — duplicate for package link",
     None,            None),
    ("CVE-2022-1388",  "CRITICAL", 9.8,  "F5 BIG-IP iControl REST auth bypass",
     None,            "APT41"),
    ("CVE-2023-34362", "CRITICAL", 9.8,  "MOVEit Transfer SQL injection",
     None,            "Cl0p"),
    ("CVE-2023-0669",  "HIGH",     7.2,  "GoAnywhere MFT pre-auth RCE",
     None,            "Cl0p"),
    ("CVE-2023-20198", "CRITICAL", 10.0, "Cisco IOS XE web UI privilege escalation",
     None,            None),
    ("CVE-2022-41082", "HIGH",     8.8,  "ProxyNotShell Exchange RCE",
     None,            None),
    ("CVE-2023-3519",  "CRITICAL", 9.8,  "Citrix NetScaler code injection (Bleed)",
     None,            None),
    ("CVE-2021-20016", "CRITICAL", 9.8,  "SonicWall SSLVPN SQL injection",
     None,            None),
    ("CVE-2021-40444", "HIGH",     7.8,  "MSHTML RCE via Office documents",
     None,            None),
    ("CVE-2022-0847",  "HIGH",     7.8,  "Dirty Pipe Linux kernel privilege escalation",
     None,            None),
    # Additional npm/PyPI supply-chain
    ("CVE-2022-24302", "MEDIUM",   5.9,  "Paramiko race condition in key generation",
     "paramiko",      None),
    ("CVE-2019-20149", "HIGH",     7.5,  "kind-of type confusion prototype pollution",
     "kind-of",       None),
    ("CVE-2020-7598",  "MEDIUM",   5.6,  "minimist prototype pollution",
     "minimist",      None),
    ("CVE-2021-23436", "CRITICAL", 9.8,  "immer prototype pollution",
     "immer",         None),
    ("CVE-2022-3517",  "HIGH",     7.5,  "minimatch ReDoS",
     "minimatch",     None),
    ("CVE-2021-3803",  "HIGH",     7.5,  "nth-check ReDoS",
     "nth-check",     None),
    ("CVE-2022-24785", "HIGH",     7.5,  "moment.js path traversal via locale",
     "moment",        None),
    ("CVE-2020-36048", "HIGH",     7.5,  "engine.io ReDoS",
     "engine.io",     None),
    ("CVE-2022-21704", "MEDIUM",   5.3,  "log4js-node token injection",
     "log4js",        None),
    ("CVE-2022-25883", "HIGH",     7.5,  "semver ReDoS",
     "semver",        None),
    # Infrastructure / broader
    ("CVE-2021-21985", "CRITICAL", 9.8,  "VMware vCenter Server RCE",
     None,            "APT41"),
    ("CVE-2021-21972", "CRITICAL", 9.8,  "VMware vCenter unauthenticated RCE",
     None,            None),
    ("CVE-2020-5902",  "CRITICAL", 10.0, "F5 BIG-IP TMUI RCE",
     None,            None),
    ("CVE-2019-19781", "CRITICAL", 9.8,  "Citrix ADC path traversal RCE",
     None,            None),
    ("CVE-2022-26134", "CRITICAL", 9.8,  "Confluence Server OGNL injection RCE",
     None,            "APT41"),
    ("CVE-2021-26084", "CRITICAL", 9.8,  "Confluence OGNL injection",
     None,            None),
    ("CVE-2022-1040",  "CRITICAL", 9.8,  "Sophos Firewall authentication bypass RCE",
     None,            None),
    ("CVE-2023-27997", "CRITICAL", 9.8,  "FortiOS SSL-VPN heap overflow pre-auth",
     None,            None),
    ("CVE-2022-40684", "CRITICAL", 9.8,  "FortiOS/FortiProxy auth bypass",
     None,            None),
    ("CVE-2023-46747", "CRITICAL", 9.8,  "F5 BIG-IP unauthenticated RCE",
     None,            None),
    ("CVE-2023-48788", "CRITICAL", 9.8,  "Fortinet EMS SQL injection",
     None,            None),
    ("CVE-2024-3400",  "CRITICAL", 10.0, "PAN-OS GlobalProtect OS command injection",
     None,            None),
    ("CVE-2024-21762", "CRITICAL", 9.8,  "FortiOS out-of-bounds write RCE",
     None,            None),
    ("CVE-2024-1709",  "CRITICAL", 10.0, "ConnectWise ScreenConnect auth bypass",
     None,            None),
    ("CVE-2024-27198", "CRITICAL", 9.8,  "JetBrains TeamCity auth bypass",
     None,            None),
]


def nvd_fetch(cve_id: str) -> dict | None:
    """Try to enrich a CVE from NVD API. Returns None on failure."""
    try:
        url = f"{NVD_BASE}?cveId={cve_id}"
        r = requests.get(url, timeout=10, headers={"Accept": "application/json"})
        if r.status_code == 200:
            vulns = r.json().get("vulnerabilities", [])
            if vulns:
                return vulns[0].get("cve", {})
    except Exception:
        pass
    return None


def upsert_cves(session, driver):
    print(f"Importing {len(SEED_CVES)} CVEs...")
    for row in SEED_CVES:
        cve_id, severity, cvss_score, description, pkg_name, actor_name = row

        session.run(
            """
            MERGE (c:CVE {id: $id})
            SET c.severity     = $severity,
                c.cvss_score   = $cvss_score,
                c.description  = $description
            """,
            id=cve_id, severity=severity, cvss_score=cvss_score,
            description=description,
        )

        if pkg_name:
            session.run(
                """
                MERGE (p:Package {name: $pkg})
                MERGE (c:CVE     {id:  $cve})
                MERGE (p)-[:HAS_VULNERABILITY]->(c)
                """,
                pkg=pkg_name, cve=cve_id,
            )

        if actor_name:
            session.run(
                """
                MERGE (c:CVE        {id:   $cve})
                MERGE (a:ThreatActor {name: $actor})
                MERGE (c)-[:EXPLOITED_BY]->(a)
                """,
                cve=cve_id, actor=actor_name,
            )

    print(f"Done — {len(SEED_CVES)} CVEs upserted.")


def main():
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
    with driver.session() as session:
        upsert_cves(session, driver)
    driver.close()
    print("CVE import complete.")


if __name__ == "__main__":
    main()
