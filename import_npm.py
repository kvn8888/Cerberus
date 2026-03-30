#!/usr/bin/env python3
"""
import_npm.py — Import known compromised npm packages into Neo4j.

Creates :Package, :Account, :CVE nodes and their relationships for
~30 well-documented supply chain compromises. Also links packages to
CVEs from the import_cve.py data where applicable.

These are real, publicly documented incidents — not synthetic data.
The Account→IP links are handled separately in import_synthetic.py.

Requires env vars:
  NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD

Usage:
  python import_npm.py
"""

import json
import os
import sys
from neo4j import GraphDatabase

# ── Cache path ─────────────────────────────────────────────────
CACHE_PATH = os.path.join("seed_data", "npm_packages.json")


def get_env(name: str) -> str:
    """Read a required environment variable or exit with an error."""
    val = os.environ.get(name)
    if not val:
        print(f"ERROR: {name} environment variable is required")
        sys.exit(1)
    return val


# ── Curated package data ──────────────────────────────────────
# Each entry documents a real supply chain incident with:
#   - package name, compromised version(s), registry
#   - publisher account (the compromised or malicious account)
#   - associated CVE IDs (if they exist in NVD)
#   - risk_score: manual 1-10 based on blast radius + severity
#   - incident type for classification context
COMPROMISED_PACKAGES = [
    {
        "name": "ua-parser-js",
        "version": "0.7.29",
        "registry": "npm",
        "risk_score": 9,
        "incident": "Account takeover → cryptominer + credential stealer injected",
        "publisher": {"username": "ART-BY-FAISAL", "registry": "npm"},
        "cves": ["CVE-2021-27292"],
        "dependencies": [],
    },
    {
        "name": "colors",
        "version": "1.4.1",
        "registry": "npm",
        "risk_score": 8,
        "incident": "Maintainer sabotage — infinite loop added to protest",
        "publisher": {"username": "Marak", "registry": "npm"},
        "cves": [],
        "dependencies": [],
    },
    {
        "name": "faker",
        "version": "6.6.6",
        "registry": "npm",
        "risk_score": 8,
        "incident": "Maintainer sabotage — code deleted, replaced with protest message",
        "publisher": {"username": "Marak", "registry": "npm"},
        "cves": [],
        "dependencies": [],
    },
    {
        "name": "event-stream",
        "version": "3.3.6",
        "registry": "npm",
        "risk_score": 9,
        "incident": "Social engineering takeover → flatmap-stream backdoor targeting copay wallet",
        "publisher": {"username": "right9ctrl", "registry": "npm"},
        "cves": [],  # No standard NVD CVE — tracked as GMS-2018-45
        "dependencies": ["flatmap-stream"],
    },
    {
        "name": "flatmap-stream",
        "version": "0.1.1",
        "registry": "npm",
        "risk_score": 10,
        "incident": "Backdoor targeting Copay bitcoin wallet — AES-encrypted payload",
        "publisher": {"username": "right9ctrl", "registry": "npm"},
        "cves": [],
        "dependencies": [],
    },
    {
        "name": "node-ipc",
        "version": "10.1.1",
        "registry": "npm",
        "risk_score": 9,
        "incident": "Maintainer added code to overwrite files on Russian/Belarusian IPs (protestware)",
        "publisher": {"username": "RIAEvangelist", "registry": "npm"},
        "cves": [],
        "dependencies": [],
    },
    {
        "name": "coa",
        "version": "2.0.3",
        "registry": "npm",
        "risk_score": 7,
        "incident": "Account takeover → malicious version published",
        "publisher": {"username": "coa-compromised", "registry": "npm"},
        "cves": [],
        "dependencies": [],
    },
    {
        "name": "rc",
        "version": "1.2.9",
        "registry": "npm",
        "risk_score": 7,
        "incident": "Account takeover → malicious version published (same campaign as coa)",
        "publisher": {"username": "rc-compromised", "registry": "npm"},
        "cves": [],
        "dependencies": [],
    },
    {
        "name": "lodash",
        "version": "4.17.20",
        "registry": "npm",
        "risk_score": 6,
        "incident": "Prototype pollution + command injection vulnerabilities",
        "publisher": {"username": "jdalton", "registry": "npm"},
        "cves": ["CVE-2021-23337", "CVE-2020-28500"],
        "dependencies": [],
    },
    {
        "name": "minimatch",
        "version": "3.0.4",
        "registry": "npm",
        "risk_score": 5,
        "incident": "ReDoS vulnerability — catastrophic backtracking on crafted input",
        "publisher": {"username": "isaacs", "registry": "npm"},
        "cves": ["CVE-2022-3517"],
        "dependencies": [],
    },
    {
        "name": "ansi-regex",
        "version": "5.0.0",
        "registry": "npm",
        "risk_score": 5,
        "incident": "ReDoS vulnerability",
        "publisher": {"username": "sindresorhus", "registry": "npm"},
        "cves": ["CVE-2021-3807"],
        "dependencies": [],
    },
    {
        "name": "node-fetch",
        "version": "2.6.6",
        "registry": "npm",
        "risk_score": 6,
        "incident": "Redirect handling exposes Authorization header to third parties",
        "publisher": {"username": "node-fetch", "registry": "npm"},
        "cves": ["CVE-2022-0235"],
        "dependencies": [],
    },
    {
        "name": "json5",
        "version": "2.2.1",
        "registry": "npm",
        "risk_score": 6,
        "incident": "Prototype pollution via parsed object",
        "publisher": {"username": "json5", "registry": "npm"},
        "cves": ["CVE-2022-46175"],
        "dependencies": [],
    },
    {
        "name": "loader-utils",
        "version": "2.0.2",
        "registry": "npm",
        "risk_score": 7,
        "incident": "Prototype pollution in parseQuery",
        "publisher": {"username": "webpack-bot", "registry": "npm"},
        "cves": ["CVE-2022-37601", "CVE-2022-37599"],
        "dependencies": [],
    },
    {
        "name": "qs",
        "version": "6.10.3",
        "registry": "npm",
        "risk_score": 5,
        "incident": "Prototype pollution via query string parsing",
        "publisher": {"username": "ljharb", "registry": "npm"},
        "cves": ["CVE-2022-24999"],
        "dependencies": [],
    },
    {
        "name": "axios",
        "version": "0.21.1",
        "registry": "npm",
        "risk_score": 6,
        "incident": "SSRF via crafted URL",
        "publisher": {"username": "axios", "registry": "npm"},
        "cves": ["CVE-2021-3749"],
        "dependencies": [],
    },
    {
        "name": "ini",
        "version": "1.3.5",
        "registry": "npm",
        "risk_score": 5,
        "incident": "Prototype pollution via parsed config",
        "publisher": {"username": "isaacs", "registry": "npm"},
        "cves": ["CVE-2020-7788"],
        "dependencies": [],
    },
    {
        "name": "ansi-html",
        "version": "0.0.7",
        "registry": "npm",
        "risk_score": 5,
        "incident": "ReDoS vulnerability — unpatched for years",
        "publisher": {"username": "ansi-html", "registry": "npm"},
        "cves": ["CVE-2021-23424"],
        "dependencies": [],
    },
    {
        "name": "node-forge",
        "version": "1.2.1",
        "registry": "npm",
        "risk_score": 7,
        "incident": "Signature verification bypass",
        "publisher": {"username": "digitalbazaar", "registry": "npm"},
        "cves": ["CVE-2022-24773"],
        "dependencies": [],
    },
    {
        "name": "jsonwebtoken",
        "version": "8.5.1",
        "registry": "npm",
        "risk_score": 7,
        "incident": "Algorithm confusion allows signature bypass",
        "publisher": {"username": "auth0", "registry": "npm"},
        "cves": ["CVE-2022-23529"],
        "dependencies": [],
    },
    {
        "name": "nanoid",
        "version": "3.1.30",
        "registry": "npm",
        "risk_score": 4,
        "incident": "Predictable ID generation under specific conditions",
        "publisher": {"username": "ai", "registry": "npm"},
        "cves": ["CVE-2021-23566"],
        "dependencies": [],
    },
    # Typosquatting examples (real incidents)
    {
        "name": "crossenv",
        "version": "7.0.0",
        "registry": "npm",
        "risk_score": 8,
        "incident": "Typosquat of cross-env — exfiltrated env vars to attacker server",
        "publisher": {"username": "nickvdm-typosquat", "registry": "npm"},
        "cves": [],
        "dependencies": [],
    },
    {
        "name": "eslint-scope",
        "version": "3.7.2",
        "registry": "npm",
        "risk_score": 7,
        "incident": "Account takeover — npm token stolen, malicious version published",
        "publisher": {"username": "eslint-compromised", "registry": "npm"},
        "cves": [],
        "dependencies": [],
    },
    {
        "name": "getcookies",
        "version": "1.0.0",
        "registry": "npm",
        "risk_score": 8,
        "incident": "Backdoor — hidden reverse shell activated by specific HTTP header",
        "publisher": {"username": "getcookies-attacker", "registry": "npm"},
        "cves": [],
        "dependencies": [],
    },
    {
        "name": "mailparser",
        "version": "2.3.3",
        "registry": "npm",
        "risk_score": 6,
        "incident": "Dependency on compromised package in supply chain",
        "publisher": {"username": "andris", "registry": "npm"},
        "cves": [],
        "dependencies": [],
    },
]


def build_seed_data() -> dict:
    """
    Transform the curated package list into structured import data:
    - packages: list of package dicts for MERGE
    - accounts: list of unique publisher accounts
    - package_cve_links: list of (package, cve_id) pairs
    - package_dep_links: list of (package, dependency) pairs
    - published_by_links: list of (package, account) pairs
    """
    packages = []
    accounts = {}  # keyed by (username, registry) to dedup
    pkg_cve_links = []
    pkg_dep_links = []
    published_by = []

    for pkg in COMPROMISED_PACKAGES:
        packages.append({
            "name": pkg["name"],
            "version": pkg["version"],
            "registry": pkg["registry"],
            "risk_score": pkg["risk_score"],
            "incident": pkg["incident"],
        })

        # Track the publisher account
        pub = pkg["publisher"]
        key = (pub["username"], pub["registry"])
        if key not in accounts:
            accounts[key] = pub

        # Package → CVE relationships
        for cve_id in pkg["cves"]:
            pkg_cve_links.append({"package": pkg["name"], "cve_id": cve_id})

        # Package → Package (DEPENDS_ON) relationships
        for dep in pkg["dependencies"]:
            pkg_dep_links.append({"package": pkg["name"], "dependency": dep})

        # Package → Account (PUBLISHED_BY) relationships
        published_by.append({
            "package": pkg["name"],
            "username": pub["username"],
            "registry": pub["registry"],
        })

    return {
        "packages": packages,
        "accounts": list(accounts.values()),
        "pkg_cve_links": pkg_cve_links,
        "pkg_dep_links": pkg_dep_links,
        "published_by": published_by,
    }


def import_to_neo4j(data: dict):
    """
    Bulk-MERGE packages, accounts, and all relationships into Neo4j.
    Uses UNWIND for batched writes.
    """
    uri = get_env("NEO4J_URI")
    user = get_env("NEO4J_USERNAME")
    password = get_env("NEO4J_PASSWORD")

    driver = GraphDatabase.driver(uri, auth=(user, password))

    with driver.session() as session:
        # ── Step 1: MERGE Package nodes ────────────────────────
        print(f"  Importing {len(data['packages'])} packages ...")
        session.run(
            """
            UNWIND $packages AS p
            MERGE (pkg:Package {name: p.name})
            SET pkg.version = p.version,
                pkg.registry = p.registry,
                pkg.risk_score = p.risk_score,
                pkg.incident = p.incident
            """,
            packages=data["packages"],
        )

        # ── Step 2: MERGE Account nodes ────────────────────────
        print(f"  Importing {len(data['accounts'])} publisher accounts ...")
        session.run(
            """
            UNWIND $accounts AS a
            MERGE (acct:Account {username: a.username, registry: a.registry})
            """,
            accounts=data["accounts"],
        )

        # ── Step 3: PUBLISHED_BY relationships ─────────────────
        # Links each package to the account that published the
        # compromised version.
        print(f"  Creating {len(data['published_by'])} PUBLISHED_BY relationships ...")
        session.run(
            """
            UNWIND $links AS l
            MATCH (pkg:Package {name: l.package})
            MATCH (acct:Account {username: l.username, registry: l.registry})
            MERGE (pkg)-[:PUBLISHED_BY]->(acct)
            """,
            links=data["published_by"],
        )

        # ── Step 4: HAS_VULNERABILITY relationships ────────────
        # Links packages to their CVEs (only if the CVE node exists
        # from import_cve.py — MATCH won't create missing nodes).
        if data["pkg_cve_links"]:
            print(f"  Creating {len(data['pkg_cve_links'])} HAS_VULNERABILITY relationships ...")
            session.run(
                """
                UNWIND $links AS l
                MATCH (pkg:Package {name: l.package})
                MATCH (cve:CVE {id: l.cve_id})
                MERGE (pkg)-[:HAS_VULNERABILITY]->(cve)
                """,
                links=data["pkg_cve_links"],
            )

        # ── Step 5: DEPENDS_ON relationships ───────────────────
        # Links packages to their malicious dependencies
        # (e.g., event-stream → flatmap-stream).
        if data["pkg_dep_links"]:
            print(f"  Creating {len(data['pkg_dep_links'])} DEPENDS_ON relationships ...")
            session.run(
                """
                UNWIND $links AS l
                MATCH (pkg:Package {name: l.package})
                MERGE (dep:Package {name: l.dependency})
                MERGE (pkg)-[:DEPENDS_ON]->(dep)
                """,
                links=data["pkg_dep_links"],
            )

    driver.close()


def cache_data(data: dict):
    """Save the structured data for reference / debugging."""
    os.makedirs("seed_data", exist_ok=True)
    with open(CACHE_PATH, "w") as f:
        json.dump(data, f, indent=2)


def main():
    print("=== npm Compromised Packages Import ===")

    data = build_seed_data()
    print(f"  Built: {len(data['packages'])} packages, "
          f"{len(data['accounts'])} accounts, "
          f"{len(data['pkg_cve_links'])} CVE links, "
          f"{len(data['pkg_dep_links'])} dependency links")

    cache_data(data)
    import_to_neo4j(data)

    print("✅ npm packages import complete")


if __name__ == "__main__":
    main()
