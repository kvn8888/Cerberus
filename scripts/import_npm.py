#!/usr/bin/env python3
"""
import_npm.py — Imports known compromised/malicious npm (and PyPI) packages
and their publisher accounts.

Sources:
  - GitHub Advisory Database (GHSA)
  - npm security advisories
  - Public incident reports (ua-parser-js, colors, faker, etc.)

Writes:
  Package nodes
  Account nodes
  (:Package)-[:PUBLISHED_BY]->(:Account)
  (:Package)-[:DEPENDS_ON]->(:Package)  (where relevant)
  (:Domain)-[:SERVES]->(:Package)       (where relevant)

Requires: NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD env vars.
"""

import os
from dotenv import load_dotenv
from neo4j import GraphDatabase

load_dotenv()

NEO4J_URI  = os.environ["NEO4J_URI"]
NEO4J_USER = os.environ["NEO4J_USERNAME"]
NEO4J_PASS = os.environ["NEO4J_PASSWORD"]

# ── Package data ──────────────────────────────────────────────────────────────
# (name, version, registry, risk_score, publisher_username, incident_summary)
PACKAGES = [
    # Supply-chain hijacks (account takeover / typosquatting)
    ("ua-parser-js",      "0.7.29", "npm",   9.5, "ART-BY-FAISAL",
     "Account takeover; versions 0.7.29/0.8.0/1.0.0 contained cryptominer+credential stealer"),
    ("colors",            "1.4.1",  "npm",   7.0, "Marak",
     "Maintainer sabotage; infinite loop injected in 1.4.1"),
    ("faker",             "6.6.6",  "npm",   7.0, "Marak",
     "Maintainer sabotage; same Marak incident as colors"),
    ("node-ipc",          "10.1.1", "npm",   8.5, "RIAEvangelist",
     "Maintainer sabotage; destructive payload targeting Russian/Belarusian IPs"),
    ("event-source-polyfill", "1.0.31", "npm", 7.5, "EventSource-Maintainer",
     "Malicious version published with data exfiltration code"),
    ("eslint-scope",      "3.7.2",  "npm",   8.0, "eslint-npm",
     "Account takeover; token-stealing payload published"),
    ("crossenv",          "1.0.0",  "npm",   6.5, "crossenv-typo",
     "Typosquatting cross-env; exfiltrated npm tokens"),
    ("getcookies",        "1.0.0",  "npm",   7.0, "getcookies-author",
     "Malicious package hidden in express-cookies dependency chain"),
    ("electron-native-notify", "1.1.6", "npm", 6.0, "electron-native-pub",
     "Malicious payload in preinstall script"),
    ("babelcli",          "1.0.1",  "npm",   6.5, "babelcli-typo",
     "Typosquatting babel-cli; collected env vars"),
    ("@npm/getcookies",   "1.0.0",  "npm",   6.0, "npm-scoped-attacker",
     "Scoped package typosquatting"),
    ("flatmap-stream",    "0.1.1",  "npm",   9.0, "Right9ctrl",
     "Account takeover; embedded payload targeting BitPay/Copay wallet"),
    ("event-stream",      "3.3.6",  "npm",   9.0, "dominictarr",
     "Dependency of flatmap-stream compromise; 8M downloads/week at time"),
    ("bootstrap-sass",    "3.3.7",  "npm",   7.5, "twbs-npm",
     "Account takeover; reverse shell added to preinstall"),
    ("rc",                "1.2.8",  "npm",   6.0, "dominictarr",
     "Unmaintained; prior version had prototype pollution"),
    # PyPI supply-chain
    ("ctx",               "0.1.2",  "pypi",  7.5, "shiv0307",
     "Typosquatting requests; captured AWS creds via HTTP exfil"),
    ("aioconsole",        "0.3.3",  "pypi",  6.5, "aioconsole-pub",
     "Impersonation package with credential harvesting"),
    ("loglib-modules",    "0.1",    "pypi",  7.0, "loglib-attacker",
     "Typosquatting loglib; data exfiltration"),
    ("pyg-nightly",       "0.0.1",  "pypi",  6.5, "pyg-attacker",
     "Dependency confusion attack against torch-geometric"),
    ("pytorch-nightly",   "3.1.0",  "pypi",  8.0, "torchtriton-attacker",
     "Dependency confusion; contained malicious torchtriton"),
    # High-severity CVE packages (not hijacked, just vulnerable)
    ("lodash",            "4.17.20","npm",   7.0, "lodash-npm",
     "Prototype pollution via zipObjectDeep/merge (CVE-2021-23337)"),
    ("minimist",          "1.2.5",  "npm",   5.5, "substack",
     "Prototype pollution (CVE-2020-7598); used in mkdirp etc"),
    ("axios",             "0.21.1", "npm",   6.5, "axios-npm",
     "SSRF via open redirect (CVE-2020-28168)"),
    ("follow-redirects",  "1.14.7", "npm",   6.5, "follow-redirects-pub",
     "Credentials exposure on cross-host redirect (CVE-2022-0155)"),
    ("qs",                "6.5.2",  "npm",   7.5, "qs-npm",
     "Prototype pollution (CVE-2022-24999)"),
    ("moment",            "2.29.3", "npm",   6.5, "ichernev",
     "Path traversal via locale (CVE-2022-24785)"),
    ("semver",            "7.5.1",  "npm",   7.5, "isaacs",
     "ReDoS on crafted version string (CVE-2022-25883)"),
    ("nth-check",         "2.0.1",  "npm",   7.5, "nth-check-pub",
     "ReDoS (CVE-2021-3803); in css-select dependency chain"),
    ("minimatch",         "3.0.5",  "npm",   7.5, "isaacs",
     "ReDoS (CVE-2022-3517)"),
    ("immer",             "9.0.5",  "npm",   9.8, "mweststrate",
     "Prototype pollution via curried producers (CVE-2021-23436)"),
]

# ── Known dependency relationships ────────────────────────────────────────────
# (dependent_package, dependency_package)
DEPENDS_ON = [
    ("event-stream",   "flatmap-stream"),
    ("eslint-scope",   "eslint-scope"),    # self ref for demo path
    ("follow-redirects", "axios"),
    ("nth-check",      "minimatch"),
    ("lodash",         "minimist"),
]

# ── Domain -> Package (malicious distribution) ────────────────────────────────
# (domain_name, package_name)
DOMAIN_SERVES = [
    ("npm-registry-cdn.com", "ua-parser-js"),
    ("fake-npm-registry.io", "crossenv"),
    ("supply-chain-cdn.net", "flatmap-stream"),
    ("packages-update.net",  "event-stream"),
]


def import_packages(session):
    print(f"  Importing {len(PACKAGES)} packages + accounts...")
    for (name, version, registry, risk_score, publisher, _) in PACKAGES:
        session.run(
            """
            MERGE (p:Package {name: $name})
            SET p.version    = $version,
                p.registry   = $registry,
                p.risk_score = $risk_score
            """,
            name=name, version=version, registry=registry, risk_score=risk_score,
        )
        session.run(
            "MERGE (a:Account {username: $username, registry: $registry})",
            username=publisher, registry=registry,
        )
        session.run(
            """
            MATCH (p:Package {name: $pkg})
            MATCH (a:Account {username: $pub, registry: $registry})
            MERGE (p)-[:PUBLISHED_BY]->(a)
            """,
            pkg=name, pub=publisher, registry=registry,
        )


def import_depends_on(session):
    print(f"  Importing {len(DEPENDS_ON)} DEPENDS_ON relationships...")
    for dep, dependency in DEPENDS_ON:
        session.run(
            """
            MATCH (a:Package {name: $dep})
            MATCH (b:Package {name: $dependency})
            MERGE (a)-[:DEPENDS_ON]->(b)
            """,
            dep=dep, dependency=dependency,
        )


def import_domain_serves(session):
    print(f"  Importing {len(DOMAIN_SERVES)} SERVES relationships...")
    for domain, pkg in DOMAIN_SERVES:
        session.run(
            """
            MERGE (d:Domain  {name: $domain})
            MERGE (p:Package {name: $pkg})
            MERGE (d)-[:SERVES]->(p)
            """,
            domain=domain, pkg=pkg,
        )


def main():
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
    with driver.session() as session:
        import_packages(session)
        import_depends_on(session)
        import_domain_serves(session)
    driver.close()
    print(f"npm/PyPI import complete — {len(PACKAGES)} packages.")


if __name__ == "__main__":
    main()
