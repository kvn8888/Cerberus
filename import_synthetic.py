#!/usr/bin/env python3
"""
import_synthetic.py — Create synthetic cross-domain bridge data in Neo4j.

This script creates the relationships that make Cerberus's cross-domain
traversal work but don't exist in any public data source:

  1. Account → LINKED_TO → IP
     Maps compromised npm publisher accounts to known malicious IPs.
     In production: would come from Git metadata, npm audit logs, or SIEM.

  2. FraudSignal nodes + IP → ASSOCIATED_WITH → FraudSignal
     Simulated Juspay financial fraud signals linked to IPs.
     Creates the third domain (financial) in the cross-domain graph.

  3. CVE → EXPLOITED_BY → ThreatActor
     Links specific CVEs to known threat actor groups.
     Some of these are real attributions, others are plausible.

  4. ThreatActor → OPERATES → IP
     Links threat actors to their operational infrastructure.

All synthetic data is clearly marked in the graph with a `synthetic: true`
property so it can be distinguished from real intelligence.

IMPORTANT: This script depends on data from the other import scripts.
Run order: constraints.cypher → import_mitre.py → import_cve.py →
           import_threats.py → import_npm.py → import_synthetic.py

Requires env vars:
  NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD

Usage:
  python import_synthetic.py
"""

import json
import os
import sys
from neo4j import GraphDatabase

CACHE_PATH = os.path.join("seed_data", "synthetic_links.json")


def get_env(name: str) -> str:
    """Read a required environment variable or exit with an error."""
    val = os.environ.get(name)
    if not val:
        print(f"ERROR: {name} environment variable is required")
        sys.exit(1)
    return val


# ── Synthetic Account → IP links ──────────────────────────────
# These create the critical bridge between the software supply chain
# (Package → Account) and infrastructure (IP → Domain → ThreatActor).
# Without these, the graph has two disconnected islands.
#
# Each entry simulates: "this npm account published from this IP."
# In the real world, attackers reuse infrastructure across campaigns.
ACCOUNT_IP_LINKS = [
    # ua-parser-js compromised account → known malicious IP
    # This is THE demo link — the traversal from ua-parser-js to a
    # threat actor goes through this synthetic bridge.
    {"username": "ART-BY-FAISAL", "registry": "npm", "ip": "203.0.113.42"},

    # event-stream attacker reused infra
    {"username": "right9ctrl", "registry": "npm", "ip": "198.51.100.10"},

    # Typosquatter on shared infrastructure
    {"username": "nickvdm-typosquat", "registry": "npm", "ip": "198.51.100.20"},

    # coa/rc compromise — same campaign, shared IP
    {"username": "coa-compromised", "registry": "npm", "ip": "203.0.113.100"},
    {"username": "rc-compromised", "registry": "npm", "ip": "203.0.113.100"},

    # eslint-scope — different infrastructure
    {"username": "eslint-compromised", "registry": "npm", "ip": "203.0.113.200"},

    # node-ipc protestware actor
    {"username": "RIAEvangelist", "registry": "npm", "ip": "198.51.100.30"},

    # getcookies backdoor
    {"username": "getcookies-attacker", "registry": "npm", "ip": "203.0.113.50"},

    # Shared infra across multiple campaigns (simulates attacker reuse)
    {"username": "ART-BY-FAISAL", "registry": "npm", "ip": "198.51.100.1"},
    {"username": "right9ctrl", "registry": "npm", "ip": "203.0.113.1"},
]


# ── Synthetic Juspay fraud signals ────────────────────────────
# Simulated financial fraud data linked to some of the same IPs
# used by the software supply chain attackers. This creates the
# third domain (financial) in the cross-domain traversal.
#
# The Juspay integration story: "Transaction fraud from the SAME
# IP infrastructure used by npm supply chain attackers."
FRAUD_SIGNALS = [
    {
        "juspay_id": "JPFS-2024-001",
        "type": "card_fraud",
        "amount": 15000.00,
        "currency": "INR",
        "timestamp": "2024-01-15T08:30:00Z",
        "ip": "203.0.113.42",  # Same IP as ua-parser-js attacker → KEY DEMO LINK
    },
    {
        "juspay_id": "JPFS-2024-002",
        "type": "account_takeover",
        "amount": 45000.00,
        "currency": "INR",
        "timestamp": "2024-01-16T14:22:00Z",
        "ip": "203.0.113.42",  # Same IP — shows pattern of multi-surface attack
    },
    {
        "juspay_id": "JPFS-2024-003",
        "type": "credential_stuffing",
        "amount": 0.00,
        "currency": "INR",
        "timestamp": "2024-01-17T02:45:00Z",
        "ip": "198.51.100.10",  # Same IP as event-stream attacker
    },
    {
        "juspay_id": "JPFS-2024-004",
        "type": "card_fraud",
        "amount": 89000.00,
        "currency": "INR",
        "timestamp": "2024-01-18T19:10:00Z",
        "ip": "203.0.113.100",  # Same IP as coa/rc campaign
    },
    {
        "juspay_id": "JPFS-2024-005",
        "type": "money_laundering",
        "amount": 250000.00,
        "currency": "INR",
        "timestamp": "2024-01-19T11:05:00Z",
        "ip": "198.51.100.20",  # Same IP as typosquatter
    },
    {
        "juspay_id": "JPFS-2024-006",
        "type": "card_fraud",
        "amount": 7500.00,
        "currency": "INR",
        "timestamp": "2024-02-01T16:30:00Z",
        "ip": "203.0.113.200",  # Same IP as eslint-scope
    },
    {
        "juspay_id": "JPFS-2024-007",
        "type": "account_takeover",
        "amount": 32000.00,
        "currency": "INR",
        "timestamp": "2024-02-03T09:15:00Z",
        "ip": "203.0.113.50",  # Same IP as getcookies
    },
    {
        "juspay_id": "JPFS-2024-008",
        "type": "card_not_present",
        "amount": 18500.00,
        "currency": "INR",
        "timestamp": "2024-02-05T22:40:00Z",
        "ip": "198.51.100.1",  # Shared ART-BY-FAISAL infra
    },
    {
        "juspay_id": "JPFS-2024-009",
        "type": "suspicious_velocity",
        "amount": 125000.00,
        "currency": "INR",
        "timestamp": "2024-02-07T04:12:00Z",
        "ip": "198.51.100.30",  # Same IP as node-ipc actor
    },
    {
        "juspay_id": "JPFS-2024-010",
        "type": "card_fraud",
        "amount": 9800.00,
        "currency": "INR",
        "timestamp": "2024-02-10T13:55:00Z",
        "ip": "203.0.113.1",  # Shared right9ctrl infra
    },
    # Additional signals on different IPs (shows not ALL infra is shared)
    {
        "juspay_id": "JPFS-2024-011",
        "type": "refund_fraud",
        "amount": 42000.00,
        "currency": "INR",
        "timestamp": "2024-02-12T07:20:00Z",
        "ip": "192.0.2.100",  # Unlinked IP — different fraud ring
    },
    {
        "juspay_id": "JPFS-2024-012",
        "type": "card_fraud",
        "amount": 3200.00,
        "currency": "INR",
        "timestamp": "2024-02-14T18:45:00Z",
        "ip": "192.0.2.200",  # Unlinked IP — different fraud ring
    },
]


# ── CVE → ThreatActor attributions ────────────────────────────
# Some of these are based on real MITRE ATT&CK attributions,
# others are plausible connections for demo purposes.
CVE_ACTOR_LINKS = [
    # ProxyLogon exploited by HAFNIUM (real attribution)
    {"cve_id": "CVE-2021-26855", "actor_name": "HAFNIUM"},
    {"cve_id": "CVE-2021-26857", "actor_name": "HAFNIUM"},
    {"cve_id": "CVE-2021-27065", "actor_name": "HAFNIUM"},

    # Log4Shell widely exploited — attributed to multiple actors
    {"cve_id": "CVE-2021-44228", "actor_name": "APT41"},

    # ua-parser-js — linked to a synthetic actor for demo traversal
    {"cve_id": "CVE-2021-27292", "actor_name": "CryptoJacker-Alpha"},

    # Spring4Shell
    {"cve_id": "CVE-2022-22965", "actor_name": "APT41"},

    # Confluence exploitation
    {"cve_id": "CVE-2022-26134", "actor_name": "APT41"},
]


# ── ThreatActor → IP (operational infrastructure) ─────────────
# Links threat actors to the IPs they operate from.
# This closes the graph loop: Package → Account → IP ← ThreatActor.
ACTOR_IP_LINKS = [
    # CryptoJacker-Alpha operates from the same IP cluster
    # as the ua-parser-js compromise
    {"actor_name": "CryptoJacker-Alpha", "ip": "203.0.113.42"},
    {"actor_name": "CryptoJacker-Alpha", "ip": "198.51.100.1"},

    # APT41 infrastructure
    {"actor_name": "APT41", "ip": "203.0.113.100"},
    {"actor_name": "APT41", "ip": "203.0.113.200"},

    # HAFNIUM infrastructure
    {"actor_name": "HAFNIUM", "ip": "198.51.100.10"},
    {"actor_name": "HAFNIUM", "ip": "198.51.100.20"},
]


def import_to_neo4j():
    """
    Create all synthetic cross-domain bridges in Neo4j.
    Each synthetic relationship gets a `synthetic: true` property
    for visual distinction (dashed edges in neovis.js).
    """
    uri = get_env("NEO4J_URI")
    user = get_env("NEO4J_USERNAME")
    password = get_env("NEO4J_PASSWORD")

    driver = GraphDatabase.driver(uri, auth=(user, password))

    with driver.session() as session:
        # ── Step 1: Account → LINKED_TO → IP ──────────────────
        # The critical cross-domain bridge. MERGE ensures we don't
        # create duplicate relationships on re-runs.
        print(f"  Creating {len(ACCOUNT_IP_LINKS)} Account→IP links ...")
        session.run(
            """
            UNWIND $links AS l
            MATCH (acct:Account {username: l.username, registry: l.registry})
            MERGE (ip:IP {address: l.ip})
            MERGE (acct)-[r:LINKED_TO]->(ip)
            SET r.synthetic = true,
                r.rationale = 'Simulated from threat intel correlation'
            """,
            links=ACCOUNT_IP_LINKS,
        )

        # ── Step 2: FraudSignal nodes + IP → ASSOCIATED_WITH ──
        # Create the Juspay fraud signal nodes and link them to IPs.
        print(f"  Creating {len(FRAUD_SIGNALS)} FraudSignal nodes ...")
        session.run(
            """
            UNWIND $signals AS s
            MERGE (fs:FraudSignal {juspay_id: s.juspay_id})
            SET fs.type = s.type,
                fs.amount = s.amount,
                fs.currency = s.currency,
                fs.timestamp = s.timestamp,
                fs.synthetic = true
            WITH fs, s
            MERGE (ip:IP {address: s.ip})
            MERGE (ip)-[r:ASSOCIATED_WITH]->(fs)
            SET r.synthetic = true
            """,
            signals=FRAUD_SIGNALS,
        )

        # ── Step 3: Create synthetic ThreatActor if needed ─────
        # CryptoJacker-Alpha doesn't exist in MITRE ATT&CK — it's
        # our synthetic actor for the ua-parser-js demo chain.
        print("  Ensuring synthetic threat actors exist ...")
        session.run(
            """
            MERGE (ta:ThreatActor {name: 'CryptoJacker-Alpha'})
            SET ta.aliases = ['CJ-Alpha', 'CryptoJack Group'],
                ta.attribution_confidence = 'LOW',
                ta.synthetic = true
            """
        )

        # ── Step 4: CVE → EXPLOITED_BY → ThreatActor ──────────
        print(f"  Creating {len(CVE_ACTOR_LINKS)} CVE→ThreatActor links ...")
        session.run(
            """
            UNWIND $links AS l
            MATCH (cve:CVE {id: l.cve_id})
            MERGE (ta:ThreatActor {name: l.actor_name})
            MERGE (cve)-[r:EXPLOITED_BY]->(ta)
            SET r.synthetic = CASE WHEN ta.synthetic IS NOT NULL THEN true ELSE false END
            """,
            links=CVE_ACTOR_LINKS,
        )

        # ── Step 5: ThreatActor → OPERATES → IP ───────────────
        print(f"  Creating {len(ACTOR_IP_LINKS)} ThreatActor→IP links ...")
        session.run(
            """
            UNWIND $links AS l
            MATCH (ta:ThreatActor {name: l.actor_name})
            MERGE (ip:IP {address: l.ip})
            MERGE (ta)-[r:OPERATES]->(ip)
            SET r.synthetic = true
            """,
            links=ACTOR_IP_LINKS,
        )

    driver.close()


def cache_data():
    """Save synthetic link data for reference / debugging."""
    os.makedirs("seed_data", exist_ok=True)
    data = {
        "account_ip_links": ACCOUNT_IP_LINKS,
        "fraud_signals": FRAUD_SIGNALS,
        "cve_actor_links": CVE_ACTOR_LINKS,
        "actor_ip_links": ACTOR_IP_LINKS,
    }
    with open(CACHE_PATH, "w") as f:
        json.dump(data, f, indent=2)


def main():
    print("=== Synthetic Cross-Domain Bridge Import ===")

    cache_data()

    print(f"  Account→IP links: {len(ACCOUNT_IP_LINKS)}")
    print(f"  Fraud signals: {len(FRAUD_SIGNALS)}")
    print(f"  CVE→ThreatActor links: {len(CVE_ACTOR_LINKS)}")
    print(f"  ThreatActor→IP links: {len(ACTOR_IP_LINKS)}")

    import_to_neo4j()

    print("✅ Synthetic bridge data import complete")
    print()
    print("KEY DEMO PATH NOW AVAILABLE:")
    print("  ua-parser-js → ART-BY-FAISAL → 203.0.113.42 → CryptoJacker-Alpha")
    print("  ua-parser-js → ART-BY-FAISAL → 203.0.113.42 → FraudSignal JPFS-2024-001")


if __name__ == "__main__":
    main()
