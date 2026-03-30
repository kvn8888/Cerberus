#!/usr/bin/env python3
"""
import_synthetic.py — Generates synthetic cross-domain bridge data.

Creates:
  (:Account)-[:LINKED_TO]->(:IP)           ~15 links
  (:FraudSignal) nodes                     ~20 nodes
  (:IP)-[:ASSOCIATED_WITH]->(:FraudSignal) ~20 links

This is the critical cross-domain bridge between software supply-chain and
infrastructure/financial layers.

SYNTHETIC DATA DISCLAIMER:
  These Account->IP links are simulated. In production they would come from:
  - Git commit metadata (author email -> correlated IP)
  - npm publish audit logs
  - SIEM data capturing actual publish connection events
  The IP addresses are real known-malicious IPs; the account-IP correlations
  are plausible based on threat-intel campaign clustering.

Requires: NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD env vars.
"""

import os
import uuid
import random
from datetime import datetime, timedelta
from dotenv import load_dotenv
from neo4j import GraphDatabase

load_dotenv()

NEO4J_URI  = os.environ["NEO4J_URI"]
NEO4J_USER = os.environ["NEO4J_USERNAME"]
NEO4J_PASS = os.environ["NEO4J_PASSWORD"]

# ── Synthetic Account -> IP links ─────────────────────────────────────────────
# (username, registry, ip_address, confidence)
# These represent the synthetic bridge: npm publisher correlated to known-bad IP
ACCOUNT_IP_LINKS = [
    # ua-parser-js incident — primary demo path
    ("ART-BY-FAISAL",        "npm",   "203.0.113.42",   0.92),
    # flatmap-stream / event-stream incident
    ("Right9ctrl",            "npm",   "45.142.212.100", 0.85),
    # Colors/Faker incident (Marak used VPN from known RU exit node)
    ("Marak",                 "npm",   "185.220.101.47", 0.60),  # lower confidence, VPN
    # eslint-scope account takeover
    ("eslint-npm",            "npm",   "192.42.116.16",  0.78),
    # node-ipc maintainer sabotage
    ("RIAEvangelist",         "npm",   "195.82.146.67",  0.70),
    # Dependency confusion attacks — PyPI
    ("shiv0307",              "pypi",  "203.0.113.99",   0.88),
    ("loglib-attacker",       "pypi",  "203.0.113.42",   0.82),
    # Typosquatters linked to same infrastructure cluster
    ("crossenv-typo",         "npm",   "79.137.202.200", 0.75),
    ("babelcli-typo",         "npm",   "46.101.116.100", 0.73),
    ("npm-scoped-attacker",   "npm",   "167.99.133.109", 0.80),
    ("getcookies-author",     "npm",   "159.89.1.194",   0.71),
    # Lazarus Group supply-chain accounts
    ("pyg-attacker",          "pypi",  "175.45.176.0",   0.90),
    ("torchtriton-attacker",  "pypi",  "210.52.109.22",  0.88),
    # Bootstrap-sass compromise
    ("twbs-npm",              "npm",   "161.35.45.243",  0.65),
    # electron-native compromise
    ("electron-native-pub",   "npm",   "165.232.154.23", 0.72),
]

# ── Synthetic Juspay FraudSignal data ─────────────────────────────────────────
# (juspay_id, fraud_type, amount, currency, ip_address)
# These represent financial fraud signals correlated to known-bad IPs.
FRAUD_SIGNALS = [
    # Linked to APT41 demo IP (203.0.113.42)
    ("JS-2024-0001", "card_not_present",    1250.00, "USD", "203.0.113.42"),
    ("JS-2024-0002", "account_takeover",    3800.00, "USD", "203.0.113.42"),
    ("JS-2024-0003", "synthetic_identity",  9999.00, "USD", "203.0.113.42"),
    ("JS-2024-0004", "card_not_present",     450.00, "EUR", "203.0.113.99"),
    ("JS-2024-0005", "refund_fraud",        2100.00, "USD", "203.0.113.99"),
    # Linked to APT28 IPs
    ("JS-2024-0006", "account_takeover",    5500.00, "USD", "185.220.101.47"),
    ("JS-2024-0007", "card_not_present",     750.00, "GBP", "185.220.101.47"),
    ("JS-2024-0008", "money_laundering",   15000.00, "USD", "192.42.116.16"),
    # Linked to typosquatter infrastructure
    ("JS-2024-0009", "card_not_present",    1100.00, "USD", "79.137.202.200"),
    ("JS-2024-0010", "credential_stuffing",  320.00, "USD", "46.101.116.100"),
    ("JS-2024-0011", "account_takeover",    4200.00, "EUR", "167.99.133.109"),
    ("JS-2024-0012", "synthetic_identity",  8750.00, "USD", "159.89.1.194"),
    # Linked to Lazarus Group infrastructure
    ("JS-2024-0013", "cryptocurrency_theft", 25000.00, "USD", "175.45.176.0"),
    ("JS-2024-0014", "card_not_present",    1800.00,  "USD", "210.52.109.22"),
    # Linked to Cl0p infrastructure
    ("JS-2024-0015", "ransomware_payment",  50000.00, "USD", "5.8.18.7"),
    ("JS-2024-0016", "money_laundering",    12000.00, "EUR", "194.165.16.75"),
    # Linked to generic malicious IPs
    ("JS-2024-0017", "card_not_present",      980.00, "USD", "51.210.242.234"),
    ("JS-2024-0018", "account_takeover",     2300.00, "USD", "194.147.78.12"),
    ("JS-2024-0019", "refund_fraud",          670.00, "USD", "178.128.21.50"),
    ("JS-2024-0020", "credential_stuffing",   140.00, "USD", "165.22.195.202"),
]

BASE_TIMESTAMP = datetime(2024, 1, 1, 0, 0, 0)


def import_account_ip_links(session):
    print(f"  Importing {len(ACCOUNT_IP_LINKS)} synthetic Account->IP links...")
    for username, registry, ip, confidence in ACCOUNT_IP_LINKS:
        session.run(
            """
            MERGE (a:Account {username: $username, registry: $registry})
            MERGE (i:IP      {address:  $ip})
            MERGE (a)-[r:LINKED_TO]->(i)
            SET r.synthetic   = true,
                r.confidence  = $confidence,
                r.source      = 'threat_intel_correlation'
            """,
            username=username, registry=registry, ip=ip, confidence=confidence,
        )
    print(f"  Done — {len(ACCOUNT_IP_LINKS)} LINKED_TO relationships upserted.")


def import_fraud_signals(session):
    print(f"  Importing {len(FRAUD_SIGNALS)} Juspay fraud signals...")
    for i, (juspay_id, fraud_type, amount, currency, ip) in enumerate(FRAUD_SIGNALS):
        ts = int((BASE_TIMESTAMP + timedelta(days=i * 7, hours=random.randint(0, 23))).timestamp() * 1000)
        session.run(
            """
            MERGE (fs:FraudSignal {juspay_id: $juspay_id})
            SET fs.type      = $type,
                fs.amount    = $amount,
                fs.currency  = $currency,
                fs.timestamp = $ts,
                fs.synthetic = true
            WITH fs
            MERGE (i:IP {address: $ip})
            MERGE (i)-[:ASSOCIATED_WITH]->(fs)
            """,
            juspay_id=juspay_id, type=fraud_type, amount=amount,
            currency=currency, ts=ts, ip=ip,
        )
    print(f"  Done — {len(FRAUD_SIGNALS)} FraudSignal nodes + ASSOCIATED_WITH edges upserted.")


def main():
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
    with driver.session() as session:
        import_account_ip_links(session)
        import_fraud_signals(session)
    driver.close()
    print("Synthetic data import complete.")


if __name__ == "__main__":
    main()
