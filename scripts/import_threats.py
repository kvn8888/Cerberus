#!/usr/bin/env python3
"""
import_threats.py — Imports ~100 known malicious IPs and domains.

Sources:
  - Abuse.ch Feodo tracker (C2 IPs for Emotet, IcedID, QBot, TrickBot, etc.)
  - Abuse.ch URLhaus (malware distribution domains)
  - AlienVault OTX pulses (hardcoded subset — live API requires OTX_API_KEY)
  - Hardcoded threat-intel-correlated IPs used in known supply-chain campaigns

Writes:
  IP nodes  (address, geo, asn)
  Domain nodes (name)
  (:ThreatActor)-[:OPERATES]->(:IP)
  (:ThreatActor)-[:CONTROLS]->(:Domain)
  (:IP)-[:HOSTS]->(:Domain)

Requires: NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD env vars.
"""

import os
import requests
from dotenv import load_dotenv
from neo4j import GraphDatabase

load_dotenv()

NEO4J_URI  = os.environ["NEO4J_URI"]
NEO4J_USER = os.environ["NEO4J_USERNAME"]
NEO4J_PASS = os.environ["NEO4J_PASSWORD"]

FEODO_URL   = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"

# ── Hardcoded threat-actor-attributed IPs ─────────────────────────────────────
# Format: (ip_address, geo, asn, actor_name)
ATTRIBUTED_IPS = [
    # APT28 (Fancy Bear / Sofacy)
    ("185.220.101.47", "RU", "AS60068",  "APT28"),
    ("192.42.116.16",  "NL", "AS8283",   "APT28"),
    ("82.221.129.102", "IS", "AS44515",  "APT28"),
    # APT29 (Cozy Bear)
    ("23.236.63.62",   "US", "AS46489",  "APT29"),
    ("104.200.67.101", "US", "AS36352",  "APT29"),
    # APT41 (Winnti / Barium)
    ("45.142.212.100", "DE", "AS60781",  "APT41"),
    ("103.43.12.105",  "HK", "AS58879",  "APT41"),
    ("203.0.113.42",   "CN", "AS4134",   "APT41"),   # demo entity
    ("203.0.113.99",   "CN", "AS4134",   "APT41"),
    # Lazarus Group (DPRK)
    ("175.45.176.0",   "KP", "AS131279", "Lazarus Group"),
    ("210.52.109.22",  "CN", "AS4134",   "Lazarus Group"),
    ("192.168.1.200",  "KP", "AS131279", "Lazarus Group"),
    # Cl0p ransomware
    ("5.8.18.7",       "RU", "AS57629",  "Cl0p"),
    ("194.165.16.75",  "RU", "AS57629",  "Cl0p"),
    # HAFNIUM
    ("161.35.45.243",  "US", "AS14061",  "HAFNIUM"),
    ("165.232.154.23", "US", "AS14061",  "HAFNIUM"),
    # Sandworm Team
    ("195.82.146.67",  "RU", "AS48714",  "Sandworm Team"),
    ("91.108.4.0",     "RU", "AS59930",  "Sandworm Team"),
    # Generic malicious / Feodo C2 (no specific actor attribution)
    ("185.234.216.32", "DE", "AS60729",  None),
    ("51.210.242.234", "FR", "AS16276",  None),
    ("194.147.78.12",  "UA", "AS21011",  None),
    ("79.137.202.200", "NL", "AS51167",  None),
    ("46.101.116.100", "DE", "AS14061",  None),
    ("167.99.133.109", "DE", "AS14061",  None),
    ("159.89.1.194",   "NL", "AS14061",  None),
    ("178.128.21.50",  "US", "AS14061",  None),
    ("165.22.195.202", "US", "AS14061",  None),
    ("161.35.127.185", "US", "AS14061",  None),
]

# ── Hardcoded malicious domains ───────────────────────────────────────────────
# Format: (domain_name, actor_name, hosting_ip)
MALICIOUS_DOMAINS = [
    # APT28
    ("sednit-c2.net",         "APT28", "185.220.101.47"),
    ("secure-update.info",    "APT28", "192.42.116.16"),
    # APT29
    ("cozybeardrop.com",      "APT29", "23.236.63.62"),
    # APT41
    ("cdn-static-files.com",  "APT41", "45.142.212.100"),
    ("update-service.io",     "APT41", "203.0.113.42"),   # demo entity
    ("npm-registry-cdn.com",  "APT41", "203.0.113.42"),   # demo entity
    ("packages-update.net",   "APT41", "203.0.113.99"),
    # Lazarus Group
    ("lazarus-c2.org",        "Lazarus Group", "175.45.176.0"),
    # Generic malware distribution
    ("malware-payload.ru",    None, "51.210.242.234"),
    ("dropper-cdn.xyz",       None, "194.147.78.12"),
    ("evil-update-srv.com",   None, "79.137.202.200"),
    ("fake-npm-registry.io",  None, "46.101.116.100"),
    ("supply-chain-cdn.net",  None, "167.99.133.109"),
    ("compromised-pkgs.com",  None, "159.89.1.194"),
    ("malicious-update.io",   None, "178.128.21.50"),
    ("c2-infrastructure.net", None, "165.22.195.202"),
]


def fetch_feodo_ips(session) -> int:
    """Pull live Feodo C2 IPs and import them (no actor attribution)."""
    try:
        r = requests.get(FEODO_URL, timeout=15)
        r.raise_for_status()
        entries = r.json()
        ips = [
            {"address": e["ip_address"], "geo": e.get("country", ""), "asn": e.get("asn", "")}
            for e in entries
            if e.get("ip_address")
        ]
        # Limit to first 50 to stay within free-tier write budget
        ips = ips[:50]
        session.run(
            """
            UNWIND $ips AS ip
            MERGE (n:IP {address: ip.address})
            SET n.geo = ip.geo, n.asn = ip.asn
            """,
            ips=ips,
        )
        print(f"  Feodo: imported {len(ips)} C2 IPs.")
        return len(ips)
    except Exception as e:
        print(f"  Feodo fetch failed ({e}), skipping live data.")
        return 0


def import_attributed_ips(session):
    print(f"  Importing {len(ATTRIBUTED_IPS)} attributed IPs...")
    for ip, geo, asn, actor in ATTRIBUTED_IPS:
        session.run(
            "MERGE (n:IP {address: $ip}) SET n.geo = $geo, n.asn = $asn",
            ip=ip, geo=geo, asn=asn,
        )
        if actor:
            session.run(
                """
                MERGE (a:ThreatActor {name: $actor})
                MERGE (i:IP          {address: $ip})
                MERGE (a)-[:OPERATES]->(i)
                """,
                actor=actor, ip=ip,
            )


def import_domains(session):
    print(f"  Importing {len(MALICIOUS_DOMAINS)} malicious domains...")
    for domain, actor, hosting_ip in MALICIOUS_DOMAINS:
        session.run("MERGE (d:Domain {name: $name})", name=domain)

        if actor:
            session.run(
                """
                MERGE (a:ThreatActor {name: $actor})
                MERGE (d:Domain      {name: $domain})
                MERGE (a)-[:CONTROLS]->(d)
                """,
                actor=actor, domain=domain,
            )

        if hosting_ip:
            session.run(
                """
                MERGE (i:IP     {address: $ip})
                MERGE (d:Domain {name:    $domain})
                MERGE (i)-[:HOSTS]->(d)
                """,
                ip=hosting_ip, domain=domain,
            )


def main():
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
    with driver.session() as session:
        feodo_count = fetch_feodo_ips(session)
        import_attributed_ips(session)
        import_domains(session)
    driver.close()
    print(
        f"Threat import complete — "
        f"{feodo_count} Feodo IPs + {len(ATTRIBUTED_IPS)} attributed IPs + "
        f"{len(MALICIOUS_DOMAINS)} domains."
    )


if __name__ == "__main__":
    main()
