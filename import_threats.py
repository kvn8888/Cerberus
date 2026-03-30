#!/usr/bin/env python3
"""
import_threats.py — Import threat intelligence (IPs + domains) into Neo4j.

Sources:
  - Abuse.ch Feodo Tracker: known botnet C2 IPs
  - Abuse.ch URLhaus: malicious domains/URLs
  - Fallback: curated local seed data if APIs are down

Target: ~100 malicious IPs + ~50 domains with :HOSTS relationships.

Requires env vars:
  NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD

Usage:
  python import_threats.py
"""

import csv
import io
import json
import os
import sys
import urllib.request
import urllib.error
from neo4j import GraphDatabase

# ── Cache paths ────────────────────────────────────────────────
IP_CACHE = os.path.join("seed_data", "threat_ips.json")
DOMAIN_CACHE = os.path.join("seed_data", "threat_domains.json")

# ── Abuse.ch feed URLs ────────────────────────────────────────
# Feodo Tracker: recently active botnet C2 servers (CSV format)
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"

# URLhaus: recently active malware distribution URLs (CSV format)
URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"


def get_env(name: str) -> str:
    """Read a required environment variable or exit with an error."""
    val = os.environ.get(name)
    if not val:
        print(f"ERROR: {name} environment variable is required")
        sys.exit(1)
    return val


def fetch_feodo_ips() -> list[dict]:
    """
    Fetch recently active C2 IPs from Abuse.ch Feodo Tracker.
    The feed is a comment-prefixed text file with one IP per line.
    Returns list of dicts with address, geo (empty — not in this feed),
    asn (empty), and first_seen.
    """
    print("  Fetching Feodo Tracker IPs ...")
    try:
        req = urllib.request.Request(FEODO_URL, headers={"User-Agent": "Cerberus-Import/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            text = resp.read().decode("utf-8")
    except (urllib.error.URLError, TimeoutError) as e:
        print(f"    WARN: Feodo fetch failed: {e}")
        return []

    ips = []
    for line in text.strip().split("\n"):
        line = line.strip()
        # Skip comment lines (start with #) and empty lines
        if not line or line.startswith("#"):
            continue
        # Each non-comment line is just an IP address
        ips.append({
            "address": line,
            "geo": "",
            "asn": "",
            "source": "feodo_tracker",
        })

    return ips[:100]  # Cap at 100 for demo


def fetch_urlhaus_domains() -> list[dict]:
    """
    Fetch recently active malware distribution domains from URLhaus.
    The CSV includes full URLs — we extract unique hostnames.
    Returns list of dicts with domain name and registrar (unknown).
    """
    print("  Fetching URLhaus domains ...")
    try:
        req = urllib.request.Request(URLHAUS_URL, headers={"User-Agent": "Cerberus-Import/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            text = resp.read().decode("utf-8")
    except (urllib.error.URLError, TimeoutError) as e:
        print(f"    WARN: URLhaus fetch failed: {e}")
        return []

    domains = set()
    # URLhaus CSV format: skip comment lines starting with #
    for line in text.strip().split("\n"):
        if line.startswith("#") or not line.strip():
            continue

        # CSV fields: id, dateadded, url, url_status, last_online,
        #             threat, tags, urlhaus_link, reporter
        try:
            reader = csv.reader(io.StringIO(line))
            fields = next(reader)
            if len(fields) >= 3:
                url = fields[2].strip('"')
                # Extract hostname from URL
                # e.g., "http://evil.example.com/malware.exe" → "evil.example.com"
                if "://" in url:
                    host = url.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
                    # Skip raw IPs — we only want domain names here
                    if not _is_ip(host) and "." in host:
                        domains.add(host)
        except (StopIteration, csv.Error):
            continue

    result = [{"name": d, "registrar": "unknown", "source": "urlhaus"} for d in domains]
    return result[:50]  # Cap at 50 for demo


def _is_ip(s: str) -> bool:
    """Quick check if a string looks like an IPv4 address."""
    parts = s.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def get_fallback_ips() -> list[dict]:
    """
    Fallback curated list of known malicious IPs if live feeds fail.
    These are documented C2/malware IPs from public threat reports.
    Using RFC 5737 documentation ranges (192.0.2.x, 198.51.100.x, 203.0.113.x)
    plus a few real known-bad IPs from public abuse reports.
    """
    return [
        {"address": "185.220.101.1", "geo": "DE", "asn": "AS205100", "source": "manual"},
        {"address": "185.220.101.2", "geo": "DE", "asn": "AS205100", "source": "manual"},
        {"address": "185.220.101.10", "geo": "DE", "asn": "AS205100", "source": "manual"},
        {"address": "45.33.32.156", "geo": "US", "asn": "AS63949", "source": "manual"},
        {"address": "198.51.100.1", "geo": "XX", "asn": "AS0", "source": "synthetic"},
        {"address": "198.51.100.2", "geo": "XX", "asn": "AS0", "source": "synthetic"},
        {"address": "198.51.100.10", "geo": "XX", "asn": "AS0", "source": "synthetic"},
        {"address": "198.51.100.20", "geo": "XX", "asn": "AS0", "source": "synthetic"},
        {"address": "198.51.100.30", "geo": "XX", "asn": "AS0", "source": "synthetic"},
        {"address": "203.0.113.1", "geo": "XX", "asn": "AS0", "source": "synthetic"},
        {"address": "203.0.113.42", "geo": "XX", "asn": "AS0", "source": "synthetic"},
        {"address": "203.0.113.50", "geo": "XX", "asn": "AS0", "source": "synthetic"},
        {"address": "203.0.113.100", "geo": "XX", "asn": "AS0", "source": "synthetic"},
        {"address": "203.0.113.200", "geo": "XX", "asn": "AS0", "source": "synthetic"},
    ]


def get_fallback_domains() -> list[dict]:
    """Fallback curated domains if live feeds fail."""
    return [
        {"name": "evil-cdn.example.com", "registrar": "unknown", "source": "synthetic"},
        {"name": "c2-server.example.net", "registrar": "unknown", "source": "synthetic"},
        {"name": "malware-dist.example.org", "registrar": "unknown", "source": "synthetic"},
        {"name": "phish-login.example.com", "registrar": "unknown", "source": "synthetic"},
        {"name": "crypto-mine.example.net", "registrar": "unknown", "source": "synthetic"},
    ]


def load_or_fetch_data() -> tuple[list[dict], list[dict]]:
    """Load from cache or fetch from live feeds, with fallback."""
    ips = []
    domains = []

    # Try cache first
    if os.path.exists(IP_CACHE) and os.path.exists(DOMAIN_CACHE):
        print("  Using cached threat data")
        with open(IP_CACHE) as f:
            ips = json.load(f)
        with open(DOMAIN_CACHE) as f:
            domains = json.load(f)
        return ips, domains

    os.makedirs("seed_data", exist_ok=True)

    # Fetch from live feeds
    ips = fetch_feodo_ips()
    domains = fetch_urlhaus_domains()

    # Fallback if feeds returned nothing
    if not ips:
        print("  Using fallback IP list")
        ips = get_fallback_ips()
    if not domains:
        print("  Using fallback domain list")
        domains = get_fallback_domains()

    # Cache results
    with open(IP_CACHE, "w") as f:
        json.dump(ips, f, indent=2)
    with open(DOMAIN_CACHE, "w") as f:
        json.dump(domains, f, indent=2)

    return ips, domains


def import_to_neo4j(ips: list[dict], domains: list[dict]):
    """
    Bulk-MERGE IP and Domain nodes into Neo4j.
    Also creates HOSTS relationships for IPs that host domains
    (when we can infer it — for now we create some plausible links).
    """
    uri = get_env("NEO4J_URI")
    user = get_env("NEO4J_USERNAME")
    password = get_env("NEO4J_PASSWORD")

    driver = GraphDatabase.driver(uri, auth=(user, password))

    with driver.session() as session:
        # ── MERGE IP nodes ─────────────────────────────────────
        print(f"  Importing {len(ips)} IP nodes ...")
        session.run(
            """
            UNWIND $ips AS ip
            MERGE (i:IP {address: ip.address})
            SET i.geo = ip.geo,
                i.asn = ip.asn,
                i.source = ip.source
            """,
            ips=ips,
        )

        # ── MERGE Domain nodes ─────────────────────────────────
        print(f"  Importing {len(domains)} Domain nodes ...")
        session.run(
            """
            UNWIND $domains AS d
            MERGE (dom:Domain {name: d.name})
            SET dom.registrar = d.registrar,
                dom.source = d.source
            """,
            domains=domains,
        )

        # ── Create some HOSTS relationships ────────────────────
        # In reality these come from DNS resolution. For the demo,
        # we pair the first N IPs with the first N domains to create
        # traversal paths through the graph.
        host_pairs = min(len(ips), len(domains))
        if host_pairs > 0:
            pairs = [
                {"ip": ips[i]["address"], "domain": domains[i]["name"]}
                for i in range(host_pairs)
            ]
            print(f"  Creating {len(pairs)} HOSTS relationships ...")
            session.run(
                """
                UNWIND $pairs AS p
                MATCH (i:IP {address: p.ip})
                MATCH (d:Domain {name: p.domain})
                MERGE (i)-[:HOSTS]->(d)
                """,
                pairs=pairs,
            )

    driver.close()


def main():
    print("=== Threat Intelligence Import ===")

    ips, domains = load_or_fetch_data()
    print(f"  Loaded: {len(ips)} IPs, {len(domains)} domains")

    import_to_neo4j(ips, domains)

    print("✅ Threat intelligence import complete")


if __name__ == "__main__":
    main()
