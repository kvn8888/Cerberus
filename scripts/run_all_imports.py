#!/usr/bin/env python3
"""
run_all_imports.py — Run constraints + all import scripts against live Neo4j Aura.
Meant to be run from the project root with SSL_CERT_FILE set.

Usage:
  SSL_CERT_FILE=$(python3 -c "import certifi; print(certifi.where())") python3 scripts/run_all_imports.py
"""

import os
import sys
import time

# Add scripts/ to path so we can import sibling modules
scripts_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, scripts_dir)
os.chdir(os.path.join(scripts_dir, ".."))  # set CWD to project root

from dotenv import load_dotenv
load_dotenv()

from neo4j import GraphDatabase

# Validate env vars
for var in ["NEO4J_URI", "NEO4J_USERNAME", "NEO4J_PASSWORD"]:
    if not os.environ.get(var):
        print(f"ERROR: {var} not set")
        sys.exit(1)

driver = GraphDatabase.driver(
    os.environ["NEO4J_URI"],
    auth=(os.environ["NEO4J_USERNAME"], os.environ["NEO4J_PASSWORD"])
)

# ── Step 0: Connection test ──────────────────────────────────────────────
print("=" * 60)
print("STEP 0: Connection Test")
print("=" * 60)
with driver.session() as s:
    r = s.run("RETURN 1 AS t").single()["t"]
    print(f"  Connection OK (test={r})")

    # Check APOC
    try:
        v = s.run("RETURN apoc.version() AS v").single()
        print(f"  APOC version: {v['v']}")
    except Exception as e:
        print(f"  APOC not available: {type(e).__name__}")

    nodes = s.run("MATCH (n) RETURN count(n) AS c").single()["c"]
    print(f"  Current nodes: {nodes}")

# ── Step 1: Constraints ─────────────────────────────────────────────────
print("\n" + "=" * 60)
print("STEP 1: Uniqueness Constraints")
print("=" * 60)
constraints = [
    ("pkg_name", "CREATE CONSTRAINT pkg_name IF NOT EXISTS FOR (p:Package) REQUIRE p.name IS UNIQUE"),
    ("cve_id", "CREATE CONSTRAINT cve_id IF NOT EXISTS FOR (c:CVE) REQUIRE c.id IS UNIQUE"),
    ("ip_addr", "CREATE CONSTRAINT ip_addr IF NOT EXISTS FOR (i:IP) REQUIRE i.address IS UNIQUE"),
    ("domain_name", "CREATE CONSTRAINT domain_name IF NOT EXISTS FOR (d:Domain) REQUIRE d.name IS UNIQUE"),
    ("actor_name", "CREATE CONSTRAINT actor_name IF NOT EXISTS FOR (ta:ThreatActor) REQUIRE ta.name IS UNIQUE"),
    ("technique_id", "CREATE CONSTRAINT technique_id IF NOT EXISTS FOR (t:Technique) REQUIRE t.mitre_id IS UNIQUE"),
    ("account_key", "CREATE CONSTRAINT account_key IF NOT EXISTS FOR (a:Account) REQUIRE (a.username, a.registry) IS UNIQUE"),
    ("fraud_id", "CREATE CONSTRAINT fraud_id IF NOT EXISTS FOR (fs:FraudSignal) REQUIRE fs.juspay_id IS UNIQUE"),
]

with driver.session() as s:
    for name, cypher in constraints:
        try:
            s.run(cypher)
            print(f"  OK: {name}")
        except Exception as e:
            print(f"  FAIL {name}: {e}")

# ── Step 2: Import MITRE ATT&CK ─────────────────────────────────────────
print("\n" + "=" * 60)
print("STEP 2: MITRE ATT&CK Import")
print("=" * 60)
start = time.time()
import import_mitre
bundle = import_mitre.fetch_stix_bundle()
techs, actors, uses, sid2mid, sid2name = import_mitre.parse_bundle(bundle)
print(f"  Parsed: {len(techs)} techniques, {len(actors)} actors, {len(uses)} uses")

with driver.session() as s:
    import_mitre.import_techniques(s, techs)
    import_mitre.import_actors(s, actors)
    import_mitre.import_uses(s, uses, sid2mid, sid2name)
print(f"  Done in {time.time()-start:.1f}s")

# ── Step 3: Import CVEs ─────────────────────────────────────────────────
print("\n" + "=" * 60)
print("STEP 3: CVE Import")
print("=" * 60)
start = time.time()
import import_cve
with driver.session() as s:
    import_cve.upsert_cves(s, driver)
print(f"  Done in {time.time()-start:.1f}s")

# ── Step 4: Import npm packages ─────────────────────────────────────────
print("\n" + "=" * 60)
print("STEP 4: npm Package Import")
print("=" * 60)
start = time.time()
import import_npm
with driver.session() as s:
    import_npm.import_packages(s)
    import_npm.import_depends_on(s)
    import_npm.import_domain_serves(s)
print(f"  Done in {time.time()-start:.1f}s")

# ── Step 5: Import threat intelligence ──────────────────────────────────
print("\n" + "=" * 60)
print("STEP 5: Threat Intelligence Import")
print("=" * 60)
start = time.time()
import import_threats
with driver.session() as s:
    import_threats.import_attributed_ips(s)
    import_threats.import_domains(s)
print(f"  Done in {time.time()-start:.1f}s")

# ── Step 6: Import synthetic data ───────────────────────────────────────
print("\n" + "=" * 60)
print("STEP 6: Synthetic Data Import")
print("=" * 60)
start = time.time()
import import_synthetic
with driver.session() as s:
    import_synthetic.import_account_ip_links(s)
    import_synthetic.import_fraud_signals(s)
print(f"  Done in {time.time()-start:.1f}s")

# ── Step 7: Verification ───────────────────────────────────────────────
print("\n" + "=" * 60)
print("VERIFICATION")
print("=" * 60)
with driver.session() as s:
    # Node counts by label
    counts = s.run(
        "MATCH (n) RETURN labels(n)[0] AS label, count(n) AS count ORDER BY count DESC"
    ).data()
    total_nodes = sum(c["count"] for c in counts)
    print(f"  Total nodes: {total_nodes}")
    for c in counts:
        print(f"    {c['label']}: {c['count']}")

    # Relationship counts
    rels = s.run(
        "MATCH ()-[r]->() RETURN type(r) AS type, count(r) AS count ORDER BY count DESC"
    ).data()
    total_rels = sum(r["count"] for r in rels)
    print(f"\n  Total relationships: {total_rels}")
    for r in rels:
        print(f"    {r['type']}: {r['count']}")

    # Demo chain: ua-parser-js → ... → FraudSignal
    print("\n  Demo chain verification:")
    chain = s.run("""
        MATCH (pkg:Package {name: 'ua-parser-js'})-[:PUBLISHED_BY]->(acct:Account)
              -[:LINKED_TO]->(ip:IP)
        OPTIONAL MATCH (ip)-[:ASSOCIATED_WITH]->(fs:FraudSignal)
        OPTIONAL MATCH (ip)<-[:OPERATES]-(ta:ThreatActor)
        RETURN pkg.name AS package, acct.username AS publisher,
               ip.address AS ip, ta.name AS actor,
               collect(DISTINCT fs.juspay_id) AS fraud_ids
    """).data()
    if chain:
        for row in chain:
            print(f"    {row}")
    else:
        print("    WARNING: Demo chain not found!")

driver.close()
print("\n" + "=" * 60)
print("ALL IMPORTS COMPLETE")
print("=" * 60)
