#!/usr/bin/env python3
"""
import_mitre.py — Import MITRE ATT&CK data into Neo4j.

Downloads the MITRE ATT&CK Enterprise STIX 2.1 bundle from GitHub,
extracts Technique and ThreatActor (intrusion-set) nodes, and their
USES relationships, then bulk-MERGEs everything into Neo4j.

Target volumes:
  ~200 techniques + ~100 groups → ~500 USES relationships

Requires env vars:
  NEO4J_URI        — bolt URI (e.g., neo4j+s://xxx.databases.neo4j.io)
  NEO4J_USERNAME   — usually "neo4j"
  NEO4J_PASSWORD   — Aura instance password

Usage:
  export NEO4J_URI=neo4j+s://...
  export NEO4J_USERNAME=neo4j
  export NEO4J_PASSWORD=...
  python import_mitre.py
"""

import json
import os
import sys
import urllib.request
from neo4j import GraphDatabase

# ── Configuration ──────────────────────────────────────────────
# The official MITRE ATT&CK STIX 2.1 bundle for the Enterprise matrix.
# This JSON file contains all techniques, groups, software, and relationships.
STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

# Local cache path so we don't re-download every run
CACHE_PATH = os.path.join("seed_data", "enterprise-attack.json")


def get_env(name: str) -> str:
    """Read a required environment variable or exit with an error."""
    val = os.environ.get(name)
    if not val:
        print(f"ERROR: {name} environment variable is required")
        sys.exit(1)
    return val


def download_stix_bundle() -> dict:
    """
    Download (or load from cache) the MITRE ATT&CK STIX bundle.
    Returns the parsed JSON as a dict with an 'objects' list.
    """
    if os.path.exists(CACHE_PATH):
        print(f"  Using cached STIX bundle: {CACHE_PATH}")
        with open(CACHE_PATH, "r") as f:
            return json.load(f)

    print(f"  Downloading STIX bundle from {STIX_URL} ...")
    os.makedirs("seed_data", exist_ok=True)
    urllib.request.urlretrieve(STIX_URL, CACHE_PATH)
    print(f"  Saved to {CACHE_PATH}")

    with open(CACHE_PATH, "r") as f:
        return json.load(f)


def extract_techniques(stix_objects: list) -> list[dict]:
    """
    Pull attack-pattern objects (techniques) from the STIX bundle.
    Each technique gets its MITRE ID (e.g., T1059), name, and tactic.
    We skip sub-techniques to keep the graph manageable for the demo.
    """
    techniques = []
    for obj in stix_objects:
        # attack-pattern = technique in STIX vocabulary
        if obj.get("type") != "attack-pattern":
            continue
        # Skip revoked/deprecated techniques
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        # Extract the MITRE ID from external_references
        mitre_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                mitre_id = ref.get("external_id")
                break

        if not mitre_id:
            continue

        # Skip sub-techniques (they contain a dot, e.g., T1059.001)
        if "." in mitre_id:
            continue

        # Extract the first tactic from kill_chain_phases
        tactic = None
        phases = obj.get("kill_chain_phases", [])
        if phases:
            tactic = phases[0].get("phase_name", "").replace("-", " ")

        techniques.append({
            "mitre_id": mitre_id,
            "name": obj.get("name", ""),
            "tactic": tactic or "unknown",
        })

    return techniques


def extract_groups(stix_objects: list) -> list[dict]:
    """
    Pull intrusion-set objects (threat actor groups) from the STIX bundle.
    Each group gets its name and a list of known aliases.
    """
    groups = []
    for obj in stix_objects:
        # intrusion-set = threat actor group in STIX vocabulary
        if obj.get("type") != "intrusion-set":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        groups.append({
            "name": obj.get("name", ""),
            "aliases": obj.get("aliases", []),
            "stix_id": obj.get("id"),  # needed to resolve relationships
        })

    return groups


def extract_uses_relationships(stix_objects: list) -> list[dict]:
    """
    Pull 'uses' relationships from the STIX bundle.
    These connect intrusion-sets (groups) to attack-patterns (techniques).
    Returns a list of (source_stix_id, target_stix_id) pairs.
    """
    rels = []
    for obj in stix_objects:
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "uses":
            continue
        if obj.get("revoked"):
            continue

        source = obj.get("source_ref", "")
        target = obj.get("target_ref", "")

        # We only want group → technique relationships
        if source.startswith("intrusion-set--") and target.startswith("attack-pattern--"):
            rels.append({"source": source, "target": target})

    return rels


def import_to_neo4j(techniques: list, groups: list, relationships: list):
    """
    Bulk-MERGE all extracted data into Neo4j.
    Uses UNWIND for batched writes — more efficient than individual MERGEs.
    """
    uri = get_env("NEO4J_URI")
    user = get_env("NEO4J_USERNAME")
    password = get_env("NEO4J_PASSWORD")

    driver = GraphDatabase.driver(uri, auth=(user, password))

    with driver.session() as session:
        # ── Step 1: MERGE Technique nodes ──────────────────────
        # UNWIND takes the whole list at once — Neo4j processes them
        # in a single transaction instead of one-by-one round trips.
        print(f"  Importing {len(techniques)} techniques ...")
        session.run(
            """
            UNWIND $techniques AS t
            MERGE (tech:Technique {mitre_id: t.mitre_id})
            SET tech.name = t.name,
                tech.tactic = t.tactic
            """,
            techniques=techniques,
        )

        # ── Step 2: MERGE ThreatActor nodes ────────────────────
        # We store the STIX ID temporarily so we can resolve
        # relationships, then remove it after linking.
        print(f"  Importing {len(groups)} threat actor groups ...")
        session.run(
            """
            UNWIND $groups AS g
            MERGE (ta:ThreatActor {name: g.name})
            SET ta.aliases = g.aliases,
                ta._stix_id = g.stix_id
            """,
            groups=groups,
        )

        # ── Step 3: Build a lookup map for technique STIX IDs ──
        # We need to map STIX IDs to MITRE IDs for the relationship step.
        tech_stix_map = {}
        for obj in _all_stix_objects:
            if obj.get("type") == "attack-pattern" and not obj.get("revoked"):
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        mid = ref.get("external_id")
                        if mid and "." not in mid:
                            tech_stix_map[obj["id"]] = mid

        # ── Step 4: Create USES relationships ──────────────────
        # Map STIX IDs to domain keys so we can MATCH on them.
        resolved_rels = []
        for rel in relationships:
            mitre_id = tech_stix_map.get(rel["target"])
            if mitre_id:
                resolved_rels.append({
                    "group_stix_id": rel["source"],
                    "technique_mitre_id": mitre_id,
                })

        print(f"  Creating {len(resolved_rels)} USES relationships ...")
        session.run(
            """
            UNWIND $rels AS r
            MATCH (ta:ThreatActor {_stix_id: r.group_stix_id})
            MATCH (tech:Technique {mitre_id: r.technique_mitre_id})
            MERGE (ta)-[:USES]->(tech)
            """,
            rels=resolved_rels,
        )

        # ── Step 5: Clean up temporary STIX IDs ────────────────
        # We don't need _stix_id in production — it was only used
        # to resolve the STIX relationship references.
        print("  Cleaning up temporary STIX IDs ...")
        session.run("MATCH (ta:ThreatActor) REMOVE ta._stix_id")

    driver.close()


# Module-level reference so import_to_neo4j can access the raw STIX objects
# for building the technique STIX ID → MITRE ID mapping.
_all_stix_objects = []


def main():
    global _all_stix_objects

    print("=== MITRE ATT&CK Import ===")

    # Download or load the STIX bundle
    bundle = download_stix_bundle()
    _all_stix_objects = bundle.get("objects", [])
    print(f"  Total STIX objects: {len(_all_stix_objects)}")

    # Extract the data we need
    techniques = extract_techniques(_all_stix_objects)
    groups = extract_groups(_all_stix_objects)
    relationships = extract_uses_relationships(_all_stix_objects)

    print(f"  Extracted: {len(techniques)} techniques, {len(groups)} groups, "
          f"{len(relationships)} uses-relationships")

    # Import into Neo4j
    import_to_neo4j(techniques, groups, relationships)

    print("✅ MITRE ATT&CK import complete")


if __name__ == "__main__":
    main()
