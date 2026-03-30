#!/usr/bin/env python3
"""
import_mitre.py — Imports MITRE ATT&CK Enterprise techniques and threat actor
groups from the official STIX 2.1 bundle on GitHub.

Writes:
  ~700 Technique nodes  (attack-pattern objects)
  ~130 ThreatActor nodes (intrusion-set objects)
  ~500 (:ThreatActor)-[:USES]->(:Technique) relationships

Requires: NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD env vars.
"""

import os
import json
import sys
import requests
from dotenv import load_dotenv
from neo4j import GraphDatabase

load_dotenv()

NEO4J_URI  = os.environ["NEO4J_URI"]
NEO4J_USER = os.environ["NEO4J_USERNAME"]
NEO4J_PASS = os.environ["NEO4J_PASSWORD"]

STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

BATCH_SIZE = 100


def fetch_stix_bundle() -> dict:
    print("Fetching MITRE ATT&CK STIX bundle (this is ~10MB, one moment)...")
    r = requests.get(STIX_URL, timeout=60)
    r.raise_for_status()
    return r.json()


def parse_bundle(bundle: dict):
    objects = bundle.get("objects", [])

    techniques: list[dict] = []
    actors: list[dict] = []
    stix_id_to_mitre_id: dict[str, str] = {}   # stix_id -> mitre_id (T####)
    stix_id_to_actor_name: dict[str, str] = {}  # stix_id -> group name
    uses_rels: list[tuple[str, str]] = []        # (actor_stix_id, technique_stix_id)

    for obj in objects:
        otype = obj.get("type")

        if otype == "attack-pattern" and not obj.get("revoked", False):
            mitre_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    mitre_id = ref.get("external_id")
                    break
            if mitre_id:
                tactic = None
                kill_chain = obj.get("kill_chain_phases", [])
                if kill_chain:
                    tactic = kill_chain[0].get("phase_name", "unknown")
                techniques.append({
                    "stix_id": obj["id"],
                    "mitre_id": mitre_id,
                    "name": obj.get("name", ""),
                    "tactic": tactic,
                })
                stix_id_to_mitre_id[obj["id"]] = mitre_id

        elif otype == "intrusion-set" and not obj.get("revoked", False):
            aliases = obj.get("aliases", [])
            actors.append({
                "stix_id": obj["id"],
                "name": obj.get("name", ""),
                "aliases": aliases,
                "attribution_confidence": 50,
            })
            stix_id_to_actor_name[obj["id"]] = obj.get("name", "")

        elif otype == "relationship":
            if (
                obj.get("relationship_type") == "uses"
                and obj.get("source_ref", "").startswith("intrusion-set--")
                and obj.get("target_ref", "").startswith("attack-pattern--")
            ):
                uses_rels.append((obj["source_ref"], obj["target_ref"]))

    return techniques, actors, uses_rels, stix_id_to_mitre_id, stix_id_to_actor_name


def import_techniques(session, techniques: list[dict]):
    print(f"  Importing {len(techniques)} techniques...")
    for i in range(0, len(techniques), BATCH_SIZE):
        batch = techniques[i : i + BATCH_SIZE]
        session.run(
            """
            UNWIND $batch AS t
            MERGE (n:Technique {mitre_id: t.mitre_id})
            SET n.name   = t.name,
                n.tactic = t.tactic
            """,
            batch=batch,
        )
    print(f"  Done — {len(techniques)} techniques upserted.")


def import_actors(session, actors: list[dict]):
    print(f"  Importing {len(actors)} threat actors...")
    for i in range(0, len(actors), BATCH_SIZE):
        batch = actors[i : i + BATCH_SIZE]
        session.run(
            """
            UNWIND $batch AS a
            MERGE (n:ThreatActor {name: a.name})
            SET n.aliases                = a.aliases,
                n.attribution_confidence = a.attribution_confidence
            """,
            batch=batch,
        )
    print(f"  Done — {len(actors)} actors upserted.")


def import_uses(
    session,
    uses_rels: list[tuple[str, str]],
    stix_id_to_mitre_id: dict[str, str],
    stix_id_to_actor_name: dict[str, str],
):
    print(f"  Importing {len(uses_rels)} USES relationships...")
    resolved = []
    for actor_stix, tech_stix in uses_rels:
        actor_name = stix_id_to_actor_name.get(actor_stix)
        mitre_id   = stix_id_to_mitre_id.get(tech_stix)
        if actor_name and mitre_id:
            resolved.append({"actor_name": actor_name, "mitre_id": mitre_id})

    for i in range(0, len(resolved), BATCH_SIZE):
        batch = resolved[i : i + BATCH_SIZE]
        session.run(
            """
            UNWIND $batch AS r
            MATCH (a:ThreatActor {name: r.actor_name})
            MATCH (t:Technique   {mitre_id: r.mitre_id})
            MERGE (a)-[:USES]->(t)
            """,
            batch=batch,
        )
    print(f"  Done — {len(resolved)} USES relationships upserted.")


def main():
    bundle = fetch_stix_bundle()
    techniques, actors, uses_rels, stix_id_to_mitre_id, stix_id_to_actor_name = (
        parse_bundle(bundle)
    )
    print(
        f"Parsed: {len(techniques)} techniques, {len(actors)} actors, "
        f"{len(uses_rels)} uses relationships"
    )

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
    with driver.session() as session:
        import_techniques(session, techniques)
        import_actors(session, actors)
        import_uses(session, uses_rels, stix_id_to_mitre_id, stix_id_to_actor_name)
    driver.close()
    print("MITRE ATT&CK import complete.")


if __name__ == "__main__":
    main()
