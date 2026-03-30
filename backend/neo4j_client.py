"""
neo4j_client.py — Thin wrapper around the Neo4j driver.

Provides:
  - cache_check(entity, entity_type) -> list[dict] | None
  - traverse(entity, entity_type)    -> list[dict]
  - write_back(entity, entity_type)  -> None  (analysis timestamp + narrative hash)
  - confirm(entity, entity_type)     -> None  (marks :ConfirmedThreat + r.confirmed)
"""

from __future__ import annotations

import hashlib
from typing import Any

from neo4j import GraphDatabase, ManagedTransaction

import config


# ── Driver (module-level singleton) ───────────────────────────────────────────

_driver = GraphDatabase.driver(
    config.NEO4J_URI,
    auth=(config.NEO4J_USERNAME, config.NEO4J_PASSWORD),
)


def close():
    _driver.close()


# ── Entity-type routing ───────────────────────────────────────────────────────

def _entity_key(entity_type: str) -> str:
    """Return the node property that identifies the entity."""
    return {
        "package":      "name",
        "ip":           "address",
        "domain":       "name",
        "cve":          "id",
        "threatactor":  "name",
    }.get(entity_type.lower(), "name")


def _entity_label(entity_type: str) -> str:
    return {
        "package":     "Package",
        "ip":          "IP",
        "domain":      "Domain",
        "cve":         "CVE",
        "threatactor": "ThreatActor",
    }.get(entity_type.lower(), "Package")


# ── Cache check ───────────────────────────────────────────────────────────────

_CACHE_CHECK_TMPL = """
MATCH path = shortestPath(
  (start:{label} {{{key}: $value}})-[*]-(ta:ThreatActor)
)
WHERE ALL(r IN relationships(path) WHERE r.confirmed = true)
RETURN path, true AS from_cache
LIMIT 1
"""

def cache_check(entity: str, entity_type: str) -> list[dict] | None:
    label = _entity_label(entity_type)
    key   = _entity_key(entity_type)
    cypher = _CACHE_CHECK_TMPL.format(label=label, key=key)
    with _driver.session() as s:
        result = s.run(cypher, value=entity)
        records = [r.data() for r in result]
        return records if records else None


# ── Traversal queries (by domain) ─────────────────────────────────────────────

# software_supply_chain: Package -> Account -> IP -> ThreatActor
_TRAVERSE_PACKAGE = """
MATCH path = shortestPath(
  (p:Package {name: $value})-[*..6]->(ta:ThreatActor)
)
RETURN path
LIMIT 10
"""

# Also try the cross-domain connection discovery query
_TRAVERSE_PACKAGE_CROSS = """
MATCH (pkg:Package {name: $value})-[:PUBLISHED_BY]->(acct:Account)
      -[:LINKED_TO]->(ip:IP)
OPTIONAL MATCH (ip)-[:ASSOCIATED_WITH]->(fs:FraudSignal)
OPTIONAL MATCH (ip)<-[:OPERATES]-(ta:ThreatActor)
RETURN pkg.name         AS package,
       acct.username    AS publisher,
       ip.address       AS ip,
       ta.name          AS actor,
       collect(fs.type) AS fraud_types,
       collect(fs.amount) AS fraud_amounts
LIMIT 10
"""

# infrastructure: IP -> Domain -> ThreatActor
_TRAVERSE_IP = """
MATCH path = shortestPath(
  (i:IP {address: $value})-[*..5]->(ta:ThreatActor)
)
RETURN path
LIMIT 10
"""

# financial: FraudSignal -> IP -> Account -> Package
_TRAVERSE_FRAUD = """
MATCH path = shortestPath(
  (fs:FraudSignal)-[*..6]-(p:Package {name: $value})
)
RETURN path
LIMIT 10
"""

# fallback: bidirectional
_TRAVERSE_GENERIC = """
MATCH path = allShortestPaths(
  (start:{label} {{{key}: $value}})-[*]-(ta:ThreatActor)
)
WHERE length(path) <= 5
RETURN path
LIMIT 10
"""


def traverse(entity: str, entity_type: str) -> dict[str, Any]:
    """
    Run domain-appropriate traversal.  Returns:
      {"paths": [...], "cross_domain": [...], "paths_found": int}
    """
    etype = entity_type.lower()
    paths: list[dict]       = []
    cross_domain: list[dict] = []

    with _driver.session() as s:
        if etype == "package":
            r1 = s.run(_TRAVERSE_PACKAGE, value=entity)
            paths = [r.data() for r in r1]
            r2 = s.run(_TRAVERSE_PACKAGE_CROSS, value=entity)
            cross_domain = [r.data() for r in r2]

        elif etype == "ip":
            r1 = s.run(_TRAVERSE_IP, value=entity)
            paths = [r.data() for r in r1]

        else:
            label  = _entity_label(entity_type)
            key    = _entity_key(entity_type)
            cypher = _TRAVERSE_GENERIC.format(label=label, key=key)
            r1 = s.run(cypher, value=entity)
            paths = [r.data() for r in r1]

    return {
        "paths":        paths,
        "cross_domain": cross_domain,
        "paths_found":  max(len(paths), len(cross_domain)),
    }


# ── Write-back (post-analysis tagging) ───────────────────────────────────────

_WRITE_BACK = """
MATCH path = shortestPath(
  (start:{label} {{{key}: $value}})-[*]-(ta:ThreatActor)
)
WHERE length(path) <= 6
WITH nodes(path) AS ns, relationships(path) AS rs
FOREACH (n IN ns | SET n.last_analyzed = timestamp())
FOREACH (r IN rs | SET r.last_analyzed = timestamp())
"""

def write_back(entity: str, entity_type: str) -> None:
    label  = _entity_label(entity_type)
    key    = _entity_key(entity_type)
    cypher = _WRITE_BACK.format(label=label, key=key)
    with _driver.session() as s:
        s.run(cypher, value=entity)


# ── Confirm pattern (analyst-validated, triggers cache) ──────────────────────

_CONFIRM = """
MATCH path = shortestPath(
  (start:{label} {{{key}: $value}})-[*]-(ta:ThreatActor)
)
WHERE length(path) <= 6
WITH nodes(path) AS ns, relationships(path) AS rs
FOREACH (n IN ns | SET n:ConfirmedThreat)
FOREACH (r IN rs |
  SET r.confirmed    = true,
      r.confirmed_at = timestamp()
)
"""

def confirm(entity: str, entity_type: str) -> None:
    label  = _entity_label(entity_type)
    key    = _entity_key(entity_type)
    cypher = _CONFIRM.format(label=label, key=key)
    with _driver.session() as s:
        s.run(cypher, value=entity)
