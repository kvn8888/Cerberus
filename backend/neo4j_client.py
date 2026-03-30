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

from neo4j import GraphDatabase

import config


# ── Driver (module-level singleton) ───────────────────────────────────────────

_driver = None


def _get_driver():
    global _driver
    if _driver is None:
        _driver = GraphDatabase.driver(
            config.require("NEO4J_URI"),
            auth=(
                config.require("NEO4J_USERNAME"),
                config.require("NEO4J_PASSWORD"),
            ),
        )
    return _driver


def close():
    global _driver
    if _driver is not None:
        _driver.close()
        _driver = None


# ── Entity-type routing ───────────────────────────────────────────────────────

def _entity_key(entity_type: str) -> str:
    """Return the node property that identifies the entity."""
    return {
        "package":      "name",
        "ip":           "address",
        "domain":       "name",
        "cve":          "id",
        "threatactor":  "name",
        "fraudsignal":  "juspay_id",
    }.get(entity_type.lower(), "name")


def _entity_label(entity_type: str) -> str:
    return {
        "package":     "Package",
        "ip":          "IP",
        "domain":      "Domain",
        "cve":         "CVE",
        "threatactor": "ThreatActor",
        "fraudsignal": "FraudSignal",
    }.get(entity_type.lower(), "Package")


# ── Cache check ───────────────────────────────────────────────────────────────

_CACHE_CHECK_TMPL = """
MATCH path = shortestPath(
  (start:{label} {{{key}: $value}})-[*..6]-(ta:ThreatActor)
)
WHERE ALL(r IN relationships(path) WHERE r.confirmed = true)
RETURN path, true AS from_cache, start.cached_narrative AS narrative
LIMIT 1
"""

def cache_check(entity: str, entity_type: str) -> list[dict] | None:
    label = _entity_label(entity_type)
    key   = _entity_key(entity_type)
    cypher = _CACHE_CHECK_TMPL.format(label=label, key=key)
    with _get_driver().session() as s:
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
  (start:{label} {{{key}: $value}})-[*..5]-(ta:ThreatActor)
)
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

    with _get_driver().session() as s:
        if etype == "package":
            r1 = s.run(_TRAVERSE_PACKAGE, value=entity)
            paths = [r.data() for r in r1]
            r2 = s.run(_TRAVERSE_PACKAGE_CROSS, value=entity)
            cross_domain = [r.data() for r in r2]

        elif etype == "ip":
            r1 = s.run(_TRAVERSE_IP, value=entity)
            paths = [r.data() for r in r1]

        elif etype == "fraudsignal":
            r1 = s.run(_TRAVERSE_FRAUD, value=entity)
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
  (start:{label} {{{key}: $value}})-[*..6]-(ta:ThreatActor)
)
WITH start, nodes(path) AS ns, relationships(path) AS rs
FOREACH (n IN ns | SET n.last_analyzed = timestamp())
FOREACH (r IN rs | SET r.last_analyzed = timestamp())
SET start.cached_narrative = $narrative,
    start.cached_narrative_hash = $narrative_hash
"""

def write_back(entity: str, entity_type: str, narrative: str | None = None) -> None:
    label  = _entity_label(entity_type)
    key    = _entity_key(entity_type)
    cypher = _WRITE_BACK.format(label=label, key=key)
    narrative = narrative or ""
    with _get_driver().session() as s:
        s.run(
            cypher,
            value=entity,
            narrative=narrative,
            narrative_hash=hashlib.sha256(narrative.encode("utf-8")).hexdigest(),
        )


# ── Confirm pattern (analyst-validated, triggers cache) ──────────────────────

_CONFIRM = """
MATCH path = shortestPath(
  (start:{label} {{{key}: $value}})-[*..6]-(ta:ThreatActor)
)
FOREACH (n IN nodes(path) | SET n:ConfirmedThreat)
FOREACH (r IN relationships(path) |
  SET r.confirmed    = true,
      r.confirmed_at = timestamp()
)
"""

def confirm(entity: str, entity_type: str) -> None:
    label  = _entity_label(entity_type)
    key    = _entity_key(entity_type)
    cypher = _CONFIRM.format(label=label, key=key)
    with _get_driver().session() as s:
        s.run(cypher, value=entity)


def get_graph(entity: str, entity_type: str) -> dict[str, Any]:
    """
    Run the same traversal as traverse() but return nodes + links
    formatted for the frontend force-directed graph (react-force-graph-2d).

    Returns: {"nodes": [{id, label, type, val}, ...], "links": [{source, target, type, dashed?}, ...]}
    """
    label = _entity_label(entity_type)
    key   = _entity_key(entity_type)
    etype = entity_type.lower()

    nodes_map: dict[str, dict] = {}   # dedup by id
    links: list[dict] = []

    def _add_node(name: str, node_label: str, val: int = 5):
        if name and name not in nodes_map:
            nodes_map[name] = {"id": name, "label": name, "type": node_label, "val": val}

    def _add_link(src: str, tgt: str, rel_type: str, dashed: bool = False):
        if src and tgt:
            links.append({"source": src, "target": tgt, "type": rel_type, "dashed": dashed})

    # Extract nodes and links from Neo4j Path objects
    _GRAPH_PATH_QUERY = """
    MATCH path = shortestPath(
      (start:{label} {{{key}: $value}})-[*..6]-(ta:ThreatActor)
    )
    RETURN path
    LIMIT 10
    """.format(label=label, key=key)

    with _get_driver().session() as s:
        # Main path traversal
        result = s.run(_GRAPH_PATH_QUERY, value=entity)
        for record in result:
            path = record["path"]
            for node in path.nodes:
                labels = list(node.labels)
                # Pick the most specific label (skip ConfirmedThreat)
                node_type = next((l for l in labels if l != "ConfirmedThreat"), labels[0] if labels else "Unknown")
                # Determine the display name from common properties
                name = (
                    node.get("name")
                    or node.get("id")
                    or node.get("address")
                    or node.get("juspay_id")
                    or node.get("username")
                    or node.get("mitre_id")
                    or str(node.element_id)
                )
                size = 7 if node_type in ("Package", "ThreatActor") else 5
                _add_node(name, node_type, size)

            for rel in path.relationships:
                start_node = rel.start_node
                end_node   = rel.end_node
                src = (
                    start_node.get("name") or start_node.get("id")
                    or start_node.get("address") or start_node.get("juspay_id")
                    or start_node.get("username") or start_node.get("mitre_id")
                    or str(start_node.element_id)
                )
                tgt = (
                    end_node.get("name") or end_node.get("id")
                    or end_node.get("address") or end_node.get("juspay_id")
                    or end_node.get("username") or end_node.get("mitre_id")
                    or str(end_node.element_id)
                )
                rel_type = rel.type
                # Mark LINKED_TO as synthetic (dashed edge)
                is_synthetic = rel_type == "LINKED_TO"
                _add_link(src, tgt, rel_type, dashed=is_synthetic)

        # Cross-domain query for package type (adds fraud signals)
        if etype == "package":
            cross = s.run(_TRAVERSE_PACKAGE_CROSS, value=entity)
            for r in cross:
                pkg_name = r.get("package")
                publisher = r.get("publisher")
                ip_addr = r.get("ip")
                actor = r.get("actor")
                fraud_types = r.get("fraud_types", [])

                if pkg_name: _add_node(pkg_name, "Package", 7)
                if publisher: _add_node(publisher, "Account", 4)
                if ip_addr: _add_node(ip_addr, "IP", 5)
                if actor: _add_node(actor, "ThreatActor", 7)

                if pkg_name and publisher:
                    _add_link(pkg_name, publisher, "PUBLISHED_BY")
                if publisher and ip_addr:
                    _add_link(publisher, ip_addr, "LINKED_TO", dashed=True)
                if ip_addr and actor:
                    _add_link(actor, ip_addr, "OPERATES")

                # Add fraud signal nodes if any
                for i, ft in enumerate(fraud_types):
                    if ft and ip_addr:
                        fs_id = f"fraud-{ip_addr}-{i}"
                        _add_node(fs_id, "FraudSignal", 4)
                        _add_link(ip_addr, fs_id, "ASSOCIATED_WITH")

    # Ensure the queried entity is always the root node with largest size
    if entity in nodes_map:
        nodes_map[entity]["val"] = 8

    return {"nodes": list(nodes_map.values()), "links": links}


def get_schema() -> dict[str, list[dict[str, Any]] | list[str]]:
    with _get_driver().session() as s:
        labels = [r["label"] for r in s.run("CALL db.labels() YIELD label")]
        rel_types = [
            r["relationshipType"]
            for r in s.run("CALL db.relationshipTypes() YIELD relationshipType")
        ]
        counts = s.run(
            "MATCH (n) RETURN labels(n)[0] AS label, count(n) AS count"
        ).data()
    return {"labels": labels, "relationship_types": rel_types, "counts": counts}


def ingest_fraud_signals(signals: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Upsert Juspay-style fraud signals and connect them to IPs.
    Returns a small summary useful for UI and pipeline output.
    """
    if not signals:
        return {"ingested": 0, "linked_ips": 0, "signal_ids": []}

    cypher = """
    UNWIND $signals AS sig
    MERGE (fs:FraudSignal {juspay_id: sig.juspay_id})
    SET fs.type      = sig.fraud_type,
        fs.amount    = sig.amount,
        fs.currency  = sig.currency,
        fs.timestamp = sig.timestamp,
        fs.merchant_id = sig.merchant_id,
        fs.synthetic = coalesce(sig.synthetic, false),
        fs.source    = coalesce(sig.source, 'juspay')
    WITH fs, sig
    MERGE (ip:IP {address: sig.ip_address})
    MERGE (ip)-[:ASSOCIATED_WITH]->(fs)
    RETURN count(fs) AS ingested
    """
    with _get_driver().session() as s:
        result = s.run(cypher, signals=signals)
        ingested = result.single()["ingested"]
    return {
        "ingested": ingested,
        "linked_ips": len({sig["ip_address"] for sig in signals}),
        "signal_ids": [sig["juspay_id"] for sig in signals],
    }


def get_juspay_summary(limit: int = 10) -> dict[str, Any]:
    with _get_driver().session() as s:
        totals = s.run(
            """
            MATCH (fs:FraudSignal)
            OPTIONAL MATCH (ip:IP)-[:ASSOCIATED_WITH]->(fs)
            RETURN count(DISTINCT fs) AS signals,
                   count(DISTINCT ip) AS ips,
                   coalesce(sum(fs.amount), 0) AS total_amount
            """
        ).single()
        by_type = s.run(
            """
            MATCH (fs:FraudSignal)
            RETURN fs.type AS type, count(*) AS count
            ORDER BY count DESC, type ASC
            """
        ).data()
        actor_links = s.run(
            """
            MATCH (ta:ThreatActor)-[:OPERATES]->(ip:IP)-[:ASSOCIATED_WITH]->(fs:FraudSignal)
            RETURN ta.name AS actor, count(DISTINCT fs) AS signal_count
            ORDER BY signal_count DESC, actor ASC
            LIMIT $limit
            """,
            limit=limit,
        ).data()
        recent = s.run(
            """
            MATCH (ip:IP)-[:ASSOCIATED_WITH]->(fs:FraudSignal)
            RETURN fs.juspay_id AS juspay_id,
                   fs.type AS type,
                   fs.amount AS amount,
                   fs.currency AS currency,
                   ip.address AS ip_address
            ORDER BY fs.timestamp DESC, fs.juspay_id ASC
            LIMIT $limit
            """,
            limit=limit,
        ).data()

    return {
        "signals": totals["signals"],
        "linked_ips": totals["ips"],
        "total_amount": totals["total_amount"],
        "by_type": by_type,
        "actor_links": actor_links,
        "recent_signals": recent,
    }
