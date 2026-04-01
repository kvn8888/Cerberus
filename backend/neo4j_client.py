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


# ── Entity alias normalization ─────────────────────────────────────────────────
# Maps common vulnerability/malware nicknames to canonical identifiers + type.
# Applied before every graph query so "log4shell" resolves to CVE-2021-44228.

_ENTITY_ALIASES: dict[str, tuple[str, str]] = {
    # (canonical_value, canonical_type)
    # CVE nicknames
    "log4shell":      ("CVE-2021-44228",  "cve"),
    "log4j":          ("CVE-2021-44228",  "cve"),
    "spring4shell":   ("CVE-2022-22965",  "cve"),
    "springshell":    ("CVE-2022-22965",  "cve"),
    "heartbleed":     ("CVE-2014-0160",   "cve"),
    "shellshock":     ("CVE-2014-6271",   "cve"),
    "eternalblue":    ("CVE-2017-0144",   "cve"),
    "bluekeep":       ("CVE-2019-0708",   "cve"),
    "zerologon":      ("CVE-2020-1472",   "cve"),
    "proxylogon":     ("CVE-2021-26855",  "cve"),
    "proxyshell":     ("CVE-2021-34473",  "cve"),
    "proxynotshell":  ("CVE-2022-41040",  "cve"),
    "dirty pipe":     ("CVE-2022-0847",   "cve"),
    "dirtypipe":      ("CVE-2022-0847",   "cve"),
    "dirty cow":      ("CVE-2016-5195",   "cve"),
    "dirtycow":       ("CVE-2016-5195",   "cve"),
    "poodle":         ("CVE-2014-3566",   "cve"),
    "spectre":        ("CVE-2017-5753",   "cve"),
    "meltdown":       ("CVE-2017-5754",   "cve"),
    "krack":          ("CVE-2017-13077",  "cve"),
    "printnightmare": ("CVE-2021-34527",  "cve"),
    "follina":        ("CVE-2022-30190",  "cve"),
    "citrixbleed":    ("CVE-2023-4966",   "cve"),
    "moveit":         ("CVE-2023-34362",  "cve"),
    "regresshion":    ("CVE-2024-6387",   "cve"),
    # Malware/campaign → threat actor
    "wannacry":       ("Lazarus Group",   "threatactor"),
    "notpetya":       ("Sandworm Team",   "threatactor"),
    "stuxnet":        ("Equation",        "threatactor"),
    "solarwinds":     ("APT29",           "threatactor"),
    "sunburst":       ("APT29",           "threatactor"),
    "revil":          ("REvil",           "threatactor"),
    "darkside":       ("DarkSide",        "threatactor"),
    "conti":          ("Wizard Spider",   "threatactor"),
    "emotet":         ("Mummy Spider",    "threatactor"),
    "trickbot":       ("Wizard Spider",   "threatactor"),
    "ryuk":           ("Wizard Spider",   "threatactor"),
    "lockbit":        ("LockBit",         "threatactor"),
    "cl0p":           ("FIN11",           "threatactor"),
    "clop":           ("FIN11",           "threatactor"),
}


def normalize_entity(entity: str, entity_type: str) -> tuple[str, str]:
    """Resolve common nicknames to canonical (entity, entity_type) pairs."""
    alias = _ENTITY_ALIASES.get(entity.strip().lower())
    if alias:
        return alias
    return (entity, entity_type)


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
    entity, entity_type = normalize_entity(entity, entity_type)
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
  (p:Package {name: $value})-[*..6]-(ta:ThreatActor)
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

# infrastructure: IP — bidirectional because relationships point inward
# (ThreatActor -[OPERATES]-> IP, Account -[LINKED_TO]-> IP)
_TRAVERSE_IP = """
MATCH path = shortestPath(
  (i:IP {address: $value})-[*..5]-(ta:ThreatActor)
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


_NEIGHBORHOOD = """
MATCH (start:{label} {{{key}: $value}})-[r]-(neighbor)
RETURN start, type(r) AS rel_type, labels(neighbor)[0] AS neighbor_label,
       coalesce(neighbor.name, neighbor.id, neighbor.address,
                neighbor.juspay_id, neighbor.username, neighbor.mitre_id) AS neighbor_id
LIMIT 25
"""


def traverse(entity: str, entity_type: str) -> dict[str, Any]:
    """
    Run domain-appropriate traversal.  Returns:
      {"paths": [...], "cross_domain": [...], "neighborhood": [...], "paths_found": int}

    If primary traversal finds no ThreatActor-anchored paths, falls back
    to a neighborhood query showing directly connected nodes so the user
    always sees *something* for entities that exist in the graph.
    """
    entity, entity_type = normalize_entity(entity, entity_type)
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
            r2 = s.run("""
                MATCH (ip:IP {address: $value})
                OPTIONAL MATCH (ip)<-[:LINKED_TO]-(acct:Account)-[:PUBLISHED_BY]-(pkg:Package)
                OPTIONAL MATCH (ip)-[:ASSOCIATED_WITH]->(fs:FraudSignal)
                OPTIONAL MATCH (ip)<-[:OPERATES]-(ta:ThreatActor)
                OPTIONAL MATCH (ip)-[:HOSTS]->(d:Domain)
                RETURN ip.address AS ip,
                       collect(DISTINCT ta.name) AS actors,
                       collect(DISTINCT acct.username) AS accounts,
                       collect(DISTINCT pkg.name) AS packages,
                       collect(DISTINCT d.name) AS domains,
                       collect(DISTINCT fs.type) AS fraud_types
                LIMIT 1
            """, value=entity)
            cross_domain = [r.data() for r in r2]

        elif etype == "fraudsignal":
            r1 = s.run(_TRAVERSE_FRAUD, value=entity)
            paths = [r.data() for r in r1]

        else:
            label  = _entity_label(entity_type)
            key    = _entity_key(entity_type)
            cypher = _TRAVERSE_GENERIC.format(label=label, key=key)
            r1 = s.run(cypher, value=entity)
            paths = [r.data() for r in r1]

    found = max(len(paths), len(cross_domain))

    # Fallback: if no ThreatActor path, show immediate neighbors
    neighborhood: list[dict] = []
    if found == 0:
        label = _entity_label(entity_type)
        key   = _entity_key(entity_type)
        cypher = _NEIGHBORHOOD.format(label=label, key=key)
        with _get_driver().session() as s:
            neighborhood = [r.data() for r in s.run(cypher, value=entity)]

    return {
        "paths":        paths,
        "cross_domain": cross_domain,
        "neighborhood": neighborhood,
        "paths_found":  max(found, len(neighborhood)),
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
    entity, entity_type = normalize_entity(entity, entity_type)
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

def confirm(entity: str, entity_type: str) -> dict:
    """
    Mark all relationships on the shortest threat path as confirmed=true
    and tag nodes as :ConfirmedThreat. Returns the count of confirmed relationships
    so the frontend can display feedback about the self-improvement write-back.
    """
    entity, entity_type = normalize_entity(entity, entity_type)
    label  = _entity_label(entity_type)
    key    = _entity_key(entity_type)
    cypher = _CONFIRM.format(label=label, key=key)
    # Run confirmation, then count how many relationships were tagged
    count_cypher = f"""
        MATCH path = shortestPath(
            (start:{label} {{{key}: $value}})-[*..6]-(ta:ThreatActor)
        )
        WHERE ALL(r IN relationships(path) WHERE r.confirmed = true)
        RETURN size(relationships(path)) AS rel_count
        LIMIT 1
    """
    with _get_driver().session() as s:
        s.run(cypher, value=entity)
        count_result = s.run(count_cypher, value=entity)
        if hasattr(count_result, "single"):
            result = count_result.single()
        else:
            result = next(iter(count_result), None)
        rel_count = result["rel_count"] if result else 0
    return {"count": rel_count}


def get_graph(entity: str, entity_type: str) -> dict[str, Any]:
    """
    Run the same traversal as traverse() but return nodes + links
    formatted for the frontend force-directed graph (react-force-graph-2d).

    Returns: {"nodes": [{id, label, type, val}, ...], "links": [{source, target, type, dashed?}, ...]}
    """
    entity, entity_type = normalize_entity(entity, entity_type)
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

        # Cross-domain enrichment for IP type
        if etype == "ip":
            cross = s.run("""
                MATCH (ip:IP {address: $value})
                OPTIONAL MATCH (ip)<-[:LINKED_TO]-(acct:Account)-[:PUBLISHED_BY]-(pkg:Package)
                OPTIONAL MATCH (ip)-[:ASSOCIATED_WITH]->(fs:FraudSignal)
                OPTIONAL MATCH (ip)<-[:OPERATES]-(ta:ThreatActor)
                OPTIONAL MATCH (ip)-[:HOSTS]->(d:Domain)
                RETURN ip.address AS ip, acct.username AS publisher, pkg.name AS package,
                       ta.name AS actor, d.name AS domain,
                       fs.juspay_id AS fraud_id, fs.type AS fraud_type
            """, value=entity)
            for r in cross:
                ip_addr = r.get("ip")
                publisher = r.get("publisher")
                pkg_name = r.get("package")
                actor = r.get("actor")
                domain = r.get("domain")
                fraud_id = r.get("fraud_id")
                fraud_type = r.get("fraud_type")

                if ip_addr: _add_node(ip_addr, "IP", 8)
                if publisher: _add_node(publisher, "Account", 4)
                if pkg_name: _add_node(pkg_name, "Package", 7)
                if actor: _add_node(actor, "ThreatActor", 7)
                if domain: _add_node(domain, "Domain", 5)
                if fraud_id: _add_node(fraud_id, "FraudSignal", 4)

                if publisher and ip_addr:
                    _add_link(publisher, ip_addr, "LINKED_TO", dashed=True)
                if pkg_name and publisher:
                    _add_link(pkg_name, publisher, "PUBLISHED_BY")
                if actor and ip_addr:
                    _add_link(actor, ip_addr, "OPERATES")
                if ip_addr and domain:
                    _add_link(ip_addr, domain, "HOSTS")
                if ip_addr and fraud_id:
                    _add_link(ip_addr, fraud_id, "ASSOCIATED_WITH")

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


def get_memory() -> dict[str, Any]:
    """
    Return memorized entities and their confirmed relationships for the
    Memory visualization. Excludes Technique nodes (MITRE ATT&CK) to keep
    the view focused on the core entities the user actually investigated.
    """
    nodes_map: dict[str, dict] = {}
    links_set: set[tuple[str, str, str]] = set()
    links: list[dict] = []

    def _node_name(node) -> str:
        return (
            node.get("name") or node.get("id") or node.get("address")
            or node.get("juspay_id") or node.get("username")
            or node.get("mitre_id") or str(node.element_id)
        )

    with _get_driver().session() as s:
        result = s.run("""
            MATCH (n:ConfirmedThreat)-[r]-(m:ConfirmedThreat)
            WHERE r.confirmed = true
              AND elementId(n) < elementId(m)
              AND NOT n:Technique AND NOT m:Technique
            RETURN DISTINCT n, r, m, r.confirmed_at AS confirmed_at
        """)
        for record in result:
            for node in [record["n"], record["m"]]:
                labels = list(node.labels)
                node_type = next(
                    (l for l in labels if l not in ("ConfirmedThreat", "Technique")),
                    labels[0] if labels else "Unknown",
                )
                name = _node_name(node)
                if name and name not in nodes_map:
                    nodes_map[name] = {
                        "id": name,
                        "label": name,
                        "type": node_type,
                        "val": 7 if node_type in ("Package", "ThreatActor") else 5,
                        "confirmed": True,
                    }

            src = _node_name(record["r"].start_node)
            tgt = _node_name(record["r"].end_node)
            rel_type = record["r"].type
            link_key = (min(src, tgt), max(src, tgt), rel_type)
            if src and tgt and link_key not in links_set:
                links_set.add(link_key)
                links.append({
                    "source": src,
                    "target": tgt,
                    "type": rel_type,
                    "confirmed_at": record.get("confirmed_at"),
                })

    # Mark nodes that have hidden children (Techniques or other confirmed neighbors)
    if nodes_map:
        with _get_driver().session() as s:
            for name, node_data in nodes_map.items():
                result = s.run("""
                    MATCH (n:ConfirmedThreat)-[r {confirmed: true}]-(child:ConfirmedThreat)
                    WHERE coalesce(n.name, n.id, n.address, n.juspay_id, n.username, n.mitre_id) = $name
                      AND NOT coalesce(child.name, child.id, child.address, child.juspay_id, child.username, child.mitre_id) IN $visible
                    RETURN count(child) AS hidden_count
                """, name=name, visible=list(nodes_map.keys()))
                record = result.single()
                node_data["expandable"] = (record["hidden_count"] > 0) if record else False
                node_data["hidden_children"] = record["hidden_count"] if record else 0

    return {
        "nodes": list(nodes_map.values()),
        "links": links,
        "total_memorized": len(nodes_map),
    }


def get_memory_expand(node_id: str) -> dict[str, Any]:
    """
    Return the direct confirmed neighbors of a specific node, used for
    click-to-expand in the Memory visualization.
    """
    nodes_map: dict[str, dict] = {}
    links_set: set[tuple[str, str, str]] = set()
    links: list[dict] = []

    def _node_name(node) -> str:
        return (
            node.get("name") or node.get("id") or node.get("address")
            or node.get("juspay_id") or node.get("username")
            or node.get("mitre_id") or str(node.element_id)
        )

    with _get_driver().session() as s:
        result = s.run("""
            MATCH (parent:ConfirmedThreat)-[r {confirmed: true}]-(child:ConfirmedThreat)
            WHERE coalesce(parent.name, parent.id, parent.address,
                           parent.juspay_id, parent.username, parent.mitre_id) = $node_id
            RETURN parent, r, child
        """, node_id=node_id)

        for record in result:
            child = record["child"]
            labels = list(child.labels)
            node_type = next(
                (l for l in labels if l not in ("ConfirmedThreat",)),
                labels[0] if labels else "Unknown",
            )
            name = _node_name(child)
            if name and name not in nodes_map:
                nodes_map[name] = {
                    "id": name,
                    "label": name,
                    "type": node_type,
                    "val": 5,
                    "confirmed": True,
                    "expandable": False,
                    "hidden_children": 0,
                }

            src = _node_name(record["r"].start_node)
            tgt = _node_name(record["r"].end_node)
            rel_type = record["r"].type
            link_key = (min(src, tgt), max(src, tgt), rel_type)
            if src and tgt and link_key not in links_set:
                links_set.add(link_key)
                links.append({
                    "source": src,
                    "target": tgt,
                    "type": rel_type,
                })

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


def get_geo_points(entity: str, entity_type: str) -> list[dict[str, Any]]:
    """
    Return geo-plottable points related to an investigation target.
    Two passes:
      1. IPs operated by connected ThreatActors (with geo from the IP node)
      2. ThreatActors themselves plotted at their attributed country when
         they have no IPs — so actors like OilRig/FIN7 still appear on the map
    """
    entity, entity_type = normalize_entity(entity, entity_type)
    label = _entity_label(entity_type)
    key = _entity_key(entity_type)

    # Pass 1: IPs operated by connected actors
    ip_query = """
    MATCH path = shortestPath(
      (start:{label} {{{key}: $value}})-[*..6]-(ta:ThreatActor)
    )
    WITH DISTINCT ta
    OPTIONAL MATCH (ta)-[:OPERATES]->(ip:IP)
    WITH DISTINCT ip, collect(DISTINCT ta.name) AS actors
    WHERE ip IS NOT NULL
    RETURN ip.address AS ip,
           coalesce(ip.geo, 'UN') AS geo,
           actors
    LIMIT 25
    """.format(label=label, key=key)

    # Pass 2: Actors with no IPs — plot at their attributed country
    actor_query = """
    MATCH path = shortestPath(
      (start:{label} {{{key}: $value}})-[*..6]-(ta:ThreatActor)
    )
    WITH DISTINCT ta
    WHERE NOT (ta)-[:OPERATES]->(:IP)
    RETURN ta.name AS actor
    LIMIT 25
    """.format(label=label, key=key)

    points: list[dict[str, Any]] = []
    seen_actors: set[str] = set()

    with _get_driver().session() as s:
        for record in s.run(ip_query, value=entity):
            geo = record["geo"]
            if geo not in _COUNTRY_COORDS:
                continue
            lat, lon = _COUNTRY_COORDS[geo]
            actors = [a for a in record["actors"] if a]
            for a in actors:
                seen_actors.add(a)
            points.append({
                "ip": record["ip"],
                "geo": geo,
                "lat": lat,
                "lon": lon,
                "actors": actors,
            })

        # Plot actors that don't have IP infrastructure
        for record in s.run(actor_query, value=entity):
            actor = record["actor"]
            if not actor or actor in seen_actors:
                continue
            seen_actors.add(actor)
            country = _ACTOR_GEO.get(actor)
            if not country or country not in _COUNTRY_COORDS:
                continue
            lat, lon = _COUNTRY_COORDS[country]
            # Small random-ish offset so actors in the same country don't overlap
            offset = (hash(actor) % 10 - 5) * 0.5
            points.append({
                "ip": actor,
                "geo": country,
                "lat": lat + offset,
                "lon": lon + offset,
                "actors": [actor],
                "actor_only": True,
            })

    return points


# Maps known threat actors to their attributed country code for geo plotting.
_ACTOR_GEO: dict[str, str] = {
    "APT28": "RU", "APT29": "RU", "APT41": "CN", "APT40": "CN",
    "APT31": "CN", "APT10": "CN", "APT1": "CN", "APT3": "CN",
    "APT17": "CN", "APT27": "CN", "APT30": "CN", "APT32": "VN",
    "APT33": "IR", "APT34": "IR", "APT35": "IR", "APT43": "KP",
    "Lazarus Group": "KP", "Kimsuky": "KP", "Andariel": "KP",
    "BlueNoroff": "KP", "Sandworm Team": "RU", "Turla": "RU",
    "Gamaredon Group": "RU", "Ember Bear": "RU",
    "Wizard Spider": "RU", "Indrik Spider": "RU",
    "FIN7": "RU", "FIN11": "RU", "Evil Corp": "RU",
    "Mummy Spider": "RU", "TA505": "RU", "TeamTNT": "DE",
    "HAFNIUM": "CN", "LuminousMoth": "CN", "Naikon": "CN",
    "Mustang Panda": "CN", "Winnti Group": "CN", "Ke3chang": "CN",
    "Stone Panda": "CN", "Emissary Panda": "CN",
    "UNC3886": "CN", "Velvet Ant": "CN", "Aquatic Panda": "CN",
    "Daggerfly": "CN", "Elderwood": "CN",
    "MuddyWater": "IR", "Charming Kitten": "IR", "OilRig": "IR",
    "Fox Kitten": "IR",
    "OceanLotus": "VN", "Equation": "US",
    "WIRTE": "IR", "Dragonfly": "RU",
    "Medusa Group": "RU", "Scattered Spider": "US",
}


def get_memory_geo() -> list[dict[str, Any]]:
    """
    Return geo-plottable points from all confirmed/memorized entities.
    Finds confirmed IP nodes and confirmed ThreatActors with their OPERATES->IP
    connections so saved investigations appear on the map.
    """
    points: list[dict[str, Any]] = []
    seen_ips: set[str] = set()

    with _get_driver().session() as s:
        # 1) Confirmed IPs that have a geo property
        for record in s.run("""
            MATCH (ip:IP:ConfirmedThreat)
            WHERE ip.address IS NOT NULL
            OPTIONAL MATCH (ta:ThreatActor:ConfirmedThreat)-[:OPERATES]->(ip)
            RETURN ip.address AS ip, coalesce(ip.geo, 'UN') AS geo,
                   collect(DISTINCT ta.name) AS actors
        """):
            geo = record["geo"]
            if geo not in _COUNTRY_COORDS:
                continue
            addr = record["ip"]
            if addr in seen_ips:
                continue
            seen_ips.add(addr)
            lat, lon = _COUNTRY_COORDS[geo]
            points.append({
                "ip": addr, "geo": geo, "lat": lat, "lon": lon,
                "actors": [a for a in record["actors"] if a],
                "memorized": True,
            })

        # 2) Confirmed ThreatActors → find their IPs (even if IP isn't confirmed)
        for record in s.run("""
            MATCH (ta:ThreatActor:ConfirmedThreat)
            OPTIONAL MATCH (ta)-[:OPERATES]->(ip:IP)
            WHERE ip.address IS NOT NULL
            RETURN ta.name AS actor, ip.address AS ip,
                   coalesce(ip.geo, 'UN') AS geo
        """):
            geo = record["geo"]
            addr = record["ip"]
            if not addr or geo not in _COUNTRY_COORDS or addr in seen_ips:
                continue
            seen_ips.add(addr)
            lat, lon = _COUNTRY_COORDS[geo]
            points.append({
                "ip": addr, "geo": geo, "lat": lat, "lon": lon,
                "actors": [record["actor"]] if record["actor"] else [],
                "memorized": True,
            })

    return points


# ── Graph Intelligence Functions ──────────────────────────────────────────────
# These power the /api/threat-score, /api/blast-radius, /api/shortest-path,
# and /api/suggestions endpoints with advanced graph analytics.

# -- Threat Score --
# Separate fast queries for each scoring factor — avoids cartesian explosion
# from multiple variable-length OPTIONAL MATCH clauses in one query.
_THREAT_SCORE_EXISTS = "MATCH (start:{label} {{{key}: $value}}) RETURN start, labels(start) AS start_labels LIMIT 1"
_THREAT_SCORE_ACTORS = "MATCH (start:{label} {{{key}: $value}})-[*1..3]-(ta:ThreatActor) RETURN collect(DISTINCT ta.name)[0..5] AS actors LIMIT 1"
_THREAT_SCORE_CVES   = "MATCH (start:{label} {{{key}: $value}})-[*1..3]-(cve:CVE) RETURN collect(DISTINCT cve.id)[0..5] AS cves LIMIT 1"
_THREAT_SCORE_FRAUD  = "MATCH (start:{label} {{{key}: $value}})-[*1..3]-(fs:FraudSignal) RETURN count(DISTINCT fs) AS cnt LIMIT 1"
_THREAT_SCORE_IPS    = "MATCH (start:{label} {{{key}: $value}})-[*1..2]-(ip:IP) RETURN count(DISTINCT ip) AS cnt LIMIT 1"
_THREAT_SCORE_TYPES  = "MATCH (start:{label} {{{key}: $value}})-[*1..3]-(any) RETURN collect(DISTINCT labels(any)[0])[0..10] AS label_types LIMIT 1"


def threat_score(entity: str, entity_type: str) -> dict[str, Any]:
    """
    Compute a 0-100 threat score based on graph connectivity around an entity.
    Considers connections to ThreatActors, CVEs, FraudSignals, malicious IPs,
    cross-domain hops, and ConfirmedThreat status. Returns the numeric score,
    a list of human-readable factors, and a severity label.
    """
    entity, entity_type = normalize_entity(entity, entity_type)
    label = _entity_label(entity_type)
    key = _entity_key(entity_type)
    score = 0
    factors: list[str] = []

    with _get_driver().session() as s:
        # Check entity exists
        rec = s.run(_THREAT_SCORE_EXISTS.format(label=label, key=key), value=entity).single()
        if not rec:
            return {"score": 0, "factors": ["Entity not found in graph"], "severity": "info"}
        score += 10
        factors.append("Entity exists in graph")

        start_labels = rec["start_labels"]
        if "ConfirmedThreat" in start_labels:
            score += 10
            factors.append("Entity is a ConfirmedThreat")

        # ThreatActors
        rec2 = s.run(_THREAT_SCORE_ACTORS.format(label=label, key=key), value=entity).single()
        actors = [a for a in (rec2["actors"] if rec2 else []) if a]
        if actors:
            score += 15
            factors.append(f"Connected to ThreatActor {actors[0]}")
            if len(actors) > 1:
                score += 10
                factors.append(f"Multiple threat actors ({len(actors)} total)")

        # CVEs
        rec3 = s.run(_THREAT_SCORE_CVES.format(label=label, key=key), value=entity).single()
        cves = [c for c in (rec3["cves"] if rec3 else []) if c]
        if cves:
            score += 15
            factors.append(f"Connected to CVE {cves[0]}")

        # FraudSignals
        rec4 = s.run(_THREAT_SCORE_FRAUD.format(label=label, key=key), value=entity).single()
        fraud_cnt = rec4["cnt"] if rec4 else 0
        if fraud_cnt:
            score += 10
            factors.append(f"Connected to {fraud_cnt} FraudSignal(s)")

        # IPs
        rec5 = s.run(_THREAT_SCORE_IPS.format(label=label, key=key), value=entity).single()
        ip_cnt = rec5["cnt"] if rec5 else 0
        if ip_cnt:
            score += 10
            factors.append(f"Connected to {ip_cnt} malicious IP(s)")

        # Cross-domain label types
        rec6 = s.run(_THREAT_SCORE_TYPES.format(label=label, key=key), value=entity).single()
        label_types = [lt for lt in (rec6["label_types"] if rec6 else []) if lt]
        distinct_types = set(label_types)
        cross_domain_count = min(len(distinct_types), 3)
        if cross_domain_count > 0:
            score += cross_domain_count * 10
            factors.append(f"Cross-domain reach: {len(distinct_types)} entity type(s)")

    # Cap at 100
    score = min(score, 100)

    # Severity mapping
    if score >= 80:
        severity = "critical"
    elif score >= 60:
        severity = "high"
    elif score >= 40:
        severity = "medium"
    elif score >= 20:
        severity = "low"
    else:
        severity = "info"

    return {"score": score, "factors": factors, "severity": severity}


# -- Blast Radius --
# Counts how many distinct entities are reachable within 4 hops of the target,
# grouped by node type. Helps analysts understand the potential impact area.
_BLAST_RADIUS = """
MATCH (start:{label} {{{key}: $value}})-[*1..4]-(connected)
RETURN labels(connected)[0] AS type, count(DISTINCT connected) AS count
"""


def blast_radius(entity: str, entity_type: str) -> dict[str, Any]:
    """
    Count how many distinct entities are reachable within 4 hops, grouped by
    node label. Returns a total count and a breakdown by entity type so the
    frontend can visualize the 'blast radius' of a compromise.
    """
    entity, entity_type = normalize_entity(entity, entity_type)
    label = _entity_label(entity_type)
    key = _entity_key(entity_type)
    cypher = _BLAST_RADIUS.format(label=label, key=key)

    by_type: dict[str, int] = {}
    total = 0

    with _get_driver().session() as s:
        result = s.run(cypher, value=entity)
        for record in result:
            node_type = record["type"]
            count = record["count"]
            by_type[node_type] = count
            total += count

    return {"total": total, "by_type": by_type}


# -- Shortest Path --
# Finds the shortest path between any two entities in the graph (up to 8 hops).
# Returns nodes and links in the same format as get_graph() for visualization.
_SHORTEST_PATH = """
MATCH path = shortestPath(
  (a:{from_label} {{{from_key}: $from_value}})-[*..8]-(b:{to_label} {{{to_key}: $to_value}})
)
RETURN path, length(path) AS hops
LIMIT 1
"""


def shortest_path(
    from_entity: str, from_type: str, to_entity: str, to_type: str
) -> dict[str, Any]:
    """
    Find the shortest path between two entities in the graph. Returns nodes
    and links formatted for the frontend force-directed graph, plus a hop count.
    Uses the same _add_node/_add_link pattern as get_graph().
    """
    from_entity, from_type = normalize_entity(from_entity, from_type)
    to_entity, to_type = normalize_entity(to_entity, to_type)
    from_label = _entity_label(from_type)
    from_key = _entity_key(from_type)
    to_label = _entity_label(to_type)
    to_key = _entity_key(to_type)

    cypher = _SHORTEST_PATH.format(
        from_label=from_label, from_key=from_key,
        to_label=to_label, to_key=to_key,
    )

    nodes_map: dict[str, dict] = {}
    links: list[dict] = []

    def _add_node(name: str, node_label: str, val: int = 5):
        if name and name not in nodes_map:
            nodes_map[name] = {"id": name, "label": name, "type": node_label, "val": val}

    def _add_link(src: str, tgt: str, rel_type: str, dashed: bool = False):
        if src and tgt:
            links.append({"source": src, "target": tgt, "type": rel_type, "dashed": dashed})

    hops = 0

    with _get_driver().session() as s:
        result = s.run(cypher, from_value=from_entity, to_value=to_entity)
        record = result.single()

        if not record:
            return {"nodes": [], "links": [], "hops": -1}

        hops = record["hops"]
        path = record["path"]

        # Extract nodes from the path
        for node in path.nodes:
            labels = list(node.labels)
            node_type = next(
                (l for l in labels if l != "ConfirmedThreat"),
                labels[0] if labels else "Unknown",
            )
            name = (
                node.get("name") or node.get("id") or node.get("address")
                or node.get("juspay_id") or node.get("username")
                or node.get("mitre_id") or str(node.element_id)
            )
            size = 7 if node_type in ("Package", "ThreatActor") else 5
            _add_node(name, node_type, size)

        # Extract relationships from the path
        for rel in path.relationships:
            start_node = rel.start_node
            end_node = rel.end_node
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
            is_synthetic = rel_type == "LINKED_TO"
            _add_link(src, tgt, rel_type, dashed=is_synthetic)

    return {"nodes": list(nodes_map.values()), "links": links, "hops": hops}


# -- Suggest Next --
# Recommends the top 5 most-connected neighbors (within 3 hops) that haven't
# been confirmed yet, helping analysts decide what to investigate next.
_SUGGEST_NEXT = """
MATCH (start:{label} {{{key}: $value}})-[*1..3]-(neighbor)
WHERE NOT neighbor:ConfirmedThreat
WITH DISTINCT neighbor, labels(neighbor)[0] AS type
OPTIONAL MATCH (neighbor)-[r]-(other)
RETURN type,
       coalesce(neighbor.name, neighbor.id, neighbor.address, neighbor.juspay_id, neighbor.username, neighbor.mitre_id) AS entity,
       count(DISTINCT other) AS connections
ORDER BY connections DESC
LIMIT 5
"""

# Maps Neo4j labels to EntityType enum values for the suggestions response
_LABEL_TO_ENTITY_TYPE: dict[str, str] = {
    "Package": "package",
    "IP": "ip",
    "Domain": "domain",
    "CVE": "cve",
    "ThreatActor": "threatactor",
    "FraudSignal": "fraudsignal",
}


def suggest_next(entity: str, entity_type: str) -> list[dict[str, Any]]:
    """
    Suggest what to investigate next based on graph neighbors. Returns up to 5
    unconfirmed neighbors sorted by connectivity (most connections first).
    Each suggestion includes the entity name, type, a human-readable reason,
    and the raw connection count.
    """
    entity, entity_type = normalize_entity(entity, entity_type)
    label = _entity_label(entity_type)
    key = _entity_key(entity_type)
    cypher = _SUGGEST_NEXT.format(label=label, key=key)

    suggestions: list[dict[str, Any]] = []

    with _get_driver().session() as s:
        result = s.run(cypher, value=entity)
        for record in result:
            neo4j_label = record["type"]
            mapped_type = _LABEL_TO_ENTITY_TYPE.get(neo4j_label, neo4j_label.lower())
            connections = record["connections"]
            suggestions.append({
                "entity": record["entity"],
                "type": mapped_type,
                "reason": f"High connectivity ({connections} connections)",
                "connections": connections,
            })

    return suggestions


_COUNTRY_COORDS: dict[str, tuple[float, float]] = {
    # Americas
    "US": (39.5, -98.35),
    "CA": (56.1, -106.3),
    "BR": (-14.2, -51.9),
    "MX": (23.6, -102.5),
    # Europe
    "GB": (55.3, -3.4),
    "DE": (51.2, 10.4),
    "FR": (46.2, 2.2),
    "NL": (52.1, 5.3),
    "UA": (48.3, 31.2),
    "IS": (64.9, -19.0),
    "RO": (45.9, 24.9),
    "PL": (51.9, 19.1),
    "SE": (60.1, 18.6),
    "CH": (46.8, 8.2),
    "IT": (41.9, 12.5),
    "ES": (40.5, -3.7),
    # Russia & Central Asia
    "RU": (61.5, 105.3),
    "KZ": (48.0, 68.0),
    # Middle East
    "IR": (32.4, 53.7),
    "IL": (31.0, 34.9),
    "SA": (23.9, 45.1),
    "AE": (23.4, 53.8),
    "TR": (38.9, 35.2),
    # East & Southeast Asia
    "CN": (35.9, 104.2),
    "HK": (22.3, 114.2),
    "KP": (40.3, 127.5),
    "KR": (35.9, 127.8),
    "JP": (36.2, 138.3),
    "TW": (23.7, 121.0),
    "VN": (14.1, 108.3),
    "TH": (15.9, 100.9),
    "SG": (1.35, 103.8),
    "IN": (20.6, 79.0),
    "PK": (30.4, 69.3),
    # Africa
    "NG": (9.1, 8.7),
    "ZA": (-30.6, 22.9),
    "EG": (26.8, 30.8),
    # Oceania
    "AU": (-25.3, 133.8),
    "NZ": (-40.9, 174.9),
    # Unknown
    "UN": (0.0, 0.0),
}
