# Cerberus — Cross-Domain Threat Intelligence Platform

**Hackathon:** HackWithBay 2.0
**Theme:** Thoughtful Agents for Productivity
**Team:** 2 people
**Timeline:** 8 hours on-site + 2-3 days polish
**Sponsors:** Neo4j (primary DB), RocketRide AI (orchestration), Juspay (financial signals)
**Spec version:** v2 — fixes applied from validation review

---

## One-Line Pitch

> Cerberus is a thoughtful security agent that eliminates the 4-hour manual graph-traversal process of tracing cross-domain attack chains — it reasons about which domains to query, connects the signals no single-surface tool can see, and learns from analyst feedback to get faster with every investigation.

## The Reframe (for submission opening)

> Every security tool watches one surface. Attackers coordinate across all of them.
> Snyk scans your dependencies. Shodan maps your infrastructure. Fraud systems watch transactions. None of them talk to each other — so a compromised npm publisher who also operates a fraud ring and controls a malicious IP goes undetected until damage is done.
> Cerberus connects these surfaces in a single graph and traces the attack chain that no single-domain tool can see.

---

## Judging Criteria Mapping

| Criterion | How Cerberus scores |
|-----------|-------------------|
| **Neo4j effectiveness** | Multi-hop cross-domain traversal — the core value prop is impossible without a graph DB. Uniqueness constraints, directed pattern matching, `shortestPath` queries. |
| **RocketRide AI effectiveness** | Orchestrates the full intelligence pipeline: NER → entity resolution → graph write → graph query → AI narrative. The agent *decides* which domains to query based on entity type. |
| **Innovation/originality** | Cross-domain entity resolution across financial + software + infrastructure — not a standard dependency scanner |
| **Technical complexity** | Async pipeline, MCP bridge for Neo4j↔RocketRide, self-improvement write-back loop, multi-source ingestion |
| **Real-world impact** | Catches coordinated attacks that span surfaces — reframed as analyst productivity (theme alignment) |
| **Demo quality** | Live: paste a package → watch graph materialize → AI narrates the cross-domain chain → compare to a standard scanner that sees nothing |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        INPUT LAYER                              │
│  GitHub repo URL · npm package name · IP · domain · Juspay ID   │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                    ROCKETRIDE PIPELINE                           │
│                  (the "thoughtful agent")                        │
│                                                                 │
│  Webhook Source                                                 │
│       ↓                                                         │
│  NER Node ─── extract entities (IPs, CVEs, packages, domains)   │
│       ↓                                                         │
│  Text Classification ─── categorize threat type                 │
│       │    ↓ decides which domain to query based on entity type  │
│       ↓                                                         │
│  MCP Client Node ──→ Neo4j MCP Server (write-cypher)            │
│       │                 ↑                                       │
│       │        neo4j-mcp v1.5.0 (confirmed locally)             │
│       │        tools: get-schema, read-cypher, write-cypher     │
│       ↓                                                         │
│  MCP Client Node ──→ Neo4j MCP Server (read-cypher)             │
│       ↓                 returns cross-domain subgraph           │
│  LLM Node (Anthropic) ─── graph context injected into prompt    │
│       ↓                                                         │
│  Text Output ─── streams threat narrative via SSE               │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                    SELF-IMPROVEMENT LOOP                         │
│  Confirmed threat pattern → labeled subgraph written to Neo4j   │
│  Next query: pattern match against known chains → faster,       │
│  richer context for LLM → better narrative                      │
└─────────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                      FRONTEND                                   │
│  React + Tailwind + shadcn/ui                                   │
│  ├── Input panel (package name / IP / domain / repo URL)        │
│  ├── Graph visualization (neovis.js via backend proxy)          │
│  ├── Streaming AI narrative panel (SSE)                         │
│  └── Pipeline stage indicator (visible agent reasoning)         │
└─────────────────────────────────────────────────────────────────┘
```

---

## Neo4j Schema

### Uniqueness Constraints (run first, before any imports)

```cypher
CREATE CONSTRAINT pkg_name IF NOT EXISTS FOR (p:Package) REQUIRE p.name IS UNIQUE;
CREATE CONSTRAINT cve_id IF NOT EXISTS FOR (c:CVE) REQUIRE c.id IS UNIQUE;
CREATE CONSTRAINT ip_addr IF NOT EXISTS FOR (i:IP) REQUIRE i.address IS UNIQUE;
CREATE CONSTRAINT domain_name IF NOT EXISTS FOR (d:Domain) REQUIRE d.name IS UNIQUE;
CREATE CONSTRAINT actor_name IF NOT EXISTS FOR (ta:ThreatActor) REQUIRE ta.name IS UNIQUE;
CREATE CONSTRAINT technique_id IF NOT EXISTS FOR (t:Technique) REQUIRE t.mitre_id IS UNIQUE;
CREATE CONSTRAINT account_key IF NOT EXISTS FOR (a:Account) REQUIRE (a.username, a.registry) IS UNIQUE;
CREATE CONSTRAINT fraud_id IF NOT EXISTS FOR (fs:FraudSignal) REQUIRE fs.juspay_id IS UNIQUE;
```

These are critical for two reasons: (1) `MERGE` operations use them for dedup instead of full label scans, and (2) they prevent duplicate nodes during rapid import. Person A runs these in minute 1.

### Node Labels

| Label | Properties | Source |
|-------|-----------|--------|
| `Package` | name, version, registry (npm/pypi), risk_score | npm registry, package.json |
| `CVE` | id, severity, cvss_score, description, published_date | NVD/MITRE |
| `IP` | address, geo, asn, first_seen, last_seen | threat intel feeds |
| `Domain` | name, registrar, created_date | DNS/WHOIS |
| `ThreatActor` | name, aliases, attribution_confidence | MITRE ATT&CK |
| `Technique` | mitre_id, name, tactic | MITRE ATT&CK STIX import |
| `Account` | username, registry, created_date | npm/GitHub |
| `FraudSignal` | juspay_id, type, amount, timestamp | Juspay API |

### Relationship Types

```
(:Package)-[:DEPENDS_ON]->(:Package)
(:Package)-[:HAS_VULNERABILITY]->(:CVE)
(:Package)-[:PUBLISHED_BY]->(:Account)
(:CVE)-[:EXPLOITED_BY]->(:ThreatActor)
(:ThreatActor)-[:USES]->(:Technique)
(:ThreatActor)-[:OPERATES]->(:IP)
(:ThreatActor)-[:CONTROLS]->(:Domain)
(:IP)-[:HOSTS]->(:Domain)
(:IP)-[:ASSOCIATED_WITH]->(:FraudSignal)
(:Account)-[:LINKED_TO]->(:IP)          // ⚠ See "Synthetic Data" note below
(:Domain)-[:SERVES]->(:Package)
```

### ⚠ Synthetic Data: `Account → LINKED_TO → IP`

This relationship is the critical cross-domain bridge between software and infrastructure. **No public data source provides this mapping** — npm doesn't expose publisher IPs, and GitHub doesn't either.

For the hackathon demo, this data is **synthetic/simulated**: we construct plausible links between known compromised npm publisher accounts and known malicious IPs from threat intel feeds. The simulation is based on the real-world pattern where supply-chain attackers reuse infrastructure across campaigns.

**If judges ask:** "The Account-to-IP link is simulated from threat intel correlation. In production, this would be sourced from Git commit metadata (author email → correlated IP), npm publish audit logs (if the org has access), or SIEM data that captures the actual connection events. The graph schema supports any of these data sources — the demo shows the analytical power of the traversal once the data exists."

### Key Cypher Queries

**The demo query — cross-domain traversal (directed, bounded):**
```cypher
// Given a package, find threat actors via directed relationship paths
MATCH path = shortestPath(
  (p:Package {name: $packageName})-[*..5]->(ta:ThreatActor)
)
RETURN path
LIMIT 10
```

**Cross-domain connection discovery:**
```cypher
// Find entities that appear in both software and fraud domains
MATCH (pkg:Package)-[:PUBLISHED_BY]->(acct:Account)-[:LINKED_TO]->(ip:IP)-[:ASSOCIATED_WITH]->(fs:FraudSignal)
RETURN pkg.name AS package, acct.username AS publisher, ip.address AS ip, fs.type AS fraud_type, fs.amount AS amount
```

**Attack chain reconstruction:**
```cypher
// Shortest path from a package to a fraud signal
MATCH path = shortestPath(
  (pkg:Package {name: $packageName})-[*]-(fs:FraudSignal)
)
RETURN path
```

**Bidirectional cross-domain scan (use sparingly, more expensive):**
```cypher
// All shortest paths from a package to any threat actor (directed or undirected)
MATCH path = allShortestPaths(
  (p:Package {name: $packageName})-[*]-(ta:ThreatActor)
)
WHERE length(path) <= 5
RETURN path
LIMIT 10
```

**Self-improvement: label confirmed patterns (using domain keys, not internal IDs):**
```cypher
// After analyst confirmation, tag the subgraph as a known pattern
MATCH path = shortestPath(
  (start {name: $startName})-[*]-(end {name: $endName})
)
WHERE length(path) <= 5
WITH nodes(path) AS ns, relationships(path) AS rs
FOREACH (n IN ns | SET n:ConfirmedThreat)
FOREACH (r IN rs | SET r.confirmed = true, r.confirmed_at = timestamp())
```

**Cache check (skip LLM if pattern already confirmed):**
```cypher
// Check if this traversal path is already confirmed
MATCH path = shortestPath(
  (p:Package {name: $packageName})-[*]-(ta:ThreatActor)
)
WHERE ALL(r IN relationships(path) WHERE r.confirmed = true)
RETURN path, true AS from_cache
LIMIT 1
```

---

## Neo4j MCP Bridge (Confirmed Working)

```
neo4j-mcp v1.5.0 — HTTP mode on 127.0.0.1:8787
Tools: get-schema, read-cypher, write-cypher

Connection: Neo4j Aura
Transport: neo4j+s://
```

**RocketRide integration path:**
RocketRide MCP Client node → HTTP → neo4j-mcp server → Bolt → Neo4j Aura

This is the critical bridge since RocketRide has no native Neo4j store node. The MCP Client node in RocketRide calls the neo4j-mcp tools (read-cypher, write-cypher) over HTTP. Validate this connection in the first hour.

---

## RocketRide Pipeline Spec

### Pipeline: `cerberus-ingest`

**Purpose:** Take raw input (package name, IP, domain) → extract entities → write to graph

```
Webhook Source (receives input JSON)
    ↓
Preprocessor (normalize input, detect input type)
    ↓
NER Node (extract entities: IPs, CVEs, package names, domains from any free text)
    ↓
Text Classification (categorize: software_supply_chain | infrastructure | financial)
    ↓
MCP Client → neo4j-mcp write-cypher (upsert entities + relationships via MERGE)
    ↓
Text Output (confirmation: "Ingested N entities, M relationships")
```

### Pipeline: `cerberus-query` (the "thoughtful agent" pipeline)

**Purpose:** Take an entity → reason about which domains to query → traverse graph → generate threat narrative → learn from result

The "thoughtful agent" behavior lives here: the classification node determines the entity type, and the pipeline *decides* which cross-domain traversal to run (software→infra, infra→financial, or full cross-domain). This isn't a static chain — the agent routes based on input.

```
Chat Source (user query: "analyze ua-parser-js" or "investigate 203.0.113.42")
    ↓
NER Node (extract the target entity)
    ↓
Text Classification → routes to appropriate Cypher template:
    software_supply_chain → Package→Account→IP→ThreatActor path
    infrastructure        → IP→Domain→ThreatActor path
    financial             → FraudSignal→IP→Account→Package path
    ↓
MCP Client → neo4j-mcp read-cypher (domain-appropriate traversal)
    ↓
[Branch: check if path already confirmed in graph]
    → If confirmed: return cached narrative, skip LLM (self-improvement!)
    → If new: continue to LLM
    ↓
Anthropic LLM Node
    System prompt: "You are a threat intelligence analyst. Given this graph
    traversal result, explain the cross-domain attack chain in plain language.
    Highlight which connections cross domain boundaries (software→infrastructure,
    infrastructure→financial). Rate the overall threat level. Be specific about
    node names and relationship types."
    User prompt: {graph_traversal_result_json}
    ↓
Text Output → SSE stream to frontend
    ↓
MCP Client → neo4j-mcp write-cypher (write-back: tag entities with
    analysis timestamp, store narrative hash for cache hit next time)
```

### Pipeline: `cerberus-juspay` (if time permits)

**Purpose:** Enrich graph with financial fraud signals from Juspay

```
Webhook Source (Juspay fraud alert or batch import)
    ↓
Data Parser (extract transaction IDs, amounts, IPs, merchant IDs)
    ↓
MCP Client → neo4j-mcp write-cypher (MERGE FraudSignal nodes, link to IPs)
    ↓
Text Output (confirmation)
```

---

## Data Sources & Pre-Import Strategy

### Pre-import before hackathon (have scripts ready):

| Data | Source | Format | Import method |
|------|--------|--------|--------------|
| MITRE ATT&CK | STIX 2.1 JSON from GitHub | JSON | Python script → Cypher bulk MERGE |
| CVE database | NVD API or pre-downloaded JSON feed | JSON | Python script → batch MERGE |
| npm advisory data | GitHub Advisory Database or `npm audit` JSON | JSON | Python script → Package + CVE nodes |
| Sample threat intel | Abuse.ch, AlienVault OTX (free tier) | CSV/JSON | Python script → IP + Domain nodes |

### Live during hackathon:

| Data | Source | Trigger |
|------|--------|---------|
| Dependency tree | npm registry API given a package name | User input |
| Juspay fraud signals | Juspay API (if sponsor provides sandbox) | Webhook or batch |
| Package metadata | npm registry | On-demand per query |

### Seed data volumes (target):

- ~200 MITRE ATT&CK techniques + ~100 groups → ~500 USES relationships
- ~50 high-profile CVEs (recent, well-known) with affected packages
- ~100 known malicious IPs (from Abuse.ch)
- ~30 known compromised npm packages (ua-parser-js, colors, faker, etc.)
- ~20 synthetic Juspay fraud signals linked to some of the same IPs
- ~15 synthetic Account→IP links (see "Synthetic Data" note above)

This is enough to produce compelling demo traversals without overwhelming the free-tier Aura instance.

### Demo entity: `ua-parser-js`

The primary demo uses `ua-parser-js` — hijacked in Oct 2021, tracked as **CVE-2021-27292** (ReDoS in versions before 0.7.24) and the supply-chain compromise of versions 0.7.29, 0.8.0, 1.0.0 which contained cryptomining and credential-stealing malware.

**Why this instead of event-stream:** ua-parser-js has a proper NVD CVE assignment, making the demo data verifiable. The event-stream incident (flatmap-stream backdoor) was tracked as `GMS-2018-45` in the GitLab Advisory Database without a standard CVE — using a wrong CVE ID in front of security-aware judges would undermine credibility.

Fallback demo entity: `colors` (v1.4.1 sabotage by maintainer, Jan 2022) — different attack vector, still has a strong graph story.

---

## Frontend Spec

### Tech Stack
- React 18 + Vite + Tailwind + shadcn/ui
- neovis.js for graph visualization
- SSE for streaming AI narrative

### neovis.js Credential Handling

neovis.js uses the Neo4j JavaScript driver, which means credentials would be embedded in frontend JS if connected directly. **For the hackathon demo, proxy Cypher queries through the backend** — the FastAPI backend runs the query and returns visualization-ready JSON to neovis.js. This avoids credential exposure.

If time is short and you must connect neovis.js directly to Aura: acknowledge this as a demo-only shortcut if a judge inspects the network tab. Have the one-sentence answer ready: "In production, all graph queries route through the backend API — the direct connection is a demo convenience."

### Layout

```
┌──────────────────────────────────────────────────────┐
│  CERBERUS                              [theme toggle] │
├──────────────┬───────────────────────────────────────┤
│              │                                       │
│  INPUT       │         GRAPH VISUALIZATION           │
│  PANEL       │         (neovis.js)                   │
│              │                                       │
│  [Package]   │    ○──○──○                            │
│  [IP]        │   /      \──○                         │
│  [Domain]    │  ○        \                           │
│  [Repo URL]  │   \──○──○──○                          │
│              │                                       │
│  [Analyze]   │                                       │
│              │                                       │
├──────────────┼───────────────────────────────────────┤
│  PIPELINE    │         AI NARRATIVE                  │
│  STAGES      │         (streaming)                   │
│              │                                       │
│  ✓ NER       │  "ua-parser-js's compromised version  │
│  ✓ Classify  │   was published from an account       │
│  ✓ Route     │   sharing infrastructure with a       │
│  ◉ Graph     │   threat actor linked to CVE-2021-    │
│  ○ Analyze   │   27292 and financial fraud signals.   │
│  ○ Narrate   │   The chain crosses 3 domains..."     │
│              │                                       │
└──────────────┴───────────────────────────────────────┘
```

### Pipeline Stage Indicator

Show each RocketRide pipeline stage as it fires. This is visible reasoning — judges see the agent working, not a spinner. The "Route" stage is new — it shows the agent *deciding* which domain to query based on entity classification. This reinforces the "Thoughtful Agent" theme.

States: `○ pending` → `◉ running` → `✓ complete` → `✗ failed`

### Graph Visualization

neovis.js config:
- Node colors by label: Package (blue), CVE (red), IP (orange), ThreatActor (purple), FraudSignal (yellow), Domain (green), Account (teal)
- Edge thickness by confirmation status (confirmed = thick)
- Click a node → sidebar shows properties
- Highlight the traversal path returned by the query in a contrasting color
- Synthetic relationships (Account→IP) rendered with dashed edges to visually distinguish

---

## Self-Improvement Loop (Eval Plan)

### 3-Phase Proof

| Phase | Graph State | Expected Behavior |
|-------|------------|-------------------|
| **Phase 1** (empty) | No prior patterns | Full LLM analysis for every query. Baseline: ~8s response, full token usage |
| **Phase 2** (seeded) | MITRE + CVE data imported | Graph context shortens LLM prompt, some paths pre-resolved. ~5s response |
| **Phase 3** (after N queries) | Confirmed patterns tagged | Cache hit on confirmed subgraphs skips LLM entirely. ~2s for cache hits |

### Eval Script (runnable, not pseudocode)

```python
#!/usr/bin/env python3
"""
eval_improvement.py — Proves Cerberus gets smarter over time.

Run against a live Neo4j Aura instance + RocketRide pipeline.
Requires: NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD env vars.
"""
import time
import os
import requests
from neo4j import GraphDatabase

NEO4J_URI = os.environ["NEO4J_URI"]
NEO4J_USER = os.environ["NEO4J_USERNAME"]
NEO4J_PASS = os.environ["NEO4J_PASSWORD"]
CERBERUS_API = os.environ.get("CERBERUS_API", "http://localhost:8000")
DEMO_PACKAGE = "ua-parser-js"

driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))


def clear_graph():
    with driver.session() as s:
        s.run("MATCH (n) DETACH DELETE n")


def count_nodes():
    with driver.session() as s:
        return s.run("MATCH (n) RETURN count(n) AS c").single()["c"]


def query_cerberus(package_name: str) -> dict:
    """Hit the Cerberus query endpoint and measure response."""
    start = time.perf_counter()
    resp = requests.post(
        f"{CERBERUS_API}/api/query",
        json={"entity": package_name, "type": "package"},
        timeout=30,
    )
    elapsed_ms = (time.perf_counter() - start) * 1000
    data = resp.json()
    return {
        "response_time_ms": elapsed_ms,
        "threat_paths_found": data.get("paths_found", 0),
        "from_cache": data.get("from_cache", False),
        "llm_called": data.get("llm_called", True),
        "narrative_length": len(data.get("narrative", "")),
    }


def confirm_pattern(package_name: str):
    """Simulate analyst confirming a threat pattern."""
    requests.post(
        f"{CERBERUS_API}/api/confirm",
        json={"entity": package_name, "type": "package"},
        timeout=10,
    )


def run_eval():
    print("=== Phase 1: Empty graph ===")
    clear_graph()
    assert count_nodes() == 0
    result_a = query_cerberus(DEMO_PACKAGE)
    print(f"  Response time: {result_a['response_time_ms']:.0f}ms")
    print(f"  Paths found: {result_a['threat_paths_found']}")
    print(f"  LLM called: {result_a['llm_called']}")

    print("\n=== Phase 2: Seeded graph (running import scripts) ===")
    os.system("python import_mitre.py && python import_cve.py && python import_npm.py && python import_threats.py")
    node_count = count_nodes()
    print(f"  Nodes in graph: {node_count}")
    result_b = query_cerberus(DEMO_PACKAGE)
    print(f"  Response time: {result_b['response_time_ms']:.0f}ms")
    print(f"  Paths found: {result_b['threat_paths_found']}")
    print(f"  LLM called: {result_b['llm_called']}")

    print("\n=== Phase 3: After analyst confirmation ===")
    confirm_pattern(DEMO_PACKAGE)
    result_c = query_cerberus(DEMO_PACKAGE)
    print(f"  Response time: {result_c['response_time_ms']:.0f}ms")
    print(f"  Paths found: {result_c['threat_paths_found']}")
    print(f"  From cache: {result_c['from_cache']}")
    print(f"  LLM called: {result_c['llm_called']}")

    # Assertions
    print("\n=== Assertions ===")
    assert result_b["threat_paths_found"] > result_a["threat_paths_found"], \
        f"Seeded graph should find more paths ({result_b['threat_paths_found']} vs {result_a['threat_paths_found']})"
    print("  ✓ More paths found with seeded data")

    assert result_c["from_cache"] is True, \
        "Confirmed pattern should be served from cache"
    print("  ✓ Confirmed pattern served from cache")

    assert result_c["llm_called"] is False, \
        "Cache hit should skip LLM call"
    print("  ✓ LLM skipped on cache hit")

    assert result_c["response_time_ms"] < result_b["response_time_ms"], \
        f"Cache hit should be faster ({result_c['response_time_ms']:.0f}ms vs {result_b['response_time_ms']:.0f}ms)"
    print("  ✓ Cache hit is faster than full analysis")

    print("\n✅ All improvement assertions passed")
    return {"phase_1": result_a, "phase_2": result_b, "phase_3": result_c}


if __name__ == "__main__":
    results = run_eval()
    driver.close()
```

---

## Demo Script (3 minutes)

**Pre-cache strategy:** Before presenting, run the full demo flow once and record all outputs (graph visualization state, AI narrative text, timing). If anything is slow live, the pre-cached version plays seamlessly. Record a backup video of the full demo as last-resort insurance.

```
0:00  "Security analysts spend 4 hours a day manually tracing attack chains
       across disconnected tools. Cerberus is a thoughtful agent that does
       it in 30 seconds — it reasons about which domains to query, connects
       the signals, and learns from every investigation."

0:20  [INPUT] Paste: "ua-parser-js"

0:30  [PIPELINE STAGES light up one by one]
       ✓ NER extracted: package name, version range
       ✓ Classification: software_supply_chain
       ✓ Route: querying Package→Account→IP→ThreatActor path
       ◉ Graph traversal running...

0:50  [GRAPH VISUALIZATION animates]
       ua-parser-js → compromised publisher account → IP cluster →
       known ThreatActor → CVE-2021-27292 → FraudSignal

1:05  [AI NARRATIVE streams]
       "ua-parser-js versions 0.7.29/0.8.0/1.0.0 were published from a
        compromised account sharing IP infrastructure with a threat actor
        linked to CVE-2021-27292. That same IP cluster appears in Juspay
        fraud signals. The attack chain crosses 3 domains:
        software → infrastructure → financial."

1:25  [COMPARE — THE KILLER BEAT]
       "Now watch what npm audit sees."
       Split-screen: Cerberus graph (multi-domain chain visible)
                  vs npm audit output (flags the CVE but misses everything else)
       "npm audit sees one surface. Cerberus sees all three."

       [If time: click "Confirm" on the pattern to show the write-back]

1:50  [ARCHITECTURE — 20 seconds]
       "Neo4j stores the cross-domain entity graph — the only way to
        traverse software→infrastructure→financial in a single query.
        RocketRide orchestrates the agent pipeline — NER, classification,
        domain routing, graph query, and AI narrative as composable nodes.
        The MCP bridge connects them."

2:15  [SELF-IMPROVEMENT — 15 seconds]
       "Each confirmed pattern gets written back. Watch:"
       Query ua-parser-js again → cache hit, no LLM call, instant response.
       "The agent learned. Here are the eval numbers."
       [Show eval output: Phase 1 → Phase 2 → Phase 3 assertions passing]

2:40  [ROADMAP]
       "Next: real-time feed ingestion, deeper Juspay integration for
        live transaction monitoring, and automated SOAR playbook generation."

2:55  [CLOSE]
       "Every security tool watches one surface. Cerberus watches all of them."
```

---

## Submission Framing

### How Neo4j Is Used (deliverable field)

> Neo4j is the persistent cross-domain entity graph — the architectural backbone that makes Cerberus possible. Attack chains span multiple surfaces (software dependencies, IP infrastructure, financial transactions), and the relationships between these entities are the intelligence, not the entities themselves. Uniqueness constraints on every node label ensure data integrity during rapid ingestion. Neo4j's `shortestPath` and directed pattern matching answer questions that no flat database can: "Given this npm package, what threat actors are reachable, and do any of them touch financial fraud signals?" The self-improvement loop writes confirmed patterns back as labeled subgraphs, turning the graph into a learning engine. Without Neo4j, Cerberus is three disconnected scanners. With it, it's one intelligence platform.

### How RocketRide AI Is Used (deliverable field)

> RocketRide orchestrates Cerberus as a thoughtful agent, not just a static pipeline. NER extracts structured entities from raw threat data. Text Classification categorizes the threat domain and routes the query to the appropriate cross-domain traversal — the agent *decides* which path to explore based on what it finds. The MCP Client node bridges to Neo4j (via the neo4j-mcp server) for both graph writes and reads. The Anthropic LLM node receives graph traversal results as context and generates human-readable threat narratives — but only when the pattern isn't already confirmed in the graph. On cache hits, the pipeline short-circuits and returns immediately. Without RocketRide, this adaptive pipeline would require custom glue code for each routing decision — RocketRide's node system makes the stages composable, the routing visible in the pipeline editor, and the self-improvement loop a natural extension of the existing flow.

### How Juspay Is Used (deliverable field)

> Juspay provides the financial fraud signal layer — the third threat domain that makes Cerberus's cross-domain intelligence unique. Transaction fraud signals from Juspay are ingested as FraudSignal nodes linked to IPs and merchant accounts. When a graph traversal from a software vulnerability reaches a FraudSignal node, that's a cross-domain connection that no single-surface tool would detect. Juspay data turns Cerberus from a two-domain tool into a three-domain intelligence platform.

---

## Build Order (8 Hours, 2 People)

### Person A — Graph + Data + Visualization

| Hour | Task | Deliverable |
|------|------|-------------|
| 1 | **Create uniqueness constraints** (8 statements). Neo4j Aura schema live. Run MITRE ATT&CK import. Validate neo4j-mcp server. **Test APOC availability** (`RETURN apoc.version()`). | Schema + constraints live, ~700 nodes imported, APOC confirmed |
| 2 | Run CVE + npm advisory + threat intel + synthetic import scripts. Write core Cypher queries (shortestPath, directed). | Full seed data loaded, queries validated manually |
| 3 | **INTEGRATION** — connect to Person B's pipeline output. Validate end-to-end: RocketRide MCP Client → neo4j-mcp → Aura | One full flow: input → graph write → graph read |
| 4 | Cross-domain traversal queries. Self-improvement write-back Cypher (using domain keys). Cache-check query. | Demo query returns multi-hop paths, write-back works |
| 5 | neovis.js graph visualization wired to backend proxy (not direct Aura connection). Node colors, edge styling, dashed edges for synthetic links. | Graph renders in browser via proxy |
| 6 | Run eval script (`eval_improvement.py`). Capture numbers. Fix any failing assertions. | Eval assertions passing, numbers recorded |
| 7 | **DEMO RUN-THROUGH** together. Fix what breaks. Pre-cache the full demo flow. | - |
| 8 | Buffer / polish / record backup video | - |

### Person B — Pipeline + AI + Frontend

| Hour | Task | Deliverable |
|------|------|-------------|
| 1 | RocketRide Docker running. Minimal pipeline: Webhook → LLM → Output working. | Pipeline responds to POST |
| 2 | Build NER + Classification nodes. Validate entity extraction on sample CVE text. Add routing logic (classification → Cypher template selection). | Structured entity JSON from raw text, routing works |
| 3 | **INTEGRATION** — wire MCP Client node to neo4j-mcp server. Test write-cypher + read-cypher through RocketRide. | Pipeline can read/write Neo4j |
| 4 | LLM prompt engineering with graph context. Add cache-check branch (skip LLM on confirmed patterns). SSE streaming output. | AI narrative streams, cache hits skip LLM |
| 5 | React frontend: input panel + pipeline stage indicator (including "Route" stage) + narrative panel. | UI layout complete |
| 6 | Hook frontend to RocketRide pipeline via SSE. Polish streaming UX. Wire neovis.js to backend proxy. | Full UI flow works |
| 7 | **DEMO RUN-THROUGH** together. Fix what breaks. Pre-cache the full demo flow. | - |
| 8 | Buffer / polish / record backup video | - |

### Integration Contract (agree before hour 1)

**Entity JSON format** (Person B's NER output → Person A's Cypher upsert):

```json
{
  "entities": [
    { "type": "Package", "properties": { "name": "ua-parser-js", "version": "0.7.29", "registry": "npm" } },
    { "type": "CVE", "properties": { "id": "CVE-2021-27292", "severity": "HIGH", "cvss_score": 7.5 } },
    { "type": "Account", "properties": { "username": "ART-BY-FAISAL", "registry": "npm" } },
    { "type": "IP", "properties": { "address": "203.0.113.42" } }
  ],
  "relationships": [
    { "from": { "type": "Package", "key": "ua-parser-js" }, "to": { "type": "CVE", "key": "CVE-2021-27292" }, "type": "HAS_VULNERABILITY" },
    { "from": { "type": "Package", "key": "ua-parser-js" }, "to": { "type": "Account", "key": "ART-BY-FAISAL" }, "type": "PUBLISHED_BY" },
    { "from": { "type": "Account", "key": "ART-BY-FAISAL" }, "to": { "type": "IP", "key": "203.0.113.42" }, "type": "LINKED_TO" }
  ]
}
```

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| RocketRide MCP Client → neo4j-mcp doesn't work | Medium | Critical | Validate in hour 1. Fallback: Python script outside RocketRide for graph writes, still use RocketRide for NER + LLM |
| **APOC plugin missing on Aura free tier** | Medium | Critical | **Test `RETURN apoc.version()` in hour 1.** If missing, `get-schema` tool won't work — use `read-cypher` with manual schema queries instead. neo4j-mcp in HTTP mode skips startup verification (helps), but APOC is still needed at query time for schema inspection. |
| Neo4j Aura free tier too slow for demo | Low | High | Pre-cache the demo query result. Replay with staggered delay. |
| Juspay sandbox not available | Medium | Low | Use synthetic fraud data. Label it as "simulated Juspay signals" in demo. Still shows the architecture. |
| neovis.js rendering issues | Low | Medium | Fallback: D3.js force-directed graph. More work but guaranteed to work. |
| LLM narrative is slow or incoherent | Low | Medium | Pre-cache one complete narrative. Tune prompt during hour 4. |
| Scope creep into real-time monitoring | High | High | Do not build streaming ingestion for the 8-hour demo. Mention it in roadmap only. |
| Judge asks about Account→IP data source | High | Medium | Have the synthetic data answer rehearsed (see "Synthetic Data" note in schema section). |
| Demo timing overruns (LLM or Aura latency) | Medium | Medium | Pre-cache full demo flow. Record backup video. Run live demo as "also showing this live" alongside cached fallback. |

---

## Files to Prepare Tonight

- [ ] `constraints.cypher` — All 8 uniqueness constraint statements (run first)
- [x] `import_mitre.py` — MITRE ATT&CK STIX → Neo4j bulk MERGE (ready to run)
- [x] `import_cve.py` — NVD CVE data → Neo4j (top 50 high-profile CVEs including CVE-2021-27292)
- [x] `import_threats.py` — Abuse.ch + OTX → IP/Domain nodes
- [x] `import_npm.py` — Known compromised packages (ua-parser-js, colors, faker, etc.) → Package + Account nodes
- [x] `import_synthetic.py` — Synthetic Account→IP links + Juspay fraud signals linked to known IPs
- [x] `eval_improvement.py` — Runnable 3-phase eval script (above)
- [x] ~~`seed_data/` directory~~ — Removed; data now lives in Neo4j Aura
- [x] `docker-compose.yml` for RocketRide + neo4j-mcp + frontend dev server
- [x] Entity JSON schema (moved to `docs/entity_schema.json`)
- [ ] Test APOC availability: `RETURN apoc.version()` against Aura instance

---

## Changelog (v1 → v2)

| # | Issue | Fix applied |
|---|-------|-------------|
| 🔴1 | Wrong CVE ID (CVE-2018-16490 is mpath, not event-stream) | Pivoted demo entity to `ua-parser-js` + `CVE-2021-27292`. event-stream lacks standard NVD CVE. |
| 🔴3 | APOC dependency not in risk register | Added to risk register with hour-1 validation step and fallback. |
| 🟡4 | Undirected `()-[*1..4]-()` will explode on dense graph | Replaced with `shortestPath` + directed patterns everywhere. Added bounded `allShortestPaths` as fallback. |
| 🟡5 | `id()` internal node IDs in write-back Cypher | Replaced with domain keys (`{name: $startName}`). |
| 🟡6 | neovis.js exposes Neo4j credentials in frontend JS | Added backend proxy approach. Documented fallback answer for judges. |
| 🟡7 | No uniqueness constraints | Added 8 constraint statements as first schema step. Added to Person A hour 1. |
| 🟡8 | Account→IP has no real data source | Explicitly marked as synthetic. Added judge-ready answer. Dashed edges in visualization. |
| 🟢9 | Eval script was pseudocode | Rewrote as runnable Python with `time.perf_counter()`, real Cypher, real HTTP calls. |
| 🟢10 | Theme alignment thin ("Thoughtful Agents") | Strengthened agent framing throughout: routing decisions, cache-check branching, "the agent decides." Added "Route" pipeline stage. Updated pitch and submission text. |
| 🟢11 | Demo timing tight | Added pre-cache strategy, backup video recording, adjusted timing with buffer. |
| ℹ️2 | Reviewer flagged neo4j-mcp v1.5.0 as non-existent | **False positive** — Kevin confirmed v1.5.0 running locally. Kept as-is. |

---

## Post-Hackathon Polish (Days 2-3)

- Juspay deep integration (real API, not synthetic)
- Real-time feed ingestion via RocketRide webhook triggers
- Executive summary view (high-level risk score, not just analyst detail)
- SOAR playbook generation from confirmed attack chains
- Historical timeline view (when did each entity first appear in the graph?)
- Confidence scoring on entity resolution (fuzzy matching IPs, account aliases)
- Replace synthetic Account→IP links with real data sources (SIEM, Git metadata)