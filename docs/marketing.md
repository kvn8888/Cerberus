# Cerberus — Technical Onboarding & Pitch Document

> **Audience:** Anyone who needs to understand, demo, or pitch Cerberus without having built it.
> **Read time:** 15 minutes. After reading, you should be able to explain every feature to a judge, investor, or security professional.

---

## 1. The Problem

Security analysts today face a fragmented world. When a suspicious npm package appears in their codebase, they have to manually cross-reference across **4+ disconnected tools**:

| What they need to know                   | Where they look                   | Time          |
| ---------------------------------------- | --------------------------------- | ------------- |
| Is this package vulnerable?              | Snyk, npm audit                   | 5 min         |
| Who published it?                        | npm registry                      | 5 min         |
| Is that publisher suspicious?            | GitHub, manual OSINT              | 20 min        |
| What infrastructure is involved?         | Shodan, VirusTotal                | 30 min        |
| Is the IP linked to known threat actors? | MITRE ATT&CK, threat feeds        | 30 min        |
| Are there financial fraud signals?       | Internal fraud dashboard          | 20 min        |
| How does it all connect?                 | **Analyst's brain + spreadsheet** | **2-3 hours** |

The last step is the killer. The analyst has 6 browser tabs open, mentally connecting dots across completely different domains:

```text
Software supply chain → Infrastructure → Threat intelligence → Financial fraud
```

No single tool shows the full picture. The cross-domain attack chain — the thing that actually matters — lives only in the analyst's head.

**That manual correlation process takes ~4 hours per investigation.**

---

## 2. What Cerberus Does

Cerberus replaces that 4-hour process with a **single query that takes 5-8 seconds**.

```text
Input:   "ua-parser-js"
Output:  A visual attack chain + AI narrative connecting the package
         to its vulnerabilities, threat actors, malicious infrastructure,
         and fraud signals — across all four domains.
```

Even for entities **not in the database**, Cerberus fetches real-time threat intelligence from public APIs (OSV.dev, NVD, Abuse.ch), ingests the data into the graph on-the-fly, and completes the investigation — all within the same query.

It's a **thoughtful security agent** — not a chatbot, not a dashboard. It reasons about which domains to query, traverses a knowledge graph to connect signals no single-surface tool can see, enriches gaps with live threat intelligence, and learns from analyst feedback to get faster with every investigation.

---

## 3. The Four Domains

Cerberus operates across four security domains that are traditionally siloed:

```text
┌─────────────────┐   ┌──────────────────┐   ┌─────────────────┐   ┌──────────────┐
│   SOFTWARE       │   │  INFRASTRUCTURE  │   │    THREAT       │   │  FINANCIAL   │
│   SUPPLY CHAIN   │   │                  │   │    INTEL        │   │              │
│                  │   │                  │   │                 │   │              │
│  npm packages    │   │  IPs             │   │  Threat actors  │   │  Fraud       │
│  CVEs            │   │  Domains         │   │  MITRE          │   │  signals     │
│  Publishers      │   │  Hosting         │   │  techniques     │   │  from Juspay │
└────────┬─────────┘   └────────┬─────────┘   └────────┬────────┘   └──────┬───────┘
         │                      │                      │                    │
         └──────────────────────┴──────────────────────┴────────────────────┘
                                        │
                              ┌─────────┴──────────┐
                              │     CERBERUS        │
                              │  Connects all four  │
                              │  in one query       │
                              └─────────────────────┘
```

**This is the core value proposition.** npm audit sees domain 1. Shodan sees domain 2. MITRE ATT&CK sees domain 3. Fraud dashboards see domain 4. Cerberus sees all four and the connections between them.

---

## 4. The Knowledge Graph

### Why a Graph Database

The insight in threat intelligence isn't the entities — it's the **relationships between them**. A vulnerability alone is a data point. A vulnerability linked to a threat actor linked to a malicious IP linked to fraud signals is an **attack chain**.

Graph databases store relationships as first-class objects. Instead of joining tables, you traverse connections directly. This means a query like "trace everything connected to this package" is a single pattern match, not 8 SQL JOINs across 5 bridge tables.

### The Schema

Cerberus has **8 entity types** and **12 relationship types**:

```text
                      Technique
                         ↑ USES
  Package ←─SERVES── Domain ←─CONTROLS── ThreatActor ──OPERATES─→ IP
     │                                        ↑ EXPLOITED_BY        │
     ├──HAS_VULNERABILITY─→ CVE ──────────────┘                     │
     │                                                              │
     └──PUBLISHED_BY─→ Account ──LINKED_TO──────────────────────────┘
                                                                    │
                                                FraudSignal ←───────┘
                                                ASSOCIATED_WITH
```

**Key design property:** Any two entity types can reach each other within **2-4 hops**. The graph is shallow and densely connected. This is critical — it means every query returns results fast, and the traversal always finds meaningful connections.

### Hub Nodes

Two entity types act as natural bridges between domains:

- **ThreatActor** — connects CVEs, techniques, IPs, and domains (bridges software ↔ infrastructure ↔ intel)
- **IP** — connects domains, accounts, threat actors, and fraud signals (bridges infrastructure ↔ financial)

These hubs are why a single traversal can span all four domains.

### Scale

The demo graph contains approximately:

- 200 MITRE ATT&CK techniques
- 100 threat actor groups
- 50 CVEs
- 100 malicious IPs
- 30 compromised packages
- 20 synthetic fraud signals
- **~1,060 nodes and ~4,500 relationships total**

This is enough for a compelling demo while staying within Neo4j Aura's free tier.

---

## 5. The Demo Walkthrough

### The Primary Demo: ua-parser-js

**Background:** In October 2021, the popular npm package `ua-parser-js` (7.9M weekly downloads) was hijacked. Malicious versions 0.7.29, 0.8.0, and 1.0.0 were published containing cryptomining and credential-stealing malware. This was a real-world supply-chain attack.

**Step 1 — Input**

The analyst types `ua-parser-js` into the search box (or clicks a quick-start button).

**Step 2 — Pipeline Stages Light Up**

The UI shows each processing stage activating in sequence:

```text
input → NER → classify → route → traverse → enrich → analyze → narrate → complete
```

This is not decorative. Each stage represents real work:

- **NER**: Identifies the input as an npm package name
- **Classify**: Determines this is a software supply chain entity
- **Route**: Decides to start traversal from Package node, expanding outward across all domains
- **Traverse**: Executes the graph query
- **Enrich**: If entity not found, fetches live threat intel from public APIs (OSV.dev, NVD, Abuse.ch) and ingests into the graph
- **Analyze**: Sends graph paths to the LLM for interpretation
- **Narrate**: Streams the threat narrative back

This visibility is the **"Thoughtful Agent"** theme in action. The user sees the agent reasoning, not a loading spinner.

**Step 3 — Graph Appears**

A force-directed graph visualization renders the attack chain:

```text
Color coding:
  🔵 Blue    = Package
  🔴 Red     = CVE
  🟠 Orange  = IP
  🟣 Purple  = ThreatActor
  🟡 Yellow  = FraudSignal
  🟢 Green   = Account
  ⬜ Gray    = Domain / Technique
  ┈┈ Dashed  = Synthetic edge (see note below)
```

The specific chain discovered:

```text
ua-parser-js (Package)
  → CVE-2021-27292 (vulnerability)
  → ART-BY-FAISAL (publisher account)
    → 203.0.113.42 (linked IP)
      → APT41 (threat actor operating from that IP)
        → 3 fraud signals from the same infrastructure
        → 12 MITRE ATT&CK techniques used by APT41
```

Clicking any node opens a sidebar with its properties.

**Step 4 — Narrative Streams In**

While the graph renders, an AI-generated threat narrative streams in real-time via SSE:

```text
## Threat Assessment: ua-parser-js

**Severity: CRITICAL**

The npm package ua-parser-js has a known vulnerability (CVE-2021-27292)
that was exploited in a supply-chain attack in October 2021. The
compromised versions contained cryptomining and credential-stealing malware.

**Cross-domain connections discovered:**
- Published by account ART-BY-FAISAL, linked to IP 203.0.113.42
- That IP is associated with threat actor APT41, a Chinese state-sponsored
  group known for supply-chain compromises
- 3 fraud signals originating from the same infrastructure

**Attack chain:** Software Supply Chain → Infrastructure → Financial Fraud
```

This narrative is generated by Claude, given the raw graph paths as context. The LLM interprets the graph; it doesn't hallucinate it.

**Step 5 — Confirm & Learn**

The analyst clicks **"Confirm Pattern"**. This:

- Tags the relevant nodes as confirmed threat patterns
- Writes a timestamp and narrative hash to the graph
- Returns: `"3 nodes marked as confirmed threat pattern"`

**Step 6 — Next Query Is Instant**

When anyone queries `ua-parser-js` again:

- The system detects a cache hit (confirmed pattern exists)
- Returns the cached narrative immediately
- **No LLM call needed**
- Response time drops from ~8s to ~2s

---

## 6. The Self-Improvement Loop

This is one of Cerberus's most important differentiators. The agent measurably gets faster with use.

```text
Phase 1 — Empty Graph
  No prior knowledge. Full LLM analysis required.
  Response time: ~8 seconds

Phase 2 — Seeded Graph
  MITRE + CVE data imported. LLM gets richer graph context,
  needs a shorter prompt.
  Response time: ~5 seconds

Phase 3 — Confirmed Patterns
  Analyst has confirmed this attack chain. Cache hit.
  Skip LLM entirely.
  Response time: ~2 seconds
```

**Why this matters:** Most AI tools have a fixed cost per query. Cerberus's cost per query **decreases over time** as the knowledge base grows and patterns get confirmed. It's an agent that learns from its operators.

The `eval_improvement.py` script benchmarks all three phases with timing assertions to prove this progression quantitatively.

---

## 7. Real-Time Threat Intel Enrichment

Most threat intelligence tools rely entirely on pre-loaded databases. If the entity isn't in the system, you get nothing.

Cerberus is different. When you query an entity that doesn't exist in the graph, the system **automatically fetches real-time threat intelligence** from public APIs and ingests the results into Neo4j — all within the same request.

### How it works

```text
Query: "lodash" (not in graph)
  → Graph traversal: 0 paths found
  → Enrichment triggered:
      → OSV.dev API: 8 CVEs found for lodash
      → MERGE Package + CVE nodes into Neo4j
  → Re-traverse: 8 paths found
  → LLM generates threat narrative
  → Response delivered to user

Next query for "lodash":
  → Graph traversal: 8 paths found (already enriched)
  → Skip enrichment (fast path)
  → LLM generates narrative
```

### Supported data sources

| Entity Type           | API                                                                                           | What it returns                                  |
| --------------------- | --------------------------------------------------------------------------------------------- | ------------------------------------------------ |
| **npm/PyPI packages** | [OSV.dev](https://osv.dev)                                                                    | Known CVEs + severity + CVSS scores              |
| **CVE IDs**           | [NVD](https://nvd.nist.gov)                                                                   | Full CVE details, CVSS v3 scoring                |
| **IP addresses**      | [Abuse.ch Feodo Tracker](https://feodotracker.abuse.ch) + [URLhaus](https://urlhaus.abuse.ch) | Malware family, first seen date, associated URLs |
| **Domains**           | [Abuse.ch URLhaus](https://urlhaus.abuse.ch)                                                  | Malicious URL count, threat types                |

All APIs are **free, public, and require no API keys**. The enrichment adds ~1-2 seconds to the first query for that entity, but all subsequent queries are instant because the data persists in Neo4j.

### Why this matters

This turns Cerberus from a "what's in the database" tool into a **live threat intelligence platform**. An analyst can query recently published CVEs, npm packages, and suspicious IPs — and get results even if Cerberus has never seen them before. The graph grows organically with every investigation.

---

## 8. Comparison: Cerberus vs. Existing Tools

### Side-by-Side: npm audit

```text
npm audit output:                    Cerberus output:
────────────────                     ────────────────
ua-parser-js <0.7.30                 ua-parser-js
  CVE-2021-27292                       → CVE-2021-27292
  Severity: High                       → ART-BY-FAISAL (publisher)
  Fix: upgrade to >=0.7.30              → 203.0.113.42 (IP)
                                         → APT41 (threat actor)
                                           → 12 MITRE techniques
                                         → 3 fraud signals
                                         → 2 malicious domains

"You have a vulnerability."          "Here's the complete attack chain
                                      across 4 security domains."
```

### Why Existing Tools Can't Do This

| Tool                 | What it sees                      | What it misses                                         |
| -------------------- | --------------------------------- | ------------------------------------------------------ |
| **npm audit / Snyk** | Package → CVE                     | Who's behind it, what infrastructure, financial impact |
| **Shodan**           | IP → open ports, services         | How it connects to software supply chain               |
| **VirusTotal**       | Domain/IP reputation scores       | The actor behind it, lateral connections               |
| **MITRE ATT&CK**     | Techniques and groups (reference) | Real-time connection to your specific entities         |
| **Fraud dashboards** | Transaction anomalies             | How fraud signals link to software compromises         |
| **Cerberus**         | **All of the above, connected**   | —                                                      |

---

## 9. Architecture (How It Works Under the Hood)

### System Flow

```text
User Input (browser)
     │
     ▼
Frontend (React + Vite + Tailwind + shadcn/ui)
     │  HTTP POST or SSE GET
     ▼
Backend (FastAPI, port 8000)
     │
     ├──→ Cache check (ConfirmedThreat pattern in Neo4j?)
     │       ├── YES → Return cached narrative (~2s, no LLM)
     │       └── NO  → Continue pipeline
     │
     ├──→ Neo4j Aura (graph traversal via Bolt driver)
     │       Returns: paths as structured data
     │       │
     │       └── No paths? → Real-time enrichment (enrich.py)
     │              ├── OSV.dev     (package CVE lookup)
     │              ├── NVD         (CVE detail lookup)
     │              ├── Abuse.ch Feodo Tracker (IP lookup)
     │              └── Abuse.ch URLhaus (domain lookup)
     │              └── Data found → MERGE into Neo4j → Re-traverse
     │              (enrichment relationships stamped with confidence,
     │               source_reliability, last_seen, corroboration_count)
     │
     ├──→ RocketRide AI — PRIMARY orchestration path
     │       agent_rocketride (wave-planning, keyed memory)
     │         → mcp_client → neo4j-mcp (schema + Cypher tools)
     │         → llm_anthropic (Claude Sonnet 4.6)
     │         → memory_internal (cross-wave context)
     │         → tool_http_request (MITRE CVE / AbuseIPDB / VirusTotal)
     │       Falls back to cerberus-query.pipe (simple prompt+LLM)
     │       Last resort: direct Anthropic SDK call (llm.py)
     │
     ├──→ Anthropic Claude Sonnet 4.6 (narrative generation)
     │       Input: graph paths as structured context
     │       Output: streamed threat narrative (Technical or Executive)
     │
     └──→ Write-back to Neo4j
             Tag analyzed nodes; store narrative hash; write Annotations;
             update Watchlist change-detection cursors
     │
     ▼
Frontend receives via SSE:
  - stage events      → pipeline stage indicators light up
  - text events       → streamed narrative (Technical or Executive)
  - threat_score      → 0-100 risk badge + contributing factors card
  - blast_radius      → affected entity count by type
  - suggestions       → "Investigate Next" entity list
  - graph data        → force-directed graph (nodes + edges + confidence)
```

### Tech Stack Summary

| Layer               | Technology                                                       | Why                                                                                        |
| ------------------- | ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| **Graph DB**        | Neo4j Aura (free tier)                                           | Relationships are first-class; cross-domain traversal in one query                         |
| **MCP Bridge**      | neo4j-mcp v1.5.0 (HTTP mode, port 8787)                          | HTTP bridge to Neo4j for agent tool-use (schema introspection, Cypher)                     |
| **Backend**         | FastAPI + Python (uvicorn, port 8000)                            | Async, SSE support, fast to build                                                          |
| **Orchestration**   | RocketRide AI — `agent_rocketride` (wave-planning, keyed memory) | Autonomous agent explores graph via MCP; parallelizes tool calls; holds cross-wave context |
| **Agent tools**     | `mcp_client` + `tool_http_request` + `memory_internal`           | Direct Neo4j queries + live HTTP enrichment (AbuseIPDB/VT/MITRE) + token-efficient memory  |
| **Enrichment**      | OSV.dev, NVD, Abuse.ch (Feodo Tracker + URLhaus)                 | Real-time threat intel for unknown entities — free, no keys; edges stamped with confidence |
| **LLM**             | Anthropic Claude Sonnet 4.6                                      | Narrative generation + detection-rule sketching from graph context                         |
| **Auth**            | PyJWT HS256                                                      | Demo JWT auth (3 roles: admin, analyst, viewer) + API key management                       |
| **Frontend**        | React 18 + Vite + Tailwind + shadcn/ui                           | Modern, fast, component library                                                            |
| **Graph Viz**       | react-force-graph-2d + custom SVG ThreatMap                      | Force-directed graph (2D) + live geo threat map                                            |
| **Streaming**       | SSE (sse-starlette + FastAPI StreamingResponse)                  | Stage events + streamed narrative + threat score + suggestions                             |
| **STIX export**     | stix2 Python library                                             | STIX 2.1 bundles with TLP markings (MISP/OpenCTI compatible)                               |
| **Detection rules** | Claude Sonnet 4.6 via `routes/detect.py`                         | Sigma + YARA sketches drafted from live investigation context                              |

### Why These Choices

**Why Neo4j over Postgres?**
The core query is a variable-depth traversal across 8 entity types and 12 relationship types. In SQL, each investigation type would require a different multi-JOIN query with different bridge tables. In Cypher, it's one pattern match that reads like the threat narrative we generate. With 8 entity types, the maximum meaningful path depth is 5 hops — right in Neo4j's sweet spot.

**Why SSE over WebSockets?**
One-directional stream (server → client). No bidirectional communication needed. SSE is simpler, works over standard HTTP, auto-reconnects, and doesn't require a separate protocol upgrade.

**Why Claude for narratives?**
The LLM receives structured graph paths and converts them to analyst-readable threat narratives. It's interpreting data, not generating it — the graph provides factual grounding, reducing hallucination risk.

---

## 10. Input Types

Cerberus accepts 6 entity types as input. The agent identifies the type and routes the traversal accordingly:

| Input Type       | Example                | Starting Traversal                                  |
| ---------------- | ---------------------- | --------------------------------------------------- |
| **Package**      | `ua-parser-js`         | Package → CVE → ThreatActor → IP → FraudSignal      |
| **IP Address**   | `203.0.113.42`         | IP → ThreatActor → CVE → Package + IP → FraudSignal |
| **Domain**       | `evil-cdn.example.com` | Domain → IP → ThreatActor → Techniques              |
| **CVE**          | `CVE-2021-27292`       | CVE → Package + CVE → ThreatActor → IP              |
| **Threat Actor** | `APT41`                | ThreatActor → Techniques + IPs + Domains + CVEs     |
| **FraudSignal**  | `JSPY-2026-0091`       | FraudSignal → IP → ThreatActor / Account / Package  |

Each input type triggers a different **route decision**, which the UI displays as part of the pipeline stages. The traversal pattern adapts to the starting domain — this is the "thoughtful" part of the agent.

---

## 11. Synthetic Data Disclaimer

One relationship in the graph is simulated:

```text
(:Account)-[:LINKED_TO]->(:IP)
```

No public data source maps npm publisher accounts to IP addresses. In the demo, these links are generated synthetically to complete the cross-domain chain.

**If asked by judges:** "The Account-to-IP link is simulated from threat intel correlation. In production, this would come from Git commit metadata, npm publish audit logs, or SIEM data."

In the visualization, these edges render as **dashed lines** to distinguish them from real data.

---

## 12. API Reference (Quick)

| Method | Endpoint                    | Purpose                                                                                     |
| ------ | --------------------------- | ------------------------------------------------------------------------------------------- |
| GET    | `/health`                   | Health check → `{"status":"ok"}`                                                            |
| GET    | `/api/schema`               | Live graph schema (labels, relationship types, counts)                                      |
| GET    | `/api/rocketride/health`    | RocketRide availability (frontend green dot)                                                |
| POST   | `/api/query`                | Main investigation: cache check → traverse → LLM narrative                                  |
| GET    | `/api/query/stream`         | SSE streaming — emits `stage`, `text`, `threat_score`, `blast_radius`, `suggestions` events |
| POST   | `/api/confirm`              | Analyst confirms threat pattern → write-back (returns count + message)                      |
| GET    | `/api/query/graph`          | Full force-directed graph data (nodes + edges)                                              |
| GET    | `/api/memory`               | Confirmed-threat subgraph (ConfirmedThreat nodes, no Techniques)                            |
| GET    | `/api/memory/geo`           | Geo points for memorized entities                                                           |
| GET    | `/api/memory/expand`        | Expand one node in memory graph (click-to-expand)                                           |
| GET    | `/api/geomap/all`           | Geo points for ALL IPs + ThreatActors (default geomap load)                                 |
| POST   | `/api/demo/natural`         | Free-text NLP entity extraction                                                             |
| POST   | `/api/demo/compare`         | Multi-entity side-by-side comparison (backend only)                                         |
| GET    | `/api/demo/map`             | Geo-IP data for map visualization                                                           |
| GET    | `/api/demo/report`          | Full investigation report                                                                   |
| POST   | `/api/juspay/ingest`        | Ingest normalized Juspay-style fraud payload(s)                                             |
| GET    | `/api/juspay/signals`       | FraudSignal summary (counts, actor links, recent signals)                                   |
| GET    | `/api/threat-score`         | 0-100 risk score with severity + contributing factors                                       |
| GET    | `/api/blast-radius`         | Reachable entity count within 4 hops, grouped by type                                       |
| GET    | `/api/shortest-path`        | Shortest path between two entities (nodes + links + hop count)                              |
| GET    | `/api/suggestions`          | Top 5 unconfirmed neighbors sorted by connectivity                                          |
| GET    | `/api/stix/bundle`          | STIX 2.1 bundle export with TLP markings (MISP/OpenCTI ready)                               |
| GET    | `/api/stix/indicator-count` | Indicator counts by STIX type                                                               |
| POST   | `/api/diff/compare`         | Structural diff between two entity graphs (overlap score)                                   |
| GET    | `/api/enrich/virustotal`    | VT-style reputation lookup (simulated if no key)                                            |
| GET    | `/api/enrich/hibp`          | Breach lookup for email (simulated if no key)                                               |
| GET    | `/api/enrich/summary`       | Unified enrichment summary (auto-detects entity type)                                       |
| POST   | `/api/auth/login`           | Demo JWT login (3 roles: admin, analyst, viewer)                                            |
| GET    | `/api/auth/me`              | Current user profile from JWT                                                               |
| GET    | `/api/auth/users`           | List demo users (admin only)                                                                |
| GET    | `/api/keys`                 | List API keys with masked previews (admin only)                                             |
| POST   | `/api/keys/create`          | Generate new API key (admin only)                                                           |
| DELETE | `/api/keys/{id}`            | Revoke an API key (admin only)                                                              |
| GET    | `/api/annotations`          | List annotations for an entity                                                              |
| POST   | `/api/annotations`          | Create annotation (`:Annotation` node with `:ANNOTATES` edge)                               |
| DELETE | `/api/annotations/{id}`     | Delete annotation                                                                           |
| GET    | `/api/watchlist`            | List watchlisted entities                                                                   |
| POST   | `/api/watchlist`            | Add entity to watchlist (`:Watchlist` node)                                                 |
| DELETE | `/api/watchlist/{id}`       | Remove from watchlist                                                                       |
| GET    | `/api/watchlist/check`      | Scan for new relationships since last check (accepts `since`)                               |
| POST   | `/api/detect/rules`         | Draft Sigma + YARA detection rules from active investigation (Claude Sonnet 4.6)            |
| POST   | `/api/threatmap`            | AI-generated SVG threat map                                                                 |

---

## 13. Post-Hackathon Feature Expansion

Cerberus shipped four phases of features after the hackathon prototype. Each phase is production-implemented.

### Phase 1 — Intelligence Upgrade

| Feature                            | What it does                                                                                                                                                                                                                                                                                                                                                       |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Threat Score (0-100)**           | Quantified risk score per entity. Factors: ThreatActor connections (+15), multiple actors (+10), CVE links (+15), FraudSignals (+10), malicious IPs (+10), cross-domain reach (+30), ConfirmedThreat tag (+10), entity exists (+10). Severity: critical (80-100), high (60-79), medium (40-59), low (20-39), info (0-19). Badge streams in NarrativePanel via SSE. |
| **Blast Radius**                   | Counts distinct entities reachable within 4 hops, broken down by type. Shows "X AFFECTED" badge in narrative header. Streams via SSE alongside threat score.                                                                                                                                                                                                       |
| **Shortest Path**                  | Finds the shortest path (up to 8 hops) between any two entities. Returns nodes + links in force-graph format with hop count.                                                                                                                                                                                                                                       |
| **"Investigate Next" suggestions** | After investigation completes, surfaces up to 5 unconfirmed high-connectivity entities. Clickable — immediately launches a new investigation.                                                                                                                                                                                                                      |
| **Relationship type filter**       | Graph toolbar checkbox panel to show/hide edges by type (EXPLOITS, LINKED_TO, OPERATES, etc.). Nodes orphaned by hidden edges are also hidden.                                                                                                                                                                                                                     |
| **Node search + highlight**        | Real-time text search in GraphPanel; matching nodes gain a gold ring + glow.                                                                                                                                                                                                                                                                                       |
| **Audience mode**                  | Toggle between **Technical** (full analyst narrative) and **Executive** (risk summary + key finding + recommended action). Persists across investigations.                                                                                                                                                                                                         |
| **Investigation history**          | Last 10 investigations saved to localStorage with entity name, severity dot, threat score, path count, and date. Click to re-investigate; clear button to wipe. Deduplicates on repeat runs.                                                                                                                                                                       |

### Phase 2 — Analyst Workflow

| Feature                       | What it does                                                                                                                                                       |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **NLP Query toggle**          | MessageSquare icon in QueryPanel toggles natural-language mode → POSTs to `/api/demo/natural` → extracts entity + type → auto-investigates.                        |
| **STIX Memory Export**        | MemoryPanel Download button batches STIX bundles for all confirmed nodes, deduplicates by STIX ID, downloads as `.json`.                                           |
| **Entity Comparison panel**   | Fifth center tab (GitCompare icon) — two entity inputs + `POST /api/diff/compare` → overlap score bar + shared/exclusive node lists.                               |
| **Collaborative Annotations** | Notes section in graph node sidebar → `:Annotation` nodes with `:ANNOTATES` edges. Full CRUD at `/api/annotations`.                                                |
| **Watchlist alerts**          | "Watch" button on any graph node. Header bell icon polls `/api/watchlist/check` every 30 s. Alert dropdown lists new relationships with bounce animation.          |
| **Memory tab**                | Visualizes the `ConfirmedThreat` subgraph from Neo4j as a force-graph. Click-to-expand nodes. Badge count in nav.                                                  |
| **MITRE Heatmap tab**         | `MitreHeatmapPanel` — tactic heatmap from `Technique` nodes in the current investigation.                                                                          |
| **Attack path stepper**       | BFS ordering from investigation root rendered in GraphPanel. Prev/Next buttons; active node highlighted in cyan.                                                   |
| **IOC extraction**            | `lib/iocExtract.ts` parses IPs, CVEs, domains, and packages from graph + narrative. Copy-all + CSV download.                                                       |
| **Session timeline**          | `TimelinePanel` at bottom of center column replays investigation step history.                                                                                     |
| **Geomap improvements**       | Auto zoom-to-fit, +/- / Reset zoom, tighter actor offsets.                                                                                                         |
| **Cross-domain fraud alerts** | QueryPanel left sidebar loads `/api/juspay/signals` and renders actor badges, IP-first rows with shared-infrastructure context (replaced raw transaction-ID list). |

### Phase 3 — RocketRide Deep Integration

The original agent used `agent_crewai` (a CrewAI wrapper with sequential tool execution). It was replaced with RocketRide's **native wave-planning agent**.

| Change                  | Details                                                                                                                                                                                             |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`agent_rocketride`**  | Wave-planning replaces sequential CrewAI. Parallelizes MCP tool calls per wave. Keyed `memory_internal` persists findings across investigation steps without re-querying.                           |
| **`extract_data` node** | Added to `cerberus-ingest.pipe`. Defines 5 typed columns (type, value, threat_domain, confidence, context). Returns tabular extraction instead of raw JSON text — eliminates fragile regex parsing. |
| **`tool_http_request`** | Added to threat agent for live enrichment mid-investigation. GET-only. URL whitelist: MITRE CVE API, AbuseIPDB, VirusTotal. Agent fetches CVE severity and IP reputation autonomously.              |

**Pipeline comparison:**

| Pipeline                     | Before                                                   | After                                                                                         |
| ---------------------------- | -------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `cerberus-threat-agent.pipe` | 5 nodes: chat → agent_crewai → llm + mcp → response      | 7 nodes: chat → agent_rocketride → llm + memory_internal + mcp + tool_http_request → response |
| `cerberus-ingest.pipe`       | 6 nodes: webhook → parse → ocr → prompt → llm → response | 8 nodes: + extract_data + llm2 for structured extraction                                      |

**Pipeline fallback chain:**

```text
cerberus-threat-agent.pipe  (agent_rocketride + MCP + memory)   ← primary
  ↓ fails
cerberus-query.pipe         (simple prompt + LLM)               ← secondary
  ↓ fails
llm.py direct Anthropic SDK call                                ← last resort
```

### Phase 4 — Analyst Operations Pack

| Feature                           | Details                                                                                                                                                                                                  |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **IOC Defanging toggle**          | Copy/CSV flows default to defanged output (`hxxp`, `[.]`) for safe sharing in Slack, Jira, and tickets. Toggle in NarrativePanel.                                                                        |
| **TLP-Aware Exports**             | TLP level selection in NarrativePanel UI. `/api/demo/report` and `/api/stix/bundle` accept `tlp` param; PDFs show TLP banner; STIX bundles emit `marking-definition` objects + `object_marking_refs`.    |
| **Markdown Summary clipboard**    | Serializes active investigation (threat score, blast radius, IOCs, MITRE techniques, suggestions) to clipboard-ready markdown.                                                                           |
| **Detection Rule Sketches**       | `POST /api/detect/rules` uses Claude Sonnet 4.6 to draft Sigma + YARA sketches from the active investigation. UI in NarrativePanel.                                                                      |
| **Bulk IOC Submission**           | QueryPanel bulk mode accepts newline/comma-separated entities, auto-detects types, throttles to 3 concurrent investigations, renders a click-through triage table.                                       |
| **Shareable Permalinks**          | Investigation URLs encode `entity` + `type`. App bootstraps from query params; NarrativePanel can copy a permalink.                                                                                      |
| **Enrichment Confidence Scoring** | Enrichment relationships now store `confidence`, `source_reliability`, `last_seen`, `corroboration_count`. Graph edge width/opacity reflects confidence. Threat score weights connections by confidence. |
| **Watchlist Change Digest**       | Header watchlist polling accumulates a digest window. "Mark reviewed" action. `/api/watchlist/check` accepts `since` param.                                                                              |
| **Authentication**                | JWT HS256 demo login (`POST /api/auth/login`) with 3 roles: admin, analyst, viewer. API key management (create/list/revoke) at `/api/keys/*`.                                                            |

---

## 14. UI Layout

```text
┌──────────────────────────────────────────────────────────────────────┐
│  Header: Cerberus logo │ RocketRide green dot │ Watchlist bell       │
├──────────────────────────────────────────────────────────────────────┤
│  LEFT PANEL           │  CENTER PANEL              │  RIGHT PANEL    │
│  QueryPanel           │  ViewNav tabs:             │  GraphPanel      │
│  ─────────────        │  • Threat Graph (2D)       │  (force-directed │
│  Entity input         │  • Geomap                  │   graph viz)     │
│  NLP toggle           │  • Memory                  │                  │
│  Bulk IOC mode        │  • MITRE Heatmap           │  Node sidebar:   │
│  Investigation hist.  │  • Compare                 │  properties,     │
│  ─────────────        │  ─────────────────────     │  annotations,    │
│  Cross-domain         │  NarrativePanel (below):   │  watch button    │
│  fraud alerts         │  Pipeline stages           │                  │
│                       │  Threat score badge        │  Filters:        │
│                       │  Blast radius badge        │  rel-type toggle │
│                       │  Audience toggle           │  node search     │
│                       │  TLP selector              │                  │
│                       │  Narrative (streaming)     │                  │
│                       │  IOC extraction + CSV      │                  │
│                       │  Detection rules           │                  │
│                       │  Markdown/Permalink copy   │                  │
│                       │  Investigate Next list     │                  │
│                       │  ─────────────────────     │                  │
│                       │  TimelinePanel (bottom)    │                  │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 15. Anticipated Questions & Answers

### "Why not just use Postgres?"

Our core query is a cross-domain traversal: package → vulnerability → threat actor → IP → fraud signal. That's 4 hops across 4 domains. In SQL, it's 8 JOINs and 5 bridge tables — and you'd need a different query for each of the 5 input types. In Cypher, it's one pattern match. With 8 entity types and a max depth of 5 hops, this is exactly what graph databases are built for.

### "Why not vector search?"

Vector search finds similar things. We need connected things. "ua-parser-js is semantically similar to event-stream" is interesting but doesn't tell you the attack chain: package → CVE → threat actor → IP → fraud signal. That's a traversal, not a similarity search. The relationships ARE the intelligence.

### "Is the Account→IP link real?"

It's simulated. No public API maps npm publishers to IPs. In production, this comes from Git commit metadata, npm publish audit logs, or SIEM correlation. We render these as dashed edges so you can see what's real vs. synthetic.

### "How does the self-improvement loop actually work?"

Three mechanisms: (1) Seeded graph data means the LLM gets richer context and needs shorter prompts. (2) Analyst-confirmed patterns get tagged in the graph. (3) On repeat queries, we detect the confirmed tag and return the cached narrative without calling the LLM. Measurably: 8s → 5s → 2s.

### "What makes this a 'thoughtful agent' vs. a chatbot?"

The pipeline makes visible decisions. It identifies the entity type (NER), classifies the threat domain (classification), chooses a traversal strategy (routing), and explains why it queried specific domains. Each stage is visible in the UI. A chatbot hides its reasoning; Cerberus shows it.

### "What's the RocketRide integration?"

RocketRide runs a **native wave-planning agent** (`agent_rocketride`) that connects to our neo4j-mcp server via an MCP Client node. The agent autonomously explores the Neo4j threat graph in parallel wave steps, stores cross-wave findings in keyed `memory_internal`, and calls `tool_http_request` to fetch live threat intel (AbuseIPDB, VirusTotal, MITRE CVE API) mid-investigation. It's not a chatbot wrapper — it decides what to query, when to call external APIs, and how to synthesize findings into a narrative using Claude Sonnet 4.6. If RocketRide is unavailable, the system falls back to a simpler prompt+LLM pipeline, then to direct Anthropic SDK calls as a last resort.

### "Could this scale to production?"

The current demo graph has ~1,060 nodes. Neo4j Aura scales to millions. The architecture supports it: bounded traversals (`[*..6]`), index-backed lookups, and the cache layer means confirmed patterns never hit the LLM again. Enrichment relationships are stamped with confidence + source_reliability metadata so signal quality degrades gracefully as data ages. The bottleneck at scale would be LLM calls — which the self-improvement loop progressively eliminates.

### "What happens when I query something not in the database?"

Cerberus automatically enriches from public threat intel APIs. If you query an npm package that's not in the graph, it hits OSV.dev to find known CVEs, writes new nodes/edges to Neo4j, and re-traverses in the same request. For CVEs, it queries NVD and creates/updates the CVE node. If that CVE has no connected package/actor edges yet, Cerberus still returns a clean assessment and neighborhood context instead of failing. Supported live lookups: packages (OSV.dev), CVEs (NVD), IPs (Abuse.ch Feodo Tracker/URLhaus), and domains (Abuse.ch URLhaus). No API keys needed.

### "How current is the threat data?"

The seed data includes MITRE ATT&CK (updated March 2025) and ~50 known CVEs. More importantly, the enrichment layer fetches live data from OSV.dev, NVD, and Abuse.ch whenever an entity is missing. In practice this means Cerberus can ingest a newly published CVE quickly (subject to upstream source freshness/propagation), persist it, and include it in future traversals.

### "Is FraudSignal integrated, and are we using Juspay?"

Yes on graph integration: `FraudSignal` is a first-class node label, linked via `(:IP)-[:ASSOCIATED_WITH]->(:FraudSignal)`, and included in traversal/cross-domain output and reporting.

Current runtime status:

- Frontend live feed currently uses demo endpoints (`/api/demo/feed`, `/api/demo/feed/ingest`) for hackathon UX.
- Backend has real Juspay-style ingestion endpoints (`/api/juspay/ingest`, `/api/juspay/signals`) that normalize payloads and write to Neo4j.
- So Juspay is integrated at the data/API layer; the default UI feed is still demo-simulated unless explicitly wired to the `/api/juspay/*` routes.

---

## 14. One-Line Pitches (Pick Your Audience)

**For judges:**

> Cerberus is a thoughtful security agent that traces cross-domain attack chains in 5 seconds instead of 4 hours — enriching gaps with live threat intel and learning from every investigation.

**For security professionals:**

> It connects your npm audit, Shodan, MITRE ATT&CK, and fraud dashboard into one queryable attack chain — and auto-enriches from OSV.dev, NVD, and Abuse.ch when entities are missing.

**For technical audiences:**

> Neo4j knowledge graph + real-time API enrichment + Claude narrative generation + self-improving cache, orchestrated through a CrewAI agent with MCP tools that shows its reasoning at every step.

**For non-technical audiences:**

> When hackers attack through software, we automatically trace the full chain — who did it, what infrastructure they used, and where the money went — in seconds instead of hours. Even if we've never seen the threat before.

---

_This document is current as of the latest implementation. Real-time enrichment from OSV.dev, NVD, and Abuse.ch is live. All imports verified against live Neo4j Aura instance (~1,060 nodes). Demo chain (ua-parser-js → APT41 → fraud signals) confirmed end-to-end._
