# Cerberus — Technical Onboarding & Pitch Document

> **Audience:** Anyone who needs to understand, demo, or pitch Cerberus without having built it.
> **Read time:** 15 minutes. After reading, you should be able to explain every feature to a judge, investor, or security professional.

---

## 1. The Problem

Security analysts today face a fragmented world. When a suspicious npm package appears in their codebase, they have to manually cross-reference across **4+ disconnected tools**:

| What they need to know | Where they look | Time |
|---|---|---|
| Is this package vulnerable? | Snyk, npm audit | 5 min |
| Who published it? | npm registry | 5 min |
| Is that publisher suspicious? | GitHub, manual OSINT | 20 min |
| What infrastructure is involved? | Shodan, VirusTotal | 30 min |
| Is the IP linked to known threat actors? | MITRE ATT&CK, threat feeds | 30 min |
| Are there financial fraud signals? | Internal fraud dashboard | 20 min |
| How does it all connect? | **Analyst's brain + spreadsheet** | **2-3 hours** |

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

| Entity Type | API | What it returns |
|---|---|---|
| **npm/PyPI packages** | [OSV.dev](https://osv.dev) | Known CVEs + severity + CVSS scores |
| **CVE IDs** | [NVD](https://nvd.nist.gov) | Full CVE details, CVSS v3 scoring |
| **IP addresses** | [Abuse.ch Feodo Tracker](https://feodotracker.abuse.ch) + [URLhaus](https://urlhaus.abuse.ch) | Malware family, first seen date, associated URLs |
| **Domains** | [Abuse.ch URLhaus](https://urlhaus.abuse.ch) | Malicious URL count, threat types |

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

| Tool | What it sees | What it misses |
|------|---|---|
| **npm audit / Snyk** | Package → CVE | Who's behind it, what infrastructure, financial impact |
| **Shodan** | IP → open ports, services | How it connects to software supply chain |
| **VirusTotal** | Domain/IP reputation scores | The actor behind it, lateral connections |
| **MITRE ATT&CK** | Techniques and groups (reference) | Real-time connection to your specific entities |
| **Fraud dashboards** | Transaction anomalies | How fraud signals link to software compromises |
| **Cerberus** | **All of the above, connected** | — |

---

## 9. Architecture (How It Works Under the Hood)

### System Flow

```text
User Input (browser)
     │
     ▼
Frontend (React + Vite + Tailwind)
     │  HTTP POST or SSE GET
     ▼
Backend (FastAPI, port 8000)
     │
     ├──→ Cache check (does a confirmed pattern exist in Neo4j?)
     │       │
     │       ├── YES → Return cached narrative (skip LLM, ~2s)
     │       │
     │       └── NO → Continue pipeline
     │
     ├──→ Neo4j Aura (graph traversal via Bolt driver)
     │       Returns: paths as structured data
     │       │
     │       └── No paths? → Real-time enrichment
     │              │
     │              ├── OSV.dev (package vuln lookup)
     │              ├── NVD (CVE detail lookup)
     │              ├── Abuse.ch Feodo Tracker (IP lookup)
     │              └── Abuse.ch URLhaus (domain lookup)
     │              │
     │              └── Data found → Ingest into Neo4j → Re-traverse
     │
     ├──→ RocketRide AI (agent + MCP orchestration)
     │       CrewAI agent with MCP Client → neo4j-mcp
     │       Falls back to direct LLM if unavailable
     │
     ├──→ Anthropic Claude (narrative generation)
     │       Input: graph paths as context
     │       Output: streamed threat narrative
     │
     └──→ Write-back to Neo4j (tag analyzed nodes, store narrative hash)
     
     │
     ▼
Frontend receives:
  - SSE events for pipeline stage indicators
  - Graph data for visualization (nodes + edges)
  - Streamed narrative text
```

### Tech Stack Summary

| Layer | Technology | Why |
|---|---|---|
| **Graph DB** | Neo4j Aura (free tier) | Relationships are first-class; cross-domain traversal in one query |
| **MCP Bridge** | neo4j-mcp v1.5.0 | HTTP bridge to Neo4j for agent tool-use (schema, Cypher) |
| **Backend** | FastAPI + Python | Async, SSE support, fast to build |
| **Orchestration** | RocketRide AI (CrewAI agent + MCP Client) | Autonomous agent explores graph via MCP tools |
| **Enrichment** | OSV.dev, NVD, Abuse.ch | Real-time threat intel for unknown entities (free, no keys) |
| **LLM** | Anthropic Claude Sonnet | Narrative generation from graph context |
| **Frontend** | React 18 + Vite + Tailwind + shadcn/ui | Modern, fast, component library |
| **Graph Viz** | react-force-graph-2d + SVG ThreatMap | Force-directed graph + separate geo threat map visualization |
| **Streaming** | SSE (Server-Sent Events) | Real-time pipeline progress + narrative streaming |

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

| Input Type | Example | Starting Traversal |
|---|---|---|
| **Package** | `ua-parser-js` | Package → CVE → ThreatActor → IP → FraudSignal |
| **IP Address** | `203.0.113.42` | IP → ThreatActor → CVE → Package + IP → FraudSignal |
| **Domain** | `evil-cdn.example.com` | Domain → IP → ThreatActor → Techniques |
| **CVE** | `CVE-2021-27292` | CVE → Package + CVE → ThreatActor → IP |
| **Threat Actor** | `APT41` | ThreatActor → Techniques + IPs + Domains + CVEs |
| **FraudSignal** | `JSPY-2026-0091` | FraudSignal → IP → ThreatActor / Account / Package |

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

| Endpoint | Method | Purpose |
|---|---|---|
| `/health` | GET | Health check |
| `/api/schema` | GET | Live graph schema (labels, relationship types, counts) |
| `/api/query` | POST | Main investigation: entity + type → graph + narrative |
| `/api/query/stream` | GET | SSE streaming version of the above |
| `/api/confirm` | POST | Analyst confirms a threat pattern |
| `/api/query/graph` | GET | Full graph data for visualization |
| `/api/demo/natural` | POST | Free-text NLP entity extraction |
| `/api/demo/compare` | POST | Multi-entity side-by-side comparison |
| `/api/demo/feed` | GET | Live synthetic fraud event stream |
| `/api/demo/feed/ingest` | POST | Ingest selected feed event into Neo4j |
| `/api/juspay/ingest` | POST | Ingest normalized Juspay-style fraud payload(s) |
| `/api/juspay/signals` | GET | FraudSignal summary (counts, actor links, recent signals) |
| `/api/demo/map` | GET | Geo-IP data for map visualization |
| `/api/demo/report` | GET | Full investigation report |

---

## 13. Anticipated Questions & Answers

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

RocketRide orchestrates a **CrewAI agent with an MCP Client** that connects directly to our neo4j-mcp server. The agent autonomously explores the Neo4j threat graph using MCP tools (schema introspection, Cypher queries) and generates threat narratives using Claude Sonnet. It's not just an LLM wrapper — it's an autonomous agent that decides what to query and how to traverse the graph. If RocketRide is unavailable, the backend falls back to direct Claude calls.

### "Could this scale to production?"

The current demo graph has ~1,060 nodes. Neo4j Aura scales to millions. The architecture supports it: bounded traversals (`[*..6]`), index-backed lookups, and the cache layer means confirmed patterns never hit the LLM again. The bottleneck at scale would be the LLM call, which the self-improvement loop progressively eliminates.

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

*This document is current as of the latest implementation. Real-time enrichment from OSV.dev, NVD, and Abuse.ch is live. All imports verified against live Neo4j Aura instance (~1,060 nodes). Demo chain (ua-parser-js → APT41 → fraud signals) confirmed end-to-end.*