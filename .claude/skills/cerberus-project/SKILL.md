# Cerberus — Cross-Domain Threat Intelligence Platform

> **Live Document** — Update this skill as the project evolves. This is the canonical reference for architecture, data model, hackathon framing, and implementation status.

## Project Context

- **Hackathon:** HackWithBay 2.0
- **Theme:** Thoughtful Agents for Productivity
- **Team:** 2 people
- **Timeline:** 8 hours on-site + 2-3 days polish
- **Sponsors:** Neo4j (primary DB), RocketRide AI (orchestration), Juspay (financial signals)

## One-Line Pitch

> Cerberus is a thoughtful security agent that eliminates the 4-hour manual graph-traversal process of tracing cross-domain attack chains — it reasons about which domains to query, connects the signals no single-surface tool can see, and learns from analyst feedback to get faster with every investigation.

## Architecture Overview

```
INPUT LAYER (GitHub URL / npm package / IP / domain / Juspay ID)
       ↓
ROCKETRIDE PIPELINE ("thoughtful agent")
  Webhook → NER → Text Classification → Route Decision
       ↓
  MCP Client → neo4j-mcp server (write-cypher / read-cypher)
       ↓
  LLM Node (Anthropic) — graph context → threat narrative
       ↓
  Text Output → SSE stream to frontend
       ↓
SELF-IMPROVEMENT LOOP
  Confirmed patterns → labeled subgraph → cache hits skip LLM
       ↓
FRONTEND (React + Tailwind + shadcn/ui + neovis.js)
```

## Key Tech Stack

| Component | Technology |
|-----------|-----------|
| Graph DB | Neo4j Aura (free tier) |
| MCP Bridge | neo4j-mcp v1.5.0 — HTTP mode on 127.0.0.1:8787 |
| Backend | FastAPI + uvicorn (port 8000) |
| Orchestration | RocketRide AI |
| Frontend | React 18 + Vite + Tailwind + shadcn/ui |
| Graph Viz | neovis.js (via backend proxy — never direct Aura connection) |
| Streaming | SSE (via sse-starlette + FastAPI StreamingResponse) |
| LLM | Anthropic Claude (claude-opus-4-6, via anthropic SDK) |
| HTTP client | httpx (async) |

## Neo4j Schema

### Node Labels

| Label | Key Property | Source |
|-------|-------------|--------|
| `Package` | name (UNIQUE) | npm registry |
| `CVE` | id (UNIQUE) | NVD/MITRE |
| `IP` | address (UNIQUE) | threat intel feeds |
| `Domain` | name (UNIQUE) | DNS/WHOIS |
| `ThreatActor` | name (UNIQUE) | MITRE ATT&CK |
| `Technique` | mitre_id (UNIQUE) | MITRE ATT&CK STIX |
| `Account` | (username, registry) UNIQUE | npm/GitHub |
| `FraudSignal` | juspay_id (UNIQUE) | Juspay API |

### Relationships

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
(:Account)-[:LINKED_TO]->(:IP)          ⚠ SYNTHETIC — see note
(:Domain)-[:SERVES]->(:Package)
```

### ⚠ Synthetic Data: Account → IP

No public source maps npm publishers to IPs. These links are simulated for demo. Render with **dashed edges** in visualization.

**Judge answer:** "The Account-to-IP link is simulated from threat intel correlation. In production, this would come from Git commit metadata, npm publish audit logs, or SIEM data."

## Demo Entity: ua-parser-js

Primary demo target. Hijacked Oct 2021 — versions 0.7.29, 0.8.0, 1.0.0 contained cryptomining + credential-stealing malware. CVE-2021-27292 (ReDoS). Fallback demo: `colors` v1.4.1 sabotage.

## RocketRide Pipelines

1. **cerberus-ingest** — Raw input → NER → classify → write to graph
2. **cerberus-query** — Entity → reason → route → traverse → narrate → learn
3. **cerberus-juspay** (stretch) — Juspay fraud alerts → enrich graph

## Self-Improvement Loop

| Phase | State | Behavior |
|-------|-------|----------|
| 1 (empty) | No prior patterns | Full LLM analysis, ~8s |
| 2 (seeded) | MITRE + CVE imported | Shorter prompts, ~5s |
| 3 (confirmed) | Analyst-confirmed patterns | Cache hit, skip LLM, ~2s |

## User Stories

### Core Investigation Flow

- **US-1: Package investigation** — As a security analyst, I can paste an npm package name (e.g., `ua-parser-js`) and get back a cross-domain attack chain showing how that package connects to threat actors, malicious IPs, and fraud signals — so I don't have to manually correlate across Snyk, Shodan, and fraud dashboards.
- **US-2: IP investigation** — As a security analyst, I can submit a suspicious IP address and see which threat actors operate from it, which domains it hosts, which packages it's linked to, and whether it appears in fraud signals — giving me full infrastructure context in one query.
- **US-3: Domain investigation** — As a security analyst, I can submit a domain and trace it to hosting IPs, threat actors who control it, and any packages it serves — revealing supply-chain attack infrastructure.
- **US-4: Streaming narrative** — As a security analyst, I can watch an AI-generated threat narrative stream in real time as the pipeline runs, explaining the cross-domain attack chain in plain language with specific node names and relationship types — so I can brief stakeholders without manually writing reports.

### Visible Agent Reasoning

- **US-5: Pipeline stage visibility** — As a user, I can see each pipeline stage (NER → Classify → Route → Graph → Analyze → Narrate) light up as it executes — so I understand what the agent is doing and trust it's reasoning, not just spinning.
- **US-6: Route decision** — As a user, I can see which cross-domain traversal the agent chose (software→infra, infra→financial, full cross-domain) and why — reinforcing the "Thoughtful Agent" theme.

### Self-Improvement Loop

- **US-7: Analyst confirmation** — As a security analyst, I can confirm a threat pattern the agent found, which tags the subgraph as a known pattern — so future queries on the same chain are instant.
- **US-8: Cache hit skip** — As a returning user, when I query an entity whose attack chain was previously confirmed, the system returns the cached result instantly (~2s) without calling the LLM — proving the agent learns from feedback.
- **US-9: Progressive improvement** — As a demo viewer, I can see eval output showing Phase 1 (empty, ~8s) → Phase 2 (seeded, ~5s) → Phase 3 (confirmed, ~2s) with assertions passing — proving the system measurably improves.

### Graph Visualization

- **US-10: Interactive graph** — As a user, I can see the attack chain rendered as a color-coded force-directed graph (Package=blue, CVE=red, IP=orange, ThreatActor=purple, FraudSignal=yellow) with the traversal path highlighted.
- **US-11: Synthetic edge distinction** — As a user, I can distinguish real data from synthetic data because Account→IP links render with dashed edges.
- **US-12: Node inspection** — As a user, I can click any node in the graph to see its properties in a sidebar.

### Data Ingestion

- **US-13: Seed data import** — As a developer, I can run the import scripts to populate the graph with ~200 MITRE techniques, ~100 groups, ~50 CVEs, ~100 malicious IPs, ~30 compromised packages, and ~20 synthetic fraud signals — enough for a compelling demo.
- **US-14: Live entity ingestion** — As a user, when I submit a new entity, the ingest pipeline extracts entities via NER, classifies the threat type, and writes new nodes/relationships to the graph — so the knowledge base grows with use.

### Comparison / Demo

- **US-15: Split-screen comparison** — As a demo viewer, I can see a side-by-side of Cerberus's multi-domain graph vs `npm audit` output for the same package — making it viscerally clear that single-surface tools miss cross-domain attack chains.

## Critical Gotchas

- **APOC availability:** Test `RETURN apoc.version()` hour 1. If missing, `get-schema` won't work — use `read-cypher` with manual schema queries.
- **neovis.js credentials:** Always proxy through backend. Never expose Neo4j creds in frontend JS.
- **Cypher patterns:** Always use `shortestPath` + directed patterns. Never unbounded undirected traversals.
- **Node IDs:** Use domain keys (`{name: $startName}`), never `id()` internal IDs.
- **Uniqueness constraints:** Run ALL 8 constraints before ANY import.

## Environment Variables

```
NEO4J_URI=neo4j+s://<aura-instance>
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=<password>
ANTHROPIC_API_KEY=sk-ant-...            # Anthropic API key
NEO4J_MCP_URL=http://127.0.0.1:8787    # MCP server (optional, has default)
ROCKETRIDE_URL=http://127.0.0.1:3000   # RocketRide (optional, has default)
CERBERUS_API=http://localhost:8000
```

⚠️ **Known issue:** `backend/config.py` reads `ANTHROPIC_KEY` from `NEO4J_API_KEY` env var (semantic mismatch). Fix before demo.

## Backend API (FastAPI)

### Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/health` | Health check → `{"status": "ok"}` |
| GET | `/api/schema` | Live graph schema (labels, rel types, counts) |
| POST | `/api/query` | Main query: cache check → traverse → LLM narrative |
| GET | `/api/query/stream` | SSE streaming version of query endpoint |
| POST | `/api/confirm` | Analyst confirms threat pattern → write-back |

### Query Pipeline Flow

```
Input: entity + type (package/ip/domain/cve/threatactor)
  ↓
Cache hit? → YES → Return cached narrative (no LLM, ~2s)
  ↓ NO
Graph traversal (domain-routed Cypher)
  ↓
Paths found? → NO → Generic "not found" message
  ↓ YES
LLM narrative generation (Claude, 600 tokens max)
  ↓
Write-back: tag nodes with analysis timestamp
  ↓
Return response
```

### Key Backend Files

| File | Purpose |
|------|---------|
| `backend/main.py` | FastAPI app, CORS, lifespan, schema endpoint |
| `backend/config.py` | Env var loader with validation |
| `backend/neo4j_client.py` | Neo4j driver wrapper, traversal queries, cache/confirm |
| `backend/llm.py` | Anthropic Claude narrative generation (blocking + streaming) |
| `backend/routes/query.py` | POST /api/query + GET /api/query/stream |
| `backend/routes/confirm.py` | POST /api/confirm |

## RocketRide Pipeline Definitions

Pipeline YAML configs live in `pipelines/`:

| File | Purpose | Key Nodes |
|------|---------|-----------|
| `cerberus-ingest.yaml` | Raw input → NER → classify → Neo4j write | webhook → NER (Claude Haiku 4.5) → classifier → cypher-builder → neo4j-write |
| `cerberus-query.yaml` | Thoughtful agent query pipeline | chat → NER → classifier → cache-check → branch → traverse → LLM → write-back |
| `cerberus-juspay.yaml` | Juspay fraud signal ingestion (stretch) | webhook → parser → validator → neo4j-write-fraud → neo4j-enrich |

## Test Suite

Three test files in `tests/`:

| File | Coverage |
|------|---------|
| `test_api_routes.py` | API routes with mocked Neo4j/LLM (health, query cache hit/miss/empty, confirm) |
| `test_import_scripts.py` | Data parsing logic, integrity checks (MITRE, CVE, npm, synthetic, threats) |
| `test_neo4j_client.py` | Entity routing, Cypher template rendering, cache/traverse/confirm logic |

## Project Structure (Current)

```
Cerberus/
├── CLAUDE.md
├── spec.md
├── .env.example
├── requirements.txt            # FastAPI, neo4j, anthropic, stix2, etc.
├── docker-compose.yml          # neo4j-mcp + backend + frontend
│
├── backend/                    # FastAPI application
│   ├── Dockerfile
│   ├── main.py                 # App entry point, CORS, /health, /api/schema
│   ├── config.py               # Env var loader
│   ├── neo4j_client.py         # Neo4j driver wrapper, traversal, cache
│   ├── llm.py                  # Anthropic Claude narrative gen
│   └── routes/
│       ├── query.py            # POST /api/query, GET /api/query/stream
│       └── confirm.py          # POST /api/confirm
│
├── pipelines/                  # RocketRide YAML definitions
│   ├── cerberus-ingest.yaml
│   ├── cerberus-query.yaml
│   └── cerberus-juspay.yaml
│
├── scripts/                    # Teammate's versions of import scripts
│   ├── constraints.cypher
│   ├── import_mitre.py
│   ├── import_cve.py
│   ├── import_npm.py
│   ├── import_synthetic.py
│   ├── import_threats.py
│   └── eval_improvement.py
│
├── tests/                      # Test suite
│   ├── test_api_routes.py
│   ├── test_import_scripts.py
│   └── test_neo4j_client.py
│
├── constraints.cypher          # Root version (documented, same 8 constraints)
├── import_mitre.py             # Root version (caching, fewer deps)
├── import_cve.py               # Root version (NVD API fetcher)
├── import_threats.py           # Root version (Abuse.ch feeds)
├── import_npm.py               # Root version (25 curated packages)
├── import_synthetic.py         # Root version (cross-domain bridges)
├── eval_improvement.py         # Root version (3-phase eval)
├── entity_schema.json          # Integration contract JSON schema
│
├── seed_data/                  # Pre-downloaded data feeds
│   ├── README.md
│   ├── enterprise-attack.json  # ~43MB MITRE ATT&CK STIX (gitignored)
│   ├── threat_ips.json         # Cached IPs
│   └── threat_domains.json     # Cached domains
│
├── neo4j-mcp_Darwin_arm64/     # MCP server binary
│   └── neo4j-mcp
│
├── frontend/                   # React app (TBD — not yet scaffolded)
└── docs/                       # Retrospectives (TBD)
```

⚠️ **Duplicate files:** Import scripts exist in both root and `scripts/`. Root versions have caching + fewer deps (urllib vs requests). `scripts/` versions use requests + stix2. Consolidate before hackathon day.

## Implementation Status

- [x] Spec v2 finalized
- [x] neo4j-mcp v1.5.0 confirmed locally
- [x] Project skill created
- [x] constraints.cypher (both versions)
- [x] Import scripts (root versions with caching)
- [x] Import scripts (scripts/ versions with stix2)
- [x] eval_improvement.py
- [x] seed_data/ — MITRE data pre-downloaded (~43MB)
- [x] docker-compose.yml (3 services: mcp + backend + frontend)
- [x] Entity JSON schema
- [x] Backend API (FastAPI) — main, config, neo4j_client, llm, routes
- [x] RocketRide pipeline YAML definitions (ingest, query, juspay)
- [x] Test suite (API routes, import scripts, neo4j client)
- [ ] Fix config.py ANTHROPIC_KEY ← NEO4J_API_KEY mismatch
- [ ] Consolidate duplicate import scripts (root vs scripts/)
- [ ] Frontend scaffolded
- [ ] End-to-end integration tested
- [ ] Demo rehearsed + pre-cached

## Known Issues

1. **config.py semantic mismatch:** `ANTHROPIC_KEY` reads from `NEO4J_API_KEY` env var — confusing and error-prone
2. **neo4j_client.py unused import:** `hashlib` imported but never used (was for narrative_hash, not implemented)
3. **neo4j_client.py Cypher templating:** Uses `.format()` for labels/keys — mitigated by enum routing but fragile
4. **CORS wide open:** `allow_origins=["*"]` in main.py — acceptable for hackathon, note for judges
5. **Duplicate import scripts:** Root versions (urllib, caching) vs scripts/ versions (requests, stix2) need consolidation
