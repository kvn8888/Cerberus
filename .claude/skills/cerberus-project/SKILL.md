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
FRONTEND (React + Tailwind + shadcn/ui + react-force-graph-2d + SVG ThreatMap)
```

## Key Tech Stack

| Component | Technology |
|-----------|-----------|
| Graph DB | Neo4j Aura (free tier) |
| MCP Bridge | neo4j-mcp v1.5.0 — HTTP mode on 127.0.0.1:8787 |
| Backend | FastAPI + uvicorn (port 8000) |
| Orchestration | RocketRide AI |
| Frontend | React 18 + Vite + Tailwind + shadcn/ui |
| Graph Viz | react-force-graph-2d + custom SVG ThreatMap |
| Streaming | SSE (via sse-starlette + FastAPI StreamingResponse) |
| LLM | Anthropic Claude (claude-sonnet-4-20250514, via anthropic SDK) |
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

### Primary: Agent + MCP Client Pipeline (`cerberus-threat-agent.pipe`)

The main pipeline uses RocketRide's **CrewAI agent** with an **MCP Client** node
that connects directly to our neo4j-mcp server. The agent autonomously explores
the Neo4j threat graph using MCP tools (get-schema, read-cypher) and generates
threat narratives using Claude Sonnet 4.6.

```
chat → agent_crewai → [invoke] → mcp_client (neo4j-mcp @ NEO4J_MCP_ENDPOINT)
                    → [invoke] → llm_anthropic (Claude Sonnet 4.6)
         ↓
    response_answers
```

This is the natural integration — RocketRide is the AI orchestration layer,
not just a wrapper around LLM calls.

### Fallbacks

| File | Purpose | Nodes | When Used |
|------|---------|-------|-----------|
| `cerberus-threat-agent.pipe` | **Primary** — Agent with MCP Client queries Neo4j directly | chat → agent_crewai → mcp_client + llm_anthropic → response_answers | Default when RocketRide + neo4j-mcp are reachable |
| `cerberus-query.pipe` | **Fallback** — Simple prompt + LLM (no MCP) | chat → prompt → llm_anthropic → response_answers | Agent pipeline fails to load |
| `cerberus-ingest.pipe` | NER entity extraction from free-text | chat → prompt → llm_anthropic (Haiku) → response_answers | `/api/demo/natural` endpoint |
| Direct Anthropic (llm.py) | **Last resort** — no RocketRide at all | Backend calls Anthropic SDK directly | RocketRide unavailable |

### RocketRide Env Vars

```
ROCKETRIDE_URI=http://localhost:5565      # RocketRide engine (local or cloud)
ROCKETRIDE_APIKEY=...                     # Auth key
ROCKETRIDE_ANTHROPIC_KEY=sk-ant-...       # Anthropic key interpolated into pipeline LLM nodes
NEO4J_MCP_ENDPOINT=http://localhost:8787/mcp  # MCP endpoint for RocketRide's MCP Client node
```

## Self-Improvement Loop

| Phase | State | Behavior |
|-------|-------|----------|
| 1 (empty) | No prior patterns | Full LLM analysis, ~8s |
| 2 (seeded) | MITRE + CVE imported | Shorter prompts, ~5s |
| 3 (confirmed) | Analyst-confirmed patterns | Cache hit, skip LLM, ~2s |

## Real-Time Enrichment (`backend/enrich.py`)

When a user queries an entity that doesn't exist in the graph, the backend
automatically fetches threat intel from public APIs and ingests findings
into Neo4j on-the-fly. Subsequent queries hit the cached data.

### Flow

```
User queries "lodash" → db.traverse() → paths_found=0
  → enrich.try_enrich("lodash", "package")
  → OSV.dev API: 8 CVEs found → MERGE into Neo4j
  → db.traverse() again → paths_found=8
  → LLM narrative generated normally
Next query for "lodash" → db.traverse() → paths_found=8 (already enriched, skip)
```

### Supported Sources

| Entity Type | API Source | Auth | Rate Limit |
|-------------|-----------|------|------------|
| package | OSV.dev (`/v1/query`) | None | Unlimited |
| cve | NVD REST API 2.0 | None (optional key) | 5 req/30s |
| ip | Abuse.ch Feodo Tracker + URLhaus | None | Public feed |
| domain | Abuse.ch URLhaus (`/v1/host/`) | None | Public |

### Frontend Pipeline Stage

The "ENRICH" stage appears in the pipeline visualization between TRAVERSE and
ANALYZE, with a cloud-download icon. Only lights up when enrichment is triggered.

## User Stories

### Core Investigation Flow

- **US-1: Package investigation** — As a security analyst, I can paste an npm package name (e.g., `ua-parser-js`) and get back a cross-domain attack chain showing how that package connects to threat actors, malicious IPs, and fraud signals — so I don't have to manually correlate across Snyk, Shodan, and fraud dashboards.
- **US-2: IP investigation** — As a security analyst, I can submit a suspicious IP address and see which threat actors operate from it, which domains it hosts, which packages it's linked to, and whether it appears in fraud signals — giving me full infrastructure context in one query.
- **US-3: Domain investigation** — As a security analyst, I can submit a domain and trace it to hosting IPs, threat actors who control it, and any packages it serves — revealing supply-chain attack infrastructure.
- **US-4: Streaming narrative** — As a security analyst, I can watch an AI-generated threat narrative stream in real time as the pipeline runs, explaining the cross-domain attack chain in plain language with specific node names and relationship types — so I can brief stakeholders without manually writing reports.

### Visible Agent Reasoning

- **US-5: Pipeline stage visibility** — As a user, I can see each pipeline stage (NER → Classify → Route → Graph → Enrich → Analyze → Narrate) light up as it executes — so I understand what the agent is doing and trust it's reasoning, not just spinning.
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
- **Frontend build-time API base:** `VITE_API_URL` is baked at build time. If it changes, rebuild the frontend image/bundle.
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
ROCKETRIDE_URI=http://localhost:5565    # RocketRide SDK server
ROCKETRIDE_APIKEY=...                   # RocketRide auth key
ROCKETRIDE_ANTHROPIC_KEY=sk-ant-...     # Anthropic key for pipeline LLM nodes
NEO4J_MCP_ENDPOINT=http://localhost:8787/mcp  # MCP endpoint for RocketRide's MCP Client node
CERBERUS_API=http://localhost:8000
```

⚠️ ~~Known issue: `backend/config.py` reads `ANTHROPIC_KEY` from `NEO4J_API_KEY` env var~~ — VERIFIED FALSE. `ANTHROPIC_KEY = _require("ANTHROPIC_API_KEY")` is correct.

## Backend API (FastAPI)

### Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/health` | Health check → `{"status": "ok"}` |
| GET | `/api/schema` | Live graph schema (labels, rel types, counts) |
| POST | `/api/query` | Main query: cache check → traverse → LLM narrative |
| GET | `/api/query/stream` | SSE streaming version of query endpoint |
| POST | `/api/confirm` | Analyst confirms threat pattern → write-back (returns count + message) |
| GET | `/api/query/graph` | Force-directed graph data (nodes + edges) for vis |
| POST | `/api/demo/natural` | NLP entity extraction from free-text |
| POST | `/api/demo/compare` | Multi-entity comparison (side-by-side) |
| GET | `/api/demo/feed` | Synthetic fraud event stream |
| POST | `/api/demo/feed/ingest` | Upsert fraud signals into graph |
| POST | `/api/juspay/ingest` | Ingest normalized Juspay-style fraud signals |
| GET | `/api/juspay/signals` | Summarize FraudSignal layer (counts, actor links, recent) |
| GET | `/api/demo/map` | Geo-IP map data (lat/lng points) |
| GET | `/api/demo/report` | Full investigation report (Juspay summary) |

### Query Pipeline Flow

```
Input: entity + type (package/ip/domain/cve/threatactor)
  ↓
Cache hit? → YES → Return cached narrative (no LLM, ~2s)
  ↓ NO
Graph traversal (domain-routed Cypher)
  ↓
Paths found? → NO → Real-time enrichment (OSV.dev / NVD / Abuse.ch)
  ↓                    ↓
  ↓               Data ingested? → YES → Re-traverse graph
  ↓                    ↓ NO
  ↓               Return "entity not found"
  ↓
Paths found → YES
  ↓
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
| `backend/neo4j_client.py` | Neo4j driver wrapper, traversal, cache/confirm, graph viz, geo, Juspay |
| `backend/llm.py` | Anthropic Claude narrative generation (blocking + streaming) |
| `backend/rocketride.py` | RocketRide pipeline integration (async httpx, SSE proxy, 60s timeout) |
| `backend/enrich.py` | Real-time threat intel enrichment (OSV.dev, NVD, Abuse.ch) |
| `backend/models.py` | Pydantic models: EntityType, QueryRequest, ConfirmRequest |
| `backend/routes/query.py` | POST /api/query + GET /api/query/stream (enrichment + rocketride fallback) |
| `backend/routes/confirm.py` | POST /api/confirm (returns confirmed count + message) |
| `backend/routes/demo.py` | Demo APIs: NLP, comparison, feed, map, report |

## RocketRide Pipeline Definitions

Pipeline definitions live in `pipelines/` as `.pipe` files (JSON format for the RocketRide SDK):

| File | Purpose | Nodes |
|------|---------|-------|
| `cerberus-threat-agent.pipe` | **Primary** — Agent with MCP Client for autonomous Neo4j exploration | chat → agent_crewai → mcp_client (neo4j-mcp) + llm_anthropic (Sonnet 4.6) → response_answers |
| `cerberus-ingest.pipe` | NER entity extraction from free-text | chat → prompt (extract+classify) → llm_anthropic (Haiku 4.5) → response_answers |
| `cerberus-query.pipe` | **Fallback** — Simple prompt+LLM narrative (no MCP) | chat → prompt (threat analyst) → llm_anthropic (Sonnet 4.6) → response_answers |

Note: `cerberus-juspay` pipeline (stretch goal) not yet ported to `.pipe` format.

## Test Suite

Three test files in `tests/`:

| File | Coverage |
|------|---------|
| `test_api_routes.py` | API routes with mocked Neo4j/LLM (health, query cache hit/miss/empty, confirm) |
| `test_import_scripts.py` | Data parsing logic, integrity checks (MITRE, CVE, npm, synthetic, threats) |
| `test_neo4j_client.py` | Entity routing, Cypher template rendering, cache/traverse/confirm logic |

**97 tests passing** as of latest push.

## Frontend Architecture

### State Machine (useInvestigation.ts)

SSE stream from `GET /api/query/stream`:
```
idle → running → complete
         ↓
SSE events:
  {"stage": "ner"}    → pipeline stage indicator
  {"stage": "traverse"}
  {"paths_found": N}  → graph metadata  
  {"text": "chunk"}   → narrative chunks
  "[DONE]"            → stream complete
```

Pipeline stages rendered in UI: `input → ner → classify → route → traverse → analyze → narrate → complete`

### Panel Components

| Panel | Features |
|-------|---------|
| `QueryPanel` | Entity input with auto-detected type badge, NLP mode, live fraud feed, quick-start buttons |
| `NarrativePanel` | Streaming text animation, confirm button, PDF export, comparison mode |
| `GraphPanel` | Force-directed graph (react-force-graph-2d), custom node/link painters, legends |
| `ThreatMap` | Standalone geo threat map view (separate from GraphPanel) |

### API Client (api.ts)

Typed functions include: `queryEntity()`, `queryEntityStream()`, `confirmEntity()`, `fetchGraph()`, `fetchSchema()`, `parseNaturalLanguage()`, `compareEntities()`, `fetchLiveFeed()`, `ingestFeedEvent()`, `fetchGeoMap()`, `fetchReport()`, `generateThreatMap()`.

Base URL uses `VITE_API_URL` when provided, otherwise defaults to `http://localhost:8000`. In unified Docker builds, `VITE_API_URL=""` makes all frontend API calls same-origin (`/api/...`).

## RocketRide Integration (rocketride.py)

Backend integrates with RocketRide AI via the official Python SDK (`pip install rocketride`):

### Architecture

The primary pipeline (`cerberus-threat-agent.pipe`) uses a CrewAI agent with an
MCP Client node that connects to neo4j-mcp. The agent autonomously explores the
Neo4j graph via MCP tools (get-schema, read-cypher) and reasons with Claude.

```
Backend → SDK use() → loads pipeline → SDK send() → sends entity name
                                                          ↓
                                              CrewAI agent explores Neo4j
                                              via MCP Client tools
                                                          ↓
                                              Agent generates narrative
                                                          ↓
                                              Response → Backend → SSE → Frontend
```

### SDK Flow

1. `_get_client()` — lazy init `RocketRideClient(uri, auth)`
2. `_load_pipeline()` — tries agent pipeline first, falls back to query pipeline
3. `_stream_via_sdk()` — sends entity name via `client.send(token, message)`
4. `_extract_narrative()` — handles both `answers[]` and `data.objects{}` response formats
5. Graceful fallback chain: agent pipeline → query pipeline → direct Anthropic LLM

### Key Differences from Previous Integration

| Before | After |
|--------|-------|
| Backend queries Neo4j, passes raw traversal data to RocketRide | RocketRide agent queries Neo4j itself via MCP Client |
| `client.chat()` with Question object | `client.send()` with plain text |
| Pipeline: prompt → LLM (just formatting) | Pipeline: agent → MCP tools + LLM (autonomous reasoning) |
| RocketRide was a glorified LLM wrapper | RocketRide is the AI orchestration brain |

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
├── pipelines/                  # RocketRide .pipe definitions (JSON)
│   ├── cerberus-threat-agent.pipe  # Agent + MCP Client (primary)
│   ├── cerberus-ingest.pipe    # NER extraction (Haiku 4.5)
│   └── cerberus-query.pipe     # Simple LLM narrative (fallback)
│
├── scripts/                    # ALL import scripts + eval (single source of truth)
│   ├── constraints.cypher      # 8 uniqueness constraints (documented)
│   ├── import_mitre.py         # MITRE ATT&CK STIX → Neo4j (with caching)
│   ├── import_cve.py           # CVE data → Neo4j (pre-populated, no API)
│   ├── import_npm.py           # Compromised npm packages
│   ├── import_synthetic.py     # Cross-domain bridges + fraud signals
│   ├── import_threats.py       # Threat IPs/domains with APT attribution
│   └── eval_improvement.py     # 3-phase self-improvement eval
│
├── tests/                      # Test suite (adds scripts/ to sys.path)
│   ├── test_api_routes.py
│   ├── test_import_scripts.py
│   └── test_neo4j_client.py
│
├── entity_schema.json          # Integration contract JSON schema
│
├── seed_data/                  # Pre-downloaded data feeds
│   ├── README.md
│   ├── enterprise-attack.json  # ~43MB MITRE ATT&CK STIX (gitignored)
│   ├── threat_ips.json         # Cached IPs
│   └── threat_domains.json     # Cached domains
│
├── neo4j-mcp_Darwin_arm64/     # MCP server binary (macOS)
│   └── neo4j-mcp
│
├── neo4j-mcp_Linux_arm64/      # MCP server binary (Linux Docker)
│   ├── neo4j-mcp
│   └── Dockerfile              # Alpine + binary, HTTP mode
│
├── frontend/                   # React + Vite + Tailwind app
│   ├── Dockerfile              # Multi-stage: dev (hot-reload) + prod (nginx)
│   ├── nginx.conf              # SPA routing + API reverse proxy
│   ├── .dockerignore
│   ├── src/
│   │   ├── components/
│   │   │   ├── Header.tsx
│   │   │   └── panels/
│   │   │       ├── QueryPanel.tsx    # NLP input, entity pills, quick-start
│   │   │       ├── NarrativePanel.tsx # Streaming text, confirm, PDF export, comparison
│   │   │       └── GraphPanel.tsx    # Force-directed graph, geo map, legends
│   │   ├── hooks/
│   │   │   └── useInvestigation.ts   # SSE state machine (idle→running→complete)
│   │   ├── lib/
│   │   │   └── api.ts               # 12 API functions (typed)
│   │   └── types/
│   │       └── api.ts               # Full TypeScript interfaces
│   └── ...
└── docs/
    └── retro-001-script-consolidation.md
```

## Implementation Status

- [x] Spec v2 finalized
- [x] neo4j-mcp v1.5.0 confirmed locally
- [x] Project skill created
- [x] constraints.cypher (8 uniqueness constraints)
- [x] Import scripts consolidated in `scripts/` (single source of truth)
- [x] import_mitre.py has local caching (avoids 43MB re-download)
- [x] eval_improvement.py (robust error handling + batched deletion)
- [x] seed_data/ — MITRE data pre-downloaded (~43MB)
- [x] docker-compose.yml (3 services: mcp + backend + frontend)
- [x] Docker fully working — all 3 images build and containers start healthy
- [x] Entity JSON schema
- [x] Backend API (FastAPI) — main, config, neo4j_client, llm, routes
- [x] RocketRide `.pipe` definitions (threat-agent, ingest, query)
- [x] Backend Juspay routes (`/api/juspay/ingest`, `/api/juspay/signals`)
- [x] Test suite (API routes, import scripts, neo4j client)
- [x] hashlib import verified needed (used in write_back for narrative_hash)
- [x] neo4j Aura connected (SSL_CERT_FILE fix on macOS)
- [x] All imports run against live Aura (1060 nodes, 4505 rels)
- [x] Backend API tested against live DB (all endpoints verified)
- [x] Demo chain verified: ua-parser-js → ART-BY-FAISAL → 203.0.113.42 → APT41 + 3 FraudSignals
- [x] Frontend scaffolded (React + Vite + Tailwind + panels + hooks + types)
- [x] RocketRide integration (rocketride.py with LLM fallback)
- [x] Demo APIs (NLP, comparison, feed, map, report)
- [x] 97 tests passing

## Docker Setup

### Architecture

| Service | Image | Port | Notes |
|---------|-------|------|-------|
| `neo4j-mcp` | Alpine 3.20 + pre-built binary | 8787 | HTTP mode, per-request Basic Auth |
| `backend` | Python 3.12-slim | 8000 | Build context = project root |
| `frontend` | Node 20-alpine (multi-stage) | 5173 (dev) / 80 (prod) | Dev: hot-reload, Prod: nginx |

### Quick Start

```bash
cp .env.example .env           # fill in Neo4j Aura + Anthropic creds
docker compose up --build      # starts all 3 services
```

### Docker Gotchas

1. **neo4j-mcp in HTTP mode** — In HTTP transport mode, Neo4j credentials must NOT be set as env vars on the MCP container. They're passed per-request via Basic Auth headers from the backend.
2. **Backend build context** — Set to project root (`.`) not `./backend`, because `requirements.txt` lives at root. Dockerfile is at `backend/Dockerfile`.
3. **neo4j-mcp binary** — The Darwin (macOS) binary won't work in Linux containers. A separate `neo4j-mcp_Linux_arm64/` directory contains the Linux binary + its own Dockerfile.
4. **neo4j-mcp CLI flags** — v1.5.0 uses `--neo4j-transport-mode`, `--neo4j-http-port`, `--neo4j-http-host` (not `--transport`, `--port`, `--host`).
5. **neo4j-mcp healthcheck** — No GET health endpoint. The `/mcp` endpoint returns 405 on GET (only accepts POST), which we grep for to confirm the server is alive.
6. **Frontend multi-stage** — docker-compose targets the `dev` stage. For production: `docker build --target prod -t cerberus-frontend frontend/` uses nginx with SPA routing.
7. **VITE_API_URL** — Baked into JS bundle at build time for prod stage. Dev uses env var.
- [ ] End-to-end integration tested with real Anthropic API key
- [ ] Demo rehearsed + pre-cached

## Known Issues

1. ~~config.py semantic mismatch~~ — VERIFIED FALSE. Config is correct (`ANTHROPIC_KEY = _require("ANTHROPIC_API_KEY")`)
2. ~~neo4j_client.py unused import~~ — VERIFIED FALSE. hashlib IS used in write_back() for narrative_hash
3. ~~neo4j_client.py Cypher templating~~ — Still uses `.format()` for labels/keys but mitigated by enum routing
4. **CORS wide open:** `allow_origins=["*"]` in main.py — acceptable for hackathon, note for judges
5. ~~Duplicate import scripts~~ — CONSOLIDATED. `scripts/` is now the single source of truth
6. ~~Unbounded shortestPath~~ — FIXED. All Cypher queries now use `[*..6]` or `[*..5]` bounds
7. ~~_WRITE_BACK Cypher bug~~ — FIXED. `start` variable now carried through WITH clause
11. ~~Directed traversal in _TRAVERSE_PACKAGE~~ — FIXED. Changed `-[*..6]->` to undirected `-[*..6]-` so paths through Account→IP←ThreatActor (OPERATES backward hop) are found
12. ~~Enrichment orphan nodes~~ — FIXED. enrich.py now creates EXPLOITED_BY and OPERATES edges after ingesting nodes, so enriched entities have traversable paths
13. ~~No results for entities without ThreatActor path~~ — FIXED. Neighborhood fallback query returns directly connected entities when no full threat chain exists
8. ~~Missing LLM error handling~~ — FIXED. Query route gracefully returns graph data when LLM unavailable
9. ~~Bad model name~~ — FIXED. Changed from `claude-opus-4-6` to `claude-sonnet-4-20250514`
10. **FastAPI version:** Requires FastAPI ≥0.115.0 (incompatible with older Starlette 0.46+)
