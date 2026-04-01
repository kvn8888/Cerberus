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
| STIX export | stix2 Python library |
| Auth | PyJWT (HS256, demo users, role-based) |
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
ROCKETRIDE_NEO4J_BASIC_AUTH=...           # Base64-encoded "user:pass" for neo4j-mcp Basic Auth
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

- **US-15 (backend retained, UI removed):** Multi-entity comparison still exists at `POST /api/demo/compare`, but the split-screen comparison UI was removed from the frontend. Prefer cross-domain narrative + graph + MITRE heatmap for demos.

### Phase 2 Features (Implemented)

- **US-16: Natural language query** ✅ — NLP toggle in QueryPanel sends natural language to `POST /api/demo/natural`, extracts entities via regex NER, auto-investigates primary entity. Toggle button with MessageSquare icon.
- **US-17: STIX export from memory** ✅ — "STIX Export" button in MemoryPanel HUD fetches bundles for all confirmed entities, merges + deduplicates, downloads as JSON. Uses batched concurrent fetches (5 at a time).
- **US-18: Entity comparison** ✅ — New ComparePanel (tab in ViewNav) with two entity inputs + type selectors. Calls `POST /api/diff/compare` for graph-level set diffing. Shows overlap score bar, summary stats, shared/exclusive node lists.
- **US-19: Collaborative annotations** ✅ — Backend CRUD at `/api/annotations` with Neo4j `:Annotation` nodes. Graph node sidebar shows notes with add/delete. `run_query()` helper in neo4j_client.
- **US-20: Watchlist alerts** ✅ — Backend CRUD at `/api/watchlist` with `/check` endpoint scanning for new relationships. "Watch" button on graph nodes. Header bell icon auto-checks every 30s with alert dropdown.

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
ROCKETRIDE_NEO4J_BASIC_AUTH=...         # Base64-encoded "user:pass" for neo4j-mcp Basic Auth
CERBERUS_API=http://localhost:8000
```

⚠️ ~~Known issue: `backend/config.py` reads `ANTHROPIC_KEY` from `NEO4J_API_KEY` env var~~ — VERIFIED FALSE. `ANTHROPIC_KEY = _require("ANTHROPIC_API_KEY")` is correct.

## Backend API (FastAPI)

### Endpoints (core + commonly used)

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/health` | Health check → `{"status": "ok"}` |
| GET | `/api/schema` | Live graph schema (labels, rel types, counts) |
| POST | `/api/query` | Main query: cache check → traverse → LLM narrative |
| GET | `/api/rocketride/health` | Proxies RocketRide availability (frontend green dot) |
| GET | `/api/query/stream` | SSE streaming — emits stage, text, threat_score, blast_radius, suggestions events |
| POST | `/api/confirm` | Analyst confirms threat pattern → write-back (returns count + message) |
| GET | `/api/query/graph` | Force-directed graph data (nodes + edges) for vis |
| GET | `/api/memory` | Confirmed-threat subgraph (excludes Technique nodes) |
| GET | `/api/memory/geo` | Geo points for memorized entities |
| GET | `/api/memory/expand` | Expand a node in memory graph (click-to-expand UI) |
| POST | `/api/demo/natural` | NLP entity extraction (optional; QueryPanel NLP block removed) |
| POST | `/api/demo/compare` | Multi-entity comparison (optional; UI removed) |
| POST | `/api/juspay/ingest` | Ingest normalized Juspay-style fraud signals |
| GET | `/api/juspay/signals` | Fraud signal summary (cross-domain alerts in QueryPanel) |
| GET | `/api/demo/map` | Geo-IP map data (lat/lng points) |
| GET | `/api/demo/report` | Full investigation report (Juspay summary) |
| POST | `/api/threatmap` | AI threat map SVG (not in main narrative UI) |
| GET | `/api/threat-score` | 0-100 risk score with severity + contributing factors |
| GET | `/api/blast-radius` | Reachable entity count within 4 hops, grouped by type |
| GET | `/api/shortest-path` | Shortest path between two entities (nodes + links + hops) |
| GET | `/api/suggestions` | Top 5 unconfirmed neighbors sorted by connectivity |
| GET | `/api/stix/bundle` | STIX 2.1 bundle export (SDOs + SROs for MISP/OpenCTI) |
| GET | `/api/stix/indicator-count` | Indicator counts by STIX type |
| POST | `/api/diff/compare` | Structural diff between two entity graphs (overlap score) |
| GET | `/api/enrich/virustotal` | VT-style reputation (simulated if no key) |
| GET | `/api/enrich/hibp` | Breach lookup for email (simulated if no key) |
| GET | `/api/enrich/summary` | Unified enrichment summary (auto-detects entity type) |
| POST | `/api/auth/login` | Demo JWT login (3 hardcoded users: admin, analyst, viewer) |
| GET | `/api/auth/me` | Current user profile from JWT |
| GET | `/api/auth/users` | List demo users (admin only) |
| GET | `/api/keys` | List API keys with masked previews (admin only) |
| POST | `/api/keys/create` | Generate new API key (admin only) |
| DELETE | `/api/keys/{id}` | Revoke an API key (admin only) |

See `backend/main.py` for the authoritative router list.

### Threat Score Factors (0-100)

- Entity exists (10) + ConfirmedThreat label (10) + ThreatActor connection (15) + multiple actors (+10) + CVE link (15) + fraud signals (10) + malicious IPs (10) + cross-domain reach (0-30)
- Severity: critical (80-100), high (60-79), medium (40-59), low (20-39), info (0-19)

### Query Pipeline Flow

```
Input: entity + type (package/ip/domain/cve/threatactor/fraudsignal)
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
Parallel: threat_score + blast_radius (SSE events)
  ↓
LLM narrative generation (Claude, 600 tokens max)
  ↓
Write-back: tag nodes with analysis timestamp
  ↓
suggestions (SSE) → [DONE]
```

### SSE Stream Event Sequence

```
data: {"stage": "input"}
data: {"stage": "ner"}
data: {"stage": "classify"}
data: {"stage": "route", "route_info": {...}}
data: {"stage": "traverse"}
data: {"paths_found": N, "from_cache": bool}
data: {"stage": "enrich"}           ← only if enrichment triggered
data: {"threat_score": {...}}
data: {"blast_radius": {...}}
data: {"stage": "narrate"}
data: {"text": "<chunk>"}           ← repeated, accumulated
data: {"stage": "complete"}
data: {"suggestions": [...]}
data: [DONE]
```

### Key Backend Files

| File | Purpose |
|------|---------|
| `backend/main.py` | FastAPI app, CORS, lifespan, schema, memory routes, router registry |
| `backend/config.py` | Env var loader with validation |
| `backend/neo4j_client.py` | Neo4j driver: traverse, cache/confirm, graph viz, geo, Juspay, threat_score, blast_radius, shortest_path, suggest_next, memory |
| `backend/llm.py` | Anthropic Claude narrative generation (blocking + streaming) |
| `backend/rocketride.py` | RocketRide pipeline integration (async httpx, SSE proxy, 60s timeout) |
| `backend/enrich.py` | Real-time threat intel enrichment (OSV.dev, NVD, Abuse.ch) |
| `backend/auth.py` | JWT authentication & RBAC (demo users, create_token, verify_token, require_role) |
| `backend/models.py` | Pydantic models: EntityType, QueryRequest, ConfirmRequest |
| `backend/routes/query.py` | POST /api/query + GET /api/query/stream (emits threat_score, blast_radius, suggestions SSE events) |
| `backend/routes/confirm.py` | POST /api/confirm (returns confirmed count + message) |
| `backend/routes/demo.py` | Demo APIs: NLP, comparison, map, report |
| `backend/routes/intelligence.py` | GET endpoints: threat-score, blast-radius, shortest-path, suggestions |
| `backend/routes/stix.py` | STIX 2.1 bundle export + indicator counts |
| `backend/routes/diff.py` | POST /api/diff/compare — structural overlap analysis |
| `backend/routes/enrichment.py` | VT / HIBP / summary enrichment (simulated fallback when no API key) |
| `backend/routes/annotations.py` | Annotation CRUD: GET/POST/DELETE /api/annotations — Neo4j :Annotation nodes |
| `backend/routes/watchlist.py` | Watchlist CRUD + /check: GET/POST/DELETE /api/watchlist — new-connection alerts |
| `backend/routes/auth_routes.py` | Login, me, list-users endpoints |
| `backend/routes/apikeys.py` | In-memory API key CRUD (demo keys pre-seeded) |

## RocketRide Pipeline Definitions

Pipeline definitions live in `pipelines/` as `.pipe` files (JSON format for the RocketRide SDK):

| File | Purpose | Nodes |
|------|---------|-------|
| `cerberus-threat-agent.pipe` | **Primary** — Agent with MCP Client for autonomous Neo4j exploration | chat → agent_crewai → mcp_client (neo4j-mcp) + llm_anthropic (Sonnet 4.6) → response_answers |
| `cerberus-ingest.pipe` | NER entity extraction from free-text | chat → prompt (extract+classify) → llm_anthropic (Haiku 4.5) → response_answers |
| `cerberus-query.pipe` | **Fallback** — Simple prompt+LLM narrative (no MCP) | chat → prompt (threat analyst) → llm_anthropic (Sonnet 4.6) → response_answers |

Note: `cerberus-juspay` pipeline (stretch goal) not yet ported to `.pipe` format.

## Test Suite

Two test files in `tests/`:

| File | Coverage |
|------|---------|
| `test_api_routes.py` | API routes with mocked Neo4j/LLM (health, query cache hit/miss/empty, confirm) |
| `test_neo4j_client.py` | Entity routing, Cypher template rendering, cache/traverse/confirm logic |

(Import-script tests removed along with the import scripts — DB is already fully seeded.)

## Frontend Architecture

### State Machine (useInvestigation.ts)

SSE stream from `GET /api/query/stream`:
```
idle → running → complete
         ↓
SSE events:
  {"stage": "ner"}          → pipeline stage indicator
  {"stage": "traverse"}
  {"paths_found": N}        → graph metadata
  {"route_info": {...}}     → route reasoning display
  {"threat_score": {...}}   → 0-100 risk score + severity
  {"blast_radius": {...}}   → reachable entity counts
  {"text": "chunk"}         → narrative chunks (accumulated)
  {"suggestions": [...]}    → investigate-next recommendations
  "[DONE]"                  → stream complete → fetch graph → pushHistory
```

Pipeline stages rendered in UI: `input → ner → classify → route → traverse → enrich → analyze → narrate → complete`

### Panel Components

| Panel | Features |
|-------|---------|
| `QueryPanel` | Entity input with auto-detected type badge, NLP toggle (natural language → entity extraction via `/api/demo/natural`), cross-domain fraud alerts (`/api/juspay/signals`), investigation history (localStorage, last 10), quick-start buttons |
| `NarrativePanel` | Streaming text, Technical/Executive toggle, threat score card + blast radius breakdown, IOC extraction (copy-all / CSV), external enrichment intel (VT/HIBP), "Investigate Next" suggestions, confirm, PDF export + STIX 2.1 bundle export |
| `GraphPanel` | Force-directed graph (react-force-graph-2d), attack-path stepper (DFS-ordered prev/next with cyan highlight, node label + auto-center), relationship type filter checkboxes, node search + gold highlight, legends, GraphMinimap, collaborative annotations on nodes (add/delete notes), "Watch Entity" button |
| `ThreatMap` | Geomap tab: scroll-wheel zoom, drag pan, actor offsets, auto zoom-to-fit |
| `MitreHeatmapPanel` | MITRE ATT&CK tactic heatmap — counts Technique nodes from investigation graph, 14-tactic grid with intensity coloring |
| `MemoryPanel` | Confirmed-threat subgraph + click-to-expand + STIX 2.1 bundle export button |
| `ComparePanel` | Entity comparison — two entity inputs with type selectors, overlap score, shared/exclusive node lists |
| `TimelinePanel` | Horizontal timeline with severity-colored dots, hover tooltip, click-to-replay |
| `Graph3DPanel` | (Not routed) WebGL 3D graph with search/filter — exists in tree but removed from ViewNav |

### Key Frontend Libraries

| File | Purpose |
|------|---------|
| `src/lib/api.ts` | Typed API client (query, graph, geo, memory, intelligence, health) |
| `src/lib/attackPath.ts` | DFS attack-path ordering from investigation root (continuous chain traversal) |
| `src/lib/iocExtract.ts` | IOC extraction (IP, CVE, domain, package, hash) from graph nodes + narrative text |
| `src/lib/mitreTactics.ts` | MITRE tactic order, T####→tactic lookup, technique ID extractor |
| `src/types/api.ts` | TypeScript types: EntityType, InvestigationState, ThreatScore, BlastRadius, Suggestion, InvestigationHistoryItem, StreamChunk, GraphNode, GraphLink |

### API Client (api.ts)

Typed functions include: `queryEntity()`, `queryEntityStream()`, `confirmEntity()`, `fetchGraph()`, `fetchSchema()`, `fetchGeoMap()`, `fetchReport()`, `fetchMemory()`, `expandMemoryNode()`, `fetchThreatScore()`, `fetchBlastRadius()`, `fetchShortestPath()`, `fetchSuggestions()`, `fetchStixBundle()`, `fetchEnrichmentSummary()`, `parseNaturalLanguage()`, `compareEntities()`, `listAnnotations()`, `createAnnotation()`, `deleteAnnotation()`, `getWatchlist()`, `addToWatchlist()`, `removeFromWatchlist()`, `checkWatchlist()`, plus health helpers.

### ViewNav Tabs

5 center views: `graph` (Threat Graph), `geomap` (Geomap), `mitre` (MITRE), `memory` (Memory with badge count), `compare` (Compare entities)

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
├── README.md
├── changes-from-hackathon.md   # Detailed add/remove ledger
├── marketing.md                # Technical onboarding & pitch document
├── spec.md
├── requirements.txt            # FastAPI, neo4j, anthropic, stix2, pyjwt, etc.
├── docker-compose.yml          # neo4j-mcp + backend + frontend
├── Dockerfile                  # Unified build (frontend + backend in one container)
├── render.yaml                 # Render deployment blueprint
│
├── backend/                    # FastAPI application
│   ├── Dockerfile
│   ├── main.py                 # App entry point, CORS, /health, /api/schema, /api/memory
│   ├── config.py               # Env var loader
│   ├── neo4j_client.py         # Neo4j driver: traverse, cache, confirm, graph viz, geo, Juspay, threat_score, blast_radius, shortest_path, suggest_next, memory
│   ├── llm.py                  # Anthropic Claude narrative gen (blocking + streaming)
│   ├── pipeline.py             # Pipeline orchestration
│   ├── enrich.py               # Real-time enrichment (OSV.dev, NVD, Abuse.ch)
│   ├── auth.py                 # JWT auth + RBAC (3 demo users, require_role decorator)
│   ├── models.py               # Pydantic models
│   └── routes/
│       ├── __init__.py
│       ├── query.py            # POST /api/query + GET /api/query/stream (full SSE pipeline)
│       ├── confirm.py          # POST /api/confirm
│       ├── demo.py             # Demo APIs: NLP, comparison, map, report
│       ├── ingest.py           # Entity ingestion pipeline
│       ├── threatmap.py        # AI-generated threat map SVG
│       ├── juspay.py           # Juspay financial integration
│       ├── intelligence.py     # threat-score, blast-radius, shortest-path, suggestions
│       ├── stix.py             # STIX 2.1 bundle export + indicator counts
│       ├── diff.py             # Graph diff between two entities (overlap score)
│       ├── enrichment.py       # VT / HIBP / summary (simulated fallback)
│       ├── auth_routes.py      # Login, me, list-users
│       ├── apikeys.py          # In-memory API key CRUD
│       ├── annotations.py      # Annotation CRUD on graph entities (GET/POST/DELETE)
│       └── watchlist.py        # Entity watchlist + change detection (GET/POST/DELETE/check)
│
├── pipelines/                  # RocketRide .pipe definitions (JSON)
│   ├── cerberus-threat-agent.pipe  # Agent + MCP Client (primary)
│   ├── cerberus-ingest.pipe    # NER extraction (Haiku 4.5)
│   └── cerberus-query.pipe     # Simple LLM narrative (fallback)
│
├── scripts/                    # Deploy + schema utilities
│   ├── constraints.cypher      # 8 uniqueness constraints (schema reference)
│   └── push_env_to_render.py   # Pushes env vars to Render from .env
│
├── tests/                      # Test suite
│   ├── test_api_routes.py
│   └── test_neo4j_client.py
│
├── frontend/                   # React + Vite + Tailwind app
│   ├── Dockerfile
│   ├── nginx.conf
│   ├── src/
│   │   ├── App.tsx             # Root layout + state orchestration
│   │   ├── hooks/
│   │   │   └── useInvestigation.ts  # SSE state machine + investigation history
│   │   ├── lib/
│   │   │   ├── api.ts               # Typed API client (~25 functions)
│   │   │   ├── attackPath.ts        # DFS attack-path ordering
│   │   │   ├── iocExtract.ts        # IOC extraction (IP, CVE, domain, hash)
│   │   │   ├── mitreTactics.ts      # MITRE tactic lookup + T####→tactic map
│   │   │   └── utils.ts
│   │   ├── types/
│   │   │   └── api.ts               # Full TypeScript interfaces (EntityType, InvestigationState, ThreatScore, BlastRadius, Suggestion, etc.)
│   │   └── components/
│   │       ├── layout/
│   │       │   ├── Header.tsx         # Status indicators, RocketRide health, watchlist bell (30s auto-check)
│   │       │   └── ViewNav.tsx       # 5 center tabs: graph, geomap, mitre, memory, compare
│   │       └── panels/
│   │           ├── QueryPanel.tsx     # Entity search, type detection, NLP toggle, cross-domain alerts, history
│   │           ├── NarrativePanel.tsx  # Streaming text, Tech/Exec toggle, threat score, blast radius, IOC, suggestions, confirm, PDF, STIX export, enrichment intel
│   │           ├── GraphPanel.tsx      # 2D force-graph, attack-path stepper, rel filter, node search, annotations, watch button
│   │           ├── GraphMinimap.tsx    # 160×120 canvas overview (bottom-right)
│   │           ├── Graph3DPanel.tsx    # 3D WebGL graph (exists but not routed)
│   │           ├── ComparePanel.tsx    # Entity comparison: overlap score, shared/exclusive nodes
│   │           ├── ThreatMap.tsx       # SVG geomap with zoom controls
│   │           ├── MitreHeatmapPanel.tsx  # 14-tactic heatmap from Technique nodes
│   │           ├── TimelinePanel.tsx   # Horizontal investigation timeline
│   │           └── PipelineStages.tsx  # 9-stage progress indicator
│   └── ...
│
│
├── neo4j-mcp_Darwin_arm64/     # MCP server binary (macOS)
├── neo4j-mcp_Linux_arm64/      # MCP server binary (Linux ARM)
├── neo4j-mcp_Linux_x86_64/     # MCP server binary (Linux x86)
│
├── deploy/
│   ├── nginx-unified.conf
│   ├── start.sh
│   └── gmi-cloud/
│
└── docs/                       # Session retrospectives
    ├── retro-001-script-consolidation.md
    ├── retro-002-frontend-build.md
    ├── retro-003-docker-setup.md
    ├── retro-004-rocketride-agent-mcp.md
    ├── retro-005-frontend-ui-fixes.md
    ├── retro-005-node-sidebar-and-route-decision.md
    ├── retro-006-cve-enrichment-orphan-fix.md
    ├── retro-007-agent-pipeline-implementation.md
    ├── retro-008-perf-and-bugfixes.md
    └── retro-009-phase2-features.md
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
- [x] seed_data/ and import scripts removed (DB is live on Neo4j Aura)
- [x] Technique nodes capped at 5 per ThreatActor in get_graph() to keep graph readable
- [x] Graph intelligence: threat_score, blast_radius, shortest_path, suggest_next
- [x] STIX 2.1 export (`GET /api/stix/bundle`, `/api/stix/indicator-count`)
- [x] Graph diff comparison (`POST /api/diff/compare` with overlap score)
- [x] External enrichment layer: VT / HIBP / summary with simulated fallback
- [x] JWT auth + RBAC (`auth.py`, 3 demo users: admin, analyst, viewer)
- [x] API key management (in-memory, 2 pre-seeded demo keys)
- [x] SSE stream emits threat_score, blast_radius, suggestions events
- [x] NarrativePanel: threat score card, blast radius breakdown, audience toggle, investigate-next suggestions, IOC extraction
- [x] GraphPanel: relationship type filter, node search + gold highlight, attack-path stepper
- [x] MitreHeatmapPanel: 14-tactic heatmap from Technique nodes
- [x] TimelinePanel: horizontal investigation timeline with replay
- [x] GraphMinimap: 160×120 canvas overview
- [x] Graph3DPanel: 3D WebGL graph (exists but not routed in ViewNav)
- [x] Investigation history: localStorage persistence, last 10 entries
- [x] Frontend libs: attackPath.ts, iocExtract.ts, mitreTactics.ts
- [x] ViewNav: 5 tabs (Threat Graph, Geomap, MITRE, Memory, Compare)
- [x] NLP query toggle in QueryPanel (US-16)
- [x] STIX export from Memory panel (US-17)
- [x] Entity comparison panel — ComparePanel (US-18)
- [x] Collaborative annotations on graph nodes (US-19)
- [x] Watchlist alerts with auto-checking (US-20)

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
