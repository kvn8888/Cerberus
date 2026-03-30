<p align="center">
  <img src="https://img.shields.io/badge/Neo4j-Graph%20DB-008CC1?style=for-the-badge&logo=neo4j" alt="Neo4j" />
  <img src="https://img.shields.io/badge/FastAPI-Backend-009688?style=for-the-badge&logo=fastapi" alt="FastAPI" />
  <img src="https://img.shields.io/badge/React-Frontend-61DAFB?style=for-the-badge&logo=react&logoColor=black" alt="React" />
  <img src="https://img.shields.io/badge/Claude-LLM-6B4FBB?style=for-the-badge&logo=anthropic" alt="Claude" />
  <img src="https://img.shields.io/badge/RocketRide-AI%20Pipelines-FF6B35?style=for-the-badge" alt="RocketRide" />
</p>

# Cerberus — Cross-Domain Threat Intelligence Platform

> Every security tool watches one surface. Attackers coordinate across all of them.
>
> Snyk scans your dependencies. Shodan maps your infrastructure. Fraud systems watch transactions. None of them talk to each other — so a compromised npm publisher who also operates a fraud ring and controls a malicious IP goes undetected until damage is done.
>
> **Cerberus connects these surfaces in a single graph and traces the attack chain that no single-domain tool can see.**

Cerberus is a thoughtful security agent that eliminates the 4-hour manual graph-traversal process of tracing cross-domain attack chains. It reasons about which domains to query, connects the signals no single-surface tool can see, and learns from analyst feedback to get faster with every investigation.

---

## Table of Contents

- [Architecture](#architecture)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Quick Start](#quick-start)
- [Environment Variables](#environment-variables)
- [Running Locally](#running-locally)
- [Deployment (Render)](#deployment-render)
- [Neo4j Schema](#neo4j-schema)
- [API Reference](#api-reference)
- [Frontend](#frontend)
- [RocketRide Pipelines](#rocketride-pipelines)
- [Seed Data & Import Scripts](#seed-data--import-scripts)
- [Tests](#tests)
- [Project Structure](#project-structure)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        INPUT LAYER                              │
│  npm package name · IP address · domain · CVE · Juspay ID       │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                    ROCKETRIDE PIPELINE                           │
│                  (the "thoughtful agent")                        │
│                                                                 │
│  CrewAI Agent ──→ MCP Client ──→ Neo4j MCP Server               │
│       │             (get-schema, read-cypher, write-cypher)      │
│       ▼                                                         │
│  LLM (Claude Sonnet) ── graph context → threat narrative        │
│       │                                                         │
│       ▼                                                         │
│  SSE stream → real-time narrative to frontend                   │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                    SELF-IMPROVEMENT LOOP                         │
│  Analyst confirms pattern → labeled subgraph → cache hit next   │
│  time → skip LLM, instant response (~2s vs ~8s)                 │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                      FRONTEND                                   │
│  React + Tailwind + shadcn/ui                                   │
│  ├── Query panel (entity input, NLP, live fraud feed)           │
│  ├── Graph visualization (force-directed + geo IP map)          │
│  ├── Streaming AI narrative panel (SSE)                         │
│  └── Pipeline stage indicator (visible agent reasoning)         │
└─────────────────────────────────────────────────────────────────┘
```

---

## Features

### Core Investigation
- **Multi-entity support** — Investigate npm packages, IPs, domains, CVEs, threat actors, and fraud signals
- **Cross-domain traversal** — Find connections across software supply chain, infrastructure, and financial surfaces
- **Streaming AI narrative** — Watch the threat analysis generate in real-time via SSE
- **Real-time enrichment** — Unknown entities are auto-enriched from OSV.dev, NVD, and Abuse.ch APIs

### Visible Agent Reasoning
- **9-stage pipeline visualization** — See each step light up: Input → NER → Classify → Route → Traverse → Enrich → Analyze → Narrate → Complete
- **Route decision display** — Understand which cross-domain traversal the agent chose and why

### Self-Improvement Loop
- **Analyst confirmation** — Confirm a threat pattern to tag it as known
- **Cache-hit acceleration** — Confirmed patterns return instantly (~2s) without calling the LLM
- **Progressive improvement** — Phase 1 (empty, ~8s) → Phase 2 (seeded, ~5s) → Phase 3 (confirmed, ~2s)

### Graph Visualization
- **Force-directed graph** — Color-coded nodes (Package=blue, CVE=red, IP=orange, ThreatActor=purple, etc.)
- **Geo IP map** — Geographic visualization of IP locations with threat actor associations
- **Synthetic edge distinction** — Dashed edges mark simulated connections (e.g., Account→IP links)

### Demo Features
- **Live fraud feed** — Simulated Juspay fraud signals with one-click ingest + investigate
- **Natural language queries** — Type "is lodash safe?" instead of selecting entity types
- **Multi-entity comparison** — Compare up to 4 entities side-by-side
- **PDF export** — Generate a full investigation report
- **AI threat map** — Claude-generated SVG threat visualization

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Graph DB | Neo4j Aura (free tier) |
| MCP Bridge | neo4j-mcp v1.5.0 (HTTP mode) |
| Backend | FastAPI + uvicorn |
| Orchestration | RocketRide AI (CrewAI agent + MCP Client) |
| LLM | Anthropic Claude (Sonnet 4.6) |
| Frontend | React 18 + Vite + Tailwind CSS + shadcn/ui |
| Graph Viz | react-force-graph-2d (d3-force) |
| Streaming | SSE (sse-starlette + EventSource) |
| HTTP Client | httpx (async) |

---

## Quick Start

### Prerequisites

- **Docker** (recommended) or Python 3.12+ and Node.js 20+
- **Neo4j Aura** free-tier instance ([create one here](https://neo4j.com/cloud/aura-free/))
- **Anthropic API key** ([get one here](https://console.anthropic.com/))

### 1. Clone and configure

```bash
git clone https://github.com/kvn8888/Cerberus.git
cd Cerberus
cp .env.example .env  # Then fill in your credentials
```

### 2. Run with Docker (recommended)

```bash
# Build the unified container (frontend + backend in one image)
docker build -t cerberus .

# Run it
docker run -p 10000:80 --env-file .env cerberus
```

Open **http://localhost:10000** — you'll see the Cerberus dashboard.

### 3. Seed the database

```bash
# Run all import scripts to populate Neo4j with demo data
python scripts/run_all_imports.py
```

This loads ~200 MITRE ATT&CK techniques, ~100 threat groups, ~50 CVEs, ~100 malicious IPs, ~30 compromised packages, and ~20 synthetic fraud signals.

### 4. Try it out

1. Type `ua-parser-js` in the search box (or click any example entity)
2. Watch the pipeline stages light up as the agent reasons
3. Read the streaming AI narrative explaining the cross-domain attack chain
4. Explore the force-directed graph visualization
5. Click **Confirm** to mark the pattern — next query will be instant

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `NEO4J_URI` | Yes | — | Neo4j Aura connection URI (`neo4j+s://...`) |
| `NEO4J_USERNAME` | Yes | — | Neo4j username (usually `neo4j`) |
| `NEO4J_PASSWORD` | Yes | — | Neo4j password |
| `ANTHROPIC_API_KEY` | Yes | — | Anthropic API key for Claude |
| `NEO4J_MCP_URL` | No | `http://127.0.0.1:8787` | neo4j-mcp server URL |
| `ROCKETRIDE_URI` | No | `http://localhost:5565` | RocketRide engine URL |
| `ROCKETRIDE_APIKEY` | No | — | RocketRide auth key |
| `ROCKETRIDE_ANTHROPIC_KEY` | No | — | Anthropic key for pipeline LLM nodes |
| `NEO4J_MCP_ENDPOINT` | No | — | MCP endpoint for RocketRide's MCP Client |
| `ROCKETRIDE_NEO4J_BASIC_AUTH` | No | — | Base64-encoded `user:pass` for neo4j-mcp auth |
| `VITE_API_URL` | No | `http://localhost:8000` | Backend URL (baked into frontend at build time) |

---

## Running Locally

### Option A: Docker (one container)

```bash
docker build -t cerberus .
docker run -p 10000:80 --env-file .env cerberus
# Frontend: http://localhost:10000
# API:      http://localhost:10000/api/...

docker stop $(docker ps -q --filter "publish=10000") to terminate
```

### Option B: Docker Compose (separate containers)

```bash
docker-compose up
# Frontend: http://localhost:5173
# Backend:  http://localhost:8000
```

### Option C: Manual (no Docker)

```bash
# Terminal 1 — Backend
cd backend
pip install -r ../requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# Terminal 2 — Frontend
cd frontend
npm install
npm run dev
# Opens at http://localhost:5173
```

---

## Deployment (Render)

The project includes a `render.yaml` Blueprint that deploys as a single unified web service:

| Service | Type | Plan | Description |
|---------|------|------|-------------|
| `cerberus` | Web Service | Starter ($7/mo) | Unified frontend + backend container |
| `neo4j-mcp` | Private Service | Starter ($7/mo) | MCP bridge to Neo4j Aura (internal only) |

**To deploy:**
1. Connect the repo in the [Render dashboard](https://dashboard.render.com/)
2. Create a Blueprint instance from `render.yaml`
3. Fill in the environment variable values
4. Deploy

The unified container runs nginx (serving the React build) + uvicorn (FastAPI) on the same port. No CORS configuration needed — everything is same-origin.

---

## Neo4j Schema

### Node Labels

| Label | Key Property | Source |
|-------|-------------|--------|
| `Package` | `name` (UNIQUE) | npm registry |
| `CVE` | `id` (UNIQUE) | NVD / MITRE |
| `IP` | `address` (UNIQUE) | Threat intel feeds |
| `Domain` | `name` (UNIQUE) | DNS / WHOIS |
| `ThreatActor` | `name` (UNIQUE) | MITRE ATT&CK |
| `Technique` | `mitre_id` (UNIQUE) | MITRE ATT&CK STIX |
| `Account` | `(username, registry)` UNIQUE | npm / GitHub |
| `FraudSignal` | `juspay_id` (UNIQUE) | Juspay API |

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
(:Account)-[:LINKED_TO]->(:IP)          ⚠ Synthetic
(:Domain)-[:SERVES]->(:Package)
```

> **Note:** Account→IP links are synthetic (simulated from threat intel correlation). In production, these would come from Git commit metadata, npm publish audit logs, or SIEM data. They render with dashed edges in the frontend.

---

## API Reference

### Core Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/api/schema` | Live graph schema (labels, relationships, counts) |
| `POST` | `/api/query` | Full investigation (non-streaming) |
| `GET` | `/api/query/stream` | SSE streaming investigation |
| `GET` | `/api/query/graph` | Graph nodes + links for visualization |
| `POST` | `/api/confirm` | Analyst confirms a threat pattern (self-improvement write-back) |

### Demo Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/demo/natural` | Parse natural language to entity + type |
| `POST` | `/api/demo/compare` | Multi-entity comparison (2-4 entities) |
| `GET` | `/api/demo/feed` | Synthetic Juspay fraud events |
| `POST` | `/api/demo/feed/ingest` | Ingest a fraud signal into Neo4j |
| `GET` | `/api/demo/map` | Geo-IP coordinates for an entity |
| `GET` | `/api/demo/report` | Full PDF-ready investigation report |
| `POST` | `/api/threatmap` | AI-generated threat map SVG |

### Query Flow

```
POST /api/query  { entity: "ua-parser-js", type: "package" }
  │
  ├─ Cache hit? → Return cached narrative instantly (~2s)
  │
  ├─ Graph traversal (domain-routed Cypher queries)
  │    │
  │    ├─ Paths found? → Continue to LLM
  │    │
  │    └─ No paths? → Real-time enrichment (OSV.dev / NVD / Abuse.ch)
  │                    → Re-traverse → Continue if data found
  │
  ├─ LLM narrative generation (Claude, streamed via SSE)
  │
  └─ Response: { narrative, paths_found, from_cache, entity, type }
```

---

## Frontend

The frontend is a three-column React dashboard:

| Panel | Purpose |
|-------|---------|
| **QueryPanel** (left) | Entity search, type selector, NLP input, example entities, live fraud feed |
| **GraphPanel** (center) | Force-directed threat graph with toggle to geo IP map |
| **NarrativePanel** (right) | Streaming AI narrative, confirm button, PDF export, threat map, comparison |
| **PipelineStages** (top bar) | 9-stage progress indicator showing agent reasoning |
| **Header** | Brand, commit hash, backend + RocketRide connection status |

### Key Frontend Files

| File | Purpose |
|------|---------|
| `src/App.tsx` | Root layout, state management, panel composition |
| `src/hooks/useInvestigation.ts` | SSE stream state machine (idle → running → complete) |
| `src/lib/api.ts` | 12 typed API client functions |
| `src/types/api.ts` | TypeScript types for all API contracts |
| `src/components/panels/QueryPanel.tsx` | Investigation input + live fraud feed |
| `src/components/panels/GraphPanel.tsx` | Force-directed graph + geo map |
| `src/components/panels/NarrativePanel.tsx` | Streaming narrative + analysis tools |
| `src/components/panels/PipelineStages.tsx` | Pipeline stage visualization |

---

## RocketRide Pipelines

Pipeline definitions live in `pipelines/` as `.pipe` files:

| File | Role | Flow |
|------|------|------|
| `cerberus-threat-agent.pipe` | **Primary** — AI agent with MCP | chat → CrewAI agent → MCP Client (neo4j-mcp) + LLM → response |
| `cerberus-query.pipe` | **Fallback** — Simple prompt + LLM | chat → prompt → LLM → response |
| `cerberus-ingest.pipe` | NER extraction | chat → prompt → LLM (Haiku) → response |

### Fallback Chain

1. **RocketRide agent pipeline** — Full autonomous graph exploration via MCP
2. **RocketRide simple pipeline** — If agent fails, falls back to prompt + LLM
3. **Direct Anthropic SDK** — If RocketRide is unavailable, calls Claude directly via `llm.py`

---

## Seed Data & Import Scripts

```bash
# Run all imports at once
python scripts/run_all_imports.py

# Or individually:
python scripts/import_mitre.py      # MITRE ATT&CK techniques + groups
python scripts/import_cve.py        # CVE vulnerability data
python scripts/import_npm.py        # npm package dependency trees
python scripts/import_threats.py    # Malicious IPs + domains
python scripts/import_synthetic.py  # Synthetic cross-domain links + fraud signals
```

### Seed Data Files

| File | Contents |
|------|----------|
| `seed_data/enterprise-attack.json` | MITRE ATT&CK STIX bundle |
| `seed_data/threat_domains.json` | Known malicious domains |
| `seed_data/threat_ips.json` | Known malicious IP addresses |

### Demo Entity: ua-parser-js

Primary demo target. Hijacked in October 2021 — versions 0.7.29, 0.8.0, and 1.0.0 contained cryptomining + credential-stealing malware. Also has CVE-2021-27292 (ReDoS). The full cross-domain attack chain spans packages → CVEs → threat actors → IPs → domains → fraud signals.

---

## Tests

```bash
# Run from project root
python -m pytest tests/ -v
```

| File | Coverage |
|------|----------|
| `tests/test_api_routes.py` | API routes with mocked Neo4j/LLM |
| `tests/test_import_scripts.py` | Data parsing logic + integrity checks |
| `tests/test_neo4j_client.py` | Entity routing, Cypher templates, cache/traverse/confirm |

97 tests passing.

---

## Project Structure

```
Cerberus/
├── Dockerfile                 # Unified build (frontend + backend in one container)
├── docker-compose.yml         # Multi-container dev setup
├── render.yaml                # Render deployment blueprint
├── requirements.txt           # Python dependencies
├── backend/
│   ├── main.py                # FastAPI app entry point
│   ├── config.py              # Environment variable loader
│   ├── neo4j_client.py        # Neo4j driver, traversal, cache, graph viz
│   ├── llm.py                 # Anthropic Claude integration
│   ├── rocketride.py          # RocketRide pipeline SDK integration
│   ├── enrich.py              # Real-time threat enrichment (OSV, NVD, Abuse.ch)
│   ├── models.py              # Pydantic request/response models
│   └── routes/
│       ├── query.py           # Investigation endpoints (POST + SSE stream)
│       ├── confirm.py         # Analyst confirmation endpoint
│       ├── demo.py            # Demo APIs (NLP, compare, feed, map, report)
│       ├── ingest.py          # Entity ingestion pipeline
│       ├── threatmap.py       # AI-generated threat map SVG
│       └── juspay.py          # Juspay financial integration
├── frontend/
│   ├── src/
│   │   ├── App.tsx            # Root component + layout
│   │   ├── hooks/             # useInvestigation SSE state machine
│   │   ├── lib/               # API client + utilities
│   │   ├── types/             # TypeScript type definitions
│   │   └── components/
│   │       ├── layout/        # Header
│   │       ├── panels/        # QueryPanel, GraphPanel, NarrativePanel, PipelineStages
│   │       └── ui/            # shadcn/ui primitives
│   └── vite.config.ts         # Vite build config (injects git commit hash)
├── pipelines/                 # RocketRide pipeline definitions (.pipe files)
├── scripts/                   # Data import + evaluation scripts
├── seed_data/                 # MITRE ATT&CK, threat IPs/domains
├── deploy/
│   ├── nginx-unified.conf     # nginx config for unified container
│   ├── start.sh               # Startup script (uvicorn + nginx)
│   └── gmi-cloud/             # GMI Cloud deployment helpers
├── neo4j-mcp_*/               # Pre-built neo4j-mcp binaries (per platform)
└── tests/                     # pytest test suite
```

---

## Hackathon Context

Built for **HackWithBay 2.0** (Theme: Thoughtful Agents for Productivity). Sponsored by Neo4j, RocketRide AI, and Juspay.

| Criterion | How Cerberus Scores |
|-----------|-------------------|
| **Neo4j effectiveness** | Multi-hop cross-domain traversal — the core value is impossible without a graph DB |
| **RocketRide AI effectiveness** | Orchestrates the full intelligence pipeline with an autonomous agent |
| **Innovation** | Cross-domain entity resolution across financial + software + infrastructure |
| **Technical complexity** | Async pipelines, MCP bridge, self-improvement loop, multi-source enrichment |
| **Real-world impact** | Catches coordinated attacks spanning multiple surfaces |
| **Demo quality** | Paste a package → watch graph materialize → AI narrates the attack chain |

---

## License

This project was built for HackWithBay 2.0. See individual component licenses in their respective directories.
