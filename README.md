<p align="center">
  <img src="https://img.shields.io/badge/Neo4j-Graph%20DB-008CC1?style=for-the-badge&logo=neo4j" alt="Neo4j" />
  <img src="https://img.shields.io/badge/FastAPI-Backend-009688?style=for-the-badge&logo=fastapi" alt="FastAPI" />
  <img src="https://img.shields.io/badge/React-Frontend-61DAFB?style=for-the-badge&logo=react&logoColor=black" alt="React" />
  <img src="https://img.shields.io/badge/Claude-LLM-6B4FBB?style=for-the-badge&logo=anthropic" alt="Claude" />
  <img src="https://img.shields.io/badge/RocketRide-AI%20Pipelines-FF6B35?style=for-the-badge" alt="RocketRide" />
</p>

# Cerberus

Security teams work in silos. A package gets compromised, an IP gets listed on a threat feed, a fraud signal fires on a transaction, and none of those tools ever talk to each other. The analyst who wants to understand the full picture has to open five tabs, run manual queries against five different databases, and stitch it together by hand. That process takes four hours on a good day. Coordinated attackers exploit that gap every time.

Cerberus is a cross-domain threat intelligence agent that closes that gap. You paste a single entity — an npm package name, an IP address, a domain, a CVE, or a Juspay fraud signal — and Cerberus autonomously traces the full attack chain across software supply chain, network infrastructure, and financial fraud surfaces simultaneously. It writes the narrative, scores the risk, maps every affected entity, and remembers confirmed patterns so the next investigation is faster than the last.

---

## Table of Contents

- [How It Works](#how-it-works)
- [Features](#features)
- [RocketRide AI Orchestration](#rocketride-ai-orchestration)
- [Tech Stack](#tech-stack)
- [Quick Start](#quick-start)
- [Environment Variables](#environment-variables)
- [Running Locally](#running-locally)
- [Deployment](#deployment)
- [Neo4j Graph Schema](#neo4j-graph-schema)
- [API Reference](#api-reference)
- [Frontend Layout](#frontend-layout)
- [Seed Data](#seed-data)
- [Tests](#tests)
- [Project Structure](#project-structure)

---

## How It Works

The core insight is that a graph database is the only data structure that can represent the connections between a software package, the IP addresses its publisher controlled, the threat actor behind those IPs, the techniques that actor uses, and the fraud ring that funds them. A relational database would require a dozen joins. A document store cannot traverse paths. Neo4j holds the full cross-domain picture natively, and a wave-planning AI agent can reason over it in seconds.

When you submit an investigation, the request flows through three layers.

The first layer is the RocketRide pipeline. An `agent_rocketride` node receives the entity and begins planning waves of tool calls. It queries Neo4j directly through an MCP client, storing intermediate findings in keyed memory so each wave builds on the last without re-reading the full graph. If the graph has no data on the entity, the agent detects that and triggers the enrichment layer, fetching live data from OSV.dev, NVD, and Abuse.ch before continuing. It can also make direct HTTP calls to MITRE's CVE API, AbuseIPDB, and VirusTotal mid-investigation to validate what the graph contains. A custom Python tool node runs a cross-domain threat scoring algorithm that maps each connected node to a domain, weights it by type, and adds a bonus for every domain boundary crossed in the path.

The second layer is the graph. Neo4j stores eight node types and eleven relationship types. The traversal is domain-routed: packages start by walking dependency trees and vulnerability links before crossing to threat actors, then to infrastructure, then to fraud signals. The route the agent chooses and the number of paths it finds directly shape the narrative it produces.

The third layer is the self-improvement loop. When an analyst confirms a threat pattern, Cerberus writes it back to Neo4j as a confirmed subgraph. Future investigations that hit a confirmed pattern skip the LLM entirely and return in roughly two seconds instead of eight. The system gets faster with every confirmation.

```
INPUT: npm package / IP / domain / CVE / Juspay fraud signal
  |
  v
ROCKETRIDE PIPELINE
  wave agent plans investigation
  MCP client queries Neo4j (get-schema, read-cypher, write-cypher)
  memory_internal stores findings across waves
  tool_http_request fetches MITRE CVE / AbuseIPDB / VirusTotal data
  tool_python scores cross-domain attack chain
  LLM generates threat narrative from graph context
  SSE stream delivers narrative to frontend in real time
  |
  v
SELF-IMPROVEMENT LOOP
  analyst confirms pattern
  confirmed subgraph written to Neo4j
  next investigation for same entity: cache hit, no LLM, ~2s
  |
  v
FRONTEND
  streaming narrative panel (Technical / Executive mode)
  force-directed threat graph with attack-path stepper
  geo IP map with threat actor overlays
  MITRE ATT&CK tactic heatmap
  confirmed-threat memory graph
  IOC extraction table with defanging and CSV export
  threat score, blast radius, and investigate-next suggestions
```

---

## Features

### Investigation

Cerberus supports six entity types as investigation entry points: npm packages, IP addresses, domains, CVEs, threat actors, and Juspay fraud signals. The type is detected automatically from the input, or you can select it manually. When you submit an entity, the agent traverses the graph looking for cross-domain connections. If the entity is unknown, real-time enrichment fetches data from public APIs and writes it to Neo4j before the traversal continues. Every investigation produces a streaming AI narrative, a scored connection map, and a set of follow-up suggestions.

### Threat Score

Every investigation produces a numeric risk score from 0 to 100. The score is computed directly from graph structure: connections to ThreatActor nodes, CVE links with their CVSS severity, FraudSignal associations, confirmed threat status, cross-domain hop count, and whether multiple distinct threat actors are involved. The score maps to five severity bands: critical (80 to 100), high (60 to 79), medium (40 to 59), low (20 to 39), and informational (0 to 19). A color-coded badge and a breakdown card showing each contributing factor appear in the narrative panel alongside the streaming analysis.

### Blast Radius

After traversal, Cerberus counts every distinct entity reachable within four hops of the investigated node and breaks that count down by type. A package with 47 affected entities might have 12 dependent packages, 8 CVEs, 4 threat actors, 11 IPs, 6 domains, and 6 fraud signals in its blast radius. That number is what an analyst uses to prioritize response. A high-scoring package with a small blast radius is a different problem than a low-scoring package that touches half the infrastructure.

### Cross-Domain Attack Chain Scorer

A dedicated Python tool node inside the RocketRide pipeline runs a custom scoring algorithm on the investigation graph. It maps every connected node to one of three domains: supply chain (Package, CVE, Account), infrastructure (IP, Domain, ThreatActor, Technique), or financial (FraudSignal). Each node type carries a weight. Every time a path crosses a domain boundary, it adds a crossing bonus. The output is a structured score, a domain crossing count, and a list of domains present in the graph. This score feeds into the narrative and is stored in agent memory for use in later investigation waves.

### Streaming AI Narrative

The investigation narrative streams token by token to the frontend via Server-Sent Events. You watch it appear in real time rather than waiting for a completed response. The narrative carries the full context of the investigation: what the entity is, what paths the agent found, which threat actors are connected, which techniques they use, what the cross-domain risk is, and what an analyst should do next.

The narrative panel has two modes. Technical mode delivers the full structured markdown analysis intended for security analysts. Executive mode condenses the same investigation into a risk summary, a single key finding, and a recommended action formatted for a non-technical audience or a leadership briefing. The mode persists across investigations within a session.

### Visible Agent Reasoning

A nine-stage pipeline bar runs across the top of the interface and lights up each stage as the agent works: Input, Parse, Classify, Route, Traverse, Enrich, Analyze, Narrate, Complete. The Enrich stage only activates when the enrichment layer actually fires. The Route stage briefly shows which cross-domain traversal strategy the agent selected. This gives the analyst visibility into what the agent is doing rather than watching a blank spinner. A stop button appears while the agent is running and aborts the in-flight request immediately.

### Self-Improvement and Memory Graph

When an investigation completes, the analyst can click Confirm to mark the threat pattern as known. Cerberus writes this back to Neo4j as a confirmed subgraph. The Memory tab in the center column visualizes all confirmed-threat nodes as a force-directed graph. You can click any node to expand its neighbors, and the full confirmed subgraph can be exported as a STIX bundle. The practical effect is that Cerberus gets faster with every confirmation: a fresh database with no confirmed patterns takes roughly eight seconds per investigation; a seeded graph with MITRE data takes five; confirmed patterns take two.

### IOC Extraction and Export

Every investigation produces an IOC table extracted from both the graph data and the narrative text. The extractor identifies IP addresses, CVEs, domains, and package names, and links each one back to its source. Each IOC row has a pivot button that immediately launches a new investigation on that entity, so you can follow the attack chain hop by hop without retyping.

The copy-all and CSV export flows default to defanged output: dots replaced with `[.]` and HTTP replaced with `hxxp`. This makes it safe to paste IOCs into Slack messages, Jira tickets, and email without triggering security scanners. The defang toggle is on by default but can be turned off for analyst tools that expect raw values.

### TLP-Aware Exports

Every investigation carries a Traffic Light Protocol classification: CLEAR, GREEN, AMBER, AMBER+STRICT, or RED. This classification flows through to every export. PDF reports render a visible TLP banner at the top. STIX 2.1 bundles include the matching `marking-definition` object and add `object_marking_refs` to every exported indicator. The classification is set in the narrative panel and persists for the session.

### STIX 2.1 Export

The STIX export endpoint generates a complete STIX 2.1 bundle for any entity, including indicators, threat actor objects, relationships, attack pattern references to MITRE techniques, and the appropriate marking definitions for the current TLP level. The Memory panel supports batch STIX export for all confirmed-threat nodes, deduplicating by STIX ID before packaging them for download.

### Force-Directed Threat Graph

The center threat graph renders every node and relationship in the current investigation as a force-directed 2D layout using d3-force. Nodes are color-coded by type: Package (blue), CVE (red), IP (orange), ThreatActor (purple), Domain (yellow), Technique (teal), Account (gray), FraudSignal (pink). Synthetic connections — relationships that are computationally inferred rather than sourced from a live feed — render as dashed edges so analysts always know which connections are authoritative versus simulated.

The graph has three interactive tools. The relationship type filter shows a checkbox panel that hides or shows edges by relationship type; nodes that become isolated after filtering are also hidden. The node search highlights matching nodes with a gold ring and glow as you type. The attack path stepper walks the shortest path from the investigation root hop by hop, highlighting the active node in cyan and letting the analyst step forward and backward through the chain with keyboard precision.

### Geo IP Map

The Geomap tab plots every IP address in the investigation on a world map with threat actor labels offset to avoid overlap. Fraud signals and cyber threat points use distinct visual markers. The map supports zoom controls and an auto fit-to-bounds button that centers the view on all plotted points regardless of geographic spread.

### MITRE ATT&CK Heatmap

The MITRE tab renders a tactic heatmap from the Technique nodes present in the current investigation graph. Each tactic column shows how many techniques from that tactic appear in the investigation. This gives a fast visual summary of what an attacker is doing — whether the pattern concentrates in Initial Access, spans the full kill chain, or focuses on Exfiltration and Impact.

### Entity Comparison

The Compare tab accepts two entity inputs and submits them to a structural diff. The backend traverses both entities, finds the intersection of their connected subgraphs, scores the overlap, and returns shared nodes, nodes exclusive to the first entity, and nodes exclusive to the second. The UI renders an overlap score bar and two columns of exclusive and shared connections. This is useful for determining whether two seemingly unrelated entities share infrastructure or threat actor attribution.

### Shortest Path

The shortest path endpoint finds the minimum-hop route between any two entities in the graph, up to eight hops. The result is returned in force-graph format with the hop count labeled. This answers the question of whether two entities that appear unrelated are actually connected across the graph and how many steps lie between them.

### Investigate Next Suggestions

After every completed investigation, Cerberus queries the graph for up to five unconfirmed entities that share connections with the current one, ranked by total connection count. The most connected unconfirmed entities are the most likely to yield new information. Each suggestion renders as a clickable button that immediately launches a new investigation without any additional input.

### Collaborative Annotations

Analysts can add freeform text annotations to any node in the graph by selecting it in the node sidebar. Annotations are stored in Neo4j as `Annotation` nodes with `ANNOTATES` relationships. They persist across sessions and are visible to any user querying the same entity. This lets a team leave operational context — confirmed malicious, vendor notified, false positive, internal scanner — directly on the graph structure without a separate ticketing system.

### Watchlist

Any entity can be added to a watchlist from the node sidebar. The header polls the watchlist every 30 seconds and batches new connection alerts into a reviewable digest. Instead of one alert per new relationship, the analyst sees a summary of everything that changed since the last check. Watchlist state is stored in Neo4j so it persists across browser sessions and server restarts.

### Investigation History

The last ten completed investigations are saved to localStorage. Each entry shows the entity name, a severity color dot, the threat score, the number of graph paths found, and the timestamp. Clicking an entry re-runs the investigation immediately. The list deduplicates by entity so re-investigating the same target updates its entry rather than adding a duplicate row.

### Shareable Permalinks

Any investigation can be encoded as a URL with `?entity=...&type=...` query parameters. Opening the URL re-runs the investigation automatically. The narrative panel includes a copy-permalink button so you can share a specific investigation in a Slack message or incident ticket without describing which entity you were looking at.

### Markdown Summary Clipboard

The narrative panel can serialize the current investigation into a structured markdown block: threat score and severity, blast radius breakdown, IOC list, MITRE techniques, and suggested next investigations. This pastes cleanly into Slack, Confluence, or a Jira ticket without any cleanup.

### NLP Query Mode

A toggle in the query panel switches from direct entity search to natural language mode. In NLP mode you type a sentence describing the threat and the backend extracts the entity name and type before running the investigation. This uses the RocketRide ingest pipeline for the extraction.

### Juspay Financial Signals

Cerberus integrates Juspay fraud signal data as a first-class node type in the graph. The `FraudSignal` node carries a Juspay transaction ID, a risk score, a fraud type label, and a timestamp. When a FraudSignal is associated with an IP that is also connected to a threat actor and a compromised package, that cross-domain link appears in the graph, the narrative, the threat score, and the blast radius. The cross-domain alerts block in the query panel loads the current fraud signal layer from the Juspay API and shows which threat actors share infrastructure with fraud activity.

### PDF Report

The narrative panel generates a full PDF investigation report: entity header, threat score with severity, blast radius, the full AI narrative, IOC table, MITRE techniques, and TLP banner. The PDF is built client-side and downloads immediately.

### Detection Rule Drafts

The backend generates starter Sigma and YARA detection rules from the investigation context. These are drafts that reference the specific IOCs, MITRE technique IDs, and entity names from the live investigation rather than being generic templates, giving an analyst a head start on detection engineering.

### Session Timeline

A timeline panel at the bottom of the center column logs each investigation stage with timestamps. This is a breadcrumb trail for the current session and can be used to reconstruct how you arrived at a particular finding during an incident review.

---

## RocketRide AI Orchestration

Cerberus treats RocketRide as the intelligence backbone, not as a wrapper around an LLM call. Every investigation routes through a RocketRide pipeline first. Direct LLM calls only happen if RocketRide is completely unreachable.

There are three pipeline files in `pipelines/`.

**cerberus-threat-agent.pipe** is the primary pipeline. It contains eight nodes: a `chat` source that accepts the investigation request, an `agent_rocketride` wave-planning agent that orchestrates all tool use, an `llm_anthropic` node for narrative generation using Claude Sonnet 4.6, a `memory_internal` node that stores findings in a keyed namespace across investigation waves, an `mcp_client` node that connects to the neo4j-mcp server and exposes graph read and write tools directly to the agent, a `tool_http_request` node for external API calls restricted by URL whitelist to MITRE CVE, AbuseIPDB, and VirusTotal, a `tool_python` node that runs the custom cross-domain threat scoring algorithm, and a `response_answers` output node.

The wave-planning agent is the key architectural decision. Unlike a chain that executes steps in sequence, `agent_rocketride` plans tool calls in parallel waves. In the first wave it might call `get-schema` on Neo4j and check memory for a prior result simultaneously. In the second wave it runs multiple `read-cypher` queries in parallel once it knows the schema. Each wave's results are stored in `memory_internal` under a keyed namespace so later waves build on earlier findings without re-reading the entire graph. This is what makes the investigation thorough without being slow.

**cerberus-ingest.pipe** handles multimodal input. It contains six nodes: a `webhook` trigger, a `parse` node for text normalization, an `ocr` node for image and document input, an `extract_data` node that performs NLP-to-structured transformation with five typed columns (type, value, threat_domain, confidence, context), an `llm_anthropic` node for control logic, and a `response_answers` output. The `extract_data` node is the multimodal capability: a security analyst can submit a screenshot of a threat report, a PDF, or unstructured free text and the pipeline normalizes it to a structured entity table without regex or manual parsing.

**cerberus-query.pipe** is the fallback for when the agent pipeline fails to load. It is a simple chain: `chat`, `prompt`, `llm_anthropic`, `response_answers`. It still routes through RocketRide but uses none of the agent, memory, or tool capabilities.

If RocketRide is unavailable entirely, `backend/pipeline.py` detects the connection failure and falls back to a direct Anthropic SDK call through `backend/llm.py`. The frontend receives the same response format regardless of which path was used.

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Graph Database | Neo4j Aura (free tier) |
| MCP Bridge | neo4j-mcp v1.5.0, HTTP mode |
| Backend | FastAPI + uvicorn |
| AI Orchestration | RocketRide AI (agent_rocketride, memory_internal, mcp_client, tool_http_request, tool_python, extract_data, ocr) |
| LLM | Anthropic Claude Sonnet 4.6 |
| Frontend | React 18 + Vite + Tailwind CSS + shadcn/ui |
| Graph Visualization | react-force-graph-2d (d3-force layout) |
| Streaming | SSE via sse-starlette and EventSource |
| HTTP Client | httpx (async) |
| Auth | PyJWT (HS256, demo users, role-based) |
| STIX Export | stix2 Python library |

---

## Quick Start

### Prerequisites

You need Docker or Python 3.12 and Node.js 20 installed separately. You also need a Neo4j Aura free-tier instance and an Anthropic API key.

Neo4j Aura free tier: https://neo4j.com/cloud/aura-free/

Anthropic API console: https://console.anthropic.com/

### 1. Clone and configure

```bash
git clone https://github.com/kvn8888/Cerberus.git
cd Cerberus
cp .env.example .env
```

Open `.env` and fill in `NEO4J_URI`, `NEO4J_USERNAME`, `NEO4J_PASSWORD`, and `ANTHROPIC_API_KEY`. The other variables are optional and documented below.

### 2. Run with Docker

```bash
docker build -t cerberus .
docker run -p 10000:80 --env-file .env cerberus
```

Open http://localhost:10000

### 3. Seed the database

```bash
python scripts/run_all_imports.py
```

This populates Neo4j with approximately 200 MITRE ATT&CK techniques, 100 threat groups, 50 CVEs, 100 malicious IPs, 30 compromised packages, and 20 synthetic fraud signals. The seed data is required for the primary demo investigation to return meaningful results.

### 4. Run an investigation

Type `ua-parser-js` in the search box and press Enter. This package was hijacked in October 2021 and shipped cryptomining and credential-stealing malware across three versions. It has documented CVEs, known threat actor connections, malicious infrastructure links, and synthetic fraud signal associations that span all three graph domains. It is the primary demo entity.

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `NEO4J_URI` | Yes | Neo4j Aura connection URI in the format `neo4j+s://...` |
| `NEO4J_USERNAME` | Yes | Neo4j username, typically `neo4j` |
| `NEO4J_PASSWORD` | Yes | Neo4j password |
| `ANTHROPIC_API_KEY` | Yes | Anthropic API key for Claude |
| `NEO4J_MCP_URL` | No | neo4j-mcp server URL, default `http://127.0.0.1:8787` |
| `ROCKETRIDE_URI` | No | RocketRide engine URL, default `http://localhost:5565` |
| `ROCKETRIDE_APIKEY` | No | RocketRide auth key |
| `ROCKETRIDE_ANTHROPIC_KEY` | No | Anthropic key interpolated into pipeline LLM nodes |
| `NEO4J_MCP_ENDPOINT` | No | MCP endpoint passed to RocketRide's mcp_client node |
| `ROCKETRIDE_NEO4J_BASIC_AUTH` | No | Base64-encoded `user:pass` for neo4j-mcp Basic Auth |
| `VITE_API_URL` | No | Backend URL baked into the frontend at build time, default `http://localhost:8000` |

---

## Running Locally

### Docker, single container

```bash
docker build -t cerberus .
docker run -p 10000:80 --env-file .env cerberus
```

Frontend and API both served from http://localhost:10000 on the same origin. No CORS configuration needed.

### Docker Compose, separate containers

```bash
docker-compose up
```

Frontend at http://localhost:5173, backend at http://localhost:8000.

### Manual, no Docker

```bash
# Terminal 1
cd backend
pip install -r ../requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# Terminal 2
cd frontend
npm install
npm run dev
```

Frontend at http://localhost:5173.

---

## Deployment

The project includes a `render.yaml` blueprint that deploys as a single unified web service on Render.

| Service | Type | Description |
|---------|------|-------------|
| `cerberus` | Web Service | Unified frontend and backend container |
| `neo4j-mcp` | Private Service | MCP bridge to Neo4j Aura, internal only |

Connect the repo in the Render dashboard, create a Blueprint instance from `render.yaml`, fill in the environment variable values, and deploy. The unified container runs nginx serving the React build alongside uvicorn running FastAPI on the same port. No CORS configuration is needed because everything is same-origin.

---

## Neo4j Graph Schema

### Node Labels

| Label | Key Property | Source |
|-------|-------------|--------|
| `Package` | `name` (UNIQUE) | npm registry |
| `CVE` | `id` (UNIQUE) | NVD, MITRE |
| `IP` | `address` (UNIQUE) | Threat intel feeds |
| `Domain` | `name` (UNIQUE) | DNS, WHOIS |
| `ThreatActor` | `name` (UNIQUE) | MITRE ATT&CK |
| `Technique` | `mitre_id` (UNIQUE) | MITRE ATT&CK STIX |
| `Account` | `(username, registry)` UNIQUE | npm, GitHub |
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
(:Account)-[:LINKED_TO]->(:IP)
(:Domain)-[:SERVES]->(:Package)
```

Account to IP links are synthetic. No public data source maps npm publisher accounts to IP addresses directly. These connections are simulated from threat intel correlation for demo purposes and render as dashed edges in the frontend. In a production deployment they would come from Git commit metadata, npm publish audit logs, or SIEM correlation data.

---

## API Reference

### Core Investigation

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/api/schema` | Live graph schema with labels, relationships, and counts |
| `POST` | `/api/query` | Full investigation, non-streaming |
| `GET` | `/api/query/stream` | SSE streaming investigation |
| `GET` | `/api/query/graph` | Graph nodes and links for visualization |
| `POST` | `/api/confirm` | Analyst confirms a threat pattern and writes it back to Neo4j |

### Intelligence

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/threat-score` | Graph-based risk score with contributing factors |
| `GET` | `/api/blast-radius` | Count of reachable entities within four hops, broken down by type |
| `GET` | `/api/shortest-path` | Shortest path between two entities, up to eight hops |
| `GET` | `/api/suggestions` | Top five unconfirmed entities to investigate next |

### Memory

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/memory` | Confirmed-threat subgraph for the Memory tab |
| `GET` | `/api/memory/geo` | Geo coordinates for memorized entities |
| `GET` | `/api/memory/expand` | Expand a node's neighbors in the memory graph |

### Export

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/stix/bundle` | STIX 2.1 bundle with TLP marking definitions |
| `GET` | `/api/stix/indicator-count` | Indicator counts by type |
| `GET` | `/api/demo/report` | Full investigation report for PDF generation |

### Enrichment and Diff

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/enrich/virustotal` | VirusTotal-style reputation, simulated if no key is configured |
| `GET` | `/api/enrich/hibp` | Breach lookup for email addresses |
| `GET` | `/api/enrich/summary` | Unified enrichment summary across sources |
| `POST` | `/api/diff/compare` | Structural graph diff between two entities |

### Annotations and Watchlist

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/annotations` | List annotations on an entity |
| `POST` | `/api/annotations` | Create an annotation on a node |
| `DELETE` | `/api/annotations/{id}` | Delete an annotation |
| `GET` | `/api/watchlist` | List watchlist entries |
| `POST` | `/api/watchlist` | Add an entity to the watchlist |
| `DELETE` | `/api/watchlist/{id}` | Remove from watchlist |
| `GET` | `/api/watchlist/check` | Check for new connections since the last watchlist check |

### Auth and API Keys

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/auth/login` | Demo JWT login |
| `GET` | `/api/auth/me` | Current user from token |
| `POST` | `/api/keys/create` | Create an API key, role-gated |
| `GET` | `/api/keys` | List API keys |

### Juspay

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/juspay/ingest` | Ingest normalized fraud signals |
| `GET` | `/api/juspay/signals` | Fraud signal summary for the cross-domain alerts block |

### Query Flow

```
POST /api/query  {entity: "ua-parser-js", type: "package"}
  |
  cache hit?  ->  return confirmed narrative instantly, ~2s
  |
  graph traversal (domain-routed Cypher)
  |
  paths found?  ->  continue to RocketRide pipeline
  |
  no paths?  ->  real-time enrichment (OSV.dev, NVD, Abuse.ch)
               ->  write results to Neo4j
               ->  re-traverse
               ->  continue if data found
  |
  RocketRide agent pipeline
    wave 1: schema inspection + memory check
    wave 2: parallel graph queries across domains
    wave 3: HTTP tool calls for external validation
    wave 4: Python scorer for cross-domain threat scoring
    wave 5: LLM narrative generation from full context
  |
  SSE stream  ->  frontend
```

---

## Frontend Layout

The interface is a three-column dashboard.

The left column is the query panel. It holds the entity search input with automatic type detection, the NLP toggle for natural language queries, the cross-domain alerts block showing Juspay fraud signals with cyber actor overlap, investigation history from localStorage, and quick-start example entities.

The center column has five tabs at the top: Threat Graph, Geomap, MITRE, Memory, and Compare. The Threat Graph tab shows the force-directed graph with the attack path stepper, node search, and relationship filter. The Geomap tab shows IP geolocation with actor labels. The MITRE tab shows the tactic heatmap. The Memory tab shows confirmed-threat nodes with expand-to-neighbors. The Compare tab renders the structural diff between two entities. Below all tabs, a session timeline logs investigation stages.

The right column is the narrative panel. It streams the AI analysis in real time, shows the threat score and blast radius badges, renders the IOC extraction table with defanging and CSV export, handles TLP classification, provides the Technical and Executive mode toggle, and contains the export controls for PDF, STIX, markdown clipboard, and permalink copy.

A nine-stage pipeline bar runs across the top of the page and lights up each stage as the agent works. A stop button appears while the agent is running.

### Key Files

| File | Purpose |
|------|---------|
| `src/App.tsx` | Root layout, state flow, panel composition |
| `src/hooks/useInvestigation.ts` | SSE stream state machine, cancel, history |
| `src/lib/api.ts` | Typed API client for all endpoints |
| `src/lib/iocExtract.ts` | IOC parsing from narrative and graph data |
| `src/lib/attackPath.ts` | BFS attack path ordering and stepper navigation |
| `src/lib/mitreTactics.ts` | MITRE tactic metadata for the heatmap |
| `src/types/api.ts` | TypeScript interfaces for all API contracts |
| `src/components/panels/QueryPanel.tsx` | Entity input, NLP mode, cross-domain block, history |
| `src/components/panels/GraphPanel.tsx` | 2D graph, attack path stepper, filter, search, annotations |
| `src/components/panels/NarrativePanel.tsx` | Streaming narrative, IOCs, score, modes, exports |
| `src/components/panels/PipelineStages.tsx` | Nine-stage pipeline visualization with stop button |
| `src/components/layout/Header.tsx` | Brand, commit hash, status indicators, watchlist bell |

---

## Seed Data

```bash
python scripts/run_all_imports.py
```

Run scripts individually if you only need specific data:

```bash
python scripts/import_mitre.py       # MITRE ATT&CK techniques and threat groups
python scripts/import_cve.py         # CVE vulnerability data from NVD
python scripts/import_npm.py         # npm package dependency trees
python scripts/import_threats.py     # Malicious IPs and domains
python scripts/import_synthetic.py   # Synthetic cross-domain links and fraud signals
```

The primary demo entity is `ua-parser-js`. This package was hijacked in October 2021. Versions 0.7.29, 0.8.0, and 1.0.0 shipped cryptomining and credential-stealing malware. It carries CVE-2021-27292 for a ReDoS vulnerability in addition to the supply chain compromise. The seeded graph connects it to known threat actors, malicious infrastructure, and synthetic fraud signals across all three cross-domain surfaces. Investigating it produces a full attack chain traversal with every graph domain active. The fallback demo entity is `colors` version 1.4.1, which was deliberately sabotaged by its author in 2022.

---

## Tests

```bash
python -m pytest tests/ -v
```

| File | Coverage |
|------|----------|
| `tests/test_api_routes.py` | API routes with mocked Neo4j and LLM dependencies |
| `tests/test_neo4j_client.py` | Entity routing, Cypher templates, traversal, cache, confirm |

97 tests passing.

---

## Project Structure

```
Cerberus/
├── Dockerfile                     unified build, frontend and backend in one container
├── docker-compose.yml             multi-container dev setup
├── render.yaml                    Render deployment blueprint
├── requirements.txt               Python dependencies
├── backend/
│   ├── main.py                    FastAPI app entry point, router registration
│   ├── config.py                  environment variable loader
│   ├── neo4j_client.py            Neo4j driver, traversal, cache, graph viz, intelligence
│   ├── llm.py                     direct Anthropic Claude fallback
│   ├── pipeline.py                RocketRide SDK integration, three-tier fallback chain
│   ├── enrich.py                  real-time enrichment from OSV, NVD, Abuse.ch
│   ├── models.py                  Pydantic request and response models
│   └── routes/
│       ├── query.py               investigation endpoints, SSE stream
│       ├── confirm.py             analyst confirmation, self-improvement write-back
│       ├── intelligence.py        threat score, blast radius, shortest path, suggestions
│       ├── stix.py                STIX 2.1 bundle export
│       ├── diff.py                structural graph diff
│       ├── enrichment.py          VirusTotal, HIBP, unified summary
│       ├── juspay.py              Juspay fraud signal ingestion and summary
│       ├── annotations.py         collaborative annotation CRUD
│       ├── watchlist.py           watchlist management and change detection
│       ├── auth_routes.py         JWT login and session
│       ├── apikeys.py             API key management
│       ├── demo.py                NLP parse, geo map, report generation
│       ├── ingest.py              entity ingestion pipeline
│       └── threatmap.py           AI threat map SVG generation
├── frontend/
│   └── src/
│       ├── App.tsx                root layout and state orchestration
│       ├── hooks/                 useInvestigation SSE state machine
│       ├── lib/                   API client, IOC extractor, attack path, MITRE tactics
│       ├── types/                 TypeScript interfaces
│       └── components/
│           ├── layout/            Header, ViewNav
│           └── panels/            QueryPanel, GraphPanel, NarrativePanel, MitreHeatmapPanel,
│                                  MemoryPanel, ComparePanel, TimelinePanel, PipelineStages
├── pipelines/
│   ├── cerberus-threat-agent.pipe primary agent pipeline, eight nodes
│   ├── cerberus-query.pipe        fallback simple pipeline
│   └── cerberus-ingest.pipe       multimodal ingest and structured extraction
├── scripts/                       schema constraints, seed imports, deploy utilities
├── seed_data/                     MITRE ATT&CK STIX bundle
├── tests/                         pytest suite, 97 tests
├── docs/                          session retrospectives
└── deploy/                        nginx config, startup script, cloud deployment guides
```

---

## Hackathon Context

Built for HackWithBay 2.0 under the theme Thoughtful Agents for Productivity. Sponsored by Neo4j, RocketRide AI, and Juspay.

The problem Cerberus solves did not exist in a single tool before this. Cross-domain threat correlation requires manually querying at least five separate systems and stitching the results by hand. Cerberus collapses that into a single investigation that takes ten seconds and produces a complete, actionable narrative.

RocketRide is not a wrapper in this project. It is the reasoning layer. The wave-planning agent decides what to query, in what order, using what tools, and how to weight the findings. The cross-domain scorer, the structured entity extraction pipeline, and the multimodal ingest are all RocketRide-native capabilities. Removing RocketRide from Cerberus would leave a graph viewer with no intelligence behind it.
