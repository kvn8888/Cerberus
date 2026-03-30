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
| Orchestration | RocketRide AI |
| Frontend | React 18 + Vite + Tailwind + shadcn/ui |
| Graph Viz | neovis.js (via backend proxy — never direct Aura connection) |
| Streaming | SSE |
| LLM | Anthropic (via RocketRide LLM Node) |

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
CERBERUS_API=http://localhost:8000
```

## Project Structure (Target)

```
Cerberus/
├── CLAUDE.md
├── spec.md
├── constraints.cypher          # 8 uniqueness constraints
├── import_mitre.py             # MITRE ATT&CK → Neo4j
├── import_cve.py               # NVD CVEs → Neo4j
├── import_threats.py           # Abuse.ch/OTX → IP/Domain nodes
├── import_npm.py               # Compromised packages → Neo4j
├── import_synthetic.py         # Synthetic Account→IP + Juspay fraud
├── eval_improvement.py         # 3-phase eval script
├── seed_data/                  # Pre-downloaded JSON/CSV feeds
├── docker-compose.yml          # RocketRide + neo4j-mcp + frontend
├── entity_schema.json          # Integration contract JSON schema
├── neo4j-mcp_Darwin_arm64/     # MCP server binary
├── frontend/                   # React app (TBD)
└── docs/                       # Retrospectives
```

## Implementation Status

- [x] Spec v2 finalized
- [x] neo4j-mcp v1.5.0 confirmed locally
- [x] Project skill created
- [ ] constraints.cypher
- [ ] Import scripts (mitre, cve, threats, npm, synthetic)
- [ ] eval_improvement.py
- [ ] seed_data/ populated
- [ ] docker-compose.yml
- [ ] Entity JSON schema
- [ ] RocketRide pipelines configured
- [ ] Frontend scaffolded
- [ ] End-to-end integration tested
- [ ] Demo rehearsed + pre-cached
