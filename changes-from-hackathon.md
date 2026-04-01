# Changes From Hackathon

## New Features Added (Pre-Judging Sprint)

### 1. Threat Score (0-100)
- Computes a quantified risk score per entity based on graph connectivity
- Factors: ThreatActor connections, CVE links, FraudSignals, cross-domain hops, ConfirmedThreat status, multiple actors
- Severity mapping: critical (80-100), high (60-79), medium (40-59), low (20-39), info (0-19)
- Visual: color-coded badge in narrative header + detailed score card with progress bar and contributing factors
- **Backend:** `threat_score()` in `neo4j_client.py`, `GET /api/threat-score` endpoint
- **Frontend:** Score badge + detail card in NarrativePanel, streamed via SSE

### 2. Blast Radius
- Counts how many distinct entities are reachable within 4 hops of the investigated entity
- Broken down by type (Package, IP, ThreatActor, etc.)
- Shows "X AFFECTED" badge in narrative header + detailed breakdown card
- **Backend:** `blast_radius()` in `neo4j_client.py`, `GET /api/blast-radius` endpoint
- **Frontend:** Badge + breakdown in NarrativePanel, streamed via SSE

### 3. Shortest Path Between Two Entities
- Find the shortest path (up to 8 hops) between any two entities in the graph
- Returns nodes + links in force-graph format with hop count
- **Backend:** `shortest_path()` in `neo4j_client.py`, `GET /api/shortest-path` endpoint
- **Frontend:** API client function added (`fetchShortestPath`)

### 4. "Investigate Next" Suggestions
- After an investigation completes, suggests up to 5 unconfirmed entities to investigate next
- Ranked by number of connections (most connected = most interesting)
- Clickable buttons that immediately launch a new investigation
- **Backend:** `suggest_next()` in `neo4j_client.py`, `GET /api/suggestions` endpoint
- **Frontend:** Suggestion list in NarrativePanel with click-to-investigate

### 5. Relationship Type Filter (Graph)
- Checkbox panel to show/hide edges by relationship type (e.g., EXPLOITS, LINKED_TO, OPERATES)
- Nodes orphaned by hidden edges are also hidden
- Filter toggle button in graph toolbar
- **Frontend:** GraphPanel filter UI + `filteredGraphData` memo

### 6. Node Search + Highlight (Graph)
- Search input that highlights matching nodes with a gold ring + glow
- Real-time filtering as you type
- **Frontend:** GraphPanel search bar + modified `paintNode` callback

### 7. Audience Mode Toggle (Technical vs Executive)
- Toggle between "Technical" (analyst) and "Executive" narrative styles
- Persists across investigations
- **Frontend:** Toggle in NarrativePanel, `audienceMode` in InvestigationState

### 8. Investigation History (localStorage)
- Saves last 10 completed investigations to localStorage
- Shows entity name, severity dot, threat score, path count, and date
- Click to re-investigate, clear button to wipe history
- Deduplicates (re-investigating same entity updates the entry)
- **Frontend:** QueryPanel history section with localStorage persistence

---

## Files Changed

### Backend
| File | Change |
|------|--------|
| `backend/neo4j_client.py` | Added `threat_score()`, `blast_radius()`, `shortest_path()`, `suggest_next()` |
| `backend/routes/intelligence.py` | **New file** — 4 GET endpoints for the new graph intelligence functions |
| `backend/routes/query.py` | SSE stream now emits `threat_score`, `blast_radius`, `suggestions` events |
| `backend/main.py` | Registered `intelligence_router` |

### Frontend
| File | Change |
|------|--------|
| `frontend/src/types/api.ts` | Added `ThreatScore`, `BlastRadius`, `Suggestion`, `InvestigationHistoryItem` interfaces; extended `InvestigationState` and `StreamChunk` |
| `frontend/src/lib/api.ts` | Added `fetchThreatScore()`, `fetchBlastRadius()`, `fetchShortestPath()`, `fetchSuggestions()` |
| `frontend/src/hooks/useInvestigation.ts` | Handles new SSE events; added `setAudienceMode`; preserves audience mode across investigations |
| `frontend/src/components/panels/GraphPanel.tsx` | Added relationship type filter, node search + highlight |
| `frontend/src/components/panels/NarrativePanel.tsx` | Added threat score card, blast radius breakdown, audience toggle, "Investigate Next" suggestions |
| `frontend/src/components/panels/QueryPanel.tsx` | Added investigation history with localStorage |
| `frontend/src/App.tsx` | Wired `setAudienceMode`, `investigationState`, and `onInvestigate` props |

---

## Later updates — what was removed

These were removed to reduce demo confusion, dead UI, or duplicate flows:

| Item | Notes |
|------|--------|
| **Live Feed tab** | Center-panel tab removed; fraud signals are surfaced in the left sidebar instead. |
| **3D Graph tab** | Tab removed from `ViewNav` (2D Threat Graph + Geomap + Memory remain). `Graph3DPanel.tsx` may still exist in the tree but is not routed. |
| **QueryPanel NLP block** | The collapsible NLP area was replaced with a toggle button (MessageSquare icon) that switches between direct entity search and natural language mode. |
| **Multi-entity comparison** | Restored as dedicated `ComparePanel` (5th center tab) using `POST /api/diff/compare`. |
| **Generate Threat Map (AI)** | Button and `generateThreatMap` client call removed from `NarrativePanel`. |
| **Unused API helpers** | Removed from `api.ts` where applicable: e.g. `fetchLiveFeed`, `ingestFeedEvent`, `parseNaturalLanguage`, `compareEntities`, `generateThreatMap` (exact set may vary by commit). |
| **“Live Fraud Signals” as raw txn IDs** | Replaced with **Cross-Domain Alerts** copy: actor badges, IP-first rows, subtitle explaining shared infrastructure between cyber and fraud. |

---

## Later updates — what was added

| Area | What |
|------|------|
| **Memory tab** | Visualizes `ConfirmedThreat` subgraph from Neo4j; force-graph with expand; badge count in nav. |
| **Cross-domain fraud block** | `QueryPanel`: loads `/api/juspay/signals`, shows actor links + IP-centric rows with context. |
| **MITRE tab** | `MitreHeatmapPanel`: tactic heatmap from `Technique` nodes in the current investigation graph (`mitreTactics.ts`). |
| **IOC extraction** | `NarrativePanel` + `lib/iocExtract.ts`: IPs, CVEs, domains, packages from graph + narrative; Copy all + CSV. |
| **Attack path stepper** | `GraphPanel` + `lib/attackPath.ts`: BFS order from investigation root; Prev/Next; cyan highlight on active node. |
| **Technical / Executive** | `NarrativePanel`: Executive shows risk summary + key finding + recommended action; Technical shows full markdown narrative. |
| **Geomap** | Tighter actor offsets, auto zoom-to-fit, +/- / Reset zoom (see recent ThreatMap commits). |
| **Backend (additive)** | Examples: `routes/stix.py` (`GET /api/stix/bundle`), `routes/diff.py` (`POST /api/diff/compare`), `routes/enrichment.py` (`GET /api/enrich/*` — VT/HIBP/summary with simulated fallback), `auth.py` + `routes/auth_routes.py` (`POST /api/auth/login`), `routes/apikeys.py` (`/api/keys/*`), `main.py` memory routes (`/api/memory`, `/api/memory/geo`, `/api/memory/expand`). |
| **Session timeline** | `TimelinePanel` at bottom of center column; `useInvestigation` history for replay. |
| **Investigation history** | `QueryPanel` localStorage recent list (may overlap with timeline; both support quick re-run). |

---

## Phase 2 — Feature Sprint

### New Features

| Feature | Details |
|---------|---------|
| **NLP Query Toggle** | `QueryPanel` MessageSquare icon toggles NLP mode → calls `/api/demo/natural` → auto-extracts entity + type |
| **STIX Memory Export** | `MemoryPanel` Download button batches STIX bundles for all confirmed nodes → deduplicates by STIX ID → browser download |
| **Entity Comparison** | New `ComparePanel.tsx` (5th center tab) → two entity inputs → `POST /api/diff/compare` → overlap score bar + shared/exclusive node lists |
| **Collaborative Annotations** | `GraphPanel` Notes section in node sidebar → `backend/routes/annotations.py` → `:Annotation` nodes with `:ANNOTATES` relationships |
| **Watchlist Alerts** | `Header.tsx` Bell icon with 30s polling → `backend/routes/watchlist.py` → `:Watchlist` nodes tracking new connections since last check |

### New Files

| File | Purpose |
|------|---------|
| `frontend/src/components/panels/ComparePanel.tsx` | Entity comparison panel (lazy-loaded) |
| `backend/routes/annotations.py` | Annotation CRUD (`GET/POST/DELETE /api/annotations`) |
| `backend/routes/watchlist.py` | Watchlist CRUD + change detection (`GET/POST/DELETE /api/watchlist`, `GET /api/watchlist/check`) |

### Modified Files

| File | Change |
|------|--------|
| `frontend/src/components/panels/QueryPanel.tsx` | NLP toggle (nlpMode state, MessageSquare icon, async handleSubmit) |
| `frontend/src/components/panels/MemoryPanel.tsx` | STIX export button (Download icon, batched fetch + dedup + download) |
| `frontend/src/components/panels/GraphPanel.tsx` | Annotations section + Watch Entity button in node sidebar |
| `frontend/src/components/layout/Header.tsx` | Watchlist bell icon, 30s auto-check, alert dropdown with bounce animation |
| `frontend/src/components/layout/ViewNav.tsx` | 5th tab: Compare (GitCompareArrows icon) |
| `frontend/src/App.tsx` | ComparePanel lazy import + render conditional |
| `frontend/src/lib/api.ts` | 9 new functions: parseNaturalLanguage, compareEntities, listAnnotations, createAnnotation, deleteAnnotation, getWatchlist, addToWatchlist, removeFromWatchlist, checkWatchlist |
| `backend/main.py` | Registered annotations_router and watchlist_router |
| `backend/neo4j_client.py` | Added `run_query()` helper for generic Cypher execution |

### Performance Sprint (same session)

| Fix | Impact |
|-----|--------|
| Viewport meta tag | Mobile Lighthouse 45 → 94 |
| React.lazy + Suspense for 4 heavy panels | Reduced initial bundle |
| Vite manualChunks (react, graph, pdf, stix) | Better caching |
| Async Google Fonts | Unblocked render |
| Dynamic PDF import | Smaller initial load |

---

## How to keep docs in sync

When you change UX or API surface again, update this file plus [README.md](README.md) and [.claude/skills/cerberus-project/SKILL.md](.claude/skills/cerberus-project/SKILL.md) so judges and future sessions see one story.
