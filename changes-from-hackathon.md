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
