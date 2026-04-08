# Cerberus — Errors & Fixes Log

> Every real bug, wrong assumption, and broken build we hit during development — and exactly how we fixed it.
> Organized by category. Full session retrospectives live in `docs/retro-*.md`.

---

## 1. Python / Backend

### `hashlib` Removed as "Unused Import" — Crashed on First Real Run

**File:** `backend/neo4j_client.py`  
**Symptom:** `NameError: name 'hashlib' is not defined` — would have crashed on the first analyst `Confirm Pattern` click during the demo.  
**Root cause:** `import hashlib` looked unused in a surface scan. The only usage was deep inside `write_back()`, which generates a SHA-256 hash of the LLM narrative to detect cache staleness. The unit tests mocked `write_back` at a higher level, so no test actually called the line — meaning all tests passed with the import removed.  
**Fix:** Restore the import. The write-back path generates `narrative_hash=hashlib.sha256(narrative.encode("utf-8")).hexdigest()` — that hash is used to skip redundant LLM calls on repeat queries.  
**Lesson:** "Unused import" is only true across all code paths, including ones your tests mock. If a mock short-circuits execution before the usage, tests pass even though the import is needed.

---

### CVE Enrichment Created Orphan Nodes (0 Traversal Paths)

**File:** `backend/enrich.py`  
**Symptom:** Querying an unknown CVE like `CVE-2025-11953` returned "0 paths found" and the narrative said the entity was "likely benign." A CVSS 9.8 critical RCE in CISA's KEV catalog was being dismissed as probably fictitious.  
**Root cause:** `_enrich_cve()` called the NVD API, got full data back, and created a bare CVE node with no edges. Graph traversal only follows relationships — an isolated node is invisible to any `shortestPath` query.  
**Fix (three parts):**

1. **CPE extraction** — Parse `configurations[].nodes[].cpeMatch[].criteria` to extract product names (index 4 of the CPE 2.3 string). `MERGE` `Package` nodes and add `HAS_VULNERABILITY` edges.
2. **CWE → ATT&CK mapping** — Map weakness IDs (e.g. `CWE-78` → `T1059`) to existing `Technique` nodes via `RELATED_TECHNIQUE` edges. 17-entry lookup table covers the most common CWEs.
3. **Rewrite narrative fallback prompt** — Replaced "explain why this is likely benign" with explicit instructions: _"Do NOT assume the entity is benign. Absence of evidence is not evidence of absence."_  
   **Lesson:** Every data-ingestion function must produce a connected subgraph, not just a node. Orphan nodes are silent failures — they produce no errors but also no intelligence.

---

### Narrative Fallback Prompt Said "Likely Benign" for Unknown Entities

**File:** `backend/llm.py` (`_CLEAN_ASSESSMENT_PROMPT`)  
**Symptom:** Zero-path queries generated narratives calling real CVEs "fictitious or test IDs."  
**Root cause:** The system prompt was written to reassure users about common service names (GitHub, npm CDN). That phrasing leaked into CVE/IP queries.  
**Fix:** Rewrote the prompt to treat absence of graph data as unknown, not safe. Added specific instructions for CVE IDs: _"Never call an unknown CVE 'fictitious' or 'invalid' unless the numeric range is provably unallocated."_ Also bumped `max_tokens` from 200 to 400 — cautious narratives are longer than dismissive ones and were truncating mid-sentence.

---

### Fragile LLM JSON Parsing in Ingest Pipeline

**File:** `backend/routes/ingest.py`  
**Symptom:** Occasional `json.loads()` failures when the LLM added commentary, changed fence syntax (`json` vs `JSON`), or included trailing newlines.  
**Root cause:** The ingest pipeline asked `llm_anthropic` to return structured JSON as plain text. LLMs add preamble and fences inconsistently.  
**Fix:** Replaced with RocketRide's `extract_data` component (Phase 3). Defines 5 typed columns (type, value, threat_domain, confidence, context) and returns structured tabular data — no parsing needed. Added `_parse_extraction_response()` in `ingest.py` as compatibility shim for legacy format during transition.

---

### `ANTHROPIC_API_KEY` Env Var Suspected Wrong Name

**File:** `backend/config.py`  
**Symptom:** Team concern that `config.py` was reading from `NEO4J_API_KEY` instead of `ANTHROPIC_API_KEY`.  
**Root cause:** A stale code comment implied the env var name was wrong. No actual bug — just misleading documentation.  
**Fix:** Verified in source: `ANTHROPIC_KEY = _require("ANTHROPIC_API_KEY")` is correct. Marked in SKILL.md as "VERIFIED FALSE — `ANTHROPIC_KEY` reads from `ANTHROPIC_API_KEY`, not `NEO4J_API_KEY`."

---

## 2. Docker / Deployment

### macOS Binary Mounted Into Linux Container

**File:** `docker-compose.yml` (original), `neo4j-mcp_Darwin_arm64/`  
**Symptom:** `neo4j-mcp` container crashed immediately on start.  
**Root cause:** The compose file mounted `./neo4j-mcp_Darwin_arm64/neo4j-mcp` as a volume into an Alpine Linux container. macOS binaries (Mach-O format) cannot execute in Linux containers (ELF format). This is an OS-level incompatibility, not a permission issue.  
**Fix:** Downloaded the Linux ARM64 binary (`neo4j-mcp_Linux_arm64/`). Replaced the volume mount with a proper `FROM alpine` Dockerfile that `COPY`s the binary in and marks it executable.

---

### Wrong CLI Flags for neo4j-mcp v1.5.0

**File:** `docker-compose.yml` (original command block)  
**Symptom:** Container started but neo4j-mcp exited with unknown flag errors.  
**Root cause:** The compose `command:` used `--transport`, `--port`, `--host` — CLI flags from documentation or a different version. Running `neo4j-mcp --help` on the actual binary revealed the real flags.  
**Fix:** Updated to actual v1.5.0 flags:

```
--neo4j-transport-mode http
--neo4j-http-port 8787
--neo4j-http-host 0.0.0.0
--neo4j-http-allow-unauthenticated-ping true
```

**Lesson:** Always run `--help` on the actual binary you have. Changelogs and third-party docs can be stale.

---

### `COPY ../requirements.txt` Fails in Docker Build

**File:** `backend/Dockerfile`  
**Symptom:** `docker build` failed with "COPY failed: forbidden path."  
**Root cause:** Docker build contexts are sandboxed. `COPY ../requirements.txt` attempts to reference a file outside the build context directory (`./backend`). This is not allowed regardless of filesystem permissions.  
**Fix:** Changed the compose build context to the project root and pointed `dockerfile:` to the relative path:

```yaml
backend:
  build:
    context: .
    dockerfile: backend/Dockerfile
```

`requirements.txt` stays at the project root as a single source of truth.

---

### Docker Layer Cache Served Stale Build After Code Change

**File:** `frontend/Dockerfile` (indirectly)  
**Symptom:** Removed a UI component from source, pushed changes, rebuilt Docker image — the old component still appeared in the running container.  
**Root cause:** Docker cached the `npm run build` layer because the `COPY frontend/ ./` layer hash matched the previous build from Docker's perspective. The file-content diff wasn't re-evaluated.  
**Fix:** `docker build --no-cache -t cerberus .`  
**Lesson:** When a code change visibly isn't showing up in a container, check Docker layer caching first. Use `--no-cache` or `--no-cache-filter` for targeted rebuilds.

---

### `VITE_API_URL` Baked at Build Time

**Symptom:** Frontend pointed at a stale API URL after the backend endpoint changed.  
**Root cause:** Vite bakes `VITE_*` env vars at `npm run build` time, not at runtime. Changing `.env` alone and restarting the container doesn't update the baked value.  
**Fix:** Rebuild the frontend image (`docker build`) whenever `VITE_API_URL` changes. Documented this as a critical gotcha in `SKILL.md`: _"If `VITE_API_URL` changes, rebuild the frontend image/bundle."_

---

## 3. Frontend / React

### Two Toggle Systems Stacking at the Same Position

**File:** `frontend/src/components/panels/GraphPanel.tsx`  
**Symptom:** Navigation text appeared doubled and garbled ("RTHATGRAPH"). Looked like a CSS blur / compositing artifact.  
**Root cause:** Two completely independent toggle systems were `absolute top-3 left-3 z-20` — `ViewNav` (parent, `rounded-md` buttons) and an internal pill toggle inside `GraphPanel` (`rounded-full` buttons). Same position, same z-index, both rendered simultaneously.  
**Fix:** Removed `GraphPanel`'s internal toggle entirely. `ViewNav` is the single source of truth for view switching.

---

### Removing One Component Left Six Dangling References

**File:** `frontend/src/components/panels/GraphPanel.tsx`  
**Symptom:** Docker build failed with repeated TypeScript errors after removing the internal `GeoMap` sub-component.  
**Root cause:** Removing 290 lines of JSX left behind: `setViewMode` (called nowhere), `viewMode` state (always-false comparison flagged by tsc), `mapPoints` state, `fetchGeoMap` import, `GeoMap` component import, `GeoPoint` type import, `useState` import. TypeScript's `tsc -b` (used in the Dockerfile) is stricter about unused declarations than `tsc --noEmit` (used locally).  
**Fix:** Tracked down all six references with `grep -n "viewMode\|mapPoints\|GeoMap"` and removed them.  
**Lesson:** When removing UI that owns state, grep every variable name before committing.

---

### `React.lazy()` Fails With Named Exports

**File:** `frontend/src/App.tsx`  
**Symptom:** "Element type is invalid: expected a string or a class/function but got undefined" after adding `lazy()` to panel imports.  
**Root cause:** `React.lazy()` requires a module with a **default export**. The panels used named exports (`export const GraphPanel = ...`).  
**Fix:** Wrap with a `.then()` remapping:

```tsx
const GraphPanel = lazy(() =>
  import("./components/panels/GraphPanel").then((m) => ({
    default: m.GraphPanel,
  })),
);
```

---

### Vite `manualChunks` Can't Split Transitive Dependencies

**File:** `frontend/vite.config.ts`  
**Symptom:** Build failed when `d3-force` was listed in `manualChunks`.  
**Root cause:** `d3-force` is a transitive dependency of `react-force-graph-2d`, not a direct dependency of the project. Vite's `manualChunks` can only split modules that appear in the project's own dependency tree.  
**Fix:** Removed `d3-force` from the manual chunks config. Only direct dependencies can be explicitly chunked:

```ts
manualChunks: {
  'vendor-graph': ['react-force-graph-2d'],   // OK — direct dep
  'vendor-geo':   ['d3-geo', 'topojson-client'],
  'vendor-pdf':   ['@react-pdf/renderer'],
  'vendor-md':    ['react-markdown'],
}
```

---

### Google Fonts Blocking First Paint (873ms)

**File:** `frontend/src/index.css`  
**Symptom:** Lighthouse flagged an 873ms render-blocking resource. FCP was 5.7–6.3s on mobile.  
**Root cause:** CSS `@import url("https://fonts.googleapis.com/css2?...")` is synchronous — the browser won't paint until the external stylesheet downloads.  
**Fix:** `media="print"` + `onload` trick in `index.html`:

```html
<link
  rel="stylesheet"
  href="https://fonts.googleapis.com/css2?..."
  media="print"
  onload="this.media='all'"
/>
```

Browsers don't block rendering for print stylesheets; `onload` flips it to `all` after download.

---

### Missing `<meta name="viewport">` Destroyed Mobile Lighthouse Score

**File:** `frontend/index.html`  
**Symptom:** Lighthouse mobile score was 45-56/100. FCP: 5.7s, LCP: 7.4s.  
**Root cause:** No `<meta name="viewport">` tag. Mobile browsers defaulted to a desktop-width render and scaled it down, which breaks every Lighthouse metric.  
**Fix:** Added `<meta name="viewport" content="width=device-width, initial-scale=1.0" />`. Score jumped to 94/100.

---

### `@react-pdf/renderer` (518KB) Loading on Every Page Visit

**File:** `frontend/src/components/panels/NarrativePanel.tsx`  
**Symptom:** Heavy initial bundle; PDF export is used rarely but paid for on every load.  
**Root cause:** Static top-level import of `@react-pdf/renderer` bundled it into the main chunk.  
**Fix:** Dynamic import inside the click handler:

```tsx
const handleExportPdf = async () => {
  const [{ pdf }, { ThreatReportPdf }] = await Promise.all([
    import("@react-pdf/renderer"),
    import("../report/ThreatReportPdf"),
  ]);
  // ...generate and download
};
```

---

### Graph Canvas Rendering Too Small (ResizeObserver Missing)

**File:** `frontend/src/components/panels/GraphPanel.tsx`  
**Symptom:** The force-directed graph rendered in a small rectangle with large empty space around it.  
**Root cause:** The canvas dimensions were set once on mount and didn't respond to layout changes or panel resizing.  
**Fix:** Added a `ResizeObserver` on the container div to update `width`/`height` state whenever the panel size changes, then passed those values to `ForceGraph2D`.

---

### Hardcoded Fake Geomap Data Showing on Every Load

**File:** `frontend/src/components/panels/ThreatMap.tsx` (original)  
**Symptom:** The geomap always displayed 10 hardcoded threat nodes (APT-28, Lazarus, etc.) regardless of what was in Neo4j.  
**Root cause:** A `THREAT_NODES` array and `THREAT_CONNECTIONS` array were statically defined in the component. Real threat actor geo data was in Neo4j but never fetched for the default view.  
**Fix:** Added `get_all_geo()` in `backend/neo4j_client.py` — queries all `IP` nodes with `geo` property and all `ThreatActor` nodes with location data, no `ConfirmedThreat` filter required. New endpoint `GET /api/geomap/all`. Frontend fetches this on mount and replaces the static arrays.

---

### Technique Nodes Overloading the Force Graph (150+ Per Actor)

**File:** `backend/neo4j_client.py` (`get_graph()`)  
**Symptom:** Querying threat actors like Lazarus Group made the force-directed graph unusable — hundreds of nodes, unreadable layout.  
**Root cause:** MITRE ATT&CK includes groups with 150+ documented techniques. Every `USES` relationship added a node to the graph response.  
**Fix:** Added a per-actor counter dict. Skip emitting technique nodes once an actor has 5:

```python
actor_tech_counts: dict[str, int] = {}
if actor_tech_counts.get(actor, 0) >= 5:
    continue
actor_tech_counts[actor] = actor_tech_counts.get(actor, 0) + 1
```

---

### Stat Badges Colliding With Viewport Navigation

**File:** `frontend/src/components/panels/ThreatMap.tsx`  
**Symptom:** ACTIVE / APT / CRITICAL badges rendered horizontally and overlapped the navigation controls.  
**Root cause:** `flex-row` layout with fixed positioning conflicted with the nav.  
**Fix:** Changed wrapper to `flex-col items-end gap-1.5`.

---

## 4. RocketRide / Pipeline

### Control Connections Go on the Controlled Node (Counterintuitive Direction)

**File:** `pipelines/cerberus-threat-agent.pipe`  
**Symptom:** Pipeline failed to wire the agent to its LLM and MCP Client.  
**Root cause:** In RocketRide, the `control` array belongs on the **tool/LLM node**, pointing back to the agent — not on the agent pointing outward. This is the opposite of intuitive "agent calls tool" wiring:

```json
// LLM declares it is controlled by the agent:
{ "id": "llm_anthropic_1", "control": [{"classType": "llm", "from": "agent_1"}] }
// MCP Client declares it is controlled as a tool:
{ "id": "mcp_client_1", "control": [{"classType": "tool", "from": "agent_1"}] }
```

**Fix:** Added `control` arrays to `llm_anthropic_1` and `mcp_client_1` pointing back to `agent_rocketride_1`.

---

### Backend Used `client.send()` Instead of `client.chat()`

**File:** `backend/pipeline.py`  
**Symptom:** RocketRide calls returned errors or malformed responses.  
**Root cause:** `client.send(token, data)` routes to webhook/dropper sources. Both Cerberus pipelines use a `chat` source node, which requires `client.chat(token, question)`.  
**Fix:** Switched all pipeline calls to `client.chat()` with a `Question` object.

---

### `agent_crewai` Had No Memory (Every Investigation Started Cold)

**File:** `pipelines/cerberus-threat-agent.pipe`  
**Symptom:** The agent re-queried the same context every wave and couldn't build on prior findings within an investigation.  
**Root cause:** `agent_crewai` is a thin CrewAI wrapper with no native memory. Each tool call was independent.  
**Fix (Phase 3):** Replaced with `agent_rocketride` + `memory_internal` node. The agent stores intermediate findings with `put/get` between waves, staying token-efficient without re-querying Neo4j for already-discovered entities. Required adding explicit memory-use instructions to the agent's `instructions` array — the agent won't use memory tools unless told to.

---

### `agent_rocketride` Config Format Differs From `agent_crewai`

**File:** `pipelines/cerberus-threat-agent.pipe`  
**Symptom:** Pipeline validation errors after replacing provider.  
**Root cause:** `agent_crewai` used a flat `"parameters": {}` field. `agent_rocketride` requires `"max_waves"` (int, 1-50) and `"instructions"` (string array). No `parameters` key.  
**Fix:** Updated config structure:

```json
{
  "provider": "agent_rocketride",
  "config": {
    "agent_description": "...",
    "instructions": ["..."],
    "max_waves": 10
  }
}
```

---

### `extract_data` Node Config Used Wrong Field Name

**File:** `pipelines/cerberus-ingest.pipe`  
**Symptom:** `extract_data` node failed to produce structured output.  
**Root cause:** Config used `"columns"` instead of RocketRide's `"fields"` key inside the `"default"` profile object. Field names are case-sensitive in the `.pipe` JSON.  
**Fix:** Updated to `"fields": [{ "column": "...", "type": "text" }]` per the component reference.

---

### neo4j-mcp `get-schema` Tool Failed When APOC Was Missing

**Symptom:** Agent couldn't introspect the graph schema; first investigation wave returned empty results.  
**Root cause:** The `get-schema` tool in neo4j-mcp uses APOC procedures. Neo4j Aura free tier includes APOC, but confirming availability wasn't done upfront.  
**Fix:** Added verification step: run `RETURN apoc.version()` in Neo4j Browser on session start. If APOC is missing, use `read-cypher` with manual schema queries (`CALL db.labels()`, `CALL db.relationshipTypes()`) instead of `get-schema`.

---

## 5. Node.js / Tooling

### `create-vite@9` Refused to Run on Node v20.9.0

**Symptom:** `npm create vite@9` failed with:

```
npm error engine Unsupported engine {
  required: { node: '^20.19.0 || >=22.12.0' },
  current: { node: 'v20.9.0' }
}
```

**Root cause:** The latest Vite scaffolder required a newer Node LTS minor. Upgrading Node mid-session risked breaking other tools.  
**Fix:** Pinned to an older scaffolder version: `npm create vite@5 frontend -- --template react-ts`. Works with Node v20.9.0.

---

## 6. Data / Graph

### `Account → IP` Link Has No Real Data Source

**Entity:** `(:Account)-[:LINKED_TO]->(:IP)`  
**Issue:** No public API maps npm publisher accounts to IP addresses. Including this relationship as if it were real would be misleading.  
**Fix:** These links are generated synthetically for the demo. They render as **dashed edges** in the visualization. Standard judge answer: _"The Account-to-IP link is simulated from threat intel correlation. In production, this comes from Git commit metadata, npm publish audit logs, or SIEM data."_

---

### Running Import Scripts on a Pre-Populated Database

**Symptom:** Risk of data corruption or duplicate nodes if scripts were run a second time.  
**Root cause:** Import scripts (`import_mitre.py`, `import_cve.py`, etc.) were validated against an empty database. The live demo database already had ~1,060 nodes. The scripts use `MERGE` for most operations, but not all edge cases were safe to re-run.  
**Fix:** Deleted all import scripts after the initial import run (Retro 009). `scripts/constraints.cypher` was retained as a schema reference. **Never re-run import scripts against the live Aura instance.**

---

## 7. Security / Exports

### TLP:CLEAR vs TLP:WHITE Naming Mismatch in STIX Bundles

**File:** `backend/routes/stix.py`  
**Symptom:** STIX bundles used `TLP:CLEAR` in the UI but downstream MISP/OpenCTI tools expected `TLP:WHITE` marking-definition objects.  
**Root cause:** TLP was updated (CLEAR replaced WHITE) but the historic STIX marking-definition IDs reference `TLP:WHITE`. Tools that import STIX bundles validate against those registered IDs.  
**Fix:** Product UI shows `TLP:CLEAR`. Backend maps it to the standard `TLP:WHITE` marking-definition object when generating STIX. `TLP:AMBER+STRICT` gets a hybrid: standard AMBER marking + a statement marking capturing stricter handling guidance.

---

### IOC Export Produced Clickable (Dangerous) Links in Slack/Jira

**File:** `frontend/src/lib/iocExtract.ts`  
**Symptom:** Copying IOC lists pasted live hyperlinks into Slack channels — a security risk if clicked.  
**Fix:** Added `defangValue()` — transforms `https:` → `hxxps:`, replaces `.` with `[.]` in IPs and domains. Default-on toggle in `NarrativePanel` for both CSV and markdown export paths.

---

### Detection Rule Output Not Reliably Parseable

**File:** `backend/llm.py`, `backend/routes/detect.py`  
**Symptom:** Claude sometimes wrapped Sigma/YARA output in markdown fences or added explanatory text, breaking structured parsing.  
**Fix:** Added `_parse_json_response()` with fence-stripping and fallback. Prompt explicitly instructs Claude to return strict JSON with no surrounding text. Endpoint returns structured `{ sigma, yara, caveats }` shape rather than raw text.

---

_Last updated: April 2026. Source of truth for all entries: `docs/retro-001` through `docs/retro-011`._
