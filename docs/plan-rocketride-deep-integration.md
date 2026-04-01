# RocketRide Deep Integration Plan

> Planning document for deeper RocketRide integration beyond the current Neo4j MCP bridge.

## Current State

Cerberus currently uses **3 RocketRide pipelines** with **9 unique components**:

| Pipeline | Purpose | Components Used |
|----------|---------|----------------|
| `cerberus-threat-agent.pipe` | Autonomous graph investigation | chat, agent_crewai, llm_anthropic, mcp_client, response_answers |
| `cerberus-ingest.pipe` | Document → entity extraction | webhook, parse, ocr, prompt, llm_anthropic, response_answers |
| `cerberus-query.pipe` | Fallback narrative generation | chat, prompt, llm_anthropic, response_answers |

The backend (`pipeline.py`) has a 3-tier fallback: agent pipeline → simple query pipeline → bare Anthropic SDK. This ensures the app works whether or not RocketRide is running.

### What's Missing

1. **No native RocketRide agent** — We use `agent_crewai`, which has no memory support and doesn't leverage RocketRide's wave-planning architecture (parallel tool calls, keyed memory, on-demand schema loading).

2. **No structured extraction** — The ingest pipeline asks the LLM to produce raw JSON. This is fragile — JSON parsing fails ~10-15% of the time due to markdown fences, trailing commas, or truncated output.

3. **No live enrichment tools** — The agent can only query Neo4j via MCP. It can't call external APIs (VirusTotal, HIBP, NVD) during investigation, so all enrichment data is either pre-imported or simulated.

---

## Feature 1: Switch to `agent_rocketride` (Native Wave-Planner)

### Why This Matters

`agent_crewai` is a wrapper around CrewAI's single-agent model. It works, but:

| Aspect | agent_crewai | agent_rocketride |
|--------|-------------|-----------------|
| Tool execution | Sequential | **Parallel (wave-based)** |
| Memory | Not supported | **Required** (keyed, token-efficient) |
| Tool schema loading | Loads all upfront | **On-demand** (saves tokens) |
| Sub-agent support | No | **Yes** (hierarchical orchestration) |
| Architecture | 3rd-party wrapper | **Native** to RocketRide engine |

The key advantage is **memory + parallel tools**. Right now, each investigation starts from scratch — the agent has zero context about previous queries. With `memory_internal`, the agent accumulates knowledge across investigations:

- "I've seen this IP linked to APT41 before"
- "This CVE was flagged in 3 previous investigations"
- "The ua-parser-js → ART-BY-FAISAL chain is a confirmed threat"

This maps directly to Cerberus's "self-improvement loop" — the spec's premise that the agent should "learn from analyst feedback to get faster with every investigation."

### Pipeline Change

**Before** (cerberus-threat-agent.pipe):
```
chat → agent_crewai → [control] → llm_anthropic
                    → [control] → mcp_client (neo4j-mcp)
         ↓
    response_answers
```

**After**:
```
chat → agent_rocketride → [control] → llm_anthropic
                        → [control] → memory_internal
                        → [control] → mcp_client (neo4j-mcp)
         ↓
    response_answers
```

### New Components

| Component | Role | Why |
|-----------|------|-----|
| `agent_rocketride` | Wave-planning agent | Parallel tool calls, keyed memory, better token efficiency |
| `memory_internal` | Persistent investigation memory | Agent remembers findings across sessions |

### Backend Impact

Minimal. `pipeline.py` doesn't care which agent type runs inside the pipeline — it sends a `Question` via `chat()` and reads the `answers`. The change is entirely within the `.pipe` file.

The one behavioral difference: `agent_rocketride` requires `max_waves` config (default 10). Each wave is a round of parallel tool calls. For threat investigation, 10 waves (explore → enrich → cross-reference → synthesize) is reasonable.

### Risk

Low. The 3-tier fallback (`pipeline.py`) already handles pipeline failures — if the new agent pipeline errors, it falls back to `cerberus-query.pipe` → then bare Anthropic. We can A/B test by changing the pipeline file without touching backend code.

---

## Feature 2: Add `extract_data` to Ingest Pipeline

### Why This Matters

The current ingest pipeline asks the LLM to return raw JSON:

```
webhook → parse → ocr → prompt → llm_anthropic → response_answers
```

The `prompt` node instructs the LLM: "Return a JSON array of entities with type, value, threat_domain, confidence, and context." This fails in several ways:

1. **LLM wraps JSON in markdown fences** (`\`\`\`json ... \`\`\``) — requires stripping
2. **Trailing commas / truncated output** — breaks `json.loads()`
3. **No schema validation** — LLM may omit required fields or add unexpected ones
4. **No separation of concerns** — one LLM call does both analysis AND formatting

`extract_data` is a RocketRide component specifically designed for this:

| Aspect | Current (prompt + LLM) | extract_data |
|--------|----------------------|--------------|
| Output format | Raw text (hope it's JSON) | **Structured table** with defined columns |
| Schema enforcement | None | **LLM-guided extraction** with field definitions |
| Error handling | Manual JSON parsing | **Built-in** — always returns structured data |
| Separation of concerns | LLM does analysis + formatting | LLM does extraction, component handles formatting |

### Pipeline Change

**Before** (cerberus-ingest.pipe):
```
webhook → parse → ocr → prompt → llm_anthropic → response_answers
```

**After**:
```
webhook → parse → ocr → prompt → llm_anthropic → extract_data → response_answers
                                                       ↑
                                                  [control] llm_anthropic
```

The `extract_data` component takes the LLM's text output and produces structured `answers`/`documents` with defined fields. It uses its own LLM invocation for the extraction step, so we wire a second `llm_anthropic` (or share the same one).

### Backend Impact

`routes/ingest.py` currently does manual JSON parsing with fence-stripping:

```python
clean = raw.strip()
if clean.startswith("```"):
    clean = "\n".join(clean.split("\n")[1:])
if clean.endswith("```"):
    clean = "\n".join(clean.split("\n")[:-1])
entities = json.loads(clean.strip())
```

With `extract_data`, the response will already be structured — this parsing workaround can be simplified or removed.

### Risk

Low. The ingest pipeline is independent from the main query flow. If `extract_data` produces unexpected output format, we still have the raw LLM text as fallback.

---

## Feature 3: Add `tool_http_request` for Live Enrichment

### Why This Matters

This is the biggest functional gap. Currently:

- **VT/HIBP/NVD enrichment is simulated** — `routes/enrichment.py` returns hardcoded data when real APIs are unavailable
- **Agent can only see Neo4j data** — it has MCP tools for graph queries but can't reach external threat intel sources
- **Enrichment is manual** — the user clicks "Enrich" in the narrative panel, which calls the backend API. The agent never enriches on its own

With `tool_http_request`, the agent can call external APIs *during* its investigation:

```
Agent thinking: "I found IP 203.0.113.42 linked to APT41. Let me check VirusTotal
for recent detections and HIBP for breach exposure..."

→ Wave 1: mcp_client (Neo4j query) + tool_http_request (VT API)
→ Wave 2: mcp_client (follow-up query) + tool_http_request (HIBP API)
→ Wave 3: Synthesize all findings into narrative
```

This is where `agent_rocketride`'s parallel waves shine — it can query Neo4j AND external APIs simultaneously in the same wave.

### Pipeline Change

**After** (with all 3 features combined):
```
chat → agent_rocketride → [control] → llm_anthropic
                        → [control] → memory_internal
                        → [control] → mcp_client (neo4j-mcp)
                        → [control] → tool_http_request
         ↓
    response_answers
```

### Agent Instructions Update

The agent's instructions need to include the enrichment tools available:

```
You have access to HTTP request tools. Use them to enrich your investigation:
- VirusTotal API: GET https://www.virustotal.com/api/v3/ip_addresses/{ip}
- NVD API: GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}
- HIBP breach check: GET https://haveibeenpwned.com/api/v3/breachedaccount/{email}

Always check external sources when you find IPs, CVEs, or domains in the graph.
Combine Neo4j graph context with external intelligence for your narrative.
```

### Backend Impact

Minimal pipeline.py changes. The agent's response format stays the same (narrative text). The enrichment happens inside the pipeline — the backend doesn't need to orchestrate it.

However, we should:
1. Add API keys to `.env` (VT_API_KEY, etc.)
2. Update the agent instructions to reference the available tools
3. Consider rate limiting (VT free tier: 4 requests/minute)

### Risk

Medium. External API calls add latency and potential failures. Mitigations:
- Agent should be instructed to proceed without enrichment if APIs timeout
- Wave-based execution means API failures don't block graph queries
- The 3-tier fallback still catches total pipeline failures

---

## Implementation Order

| # | Feature | Effort | Dependencies |
|---|---------|--------|-------------|
| 1 | `agent_rocketride` | Small | None — .pipe file change + instructions |
| 2 | `extract_data` in ingest | Small | None — independent pipeline |
| 3 | `tool_http_request` enrichment | Medium | Feature 1 (benefits from parallel waves) |

Feature 1 should go first because Feature 3 benefits from `agent_rocketride`'s parallel wave execution. Feature 2 is independent and can be done in any order.

---

## Success Criteria

- [ ] Agent pipeline uses `agent_rocketride` with `memory_internal`
- [ ] Agent remembers findings across investigations (test: investigate same entity twice)
- [ ] Ingest pipeline produces structured output from `extract_data` (no manual JSON parsing)
- [ ] Agent calls at least one external API (VT or NVD) during investigation
- [ ] All existing fallback chains still work when RocketRide is unavailable
- [ ] No regression in narrative quality or response time
