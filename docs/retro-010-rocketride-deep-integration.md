# From CrewAI Wrapper to Native Wave Agent: Deep RocketRide Integration

We had three RocketRide pipelines that technically worked, but barely scratched the surface of what the platform could do. The threat agent used `agent_crewai` — a thin wrapper around CrewAI's sequential agent — which meant no parallel tool calls, no memory across investigation waves, and no live enrichment. The ingest pipeline relied on an LLM to produce raw JSON text that we then parsed with fragile regex-and-fence-stripping code. This session replaced all of that with native RocketRide components.

## The Starting Point

Cerberus is a cross-domain threat intelligence platform built for HackWithBay 2.0. It uses Neo4j for graph storage, FastAPI for the backend, React for the frontend, and RocketRide as the AI orchestration layer. RocketRide connects to our neo4j-mcp server so the agent can autonomously explore the threat graph.

The pipeline architecture before this session:

```
cerberus-threat-agent.pipe (5 nodes):
  chat → agent_crewai → [invoke] → llm_anthropic + mcp_client → response_answers

cerberus-ingest.pipe (6 nodes):
  webhook → parse → ocr → prompt → llm_anthropic → response_answers
```

Three problems:

1. **`agent_crewai` has no memory** — every investigation starts from scratch. The agent can't remember that `APT41` was linked to 12 IPs from a previous query.
2. **No structured extraction** — the ingest pipeline asks an LLM to return JSON text, then we strip markdown fences and pray `json.loads()` works.
3. **No live enrichment** — the agent can only see what's in Neo4j. If a CVE lacks severity data, or an IP needs reputation scoring, the agent can't reach out.

## Step 1: Switching to agent_rocketride

RocketRide's native agent (`agent_rocketride`) is a wave-planning architecture. Instead of executing tools one at a time like CrewAI, it plans each step as a **wave** of parallel tool calls. It also requires a `memory_internal` node — a keyed store where the agent can `put`, `get`, `peek`, and `list` intermediate findings without bloating the LLM context window.

The swap was straightforward in the `.pipe` file — replace the provider and add a memory node:

```json
{
  "id": "agent_rocketride_1",
  "provider": "agent_rocketride",
  "config": {
    "agent_description": "Cerberus threat intelligence agent...",
    "instructions": ["..."],
    "max_waves": 10
  },
  "input": [{ "lane": "questions", "from": "chat_1" }]
}
```

The key structural difference: `agent_crewai` config had a flat `"parameters": {}` field, while `agent_rocketride` requires `"max_waves"` (integer, 1-50) and `"instructions"` (string array). No `parameters` key at all.

The memory node is minimal:

```json
{
  "id": "memory_internal_1",
  "provider": "memory_internal",
  "config": { "type": "memory_internal" },
  "control": [{ "classType": "memory", "from": "agent_rocketride_1" }]
}
```

**The gotcha I almost hit**: RocketRide's control plane rule is that the `control` array goes on the **controlled** node, not the controller. So the `memory_internal_1` node carries `"control": [{"from": "agent_rocketride_1"}]` — the memory is controlled *by* the agent. Same for LLM and tools. I'd read this in the docs but it's counterintuitive enough that I double-checked the existing mcp_client control before finalizing.

I also added a "Memory Usage" section to the agent's instructions:

```
## Memory Usage
Use your memory tools to store and recall important findings:
- Store key entities and their threat levels as you discover them
- Check memory for prior context on entities you encounter
- Build up a knowledge base across investigation waves
```

This is important because `agent_rocketride` has memory tools available by default (put/get/peek/list/clear), but the agent won't use them effectively unless instructed to.

## Step 2: Structured Extraction with extract_data

The ingest pipeline's original approach was "ask the LLM to return JSON, then parse it":

```python
# The old way — fragile
clean = raw.strip()
if clean.startswith("```"):
    clean = "\n".join(clean.split("\n")[1:])
if clean.endswith("```"):
    clean = "\n".join(clean.split("\n")[:-1])
entities = json.loads(clean.strip())
```

This worked most of the time, but LLMs love adding commentary before/after JSON, or using triple-backtick fences with language hints (`json` vs `JSON` vs no hint). Every edge case was another line of parsing code.

RocketRide's `extract_data` component solves this properly. It takes text input, uses its own LLM invoke for extraction, and outputs structured tabular data with typed columns:

```json
{
  "id": "extract_data_1",
  "provider": "extract_data",
  "config": {
    "profile": "default",
    "default": {
      "fields": [
        { "column": "type", "type": "text" },
        { "column": "value", "type": "text" },
        { "column": "threat_domain", "type": "text" },
        { "column": "confidence", "type": "text" },
        { "column": "context", "type": "text" }
      ]
    }
  },
  "input": [{ "lane": "text", "from": "llm_anthropic_1" }]
}
```

**Architecture decision**: I placed `extract_data` *after* the existing prompt+LLM combo, not as a replacement. The prompt still guides entity extraction with domain-specific instructions (what a Package vs CVE vs FraudSignal is), and `extract_data` ensures the output is properly structured. This means the pipeline has two LLM calls — the first for extraction reasoning, the second (inside extract_data) for structuring — but reliability trumps saving one cheap Haiku call.

The backend update was satisfying — I replaced two duplicate blocks of fence-stripping code with a single shared function:

```python
def _parse_extraction_response(response: dict) -> list[dict[str, Any]]:
    """Handle both structured extract_data output and legacy raw text."""
    data = response.get("entities", response.get("answers", []))

    # Structured output: already a list of dicts
    if isinstance(data, list) and data and isinstance(data[0], dict):
        return data

    # Legacy: raw text needs JSON parsing
    raw = data[0] if isinstance(data, list) and data else str(data) if data else "[]"
    try:
        clean = raw.strip()
        if clean.startswith("```"):
            clean = "\n".join(clean.split("\n")[1:])
        if clean.endswith("```"):
            clean = "\n".join(clean.split("\n")[:-1])
        return json.loads(clean.strip())
    except (json.JSONDecodeError, AttributeError):
        return []
```

The dual-format handling is deliberate — if the RocketRide engine is updated or the pipeline changes, the backend degrades gracefully to the old text parsing.

## Step 3: Live Enrichment with tool_http_request

The final piece: giving the agent the ability to call external APIs mid-investigation. RocketRide's `tool_http_request` is "curl for agents" — the agent provides method, URL, headers, and body, and the node enforces security guardrails.

The security design was the most important part. I restricted the tool to:
- **GET only** — the agent should read threat intel, not write to external services
- **URL whitelist** — regex patterns allowing only three trusted APIs:

```json
"urlWhitelist": [
  { "whitelistPattern": "^https://cveawg\\.mitre\\.org/api/" },
  { "whitelistPattern": "^https://api\\.abuseipdb\\.com/" },
  { "whitelistPattern": "^https://www\\.virustotal\\.com/api/" }
]
```

Without the whitelist, the agent could theoretically call any URL — including internal services, cloud metadata endpoints, or APIs we didn't intend to expose. The whitelist makes it a closed set.

The agent instructions got a new section explaining when to use HTTP enrichment:

```
## Live Enrichment via HTTP
Use HTTP enrichment when:
- A CVE is found in the graph but lacks severity/description details
- An IP or domain needs reputation/abuse scoring
- You want to cross-reference graph findings with live threat intel
```

## The Gotcha: extract_data's Control Plane

When I first wrote the `extract_data` node, I put the control array on the extract_data node itself:

```json
{
  "id": "extract_data_1",
  "control": [{ "classType": "llm", "from": "extract_data_1" }]  // WRONG!
}
```

This is a self-reference — `extract_data_1` invoking itself. The control should be on `llm_anthropic_2` (the LLM that extract_data invokes), with `from` pointing to `extract_data_1`:

```json
{
  "id": "llm_anthropic_2",
  "control": [{ "classType": "llm", "from": "extract_data_1" }]  // Correct
}
```

I caught this during review because I'd internalized the rule from Feature 1: "control goes on the controlled node." But it's an easy mistake, especially when you're thinking "extract_data needs an LLM" rather than "the LLM is controlled by extract_data."

## Final Architecture

```
cerberus-threat-agent.pipe (7 nodes):
  chat → agent_rocketride → [invoke] → llm_anthropic (Sonnet 4.6)
                           → [invoke] → memory_internal
                           → [invoke] → mcp_client (neo4j-mcp)
                           → [invoke] → tool_http_request (MITRE/AbuseIPDB/VT)
           ↓
      response_answers

cerberus-ingest.pipe (8 nodes):
  webhook → parse → ocr → prompt → llm_anthropic (Haiku) → extract_data → response
                                                                    ↑
                                                             llm_anthropic_2 (Haiku)
```

Three commits, three features, all docs updated in the same change sets.

## What's Next

- **Authentication headers for enrichment APIs**: AbuseIPDB and VirusTotal require API keys in headers. Right now the agent can hit the endpoints, but authenticated requests need env var injection — possibly via RocketRide's `${VAR}` syntax in the tool_http_request config.
- **extract_data field types**: I used `"text"` for all 5 columns. `confidence` could be an enum, `type` could be constrained. Worth experimenting with `extract_data`'s type validation to catch malformed extractions earlier.
- **Memory persistence across sessions**: `memory_internal` is run-scoped — it resets each pipeline invocation. For true cross-session memory, we'd need `memory_chroma` or similar persistent store.

---

The difference between "using a platform" and "leveraging a platform" is whether you use its native primitives. CrewAI inside RocketRide was duct tape; wave agents with memory and HTTP tools is the thing RocketRide was actually built for.
