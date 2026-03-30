# From Shoehorned SDK to Autonomous Agent: Rearchitecting the RocketRide Integration

When I started this session, the RocketRide integration in Cerberus was technically functional but architecturally hollow. The backend did all the heavy lifting — querying Neo4j, assembling traversal data, formatting it as context — then shipped that pre-digested blob to RocketRide, which ran it through a `prompt → LLM → response` pipeline. RocketRide was, in the words of my teammate, "shoehorned in." It was a glorified API wrapper around an Anthropic call.

By the end of this session, RocketRide became the AI orchestration brain: a CrewAI agent that autonomously explores the Neo4j threat graph via MCP tools, reasons about cross-domain attack chains, and generates threat narratives — all without the backend needing to pre-fetch anything.

## The Starting Point

Cerberus is a hackathon project (HackWithBay 2.0) that traces cross-domain attack chains in a Neo4j graph database. An npm package with a known vulnerability connects to a threat actor, who operates malicious IPs that appear in fraud signals — Cerberus finds and explains those connections.

The RocketRide integration (written by my teammate) looked like this:

```python
# Old flow in backend/rocketride.py
question = Question()
question.addContext(
    f"Entity to investigate: {entity} (type: {entity_type})\n\n"
    f"Graph traversal result:\n{json.dumps(traversal, indent=2)}"
)
question.addQuestion("Analyze the threat entity... Generate a narrative.")
response = await client.chat(token=token, question=question)
```

The pipeline definition (`cerberus-query.pipe`) was equally simple:

```
chat → prompt (system instructions) → llm_anthropic → response_answers
```

The backend called `db.traverse()` to query Neo4j, assembled the full traversal data as JSON, and stuffed it into a `Question` object as context. RocketRide's pipeline was just a prompt template feeding an LLM. You could replace it with a single `anthropic.messages.create()` call and nobody would notice.

The hackathon sponsor (RocketRide) had hinted that webhooks and deeper integration were possible. My teammate felt the integration was forced. I needed to fix this before the demo.

## Step 1: Understanding What RocketRide Actually Offers

I started by reading 30 pages of crawled RocketRide documentation. Three docs changed everything:

1. **MCP Client node** (`mcp_client`) — Connects pipelines to external MCP servers and exposes their tools to agent nodes. Supports stdio, SSE, and streamable-HTTP transports.

2. **Agent nodes** (`agent_crewai`, `agent_langchain`) — Run multi-step reasoning loops inside pipelines. Agents can call LLMs and tools via invoke connections.

3. **Nodes Overview** — 68 nodes across 14 categories. The Agentic category includes MCP Client, CrewAI, and LangChain nodes.

The lightbulb moment: RocketRide has an MCP Client node, and we already have `neo4j-mcp` running as an MCP server. If I wire them together, the RocketRide agent can query Neo4j directly — no pre-fetching needed.

```
# The architecture that makes RocketRide a natural fit:
chat → agent_crewai → [invoke] → mcp_client (← connects to neo4j-mcp)
                    → [invoke] → llm_anthropic (← Claude for reasoning)
         ↓
    response_answers
```

## Step 2: Decoding the Pipeline Wiring Syntax

RocketRide pipelines are JSON files (`.pipe` format) with a `components` array. Each component has an `id`, `provider`, `config`, and connection declarations. The tricky part was understanding the connection types:

**Input lanes** — Standard data flow. A node declares which upstream node feeds it:
```json
"input": [{ "lane": "questions", "from": "chat_1" }]
```

**Control connections** — "Invoke" wiring for agent → tool/LLM relationships. The tool or LLM node declares that it's controlled by an agent, with a `classType` indicating the role:
```json
// LLM node controlled by agent as its reasoning engine
"control": [{ "classType": "llm", "from": "agent_1" }]

// MCP Client node controlled by agent as a tool provider
"control": [{ "classType": "tool", "from": "agent_1" }]
```

This was unintuitive at first — the control connection goes on the *tool/LLM* side pointing back to the agent, not from the agent outward. The docs only showed the LLM example explicitly; I inferred `classType: "tool"` for MCP Client from the node's description as a "tool provider."

## Step 3: Building the Agent Pipeline

The new pipeline (`cerberus-threat-agent.pipe`) has five components:

```json
{
  "id": "agent_1",
  "provider": "agent_crewai",
  "config": {
    "instructions": [
      "You are a senior threat intelligence analyst with access to a Neo4j graph database...\n\n## Tools Available\n- neo4j.get-neo4j-schema\n- neo4j.read-neo4j-cypher\n\n## Investigation Procedure\n1. Get the graph schema...\n2. Search for the target entity...\n..."
    ]
  },
  "input": [{ "lane": "questions", "from": "chat_1" }]
}
```

The agent's instructions are the key differentiator. Instead of "format this data into a narrative" (old approach), the instructions say "use your MCP tools to explore the graph, follow attack chains, and generate a narrative." The agent decides what Cypher queries to run, which paths to follow, and how deep to go.

The MCP Client connects to neo4j-mcp using streamable-HTTP transport:

```json
{
  "id": "mcp_client_1",
  "provider": "mcp_client",
  "config": {
    "serverName": "neo4j",
    "transport": "streamable-http",
    "endpoint": "${NEO4J_MCP_ENDPOINT}"
  },
  "control": [{ "classType": "tool", "from": "agent_1" }]
}
```

The `${NEO4J_MCP_ENDPOINT}` variable is interpolated at pipeline startup. It points to wherever neo4j-mcp is running (`http://localhost:8787/mcp` locally, or a tunneled URL for cloud RocketRide).

## Step 4: Rewriting the Backend Integration

The backend changes were surprisingly minimal because the module already had good fallback architecture. The main changes:

**Before — pre-fetched traversal data sent via `Question` object:**
```python
question = Question()
question.addContext(f"Graph traversal result:\n{json.dumps(traversal, indent=2)}")
response = await client.chat(token=token, question=question)
```

**After — just the entity name sent via `send()`:**
```python
if _active_pipeline == "agent":
    message = (
        f"Investigate the threat entity '{entity}' (type: {entity_type}). "
        f"Use your Neo4j MCP tools to explore the graph."
    )
else:
    message = f"Entity: {entity}\n\nTraversal:\n{json.dumps(traversal)}"

response = await client.send(token, message)
```

The response parsing also needed to handle two formats — `send()` returns a different structure than `chat()`:

```python
def _extract_narrative(response: dict[str, Any]) -> str:
    # SDK chat() format: {"answers": ["text..."]}
    answers = response.get("answers", [])
    if answers:
        return answers[0]

    # SDK send() format: {"data": {"objects": {"<uuid>": {"text": "..."}}}}
    data = response.get("data", {})
    for obj in data.get("objects", {}).values():
        if isinstance(obj, dict) and "text" in obj:
            return obj["text"]
```

The fallback chain is now three levels deep:
1. **Agent pipeline** (MCP Client + CrewAI) — the showcase
2. **Query pipeline** (prompt + LLM) — if agent pipeline fails to load
3. **Direct Anthropic** (llm.py) — if RocketRide is completely unavailable

## The Connectivity Question

One challenge I anticipated but didn't fully resolve: where does the RocketRide engine run relative to neo4j-mcp?

| Scenario | Neo4j MCP Endpoint | Works? |
|----------|-------------------|--------|
| Both local | `http://localhost:8787/mcp` | ✅ |
| RocketRide in Docker, neo4j-mcp in Docker | `http://neo4j-mcp:8787/mcp` | ✅ |
| RocketRide cloud, neo4j-mcp local | `http://localhost:8787/mcp` | ❌ (cloud can't reach localhost) |
| RocketRide cloud, neo4j-mcp tunneled | `https://xxx.ngrok.io/mcp` | ✅ |

For the hackathon demo, we'll either run RocketRide locally (default `ROCKETRIDE_URI=http://localhost:5565`) or tunnel neo4j-mcp via ngrok. I made `NEO4J_MCP_ENDPOINT` a configurable env var to handle both cases, and added it to both `docker-compose.yml` and `render.yaml`.

## What Changed (Diff Summary)

| File | Change |
|------|--------|
| `pipelines/cerberus-threat-agent.pipe` | **New** — CrewAI agent + MCP Client + Anthropic LLM |
| `backend/rocketride.py` | **Rewritten** — `send()` instead of `chat()`, pipeline fallback chain, dual response format handling |
| `docker-compose.yml` | Added `NEO4J_MCP_ENDPOINT` env var |
| `render.yaml` | Added `NEO4J_MCP_ENDPOINT` for cloud deployments |
| `SKILL.md` | Updated architecture, pipeline definitions, integration docs |

## What I Got Right

- **Reading the docs first.** Spending time on the 30 crawled pages before writing any code meant I understood the MCP Client node's transport options, control connection syntax, and agent wiring before touching files.
- **Keeping the fallback chain.** Agent → Query → Direct LLM means the demo works even if MCP connectivity fails. No single point of failure.
- **Minimal backend changes.** The existing `stream_via_rocketride_or_fallback()` interface didn't change — only the internals. The query route required zero modifications.

## What I Got Wrong (or Didn't Test Yet)

- **`classType: "tool"` is inferred, not documented.** The docs explicitly show `classType: "llm"` for LLM connections but never show the corresponding type for tool providers. I used `"tool"` — logical, but it might need to be `"agentic"` or `"invoke"` or something else. This will only surface when we actually run the pipeline against a RocketRide engine.
- **streamable-http vs sse transport.** neo4j-mcp uses `--neo4j-transport-mode http`. I assumed this maps to MCP's streamable-http transport, but it might expect the older SSE transport. Needs runtime testing.
- **No end-to-end test.** The pipeline is syntactically valid JSON but hasn't been validated against a running RocketRide engine. The `validate()` API method exists for this — should have used it.

## What's Next

1. **Runtime validation** — Start the RocketRide engine, call `client.validate()` on the pipeline, fix any wiring issues.
2. **Transport testing** — Verify whether neo4j-mcp speaks streamable-http or SSE, adjust the MCP Client config accordingly.
3. **Demo rehearsal** — Run the full flow: query `ua-parser-js` → CrewAI agent explores the graph → narrative streams to frontend.
4. **Webhook variant** — The sponsor specifically mentioned webhooks. A webhook-source version of the pipeline (replacing `chat` with `webhook`) would let external services trigger investigations directly.

---

The lesson: sponsor tools at hackathons aren't just checkboxes on a judging rubric. When you read the docs deep enough, sometimes the tool solves a problem you were already solving badly. RocketRide went from "LLM wrapper we have to use" to "the agent that actually explores our graph" — and all it took was discovering the MCP Client node existed.
