# From Static Graph to Explainable Investigation: Node Inspection + Route Reasoning

The product audit found two gaps that hurt demo credibility: users could not inspect graph nodes, and the pipeline did not show what the ROUTE stage actually decided. This session fixed both gaps in a way that kept the existing architecture intact: backend emits route reasoning over SSE, frontend stores it in investigation state, and UI renders it in the pipeline bar while graph clicks open a node detail sidebar.

## The Starting Point

Cerberus already had the core threat workflow working end to end:
- React frontend with force-directed graph rendering and SSE narrative streaming
- FastAPI backend streaming pipeline stage events
- Neo4j traversal logic with entity-type-specific query behavior

The issue was explainability.
- The graph was visual only, with no drill-down interaction.
- The ROUTE stage lit up, but users could not see the selected traversal strategy.

That made the system look less "thoughtful" than it actually was.

## Step 1: Make Graph Nodes Inspectable

Goal: let analysts click a node and inspect properties without leaving the graph context.

Approach: add selected-node state in the graph panel, wire `onNodeClick`, and render a contextual overlay panel in the top-right corner.

Interesting implementation excerpt from [frontend/src/components/panels/GraphPanel.tsx](frontend/src/components/panels/GraphPanel.tsx):

```tsx
const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

<ForceGraph2D
  onNodeClick={(node: any) => setSelectedNode(node as GraphNode)}
  onBackgroundClick={() => setSelectedNode(null)}
/>

{selectedNode && (
  <div className="absolute top-4 right-4 w-64 glass-panel rounded-lg p-4 z-20">
    {/* node type, id, label, and dynamic properties */}
  </div>
)}
```

I also added a reset effect so stale node selections do not persist when a new investigation starts.

## Step 2: Surface Route Decisions from the Backend

Goal: make the ROUTE stage explain what strategy was chosen and why.

Approach: emit a new SSE payload right after the `route` stage event. I introduced `_route_info(entity_type)` in the query route, returning a strategy label, path sequence, and rationale.

Interesting implementation excerpt from [backend/routes/query.py](backend/routes/query.py):

```python
def _route_info(entity_type: str) -> dict[str, object]:
    return {
        "strategy": "Software -> Infrastructure -> Financial",
        "path": ["Package", "Account", "IP", "ThreatActor", "FraudSignal"],
        "reason": "Compromised packages often pivot through publisher accounts and shared infrastructure.",
    }

yield f"data: {json.dumps({'stage': 'route'})}\n\n"
yield f"data: {json.dumps({'route_info': _route_info(entity_type)})}\n\n"
```

This keeps the event ordering intuitive: stage marker first, decision context immediately after.

## Step 3: Carry Route Metadata Through State and UI

Goal: propagate route metadata into the existing state machine and render it in the pipeline bar.

Approach:
- Add `RouteInfo` and `routeInfo?` to shared frontend types
- Parse `route_info` chunks inside the SSE hook
- Pass route info into pipeline stages and render a compact summary row once route is reached

Interesting implementation excerpt from [frontend/src/hooks/useInvestigation.ts](frontend/src/hooks/useInvestigation.ts):

```ts
} else if ("route_info" in chunk) {
  setState((prev) => ({
    ...prev,
    routeInfo: chunk.route_info,
  }));
}
```

Interesting implementation excerpt from [frontend/src/components/panels/PipelineStages.tsx](frontend/src/components/panels/PipelineStages.tsx):

```tsx
const showRouteInfo = Boolean(routeInfo) && currentIdx >= routeIdx;

{showRouteInfo && routeInfo && (
  <div className="rounded-md border border-primary/25 bg-primary/5 px-3 py-2">
    <span>{routeInfo.strategy}</span>
    <span>{routeInfo.path.join(" -> ")}</span>
    <span>{routeInfo.reason}</span>
  </div>
)}
```

## The Gotcha: Unexpected Dirty Working Tree

Symptom: before committing, unrelated modified files were present in the working tree.

Risk: accidentally bundling unrelated changes into this feature commit.

Fix: pause, ask user for commit scope, then stage only feature-specific files.

This preserved a clean history and prevented accidental regressions from unrelated work.

## Validation and Outcome

Validation performed:
- Type/error checks on all edited files via IDE diagnostics
- Frontend production build (`npm run build`) succeeded
- Commit and push to `main` completed

Commit:
- `91e82d2` — Add graph node sidebar and route decision visibility

User-visible result:
- Clicking graph nodes now opens a detail sidebar with node properties
- ROUTE stage now displays strategy, path, and rationale during investigations

## What's Next

- Connect route rationale to live traversal evidence (for example, include actual relationship counts from the current traversal)
- Add compact mobile behavior for the node sidebar (sheet/drawer pattern)
- Add tests for `route_info` SSE handling in frontend hook and backend stream route

Explainability compounds trust: once users can see what the agent chose and inspect the evidence graph directly, the system feels far more "thoughtful" than a black box.
