# Building Five Features in One Session: NLP, STIX, Comparison, Annotations, and Watchlists

What started as "implement the Phase 2 feature plan" became a rapid-fire session of building five full-stack features for Cerberus — a threat intelligence platform backed by Neo4j, FastAPI, and React. Each feature touched both backend and frontend, required careful integration with existing code, and had to pass TypeScript strict mode and Python compile checks before shipping.

Here's how each one went, what worked, what surprised me, and what I'd do differently.

## The Plan

Five features, ranked by effort:

1. **NLP Query Toggle** (Low) — Natural language input that extracts entities via regex NER
2. **STIX Export from Memory** (Low) — Bulk export confirmed entities as a STIX 2.1 bundle
3. **Entity Comparison** (Low) — Side-by-side graph diffing with overlap scores
4. **Collaborative Annotations** (Medium) — Persistent notes on graph nodes stored in Neo4j
5. **Watchlist Alerts** (Medium) — Watch entities for new connections with periodic checking

The approach: implement SKILL.md user stories first, then build each feature end-to-end (backend → API client → UI → type-check → commit → push) before moving to the next. No branching — everything on `main` with descriptive commits.

## Feature 1: NLP Query Toggle

### The Problem

Cerberus's QueryPanel requires users to type exact entity identifiers like `CVE-2021-44228` or `203.0.113.42`. The backend already had a `POST /api/demo/natural` endpoint that extracts entities from natural language using regex patterns, but it wasn't wired to the frontend.

### The Implementation

The backend endpoint was already solid — it uses cascading regex patterns to extract CVEs, IPs, domains, threat actors, and package names from free text. I just needed to:

1. Add `parseNaturalLanguage()` to `api.ts`
2. Add NLP mode state to QueryPanel
3. Route the submit handler through the NLP endpoint when toggled

The toggle UI is a small pill button next to the search label:

```tsx
<button
  type="button"
  onClick={() => { setNlpMode(!nlpMode); setNlpError(null); }}
  className={cn(
    "flex items-center gap-1 px-2 py-0.5 rounded-full text-[9px] font-mono",
    nlpMode
      ? "bg-primary/15 text-primary border border-primary/30"
      : "bg-surface-raised text-muted-foreground border border-border/50"
  )}
>
  <MessageSquare className="h-2.5 w-2.5" />
  NLP
</button>
```

The submit handler branches based on mode:

```tsx
const handleSubmit = async (e: React.FormEvent) => {
  e.preventDefault();
  if (!query.trim()) return;

  if (nlpMode) {
    setNlpParsing(true);
    try {
      const result = await parseNaturalLanguage(query.trim());
      const primary = result.primary_entity;
      if (primary) {
        onInvestigate(primary.value, primary.type as EntityType);
      }
    } catch (err: any) {
      setNlpError(err.message || "Failed to parse query");
    } finally {
      setNlpParsing(false);
    }
  } else {
    onInvestigate(detected.extracted, detected.type);
  }
};
```

### What Worked

The key insight: **don't hide the existing auto-detect mode**. When NLP is off, the original behavior (regex-based entity detection with alias resolution) works exactly as before. The toggle is additive, not destructive.

The detected entity indicator also hides in NLP mode (via `!nlpMode && query.trim() && (...)`), since the NLP backend does its own detection.

### Gotcha

The `handleSubmit` had to become `async` because the NLP endpoint is a fetch call. The original was synchronous. This is an easy TypeScript trap — React's `onSubmit` accepts both sync and async handlers, but forgetting `await` on the fetch would silently swallow errors.

## Feature 2: STIX Export from Memory

### The Problem

Cerberus already had STIX export for individual entities (button on the NarrativePanel), but no way to export all confirmed entities from the Memory view at once. Security analysts need bulk export for feeding into MISP, OpenCTI, or other TAXII-compatible platforms.

### The Implementation

The approach: fetch individual STIX bundles for each confirmed node, then merge and deduplicate by STIX object ID. The tricky part is handling potentially many entities without hammering the backend:

```tsx
const handleStixExport = useCallback(async () => {
  const typeMap: Record<string, string> = {
    Package: "package", CVE: "cve", IP: "ip",
    Domain: "domain", ThreatActor: "threatactor", FraudSignal: "fraudsignal",
  };
  const exportable = graphData.nodes.filter(
    (n) => n.confirmed && typeMap[n.type]
  );
  if (exportable.length === 0) return;

  // Fetch in batches of 5 to avoid overwhelming the backend
  const allObjects: Record<string, unknown>[] = [];
  for (let i = 0; i < exportable.length; i += 5) {
    const batch = exportable.slice(i, i + 5);
    const results = await Promise.all(
      batch.map((n) =>
        fetchStixBundle({ entity: n.label, type: typeMap[n.type] })
          .then((b) => b.objects ?? [])
          .catch(() => [])  // Graceful degradation per entity
      )
    );
    results.forEach((objs) => allObjects.push(...objs));
  }

  // Deduplicate by STIX id
  const seen = new Set<string>();
  const deduped = allObjects.filter((obj: any) => {
    if (seen.has(obj.id)) return false;
    seen.add(obj.id);
    return true;
  });

  const merged = {
    type: "bundle",
    id: `bundle--cerberus-memory-${Date.now()}`,
    spec_version: "2.1",
    objects: deduped,
  };

  // Trigger browser download
  const blob = new Blob([JSON.stringify(merged, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `cerberus-memory-stix-${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
}, [graphData.nodes]);
```

### Design Decision: Client-Side Merge vs. Backend Endpoint

I chose client-side merging over creating a new backend endpoint. Why:

- The existing `/api/stix/bundle` endpoint works per-entity and is well-tested
- A new "merge all" endpoint would duplicate the per-entity logic
- Client-side batching with `Promise.all` is fast enough for typical watchlists (5-20 entities)
- Each `.catch(() => [])` means a single entity failure doesn't kill the whole export

The tradeoff: if someone has 100+ confirmed entities, this gets slow. A dedicated backend endpoint with a single Cypher query would be faster. But for a hackathon project, the pragmatic choice won.

## Feature 3: Entity Comparison (ComparePanel)

### The Problem

Analysts investigating two seemingly unrelated threats often want to know: "Do these share infrastructure?" The backend's `POST /api/diff/compare` endpoint already does graph-level set operations, but there was no frontend UI.

### The Implementation

A new panel added to ViewNav as a 5th tab. The ComparePanel has two entity input rows (text + type selector), a compare button, and a results area showing:

- **Overlap score bar** — 0-100% with color coding (green > 30%, yellow > 5%, red ≤ 5%)
- **Stats grid** — Shared count, Only A count, Only B count
- **Node lists** — Shared infrastructure, exclusive to A, exclusive to B

The ViewNav type needed updating:

```tsx
// Before
export type CenterView = "graph" | "geomap" | "memory" | "mitre";

// After
export type CenterView = "graph" | "geomap" | "memory" | "mitre" | "compare";
```

The panel is lazy-loaded like the others:

```tsx
const ComparePanel = lazy(() =>
  import("./components/panels/ComparePanel").then(m => ({ default: m.ComparePanel }))
);
```

### What I'd Improve

The comparison currently shows flat node lists. A visual diff — like a Venn diagram graph where shared nodes appear in the center and exclusive nodes on each side — would be far more compelling. That's a Phase 3 feature.

## Feature 4: Collaborative Annotations

### The Problem

Investigation graphs are ephemeral — analysts discover insights but have no way to leave notes for themselves or others. When a second analyst investigates the same entity, they start from scratch.

### The Full Stack

This was the first feature requiring a new backend route file:

**Backend (`routes/annotations.py`):**

```python
@router.post("", status_code=201)
async def create_annotation(req: CreateAnnotation):
    query = """
    MATCH (e)
    WHERE e.name = $entity OR e.id = $entity
    WITH e LIMIT 1
    CREATE (a:Annotation {
        id: $id, entity: $entity, text: $text,
        author: $author, created_at: $created_at
    })
    CREATE (a)-[:ANNOTATES]->(e)
    RETURN a.id AS id
    """
    records = db.run_query(query, { ... })
```

The Cypher uses `MATCH (e) WHERE e.name = $entity OR e.id = $entity` to find the target node by either its `name` property or internal ID. This is important because different node types use different property names for their primary identifier.

**Neo4j client (`run_query` helper):**

I needed a generic query execution function since all existing functions were specialized. Added:

```python
def run_query(query: str, params: dict | None = None) -> list[dict]:
    with _get_driver().session() as s:
        result = s.run(query, params or {})
        return [r.data() for r in result]
```

This is intentionally simple — no transaction wrapping or retry logic. For a hackathon, the explicit simplicity is a feature, not a bug.

**Frontend (GraphPanel node sidebar):**

Annotations appear below the node properties table in the click-to-inspect sidebar. The UI auto-fetches when the selected node changes:

```tsx
useEffect(() => {
  if (!selectedNode) { setAnnotations([]); return; }
  const entity = selectedNode.label || selectedNode.id;
  listAnnotations(entity).then(setAnnotations).catch(() => setAnnotations([]));
}, [selectedNode?.id]);
```

Each annotation shows text, author, date, and a hover-to-reveal delete button:

```tsx
<div key={ann.id} className="group p-1.5 rounded bg-surface-raised/40">
  <p className="text-[10px] text-foreground/80">{ann.text}</p>
  <div className="flex items-center justify-between mt-1">
    <span className="text-[8px] text-muted-foreground/40">
      {ann.author} · {new Date(ann.created_at).toLocaleDateString()}
    </span>
    <button
      onClick={() => handleDeleteAnnotation(ann.id)}
      className="opacity-0 group-hover:opacity-100"
    >
      <Trash2 className="h-2.5 w-2.5" />
    </button>
  </div>
</div>
```

### Architectural Decision: Dedicated Nodes vs. Properties

I stored annotations as separate `(:Annotation)-[:ANNOTATES]->(entity)` nodes rather than as properties on existing nodes. Why:

- **Multiple annotations per node** — properties would require array manipulation in Cypher
- **Queryable metadata** — each annotation has its own author, timestamp, and UUID
- **Deletable independently** — DETACH DELETE on a single annotation node doesn't affect the entity
- **Future extensibility** — could add reactions, threading, or visibility controls

The tradeoff: more nodes in Neo4j. For a hackathon, this doesn't matter.

## Feature 5: Watchlist Alerts

### The Problem

Cerberus was reactive-only — analysts had to manually re-investigate entities to check for new connections. A "watch" feature turns it into a continuous monitoring platform.

### The Full Stack

**Backend (`routes/watchlist.py`):**

The watchlist uses `:Watchlist` nodes in Neo4j with `entity`, `entity_type`, `added_at`, and `last_checked` properties. The critical endpoint is `/check`:

```python
@router.get("/check")
async def check_watchlist():
    watched = db.run_query("""
        MATCH (w:Watchlist)
        RETURN w.entity AS entity, w.entity_type AS entity_type,
               w.last_checked AS last_checked
    """)

    alerts = []
    for w in watched:
        new_connections = db.run_query("""
            MATCH (e)-[r]-(neighbor)
            WHERE (e.name = $entity OR e.id = $entity)
              AND (r.created_at > $since OR r.confirmed_at > $since)
            RETURN count(r) AS new_count,
                   collect(DISTINCT labels(neighbor)[0])[..5] AS neighbor_types
        """, {"entity": w["entity"], "since": w["last_checked"]})

        if new_connections[0]["new_count"] > 0:
            alerts.append({ ... })

    # Update last_checked for all
    db.run_query("MATCH (w:Watchlist) SET w.last_checked = $now", {"now": now})
    return {"alerts": alerts}
```

**Frontend (Header bell icon):**

The Header component polls `/api/watchlist/check` every 30 seconds. When alerts exist, the bell icon bounces and shows a count badge. Clicking reveals a dropdown with entity names and new connection counts.

The "Watch Entity" button lives in the GraphPanel node sidebar, right below the header and above the node label. It provides instant feedback:

```tsx
const handleWatch = useCallback(async () => {
  if (!selectedNode) return;
  setWatchBusy(true);
  try {
    await addToWatchlist(selectedNode.label || selectedNode.id, eType);
    setWatchSuccess(selectedNode.label || selectedNode.id);
    setTimeout(() => setWatchSuccess(null), 2000);  // Flash green for 2s
  } catch (err) {
    console.error("Watch failed:", err);
  } finally {
    setWatchBusy(false);
  }
}, [selectedNode]);
```

### Performance Consideration

The `/check` endpoint runs a Cypher query per watched entity. With 50+ watched entities, this could be slow. A better approach would be a single Cypher query that UNWIND's the watched list:

```cypher
UNWIND $entities AS e
MATCH (node)-[r]-(neighbor)
WHERE (node.name = e.entity OR node.id = e.entity)
  AND r.created_at > e.last_checked
RETURN e.entity, count(r) AS new_count
```

For the hackathon, per-entity queries are fine. For production, batch it.

## What Went Right

1. **Feature-per-commit discipline** — Each feature was committed + pushed before starting the next. This meant any one feature could fail without blocking the others.

2. **Type-check before commit** — Running `npx tsc --noEmit` after every feature caught issues immediately. Zero type errors shipped.

3. **Reusing existing endpoints** — Three of five features (NLP, STIX export, comparison) wired up existing backend endpoints. Only annotations and watchlist needed new route files.

4. **Consistent backend patterns** — The `run_query()` helper made annotations and watchlist routes trivially simple. Every Cypher query followed the same `db.run_query(cypher, params)` pattern.

5. **Lazy loading by default** — ComparePanel was automatically lazy-loaded following the pattern established for other panels, so it didn't bloat the initial bundle.

## What I'd Do Differently

1. **Batch the watchlist check** — The per-entity Cypher loop won't scale. Should use UNWIND or a single traversal query.

2. **Add a dedicated comparison visualization** — The ComparePanel's flat node lists are functional but not visually compelling. A split graph view would be more impactful for demos.

3. **Test the annotation UX with real data** — The `MATCH (e) WHERE e.name = $entity OR e.id = $entity` pattern might match multiple nodes. Adding `WITH e LIMIT 1` helps, but a more specific match (by label + type) would be safer.

4. **WebSocket for watchlist** — Polling every 30s works but wastes bandwidth when nothing changes. A WebSocket push from the backend after enrichment runs would be more efficient.

## Summary

Five features, five commits, all type-safe, all Backend + frontend. The session produced:

| Feature | Backend | Frontend | Lines Changed |
|---------|---------|----------|---------------|
| NLP Toggle | (existing) | QueryPanel.tsx, api.ts | +79 |
| STIX Memory Export | (existing) | MemoryPanel.tsx | +78 |
| Entity Comparison | (existing) | ComparePanel.tsx, ViewNav.tsx, App.tsx, api.ts | +352 |
| Annotations | annotations.py, neo4j_client.py, main.py | GraphPanel.tsx, api.ts | +270 |
| Watchlist | watchlist.py, main.py | GraphPanel.tsx, Header.tsx, api.ts | +320 |

Total: ~1,100 lines across 12 files, 5 commits, 0 type errors.
