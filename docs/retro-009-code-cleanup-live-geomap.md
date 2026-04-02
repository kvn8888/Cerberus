# From Demo Nodes to Live Data: Cleaning Up Cerberus for Hackathon Judging

We had maybe 24 hours until judges would look at the codebase. That changes your priorities fast.

## The Starting Point

Cerberus is a cross-domain threat intelligence platform — it takes an npm package, IP, or domain, traverses a Neo4j graph of threat actors, CVEs, and malicious infrastructure, and generates an AI-powered attack chain narrative. It was built in 8 hours at HackWithBay 2.0 and then polished for a few days post-hackathon.

The codebase had collected baggage: CSV import scripts that had already run, seed data files (some of which were gitignored anyway but still had README artifacts), a lighthouse report from one profiling session, and — critically — a geomap panel that looked great in demos but was showing completely fake data.

The geomap was the most embarrassing part. It had a `THREAT_NODES` array hardcoded with 10 entries:

```typescript
const THREAT_NODES: ThreatNode[] = [
  { id: "apt28", name: "APT-28 (Fancy Bear)", coordinates: [37.6, 55.8], ... },
  { id: "lazarus", name: "Lazarus Group", coordinates: [125.7, 39.0], ... },
  { id: "c2-eu", name: "C2 Server (NL)", type: "c2", coordinates: [4.9, 52.4], ... },
  // ...7 more static nodes
];
```

And a `THREAT_CONNECTIONS` array with 10 hardcoded edges. These rendered on every page load regardless of what was in Neo4j. We had real threat actor data, real malicious IPs with geo attributes — and none of it showed up on the map by default.

## Step 1: Kill the Dead Weight

The first thing was straightforward: delete files that served no purpose anymore.

**What went:** 7 import scripts (`import_cve.py`, `import_mitre.py`, `import_npm.py`, `import_synthetic.py`, `import_threats.py`, `run_all_imports.py`, `eval_improvement.py`), `seed_data/` directory (the large JSONs were already gitignored, only README was tracked), `lighthouse-report.report.html/json`, and `tests/test_import_scripts.py`.

**What stayed:** `scripts/constraints.cypher` (Neo4j schema reference you might actually need again) and `scripts/push_env_to_render.py` (utility that pushes .env to Render — you use this on every deploy).

The principle here is simple: **if code has already done its job and can't be run again in the current setup, delete it.** The import scripts assumed an empty database — our database already had ~1060 nodes and 4505 relationships. Running them again would be a no-op at best, corrupt data at worst.

## Step 2: Layout Fix — Stacking Stat Badges

A quick fix that was bothering me: the ACTIVE/APT/CRITICAL stat badges at the top of the geomap rendered horizontally and collided with the viewport navigation.

Before:
```tsx
<div className="flex items-center gap-2">
  <StatBadge ... />
  <StatBadge ... />
  <StatBadge ... />
</div>
```

After:
```tsx
<div className="flex flex-col items-end gap-1.5">
```

One class change, but it removed a visual collision that would have lost points with a design-aware judge.

## Step 3: Cap Technique Nodes at 5 Per Actor

This was a performance issue masquerading as a display issue. The MITRE ATT&CK dataset includes groups like Lazarus Group with 150+ documented techniques. When building the threat graph, every technique that an actor `USES` got added as a node. 150 technique nodes per actor made the force-directed graph unusable.

The fix was in `backend/neo4j_client.py`, in the technique enrichment block of `get_graph()`:

```python
# Track how many techniques we've emitted per actor
actor_tech_counts: dict[str, int] = {}

for record in result:
    actor = record["actor"]
    # Skip if we've already emitted 5 techniques for this actor
    if actor_tech_counts.get(actor, 0) >= 5:
        continue
    actor_tech_counts[actor] = actor_tech_counts.get(actor, 0) + 1
    # ... add technique node
```

Simple counter dict, continue to skip — no complex logic. The cap is arbitrary at 5 but it keeps graphs readable. A production system would surface the top-5 by relevance or severity.

## Step 4: The Main Event — Real Data on the Geomap

This was the most satisfying change. The geomap had been demo-only data since day one.

The existing `get_memory_geo()` function fetched geo-plottable points, but it was filtered to `ConfirmedThreat` nodes only — entities an analyst had explicitly confirmed through investigation. On a fresh load, nothing shows up.

I needed a function that returns *all* IPs and ThreatActors with geo data, no confirmation required:

```python
# backend/neo4j_client.py
def get_all_geo() -> list[dict[str, Any]]:
    """Return geo-plottable points for ALL known IPs and ThreatActors."""
    points = []
    seen_ips: set[str] = set()

    with _get_driver().session() as s:
        # All IPs with a geo (country code) property
        for record in s.run("""
            MATCH (ip:IP)
            WHERE ip.geo IS NOT NULL AND ip.address IS NOT NULL
            OPTIONAL MATCH (ta:ThreatActor)-[:OPERATES]->(ip)
            RETURN ip.address AS ip, ip.geo AS geo,
                   collect(DISTINCT ta.name) AS actors
            LIMIT 100
        """):
            geo = record["geo"]
            if geo not in _COUNTRY_COORDS:
                continue  # Skip if we don't have coords for this country
            addr = record["ip"]
            if addr in seen_ips:
                continue
            seen_ips.add(addr)
            lat, lon = _COUNTRY_COORDS[geo]
            points.append({ "ip": addr, "geo": geo, "lat": lat, "lon": lon,
                           "actors": [a for a in record["actors"] if a] })

        # ThreatActors with country_code (actor-only points)
        for record in s.run("""
            MATCH (ta:ThreatActor)
            WHERE ta.country_code IS NOT NULL
            RETURN ta.name AS actor, ta.country_code AS geo
            LIMIT 40
        """): ...
```

Key design decisions:
- **LIMIT 100 / 40** — The geomap is a visual overview, not a data table. 140 points total is plenty; more would clutter the SVG.
- **`_COUNTRY_COORDS` lookup** — The geo field in Neo4j stores ISO alpha-2 country codes (`"RU"`, `"CN"`, `"KP"`). The coords dict maps those to lat/lon. Any unknown country code is silently skipped.
- **`seen_ips`** — IPs can appear multiple times in the result (different actors operating the same IP). Dedup server-side.

The frontend side involved three parts:

1. **Delete 110 lines** from `ThreatMap.tsx` — the entire `THREAT_NODES` and `THREAT_CONNECTIONS` const arrays
2. **Add `fetchAllGeo()`** to `api.ts` pointing at the new endpoint
3. **Swap the mount `useEffect`** from `fetchMemoryGeo()` to `fetchAllGeo()`

The old mount effect also had a backwards pattern — it tried to match live IPs against the static `THREAT_NODES` array to avoid duplicating actor nodes. With static nodes gone, that logic could simplify:

```typescript
// Old: tries to match against THREAT_NODES to avoid duplicates
const matchingStatic = THREAT_NODES.find(
  (n) => n.type === "apt" && n.name.toLowerCase().includes(actor.toLowerCase().split(" ")[0])
);
if (!matchingStatic) { /* emit actor node */ }

// New: just emit actor nodes, dedup by seenActors set
for (const actor of actors) {
  if (!actor || seenActors.has(actor)) continue;
  seenActors.add(actor);
  nodes.push({ id: `base-actor-${actor}`, name: actor, type: "apt", ... });
}
```

Removing the static node dependency didn't just fix the data — it made the code simpler.

## The Gotcha: Render Build Fails and a Deleted Dockerfile

After pushing the TypeScript fixes, the `cerberus-backend` Render service kept failing with:

```
error: failed to solve: failed to read dockerfile: open Dockerfile: no such file or directory
```

A separate cleanup commit (`9331fd3`) had marked `backend/Dockerfile` as "unused" and deleted it. That was technically accurate for the unified `cerberus` service (which uses the root `./Dockerfile` with nginx + uvicorn). But the `cerberus-backend` service on Render had its `dockerfilePath` set to `./backend/Dockerfile` in the Render UI — not in `render.yaml`.

The lesson: **Render service configuration can diverge from your `render.yaml`.** The dashboard settings persist even if you change the declarative config. Always check the Render CLI or dashboard before deleting files referenced by running services:

```bash
render services -o json | python3 -c "
import sys, json
for s in json.load(sys.stdin):
    d = s['service']['serviceDetails'].get('envSpecificDetails', {})
    print(s['service']['name'], d.get('dockerfilePath', 'N/A'))
"
# cerberus-backend  ./backend/Dockerfile  ← wouldn't exist after deletion
```

Fix was simple: restore the Dockerfile with the proper `CMD`:
```dockerfile
FROM python:3.12-slim
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ .
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

## The TypeScript Errors That Weren't Mine

When pushing to Render, the frontend build caught 5 TypeScript errors in `strict` mode. None were introduced by this session's changes — they were pre-existing issues that the dev server (vite in `--no-check` mode) had been silently ignoring.

**GraphPanel.tsx** — The `react-force-graph-2d` library adds `x` and `y` properties to nodes at runtime (force simulation), but the `GraphNode` type doesn't declare them. Even with `[key: string]: unknown` as an index signature, TypeScript's strict mode rejects property access on named properties that aren't explicitly declared:

```typescript
// Fix: cast to any for runtime-injected props
const node = graphData.nodes.find((n: any) => n.id === nodeId) as any;
if (node && typeof node.x === "number" && typeof node.y === "number") {
  graphRef.current.centerAt(node.x as number, node.y as number, 300);
}
```

**MemoryPanel.tsx** — `typeMap[n.type]` returns `string | undefined`, but `fetchStixBundle()` expects `EntityType` (a union of 6 specific strings). The `.filter()` call guarantees it's defined, but TypeScript doesn't know that:

```typescript
// Fix: cast after filtering guarantees non-undefined
fetchStixBundle({ entity: n.label, type: typeMap[n.type] as EntityType })
  .then((b) => (b.objects as Record<string, unknown>[] | undefined) ?? [])
```

**MitreHeatmapPanel.tsx** — An unused `Grid3x3` import and unused `hasData` variable. The `hasData` was being computed but never referenced (likely from a UI change that removed the conditional display). Instead of deleting `total` (which `hasData` came from), I wired it into a useful summary line:

```tsx
{total > 0 && (
  <p className="text-xs text-muted-foreground font-mono mb-3 text-right">
    {total} technique{total !== 1 ? "s" : ""} across X tactics
  </p>
)}
```

The strict build caught real issues. `noUnusedLocals` is annoying until it's not.

## What's Next

The geomap now shows real data on load. The codebase is leaner. The build is clean.

What I'd do differently:
- **Audit Render service configs before deleting any file** — the dashboard vs `render.yaml` mismatch is a known footgun
- **Run `tsc --strict` locally before pushing** — would have caught the 5 frontend errors before they hit Render's build
- **Check if `cerberus-frontend` static site is also still being deployed** — there are now 3 cerberus services on Render (unified, backend-only, and a static frontend). The unified one supersedes the other two; may be worth cleaning up after the hackathon

---

Real data beats fake data, always — even when the fake data looks cleaner.
