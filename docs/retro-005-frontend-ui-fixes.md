# Retro 005 — Killing Ghost Buttons and a Starving Graph Canvas

Two overlapping toggle UIs, a backdrop-blur SVG hallucination, and a graph canvas that refused to grow. What should have been a 10-minute CSS fix became a 90-minute deep dive into Docker layer caching, React rendering quirks, and the surprising visual side effects of `backdrop-blur` over animated SVGs.

## The Starting Point

Cerberus has a three-column layout: QueryPanel (left sidebar), a center visualization area, and NarrativePanel (right sidebar). The center panel switches between two views — **Threat Graph** (a force-directed node graph) and **Geomap** (a world map with threat markers). A `ViewNav` component provides rounded-rectangle toggle buttons to switch between them.

The problem was immediately visible: **two sets of toggle buttons were stacking on top of each other**, creating garbled overlapping text. And separately, the Threat Graph canvas was rendering at a fraction of the available space.

## Step 1: Finding the Ghost — Two Toggle Systems

The screenshot showed "RTHATGRAPH" — what looked like "Threat Graph" rendered twice with slight offset. My first assumption was wrong: I thought `backdrop-blur-md` on the ViewNav was compositing the animated SVG glow effects underneath, creating a visual ghost.

The actual problem was simpler and dumber: **there were two completely independent toggle systems**.

1. **ViewNav** (in `App.tsx`) — parent-level component, `rounded-md` buttons, switches between `GraphPanel` and `ThreatMap` components
2. **GraphPanel's internal toggle** — `rounded-full` pill buttons, switches between an internal graph view and an internal `GeoMap` sub-component

Both were positioned `absolute top-3 left-3 z-20` — same exact position, same z-index. 

```tsx
// ViewNav — the keeper (rounded rectangles)
<nav className="absolute top-3 left-3 z-20 flex items-center gap-0.5 rounded-lg ...">

// GraphPanel's internal toggle — the intruder (pills)
<div className="absolute left-4 top-4 z-20 flex items-center gap-2">
  {(["graph", "map"] as const).map((mode) => (
    <button className="rounded-full border px-3 py-1 text-[10px] ...">
      {mode === "graph" ? "Threat Graph" : "Geo Map"}
    </button>
  ))}
</div>
```

The fix was obvious: remove the pills. But the cascade wasn't.

## Step 2: The Cleanup Cascade — Dead Code Removal

Removing the pill toggle was one line of JSX. But it left behind:

- `setViewMode` — now unused (declared but never called)
- `viewMode` state — no longer needed
- `viewMode === "map"` conditionals — TypeScript flagged these as always-false comparisons
- `mapPoints` state — only used by the internal `GeoMap`
- `fetchGeoMap` import — only used by the map effect
- `GeoMap` sub-component — **290 lines** of dead code (a complete world map with Mercator projection, crosshairs, animated threat arcs, zoom/pan, and a bottom legend)
- `GeoPoint` type import — only used by `GeoMap`
- `useState` import — no longer needed after removing all state

Each unused variable caused **Docker build failures**. The Dockerfile uses `tsc -b` (which is stricter about unused variables than `tsc --noEmit`), so what passed locally kept failing in Docker. I had to chase each one down sequentially:

```
error TS6133: 'setViewMode' is declared but its value is never read.
error TS6133: 'mapPoints' is declared but its value is never read.  
error TS2367: Comparison always false: '"graph"' and '"map"' have no overlap.
```

**Lesson learned:** When removing UI that uses state, trace every reference before committing. A quick `grep -n "viewMode\|mapPoints\|GeoMap"` would have found all six dangling references in one pass instead of discovering them one Docker build at a time.

## Step 3: The Backdrop-Blur Red Herring

While investigating the ghosting, I noticed the ViewNav used `backdrop-blur-md` with a semi-transparent background (`bg-surface/80`). Over ThreatMap's animated SVGs with `feGaussianBlur` glow filters, this can create visual artifacts in some browsers — the blur composites the animated glow underneath, making it look like doubled content.

I "fixed" this by making ViewNav fully opaque:

```tsx
// Before
"rounded-lg border border-border/60 bg-surface/80 backdrop-blur-md"

// After  
"rounded-lg border border-border/60 bg-surface backdrop-blur-none"
```

This was the right change for the wrong reason. The actual overlap was from the duplicate toggle, not backdrop compositing. But the change still improved rendering — an opaque nav at `z-30` is more reliable than a semi-transparent one fighting SVG filters for visual priority.

## Step 4: Docker Layer Caching — The Silent Saboteur

After removing the pills from source and pushing, I rebuilt Docker:

```bash
docker build -t cerberus .
docker run -p 10000:80 --env-file .env cerberus
```

The pills were **still there**. I spent 10 minutes confused before checking:

```bash
docker exec <container> sh -c 'grep -oP ".{50}Geo Map.{50}" /usr/share/nginx/html/assets/*.js'
```

Output: `x==="graph"?"Threat Graph":"Geo Map"` — the bundle still had the old pill logic. Docker had cached the `npm run build` layer because the `COPY frontend/ ./` step's hash hadn't changed from Docker's perspective (it was comparing layer hashes, not file content diffs).

The fix: `docker build --no-cache -t cerberus .`

**Lesson learned:** When debugging "my code change isn't showing up," always suspect Docker layer caching first. Use `--no-cache` or target-specific `--no-cache-filter` to force fresh builds. The 2-minute rebuild penalty is far cheaper than the 10-minute "am I going crazy?" debugging session.

## Step 5: The Starving Canvas — ResizeObserver to the Rescue

With the pills gone, the user reported the graph canvas was "small with so much wasted space." The force-directed graph was rendering in a tiny rectangle inside a large center panel.

Root cause — the `ForceGraph2D` component from `react-force-graph-2d` requires explicit `width` and `height` props (it renders to a `<canvas>`, not a DOM element that auto-sizes). The original code read dimensions from a ref at render time:

```tsx
<ForceGraph2D
  width={containerRef.current?.clientWidth || 600}
  height={containerRef.current?.clientHeight || 400}
/>
```

The problem: `containerRef.current?.clientWidth` is `0` during the first render (the DOM hasn't laid out yet), so it falls back to 600×400. Even on subsequent re-renders, the value is stale — it's read once and never updated.

The fix: a `ResizeObserver` that tracks the container's dimensions in state:

```tsx
const [containerSize, setContainerSize] = useState({ width: 800, height: 600 });

useEffect(() => {
  const el = containerRef.current;
  if (!el) return;
  const ro = new ResizeObserver((entries) => {
    const { width, height } = entries[0].contentRect;
    if (width > 0 && height > 0) {
      setContainerSize({ width, height });
    }
  });
  ro.observe(el);
  return () => ro.disconnect();
}, []);

// Then in the JSX:
<ForceGraph2D
  width={containerSize.width}
  height={containerSize.height}
/>
```

`ResizeObserver` fires immediately when it starts observing (giving us the initial size) and again whenever the container resizes (browser resize, sidebar collapse, etc.). The `width > 0 && height > 0` guard prevents setting zero dimensions during layout thrashing.

**Why not CSS?** Canvas elements can't auto-size with CSS `width: 100%` the way a `<div>` can. The canvas has a fixed pixel buffer, and `react-force-graph-2d` needs explicit numeric width/height to allocate it correctly. CSS scaling a canvas just stretches the pixels — it doesn't give you more rendering resolution.

## What's Next

- The `GeoMap` component that lived inside GraphPanel was a complete duplicate of the standalone `ThreatMap` component. This suggests the codebase grew organically with two people adding geo visualization independently. Worth auditing for other duplicated functionality.
- The `react-markdown` import in NarrativePanel is broken (`TS2307: Cannot find module`). Teammate dependency — needs `npm install react-markdown`.
- ViewNav's opaque background means it no longer has the glass-morphism effect that other panels have. Might want to revisit this with a solid-but-matching background color.

---

*Three bugs, one root cause: nobody owned the contract for "who renders the view toggle." When two components both think they're responsible for the same UI, you don't get redundancy — you get a pile-up.*
