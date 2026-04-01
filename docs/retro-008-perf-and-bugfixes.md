# From 45 to 94: Performance Surgery and Three Hidden Bugs in Cerberus

After pulling a 35-file update that added authentication, STIX export, MITRE heatmaps, intelligence scoring, and a dozen new API endpoints, I sat down to review the changes and update documentation. That turned into a performance deep-dive that took Lighthouse from 45/100 to 94/100, and uncovered three bugs — one of which was a classic infinite loop hiding in plain sight.

## The Starting Point

Cerberus is a threat intelligence platform built for HackWithBay 2.0. It runs Neo4j + FastAPI + React, with Claude generating threat narratives via SSE streaming. The frontend had just received a wave of new features: a 3D graph panel, a MITRE ATT&CK heatmap, PDF report export, IOC extraction, and "Investigate Next" suggestions. Lighthouse mobile scores were **45-56/100** with:

- **FCP: 5.7-6.3s** — users waited 6 seconds to see anything
- **LCP: 5.7-7.4s** — the main content was essentially invisible for 7 seconds
- **TBT: 244-690ms** — the main thread was blocked for nearly a second
- **No viewport meta tag** — the page wasn't even declaring itself as responsive

The frontend bundled everything into a single 850KB transfer. Every user paid for `@react-pdf/renderer` (518KB), `react-force-graph-2d`, `d3-geo`, and `react-markdown` on first load, regardless of which panel they were viewing.

## Step 1: The Viewport Meta Tag (The Freebie)

The `<head>` in `index.html` was missing `<meta name="viewport">`. Without it, mobile browsers render the page at a desktop viewport width and scale it down, which destroys every Lighthouse metric. This is a zero-cost fix:

```html
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
```

This is Lighthouse 101, but it's easy to miss when you're focused on functionality. If you're building a SPA and your Lighthouse score is below 50, check `<meta name="viewport">` first — it's the most common missing tag.

## Step 2: Lazy Loading Heavy Panels with React.lazy

Cerberus has a tabbed center panel: Graph, GeoMap, MITRE Heatmap, Memory. Only one is visible at a time, but all four were statically imported — meaning React loaded all their dependencies (Three.js references, d3-force, d3-geo, topojson) on first paint.

The fix: `React.lazy()` with `Suspense`. Each panel becomes a separate chunk that loads only when its tab is activated:

```tsx
const GraphPanel = lazy(() => 
  import("./components/panels/GraphPanel")
    .then(m => ({ default: m.GraphPanel }))
);
```

The `.then(m => ({ default: m.GraphPanel }))` is needed because `React.lazy` expects a default export, but these components use named exports. This is a common gotcha — if you get "Element type is invalid" after adding `lazy()`, check whether the module uses `export default` or `export const`.

The `Suspense` boundary wraps all four lazy panels:

```tsx
<Suspense fallback={
  <div className="flex items-center justify-center h-full">
    Loading view…
  </div>
}>
  {centerView === "graph" && <GraphPanel state={state} />}
  {centerView === "geomap" && <ThreatMap state={state} />}
  {/* ... */}
</Suspense>
```

## Step 3: Vendor Chunk Splitting with Vite

Even with lazy-loaded panels, Vite's default chunking can merge their dependencies back into the main bundle. I added explicit `manualChunks` in `vite.config.ts` to force heavy libraries into their own files:

```ts
build: {
  rollupOptions: {
    output: {
      manualChunks: {
        'vendor-graph': ['react-force-graph-2d'],
        'vendor-geo': ['d3-geo', 'topojson-client'],
        'vendor-pdf': ['@react-pdf/renderer'],
        'vendor-markdown': ['react-markdown'],
      },
    },
  },
},
```

**Gotcha:** I initially included `d3-force` in `vendor-graph`, but the build failed — `d3-force` isn't a direct dependency, it's a transitive dep of `react-force-graph-2d`. Vite's `manualChunks` can only split modules that appear in your own dependency tree. If a library bundles its dependency internally, you can't extract it.

## Step 4: Async Google Fonts (The 873ms Win)

Lighthouse flagged a **873ms render-blocking resource**: Google Fonts. The stylesheet was loaded via CSS `@import`:

```css
/* BAD — blocks painting until the font stylesheet downloads */
@import url("https://fonts.googleapis.com/css2?family=JetBrains+Mono...");
```

CSS `@import` is synchronous by design — the browser won't paint anything until the external stylesheet finishes downloading. The fix is the `media="print" onload` trick:

```html
<link rel="preconnect" href="https://fonts.googleapis.com" />
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
<link rel="stylesheet" 
  href="https://fonts.googleapis.com/css2?family=JetBrains+Mono..."
  media="print" 
  onload="this.media='all'" />
```

How this works: the browser doesn't block rendering for `media="print"` stylesheets (they're only needed for printing). Once the stylesheet loads, the `onload` handler switches it to `media="all"`, applying the fonts. Users see system fonts for a split second, then the custom fonts swap in — a much better UX than staring at a blank page for 873ms.

## Step 5: Dynamic PDF Import (518KB Saved)

`@react-pdf/renderer` is a massive library (518KB gzipped) that generates PDFs client-side. It was imported at the top of `NarrativePanel.tsx`, meaning every page load paid for it — even though PDF export is a rare action triggered by a button click.

Before (every page load downloads 518KB):
```tsx
import { pdf } from "@react-pdf/renderer";
import { ThreatReportPdf } from "../report/ThreatReportPdf";
```

After (518KB loads only on "Export PDF" click):
```tsx
const handleExportPdf = async () => {
  const [{ pdf }, { ThreatReportPdf }] = await Promise.all([
    import("@react-pdf/renderer"),
    import("../report/ThreatReportPdf"),
  ]);
  const report = await fetchReport({ entity, type: entityType });
  const blob = await pdf(<ThreatReportPdf report={report} />).toBlob();
  // ... trigger download
};
```

`Promise.all` loads both modules in parallel. The user sees "Generating PDF..." while the library downloads (~1-2s on first click), then it's instant on subsequent clicks because the browser caches the module.

## The Gotcha: The Infinite Loop in 4 Lines of Code

After all the performance work, the user reported: "the page freezes when I enter an entity for investigation." This wasn't a performance issue — this was a **hard freeze**. The browser tab became completely unresponsive.

The symptom pointed at the investigation flow, but the investigation hook (`useInvestigation.ts`) was clean. The SSE streaming, state updates, abort controllers — all correct. The freeze happened *during* streaming, not on submission.

I traced it to `NarrativePanel.tsx`, which calls `mergeIOCs()` inside `useMemo` every time the narrative text updates. `mergeIOCs` calls `extractIOCsFromNarrative`, which scans the text for IP addresses, CVEs, domains, and hashes using regex.

Here's the bug:

```ts
// iocExtract.ts — The original code
const IPV4 = /\b(?:(?:25[0-5]|...){3}...)\b/g;  // Note: 'g' flag ✅

function extractIOCsFromNarrative(text: string): IocRow[] {
  const ipRe = new RegExp(IPV4.source);  // ← 'g' flag GONE ❌
  while ((m = ipRe.exec(text)) !== null)  // ← infinite loop!
    pushUnique(rows, "ip", m[0], "narrative");
}
```

`IPV4` has the `g` (global) flag. But `new RegExp(IPV4.source)` extracts only the *pattern string* — **flags are not included in `.source`**. Without `g`, `exec()` always matches at position 0 and never advances `lastIndex`. If the narrative contains any IP address, the `while` loop finds the same match forever.

This is a classic JavaScript regex trap. The fix is one character per regex:

```ts
const ipRe = new RegExp(IPV4.source, "g");   // ← add flags back
const cveRe = new RegExp(CVE.source, "gi");
const hashRe = new RegExp(HASH.source, "g");
const domRe = new RegExp(DOMAIN.source, "g");
```

This bug was latent in the pulled code and would trigger the moment any investigation's narrative mentioned an IP address, CVE, hash, or domain — which is *most investigations* in a threat intelligence tool. It just hadn't been caught because the IOC extraction feature was brand new.

**Lesson:** When you copy a regex via `.source`, always check what flags you need to re-attach. Better yet, use `new RegExp(originalRegex)` (which preserves flags) or just clone with literal syntax.

## The 422 Error: When Your Suggestions Can't Be Investigated

After fixing the freeze, clicking "Investigate Next" on suggestions like "Remote Desktop Protocol" produced:

```
Investigation Failed
Stream failed: 422 Unprocessable Entity
```

The `suggest_next()` function in `neo4j_client.py` queries Neo4j for neighboring nodes and maps their labels to entity types. But it used a fallback that passed through unmapped labels:

```python
# Before — falls through to raw label name
mapped_type = _LABEL_TO_ENTITY_TYPE.get(neo4j_label, neo4j_label.lower())
# "Technique" → "technique" (not a valid EntityType!)
```

The `EntityType` enum only accepts: `package | ip | domain | cve | threatactor | fraudsignal`. "Remote Desktop Protocol" is a `Technique` node (MITRE ATT&CK), which maps to `"technique"` — not in the enum. When the frontend sends `type=technique` to `/api/query/stream`, Pydantic's validation rejects it with 422.

The fix: skip nodes that don't have a valid entity type mapping, and fetch more candidates from Cypher to compensate:

```python
# After — only include nodes with valid EntityType mappings
mapped_type = _LABEL_TO_ENTITY_TYPE.get(neo4j_label)
if not mapped_type:
    continue  # Skip Technique, Account, etc.
```

I bumped the Cypher `LIMIT` from 5 to 10 (to account for filtered rows) and capped the final list at 5 in Python. This way, users only see suggestions they can actually click on.

## The Layout Bug: Investigate Next Covering the Summary

A subtler UI issue: the "Investigate Next" suggestions were rendered as a **fixed footer** below the scrollable narrative area. On shorter screens or longer narratives, they obscured the end of the narrative text.

The panel structure was:

```
flex flex-col h-full
  ├── Header (fixed)
  ├── Export + Toggle (fixed)
  ├── Narrative body (flex-1 overflow-y-auto) ← scrollable
  ├── Investigate Next (fixed footer)         ← covered narrative!
  └── Memory Save (fixed footer)
```

The fix: move "Investigate Next" *inside* the scrollable container so it flows naturally after the narrative. The "Memory Save" button stays pinned — it's an always-visible action that makes sense as a footer.

## The Results

| Metric | Before | After |
|--------|--------|-------|
| **Lighthouse Score** | 45-56/100 | **94/100** |
| **First Contentful Paint** | 5.7-6.3s | **2.2s** |
| **Largest Contentful Paint** | 5.7-7.4s | **2.7s** |
| **Total Blocking Time** | 244-690ms | **20ms** |
| **Initial JS Bundle** | ~850KB | **231KB** |

The 94/100 is from a local Lighthouse run. The deployed Render instance will be lower due to cold-start latency and network overhead, but the JS-side improvements are real.

## What's Next

- **Self-host Google Fonts** — Even with the async trick, there's still a DNS+TLS round trip to `fonts.googleapis.com`. Self-hosting the font files would eliminate that entirely and remove the render-blocking audit finding.
- **Split frontend as Render Static Site** — The biggest deploy speed win. Static sites deploy in ~30s via CDN vs. ~3-5min for the Docker build. But it requires handling CORS or using a custom domain.
- **DOM size** — Lighthouse flagged 1,065 elements. Most of this is the graph visualization, which is inherently DOM-heavy. Virtual scrolling on the IOC table could help, but it's not a priority at current scale.
- **Bundle analysis** — `react-markdown` (125KB) is loaded for the narrative panel which is always visible. Worth investigating lighter markdown renderers or a server-side approach.

---

The most dangerous bug in this session was four characters wide: missing `"g"` flags on four regex constructors. A threat intelligence platform that freezes when it finds a threat — that's irony you don't want in production.

