# Building a Cybersecurity Dashboard in One Session: From Zero to Force-Directed Graphs

A dark-mode threat intelligence UI, a streaming SSE hook that pretends to know what pipeline stage we're on, and the Node.js version mismatch that nearly derailed the entire scaffold. This is how I built the Cerberus frontend — a reactive dashboard for a hackathon project that traces cross-domain attack chains through a Neo4j knowledge graph.

## The Starting Point

Cerberus had a working backend: FastAPI serving three endpoints (`/api/query`, `/api/query/stream`, `/api/confirm`), an Anthropic LLM generating threat narratives, and Neo4j storing the attack graph. What it didn't have was any way for a human to actually use it. Every interaction was `curl` commands and JSON blobs.

The goal: a three-panel dashboard that feels like a cybersecurity analyst's workstation. Entity search on the left, force-directed graph in the center, streaming AI narrative on the right. An 8-stage pipeline bar across the top. All wrapped in a dark, tactical aesthetic with electric cyan (#00E5FF) as the primary accent.

The constraint: we're presenting at HackWithBay 2.0 under the "Thoughtful Agents for Productivity" track. The frontend has to be legible from across the room and visually impressive enough to survive a 3-minute demo.

## Step 1: The Scaffold Fight

I reached for Vite + React + TypeScript as the stack. Vite for fast HMR during the build session, React for component composition, TypeScript because the backend has well-defined response types and I wanted compile-time safety.

The first surprise: `create-vite@9` refused to run.

```
npm error engine Unsupported engine {
  required: { node: '^20.19.0 || >=22.12.0' },
  current: { node: 'v20.9.0' }
}
```

Node v20.9.0 is LTS but not recent enough for the latest Vite scaffolder. I could've upgraded Node, but that risks breaking the backend's Python toolchain or other global tools mid-session. Instead, I pinned `create-vite@5`:

```bash
npm create vite@5 frontend -- --template react-ts
```

This worked immediately. The lesson: when a scaffolding tool breaks, check its engine requirements before debugging anything else. The fix is almost always "use an older version" rather than "upgrade your runtime."

**Dependency choices:**

| Library | Why |
|---------|-----|
| Tailwind CSS v3 | Utility-first styling with HSL variable interop |
| class-variance-authority | Component variant definitions (shadcn/ui pattern) |
| clsx + tailwind-merge | Safe class composition — `cn()` helper |
| lucide-react | Tree-shakeable icon library, consistent stroke width |
| @radix-ui/react-* | Accessible primitives (tooltip, select, dialog, slot) |
| react-force-graph-2d | Canvas-based force graph — handles 50+ nodes at 60fps |
| framer-motion | Not heavily used in v1, but installed for future page transitions |

## Step 2: The Design System — HSL Variables Everywhere

The core decision that made everything else work: **all colors are HSL channel values stored in CSS variables, not hex or RGB.** This lets Tailwind's opacity modifier syntax (`bg-primary/20`) work with semantic tokens — something that breaks if you use hex values in your config.

```css
/* index.css — tokens are just HSL channels, no hsl() wrapper */
:root {
  --primary: 185 100% 50%;           /* Electric cyan */
  --threat-critical: 0 85% 55%;      /* Red for critical severity */
  --node-package: 210 80% 60%;       /* Blue for npm packages */
  --surface: 220 18% 10%;            /* Base surface */
  --surface-raised: 220 16% 14%;     /* Cards, panels */
}
```

```typescript
// tailwind.config.ts — wraps the variables in hsl()
colors: {
  primary: {
    DEFAULT: "hsl(var(--primary))",
    glow: "hsl(var(--primary-glow))",
    muted: "hsl(var(--primary-muted))",
  },
  threat: {
    critical: "hsl(var(--threat-critical))",
    high: "hsl(var(--threat-high))",
    // ...
  },
}
```

Now I can write `bg-primary/20` and get `hsla(185, 100%, 50%, 0.2)` — a semi-transparent cyan. This pattern cascades everywhere: glow effects, border accents, hover states. One color definition, infinite opacity variants.

The threat severity spectrum (critical → high → medium → low → info) maps to red → orange → amber → yellow → blue. Eight node-type colors cover every entity in the graph: Package, CVE, IP, Domain, ThreatActor, Technique, Account, FraudSignal.

**The gotcha with canvas:** `react-force-graph-2d` renders on a `<canvas>`, which can't read CSS variables. I had to duplicate the node colors as hex strings:

```typescript
const NODE_COLORS: Record<string, string> = {
  Package: "#4D94FF",     /* must match --node-package */
  CVE: "#FF4D4D",         /* must match --node-cve */
  // ...
};
```

This is a maintenance hazard — if someone changes `--node-package` in CSS, they have to remember to update the hex constant. In production, I'd generate these from the CSS variables at build time. For a hackathon, a comment saying "MUST stay in sync" is good enough.

## Step 3: The SSE Hook — Streaming Narrative with Fake Pipeline Stages

This was the most interesting engineering problem: the backend streams narrative text via Server-Sent Events, but **the 8-stage pipeline bar needs to show progress through stages the backend doesn't actually report.**

The SSE endpoint sends chunks like:

```
data: {"chunk": "The package ua-parser-js was compromised in ", "done": false}
data: {"chunk": "October 2021 when an attacker published ", "done": false}
data: {"chunk": "three malicious versions...", "done": false}
data: {"done": true, "paths_found": 3, "from_cache": false}
```

But the pipeline bar shows 8 stages: INPUT → NER → CLASSIFY → ROUTE → TRAVERSE → ANALYZE → NARRATE → DONE. The backend doesn't emit "I'm now in the NER stage" events. So I faked it.

```typescript
const simulateStages = useCallback(
  (upTo: PipelineStage) => {
    const targetIdx = PIPELINE_STAGES.indexOf(upTo);
    let current = 0;

    const interval = setInterval(() => {
      if (current >= targetIdx) {
        clearInterval(interval);
        return;
      }
      current++;
      setState((prev) => ({
        ...prev,
        currentStage: PIPELINE_STAGES[current],
      }));
    }, 600);

    return () => clearInterval(interval);
  },
  []
);
```

Every 600ms, the pipeline bar advances to the next stage. The visual effect is convincing: the stages light up as cyan dots, connectors fill in with a CSS transition, and the active stage gets a pulsing glow ring. By the time the first SSE chunk arrives, we're usually around the TRAVERSE or ANALYZE stage — which *feels* right even though it's theatrical.

The SSE reader itself is a standard `ReadableStream` consumer:

```typescript
const reader = res.body.getReader();
const decoder = new TextDecoder();

while (true) {
  const { done, value } = await reader.read();
  if (done) break;

  const text = decoder.decode(value, { stream: true });
  const lines = text.split("\n");

  for (const line of lines) {
    if (!line.startsWith("data: ")) continue;
    const payload = JSON.parse(line.slice(6));

    if (payload.done) {
      // Terminal event — set final state
      setState(prev => ({
        ...prev,
        status: "complete",
        currentStage: "complete",
        pathsFound: payload.paths_found ?? 0,
        fromCache: payload.from_cache ?? false,
      }));
    } else if (payload.chunk) {
      // Accumulate narrative text
      setState(prev => ({
        ...prev,
        narrative: prev.narrative + payload.chunk,
      }));
    }
  }
}
```

Two subtle decisions here:

1. **`{ stream: true }` on `TextDecoder.decode()`** — Without this flag, multi-byte UTF-8 characters that span chunk boundaries get mangled. With it, the decoder buffers partial characters.

2. **`AbortController` for cancellation** — If the user starts a new investigation while one is streaming, we abort the previous SSE connection. Without this, you'd get interleaved narrative text from two investigations.

```typescript
const investigate = useCallback(async (entity, entityType) => {
  abortRef.current?.abort();        // Cancel any in-flight stream
  const controller = new AbortController();
  abortRef.current = controller;
  // ... start new stream
}, []);
```

## Step 4: The Graph Panel — Canvas Rendering with Glow Effects

`react-force-graph-2d` gives you a canvas and physics engine. You provide node/link data and custom paint functions. The interesting part was the glow effect:

```typescript
const paintNode = useCallback(
  (node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
    const color = NODE_COLORS[node.type] || "#666";
    const nodeRadius = Math.max(node.val || 5, 3);

    // Glow: set shadowColor + shadowBlur before drawing
    ctx.shadowColor = color;
    ctx.shadowBlur = 12;

    ctx.beginPath();
    ctx.arc(node.x, node.y, nodeRadius, 0, 2 * Math.PI);
    ctx.fillStyle = color;
    ctx.fill();

    // Reset shadow for crisp text labels
    ctx.shadowBlur = 0;

    ctx.font = `${Math.max(10 / globalScale, 3)}px "JetBrains Mono", monospace`;
    ctx.textAlign = "center";
    ctx.fillStyle = "rgba(200, 210, 220, 0.9)";
    ctx.fillText(node.label, node.x, node.y + nodeRadius + 2);
  },
  []
);
```

The `shadowBlur` trick is the simplest way to get neon glow effects on canvas. Set `shadowColor` to the node's color and `shadowBlur` to 12 pixels — every `fill()` call automatically gets a soft glow. Reset it to 0 before drawing text so labels stay crisp.

Dashed links distinguish "synthetic" edges (inferred relationships) from confirmed graph edges:

```typescript
if (link.dashed) {
  ctx.setLineDash([4, 4]);
  ctx.strokeStyle = "rgba(255, 200, 50, 0.4)";  // Yellow for synthetic
} else {
  ctx.setLineDash([]);
  ctx.strokeStyle = "rgba(0, 229, 255, 0.2)";    // Cyan for confirmed
}
```

**The mock data problem:** The backend SSE stream sends narrative text, not graph nodes. A production version would need a `/api/graph` endpoint that returns the traversal paths as structured data. For the demo, I wrote `generateDemoGraph()` which creates a plausible attack chain based on entity type — a Package gets connected to CVEs, ThreatActors, Techniques, IPs, and Domains in a realistic topology.

## Step 5: The Polish Pass — Micro-Interactions That Sell the Demo

After the base components worked, I did a polish pass focused on the 3-minute demo window. The principle: **everything the audience sees in the first 5 seconds needs to move or glow.**

**Pipeline stages got a radial gradient that follows the active node:**

```css
/* Radial gradient positioned at the active stage */
background: radial-gradient(
  circle at var(--active-x) 50%,
  hsl(var(--primary) / 0.08) 0%,
  transparent 60%
);
```

**The narrative panel got text-reveal animation** — each paragraph fades from blurred to clear with staggered timing:

```css
@keyframes textReveal {
  from { opacity: 0; filter: blur(3px); transform: translateY(2px); }
  to { opacity: 1; filter: blur(0); transform: translateY(0); }
}

.animate-text-reveal {
  animation: textReveal 0.4s ease-out forwards;
  opacity: 0;  /* Start hidden, animation fills forward */
}
```

```tsx
{state.narrative.split("\n").map((line, i) => (
  <p
    key={i}
    className="animate-text-reveal mb-2"
    style={{ animationDelay: `${i * 0.03}s` }}
  >
    {line || "\u00A0"}
  </p>
))}
```

Each line gets 30ms more delay than the previous one. Combined with the streaming SSE, the effect is that text materializes from a blur as the AI generates it — feels like watching an intelligence report being compiled in real time.

**The graph panel got a radar-sweep loading indicator:**

```css
.radar-sweep {
  background: conic-gradient(
    from 0deg,
    transparent 0deg,
    hsl(185, 100%, 50%, 0.15) 40deg,
    transparent 80deg
  );
  animation: radarSweep 2.5s linear infinite;
}

@keyframes radarSweep {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}
```

Three concentric rings, a pulsing center dot, and the conic-gradient sweep create a convincing radar effect with zero JavaScript and zero SVG — pure CSS. Small "blip" dots positioned with `Math.sin`/`Math.cos` add the finishing touch.

**The header got activity bars** — five tiny vertical bars that animate like an audio visualizer, using staggered CSS `float` animation with different delays. Subtle, but it signals "the system is alive" even when idle.

## The Gotcha: Terminal Paralysis Mid-Session

This wasn't a code bug — it was a tooling failure that almost cost me the polish commit. After completing the polish pass and verifying a clean build, the VS Code terminal stopped producing output. Commands like `git status`, `pwd`, even `echo "hello"` returned nothing.

The symptoms looked like stdin was consumed by a background process. The dev server was still running on port 5173 in its own background terminal. My guess: something about the terminal session state got corrupted after many rapid sequential commands.

The fix: I launched fresh background terminals for the remaining git operations. Background terminals get clean shell sessions, bypassing whatever was wrong with the foreground one. The git pull/rebase/push sequence worked on the first attempt in a new terminal.

**Lesson:** If your terminal goes silent during a session, don't waste time debugging the terminal itself. Spawn a new one and move on. The work is in the files, not the shell state.

## What's Next

The frontend is demo-ready but has several known gaps:

1. **Mock graph data** — `generateDemoGraph()` creates plausible-looking attack chains, but it's fiction. The backend needs a `/api/graph` endpoint that returns the actual Neo4j traversal paths as nodes + edges.

2. **No responsive layout** — The three-column design assumes a wide screen. On a laptop with low resolution, the side panels will squeeze the graph. Media queries would fix this, but it's not needed for the projected-screen demo.

3. **Schema panel is wired but unused** — `fetchSchema()` exists in the API client, but no component consumes it yet. A schema browser showing live node/relationship counts would help analysts understand what's in the graph.

4. **The `ANTHROPIC_KEY` bug** — The backend reads `config.ANTHROPIC_KEY` from the `NEO4J_API_KEY` environment variable. This is a semantic mismatch that will confuse anyone setting up the project. It works, but only because whoever configured the env vars knew about the swap.

5. **SSE error recovery** — If the stream fails mid-narrative, we show a red error card but don't offer a retry button. The hook supports abort, so retry would be straightforward.

---

A cybersecurity dashboard is 80% design system and 20% glue code. Get the colors, typography, and visual hierarchy right, and the components almost build themselves. Get them wrong, and no amount of animation will make `curl` output feel like an intelligence platform.

