/**
 * components/panels/GraphPanel.tsx — Force-directed graph visualization
 *
 * Renders the threat attack chain as an interactive force-directed graph.
 * Uses react-force-graph-2d for the visualization. Node colors follow
 * the design system's node-type palette.
 *
 * In the idle state, shows a placeholder with the graph legend.
 * When an investigation completes, it renders real traversal data from
 * the /api/query/graph endpoint. Falls back to a demo graph if the
 * backend doesn't return data (e.g. empty graph, API unreachable).
 */
import { useMemo, useRef, useCallback, useEffect, useState } from "react";
import ForceGraph2D from "react-force-graph-2d";
import type { InvestigationState, EntityType, GeoPoint } from "../../types/api";
import { cn } from "../../lib/utils";
import { fetchGeoMap } from "../../lib/api";

interface GraphPanelProps {
  state: InvestigationState;
}

/**
 * Map entity types to their CSS color (HSL resolved to hex for canvas).
 * Canvas APIs can't use CSS vars, so we hardcode the palette here.
 * These MUST stay in sync with the --node-* tokens in index.css.
 */
const NODE_COLORS: Record<string, string> = {
  Package: "#4D94FF",    /* --node-package: 210 80% 60% */
  CVE: "#FF4D4D",        /* --node-cve: 0 80% 60% */
  IP: "#FF8C26",         /* --node-ip: 30 85% 60% */
  Domain: "#9966FF",     /* --node-domain: 270 60% 65% */
  ThreatActor: "#E64DCC", /* --node-actor: 300 70% 60% */
  Technique: "#E6337A",  /* --node-technique: 330 70% 60% */
  Account: "#33CC80",    /* --node-account: 150 60% 50% */
  FraudSignal: "#E6CC33", /* --node-fraud: 55 85% 55% */
};

/** Color legend items for the sidebar */
const LEGEND_ITEMS = Object.entries(NODE_COLORS).map(([label, color]) => ({
  label,
  color,
}));

/**
 * Generate a demo graph structure based on the entity being investigated.
 * This simulates what a /api/graph endpoint would return.
 * Nodes are connected to show a cross-domain attack chain.
 */
function generateDemoGraph(entity: string, entityType: EntityType) {
  type GraphNode = { id: string; label: string; type: string; val: number };
  type GraphLink = { source: string; target: string; dashed?: boolean };

  const nodes: GraphNode[] = [];
  const links: GraphLink[] = [];

  /* Root node — the entity being investigated */
  const rootType = entityType === "threatactor"
    ? "ThreatActor"
    : entityType === "cve"
      ? "CVE"
      : entityType.charAt(0).toUpperCase() + entityType.slice(1);

  nodes.push({ id: entity, label: entity, type: rootType, val: 8 });

  /* Generate connected nodes based on type */
  if (entityType === "package") {
    /* Package → CVE → ThreatActor → Technique chain */
    const cve = `CVE-2021-${Math.floor(10000 + Math.random() * 89999)}`;
    const actor = "APT-" + Math.floor(Math.random() * 40 + 1);
    const technique = `T${Math.floor(1000 + Math.random() * 500)}`;
    const ip = `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 100)}.${Math.floor(Math.random() * 255)}`;
    const domain = `malware-c2-${Math.floor(Math.random() * 99)}.example.com`;
    const account = `npm-user-${Math.floor(Math.random() * 999)}`;

    nodes.push(
      { id: cve, label: cve, type: "CVE", val: 6 },
      { id: actor, label: actor, type: "ThreatActor", val: 7 },
      { id: technique, label: technique, type: "Technique", val: 4 },
      { id: ip, label: ip, type: "IP", val: 5 },
      { id: domain, label: domain, type: "Domain", val: 5 },
      { id: account, label: account, type: "Account", val: 4 }
    );

    links.push(
      { source: entity, target: cve },
      { source: cve, target: actor },
      { source: actor, target: technique },
      { source: actor, target: ip },
      { source: ip, target: domain },
      { source: entity, target: account },
      { source: account, target: ip, dashed: true } /* synthetic */
    );
  } else if (entityType === "ip") {
    const domain = `host-${Math.floor(Math.random() * 99)}.sus-domain.net`;
    const actor = "APT-" + Math.floor(Math.random() * 40 + 1);
    const pkg = `malicious-pkg-${Math.floor(Math.random() * 99)}`;

    nodes.push(
      { id: domain, label: domain, type: "Domain", val: 5 },
      { id: actor, label: actor, type: "ThreatActor", val: 7 },
      { id: pkg, label: pkg, type: "Package", val: 5 }
    );

    links.push(
      { source: entity, target: domain },
      { source: actor, target: entity },
      { source: domain, target: pkg }
    );
  } else {
    /* Generic: create a small chain */
    const related1 = `related-${Math.floor(Math.random() * 999)}`;
    const related2 = `related-${Math.floor(Math.random() * 999)}`;

    nodes.push(
      { id: related1, label: related1, type: "ThreatActor", val: 5 },
      { id: related2, label: related2, type: "IP", val: 5 }
    );

    links.push(
      { source: entity, target: related1 },
      { source: related1, target: related2 }
    );
  }

  return { nodes, links };
}

export function GraphPanel({ state }: GraphPanelProps) {
  const viewMode = "graph" as const;
  const [mapPoints, setMapPoints] = useState<GeoPoint[]>([]);
  /* Ref for the container div — used to measure dimensions */
  const containerRef = useRef<HTMLDivElement>(null);
  /* Ref for the force graph instance */
  const graphRef = useRef<any>(null);

  /* Use real graph data from backend when available, fall back to demo */
  const graphData = useMemo(() => {
    if (state.status === "complete" && state.pathsFound > 0) {
      if (state.graphData && state.graphData.nodes.length > 0) {
        return state.graphData;
      }
      return generateDemoGraph(state.entity, state.entityType);
    }
    return { nodes: [], links: [] };
  }, [state.status, state.pathsFound, state.entity, state.entityType, state.graphData]);

  /* Custom node rendering on the canvas */
  const paintNode = useCallback(
    (node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const label = node.label || node.id;
      const fontSize = Math.max(10 / globalScale, 3);
      const nodeRadius = Math.max(node.val || 5, 3);
      const color = NODE_COLORS[node.type] || "#666";

      /* Glow effect */
      ctx.shadowColor = color;
      ctx.shadowBlur = 12;

      /* Node circle */
      ctx.beginPath();
      ctx.arc(node.x, node.y, nodeRadius, 0, 2 * Math.PI);
      ctx.fillStyle = color;
      ctx.fill();

      /* Reset shadow for text */
      ctx.shadowBlur = 0;

      /* Label */
      ctx.font = `${fontSize}px "JetBrains Mono", monospace`;
      ctx.textAlign = "center";
      ctx.textBaseline = "top";
      ctx.fillStyle = "rgba(200, 210, 220, 0.9)";
      ctx.fillText(label, node.x, node.y + nodeRadius + 2);
    },
    []
  );

  /* Custom link rendering — dashed for synthetic edges */
  const paintLink = useCallback(
    (link: any, ctx: CanvasRenderingContext2D) => {
      const source = link.source;
      const target = link.target;

      ctx.beginPath();

      if (link.dashed) {
        ctx.setLineDash([4, 4]);
        ctx.strokeStyle = "rgba(255, 200, 50, 0.4)";
      } else {
        ctx.setLineDash([]);
        ctx.strokeStyle = "rgba(0, 229, 255, 0.2)";
      }

      ctx.lineWidth = 1;
      ctx.moveTo(source.x, source.y);
      ctx.lineTo(target.x, target.y);
      ctx.stroke();
      ctx.setLineDash([]);
    },
    []
  );

  /* Center the graph when data loads */
  useEffect(() => {
    if (graphRef.current && graphData.nodes.length > 0) {
      setTimeout(() => {
        graphRef.current?.zoomToFit(400, 40);
      }, 500);
    }
  }, [graphData]);

  useEffect(() => {
    if (state.status !== "complete" || state.pathsFound === 0) {
      setMapPoints([]);
      return;
    }
    fetchGeoMap({ entity: state.entity, type: state.entityType })
      .then((data) => setMapPoints(data.points))
      .catch(() => setMapPoints([]));
  }, [state.status, state.pathsFound, state.entity, state.entityType]);

  const hasGraph = graphData.nodes.length > 0;
  const hasMap = mapPoints.length > 0;

  return (
    <div
      ref={containerRef}
      className={cn(
        "relative h-full w-full overflow-hidden",
        "grid-bg"
      )}
    >
      {/* View toggle is handled by the parent ViewNav component */}

      {/* ── Graph visualization ─────────────────────────── */}
      {hasGraph && viewMode === "graph" && (
        <ForceGraph2D
          ref={graphRef}
          graphData={graphData}
          nodeCanvasObject={paintNode}
          linkCanvasObject={paintLink}
          backgroundColor="transparent"
          nodeRelSize={6}
          linkDirectionalParticles={2}
          linkDirectionalParticleWidth={1.5}
          linkDirectionalParticleColor={() => "rgba(0, 229, 255, 0.5)"}
          cooldownTicks={60}
          width={containerRef.current?.clientWidth || 600}
          height={containerRef.current?.clientHeight || 400}
        />
      )}

      {viewMode === "map" && hasMap && (
        <GeoMap points={mapPoints} />
      )}

      {/* ── Idle / waiting state ─────────────────────────── */}
      {((viewMode === "graph" && !hasGraph) || (viewMode === "map" && !hasMap)) && (
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="text-center px-8">
            {state.status === "running" ? (
              <div className="space-y-4">
                {/* Radar-style loading indicator */}
                <div className="relative w-24 h-24 mx-auto">
                  {/* Outer ring */}
                  <div className="absolute inset-0 rounded-full border border-primary/20" />
                  {/* Middle ring */}
                  <div className="absolute inset-3 rounded-full border border-primary/15" />
                  {/* Inner ring */}
                  <div className="absolute inset-6 rounded-full border border-primary/10" />
                  {/* Center dot */}
                  <div className="absolute inset-[42%] rounded-full bg-primary/40 animate-pulse" />
                  {/* Sweeping beam */}
                  <div className="absolute inset-0 rounded-full radar-sweep" />
                  {/* Blip dots */}
                  {[0, 1, 2].map((i) => (
                    <div
                      key={i}
                      className="absolute w-1.5 h-1.5 rounded-full bg-primary animate-pulse"
                      style={{
                        top: `${25 + Math.sin(i * 2.1) * 20}%`,
                        left: `${30 + Math.cos(i * 1.7) * 25}%`,
                        animationDelay: `${i * 0.5}s`,
                      }}
                    />
                  ))}
                </div>
                <p className="text-sm text-muted-foreground font-mono animate-pulse">
                  Traversing knowledge graph...
                </p>
                <p className="text-[10px] text-muted-foreground/50 font-mono">
                  Mapping cross-domain attack chains
                </p>
              </div>
            ) : (
              <div className="space-y-4 opacity-30">
                {/* Abstract network icon */}
                <svg
                  className="h-28 w-28 mx-auto text-muted-foreground animate-float"
                  viewBox="0 0 100 100"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="0.8"
                >
                  {/* Nodes */}
                  <circle cx="50" cy="18" r="5" fill="currentColor" opacity="0.3" />
                  <circle cx="22" cy="50" r="4" fill="currentColor" opacity="0.2" />
                  <circle cx="78" cy="50" r="4" fill="currentColor" opacity="0.2" />
                  <circle cx="35" cy="82" r="4.5" fill="currentColor" opacity="0.25" />
                  <circle cx="65" cy="82" r="4.5" fill="currentColor" opacity="0.25" />
                  {/* Edges */}
                  <line x1="50" y1="23" x2="22" y2="46" opacity="0.4" />
                  <line x1="50" y1="23" x2="78" y2="46" opacity="0.4" />
                  <line x1="22" y1="54" x2="35" y2="78" opacity="0.4" />
                  <line x1="78" y1="54" x2="65" y2="78" opacity="0.4" />
                  <line x1="35" y1="82" x2="65" y2="82" opacity="0.3" strokeDasharray="3 2" />
                </svg>
                <p className="text-sm text-muted-foreground">
                  Attack chain visualization
                </p>
                <p className="text-[10px] text-muted-foreground/50">
                  Start an investigation to map threat paths
                </p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Legend overlay with enhanced styling ─────────── */}
      <div
        className={cn(
          "absolute bottom-4 left-4 p-3 rounded-lg",
          "glass-panel text-[10px] font-mono",
          "transition-opacity duration-500",
          hasGraph ? "opacity-90" : "opacity-60"
        )}
      >
        <p className="text-muted-foreground uppercase tracking-[0.15em] mb-2 font-semibold flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-primary" />
          Node Types
        </p>
        <div className="grid grid-cols-2 gap-x-5 gap-y-1.5">
          {LEGEND_ITEMS.map((item) => (
            <div key={item.label} className="flex items-center gap-2">
              <span
                className="node-dot flex-shrink-0"
                style={{ backgroundColor: item.color, boxShadow: `0 0 6px ${item.color}40` }}
              />
              <span className="text-muted-foreground/80">{item.label}</span>
            </div>
          ))}
        </div>
        {hasGraph && (
          <div className="mt-2.5 pt-2 border-t border-border/30 flex items-center gap-2">
            <span className="w-5 border-t border-dashed border-threat-medium/60" />
            <span className="text-muted-foreground/60">Synthetic (simulated)</span>
          </div>
        )}
      </div>
    </div>
  );
}

function GeoMap({ points }: { points: GeoPoint[] }) {
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [dragging, setDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [hoveredIdx, setHoveredIdx] = useState<number | null>(null);

  const project = (lat: number, lon: number) => {
    const x = ((lon + 180) / 360) * 1000;
    const latRad = (lat * Math.PI) / 180;
    const mercY = Math.log(Math.tan(Math.PI / 4 + latRad / 2));
    const y = 260 - mercY * 150;
    return { x, y };
  };

  const handleWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    setZoom(Math.max(0.5, Math.min(4, zoom - e.deltaY * 0.002)));
  };

  /* Realistic simplified continent paths (Equirectangular ≈ scaled to 1000×520) */
  const LAND = [
    /* North America */
    "M38,82 L58,56 L78,52 L105,48 L125,46 L148,50 L168,62 L188,56 L196,68 L220,58 L228,72 L210,88 L195,100 L185,115 L170,128 L160,145 L152,155 L140,168 L120,178 L108,185 L95,175 L85,165 L70,158 L55,148 L42,135 L35,120 L32,105 Z",
    /* Greenland */
    "M295,25 L320,18 L345,22 L355,38 L348,56 L330,65 L310,60 L298,48 L292,35 Z",
    /* South America */
    "M170,225 L185,218 L200,215 L218,222 L230,238 L238,260 L240,285 L235,310 L228,335 L218,358 L205,378 L192,392 L178,398 L168,385 L162,360 L158,335 L155,308 L155,280 L158,255 L162,238 Z",
    /* Europe */
    "M460,55 L475,42 L495,38 L518,42 L538,50 L548,62 L542,78 L530,90 L518,98 L505,105 L492,108 L478,105 L465,98 L455,88 L450,75 Z",
    /* British Isles */
    "M438,55 L448,48 L455,52 L452,62 L445,68 L438,62 Z",
    /* Scandinavia */
    "M490,20 L505,15 L518,18 L528,28 L530,42 L525,50 L515,42 L505,38 L495,35 L488,28 Z",
    /* Africa */
    "M458,118 L478,112 L498,115 L518,120 L540,128 L555,142 L565,162 L570,185 L568,212 L562,238 L555,262 L545,282 L530,298 L515,308 L498,312 L482,308 L468,298 L458,282 L448,262 L442,238 L440,212 L442,185 L445,162 L448,142 Z",
    /* Madagascar */
    "M575,278 L582,270 L588,278 L586,295 L580,302 L574,292 Z",
    /* Asia (main mass) */
    "M548,48 L580,35 L618,28 L658,22 L698,28 L738,38 L770,48 L798,62 L818,78 L830,95 L835,115 L828,135 L818,150 L800,162 L778,168 L755,172 L732,175 L710,172 L688,168 L665,162 L645,155 L628,148 L612,138 L598,128 L585,115 L575,100 L565,85 L555,68 Z",
    /* Middle East */
    "M568,112 L585,108 L600,115 L608,128 L602,142 L588,148 L575,142 L568,128 Z",
    /* India */
    "M660,135 L680,128 L698,135 L708,155 L705,178 L695,198 L680,208 L665,202 L655,188 L650,168 L652,148 Z",
    /* Southeast Asia */
    "M730,155 L750,148 L768,155 L778,168 L775,185 L765,195 L750,198 L738,192 L730,178 L728,165 Z",
    /* Japan */
    "M832,72 L840,65 L848,70 L845,82 L838,88 L832,82 Z",
    /* Indonesia */
    "M745,218 L762,212 L778,215 L795,218 L808,222 L815,228 L808,235 L795,238 L778,238 L762,235 L750,230 L745,225 Z",
    /* Philippines */
    "M802,168 L810,162 L815,170 L812,182 L806,188 L800,180 Z",
    /* Australia */
    "M778,278 L808,265 L838,262 L865,268 L885,282 L892,302 L885,322 L868,338 L845,348 L822,350 L800,342 L785,328 L778,308 L775,292 Z",
    /* New Zealand */
    "M905,340 L912,332 L918,340 L916,355 L910,362 L904,352 Z",
    /* Central America */
    "M118,175 L128,170 L140,172 L150,178 L158,188 L152,198 L142,205 L132,208 L122,205 L115,195 L112,185 Z",
    /* Caribbean islands (simplified) */
    "M175,178 L185,175 L192,178 L190,185 L182,188 Z",
  ];

  const gridLons = [-150, -120, -90, -60, -30, 0, 30, 60, 90, 120, 150];
  const gridLats = [-60, -40, -20, 0, 20, 40, 60];

  return (
    <div className="absolute inset-0 p-3">
      <div
        className="relative h-full w-full overflow-hidden rounded-xl border border-cyan-500/10"
        style={{
          background: "radial-gradient(ellipse at 50% 40%, rgba(0,20,40,1) 0%, rgba(4,10,20,1) 60%, rgba(2,5,12,1) 100%)",
          cursor: dragging ? "grabbing" : "grab",
        }}
        onWheel={handleWheel}
        onMouseDown={(e) => { setDragging(true); setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y }); }}
        onMouseMove={(e) => { if (dragging) setPan({ x: e.clientX - dragStart.x, y: e.clientY - dragStart.y }); }}
        onMouseUp={() => setDragging(false)}
        onMouseLeave={() => setDragging(false)}
      >
        {/* Top bar */}
        <div className="absolute top-0 left-0 right-0 z-30 flex items-center justify-between px-4 py-2.5 border-b border-cyan-500/10 bg-black/40 backdrop-blur-sm">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
              <span className="text-[11px] font-mono text-red-400 font-semibold tracking-wide">LIVE THREAT MAP</span>
            </div>
            <span className="text-[10px] font-mono text-cyan-500/60">|</span>
            <span className="px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20 text-[10px] font-mono text-cyan-400">
              {points.length} ACTIVE {points.length === 1 ? "NODE" : "NODES"}
            </span>
            {points.some(p => p.actors.length > 0) && (
              <span className="px-2 py-0.5 rounded bg-red-500/10 border border-red-500/20 text-[10px] font-mono text-red-400">
                APT ATTRIBUTED
              </span>
            )}
          </div>
          <div className="flex items-center gap-1.5">
            <button onClick={() => setZoom(Math.min(4, zoom + 0.4))} className="w-6 h-6 rounded bg-white/5 border border-white/10 text-white/50 hover:text-cyan-400 hover:border-cyan-500/30 text-xs font-mono transition-colors">+</button>
            <button onClick={() => setZoom(Math.max(0.5, zoom - 0.4))} className="w-6 h-6 rounded bg-white/5 border border-white/10 text-white/50 hover:text-cyan-400 hover:border-cyan-500/30 text-xs font-mono transition-colors">−</button>
            <button onClick={() => { setZoom(1); setPan({ x: 0, y: 0 }); }} className="w-6 h-6 rounded bg-white/5 border border-white/10 text-white/50 hover:text-cyan-400 hover:border-cyan-500/30 text-[9px] font-mono transition-colors">⟳</button>
            <span className="ml-1 text-[10px] font-mono text-white/30">{zoom.toFixed(1)}x</span>
          </div>
        </div>

        {/* SVG map */}
        <svg
          viewBox="0 0 1000 520"
          className="absolute inset-0 w-full h-full"
          style={{
            transform: `scale(${zoom}) translate(${pan.x / zoom}px, ${pan.y / zoom}px)`,
            cursor: dragging ? "grabbing" : "grab",
          }}
          preserveAspectRatio="xMidYMid meet"
        >
          <defs>
            <radialGradient id="threatGlow" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#ff2222" stopOpacity="0.8" />
              <stop offset="50%" stopColor="#ff2222" stopOpacity="0.2" />
              <stop offset="100%" stopColor="#ff2222" stopOpacity="0" />
            </radialGradient>
            <radialGradient id="nodeGlow" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#00e5ff" stopOpacity="0.6" />
              <stop offset="50%" stopColor="#00e5ff" stopOpacity="0.15" />
              <stop offset="100%" stopColor="#00e5ff" stopOpacity="0" />
            </radialGradient>
            <filter id="softGlow">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
            </filter>
            <filter id="strongGlow">
              <feGaussianBlur stdDeviation="5" result="blur" />
              <feMerge><feMergeNode in="blur" /><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
            </filter>
          </defs>

          {/* Ocean gradient background */}
          <rect x="0" y="0" width="1000" height="520" fill="transparent" />

          {/* Lat/lon grid */}
          {gridLons.map((lon) => {
            const { x } = project(0, lon);
            return <line key={`glon-${lon}`} x1={x} y1={10} x2={x} y2={510} stroke="rgba(0,180,220,0.04)" strokeWidth="0.5" strokeDasharray="2 6" />;
          })}
          {gridLats.map((lat) => {
            const { y } = project(lat, 0);
            return <line key={`glat-${lat}`} x1={10} y1={y} x2={990} y2={y} stroke="rgba(0,180,220,0.04)" strokeWidth="0.5" strokeDasharray="2 6" />;
          })}
          {/* Equator highlight */}
          {(() => { const { y } = project(0, 0); return <line x1={0} y1={y} x2={1000} y2={y} stroke="rgba(0,180,220,0.06)" strokeWidth="0.8" />; })()}

          {/* Continent landmasses */}
          {LAND.map((d, i) => (
            <path
              key={`land-${i}`}
              d={d}
              fill="rgba(20,60,90,0.35)"
              stroke="rgba(0,200,240,0.12)"
              strokeWidth="0.6"
              strokeLinejoin="round"
            />
          ))}

          {/* Connection arcs between all threat points */}
          {points.map((pA, iA) =>
            points.slice(iA + 1).map((pB, iB) => {
              const a = project(pA.lat, pA.lon);
              const b = project(pB.lat, pB.lon);
              const midX = (a.x + b.x) / 2;
              const midY = Math.min(a.y, b.y) - 25 - Math.abs(a.x - b.x) * 0.08;
              return (
                <g key={`arc-${iA}-${iB}`}>
                  {/* Glow arc */}
                  <path
                    d={`M${a.x},${a.y} Q${midX},${midY} ${b.x},${b.y}`}
                    fill="none" stroke="rgba(255,50,50,0.08)" strokeWidth="4"
                  />
                  {/* Main arc */}
                  <path
                    d={`M${a.x},${a.y} Q${midX},${midY} ${b.x},${b.y}`}
                    fill="none" stroke="rgba(255,60,60,0.35)" strokeWidth="1.2"
                    strokeDasharray="6 4"
                  >
                    <animate attributeName="stroke-dashoffset" from="0" to="-10" dur="1.5s" repeatCount="indefinite" />
                  </path>
                  {/* Traveling dot */}
                  <circle r="2.5" fill="#ff4444" filter="url(#softGlow)">
                    <animateMotion
                      dur={`${2 + iB * 0.5}s`}
                      repeatCount="indefinite"
                      path={`M${a.x},${a.y} Q${midX},${midY} ${b.x},${b.y}`}
                    />
                  </circle>
                </g>
              );
            })
          )}

          {/* Threat point markers */}
          {points.map((point, idx) => {
            const { x, y } = project(point.lat, point.lon);
            const isHovered = hoveredIdx === idx;
            const hasActor = point.actors.length > 0;
            const color = hasActor ? "#ff3333" : "#00e5ff";
            const glowId = hasActor ? "threatGlow" : "nodeGlow";

            return (
              <g
                key={`pt-${point.ip}-${idx}`}
                onMouseEnter={() => setHoveredIdx(idx)}
                onMouseLeave={() => setHoveredIdx(null)}
                style={{ cursor: "pointer" }}
              >
                {/* Outer radar pulse — 2 staggered rings */}
                <circle cx={x} cy={y} r="10" fill="none" stroke={color} strokeWidth="0.6" opacity="0">
                  <animate attributeName="r" values="6;35" dur="3s" repeatCount="indefinite" begin={`${idx * 0.3}s`} />
                  <animate attributeName="opacity" values="0.5;0" dur="3s" repeatCount="indefinite" begin={`${idx * 0.3}s`} />
                </circle>
                <circle cx={x} cy={y} r="10" fill="none" stroke={color} strokeWidth="0.4" opacity="0">
                  <animate attributeName="r" values="6;35" dur="3s" repeatCount="indefinite" begin={`${idx * 0.3 + 1.5}s`} />
                  <animate attributeName="opacity" values="0.3;0" dur="3s" repeatCount="indefinite" begin={`${idx * 0.3 + 1.5}s`} />
                </circle>

                {/* Glow blob */}
                <circle cx={x} cy={y} r={isHovered ? 24 : 18} fill={`url(#${glowId})`} />

                {/* Crosshair */}
                <line x1={x - 10} y1={y} x2={x - 5} y2={y} stroke={color} strokeWidth="0.6" opacity="0.4" />
                <line x1={x + 5} y1={y} x2={x + 10} y2={y} stroke={color} strokeWidth="0.6" opacity="0.4" />
                <line x1={x} y1={y - 10} x2={x} y2={y - 5} stroke={color} strokeWidth="0.6" opacity="0.4" />
                <line x1={x} y1={y + 5} x2={x} y2={y + 10} stroke={color} strokeWidth="0.6" opacity="0.4" />

                {/* Core dot */}
                <circle cx={x} cy={y} r={isHovered ? 5 : 3.5} fill={color} filter="url(#strongGlow)" />
                <circle cx={x} cy={y} r="1.5" fill="white" opacity="0.9" />

                {/* Info card */}
                <g opacity={isHovered ? 1 : 0.85}>
                  <rect
                    x={x + 14} y={y - 26}
                    width={Math.max(point.ip.length * 7.2 + 16, 110)} height={38} rx="3"
                    fill="rgba(4,12,24,0.92)"
                    stroke={color}
                    strokeWidth={isHovered ? 1 : 0.5}
                    strokeOpacity={isHovered ? 0.8 : 0.3}
                  />
                  {/* Color tag bar */}
                  <rect x={x + 14} y={y - 26} width="3" height={38} rx="1.5" fill={color} opacity="0.6" />
                  <text x={x + 24} y={y - 10} fill={color} fontSize="11" fontFamily="monospace" fontWeight="700" letterSpacing="0.5">
                    {point.ip}
                  </text>
                  <text x={x + 24} y={y + 5} fill="rgba(180,200,220,0.7)" fontSize="9" fontFamily="monospace">
                    {point.geo}{point.actors[0] ? ` · ${point.actors[0]}` : ""}
                  </text>
                </g>

                {/* APT badge */}
                {hasActor && (
                  <g>
                    <rect x={x - 18} y={y + 12} width="36" height="14" rx="2" fill="rgba(255,30,30,0.15)" stroke="rgba(255,60,60,0.4)" strokeWidth="0.5" />
                    <text x={x} y={y + 22} fill="#ff5555" fontSize="7" fontFamily="monospace" fontWeight="700" textAnchor="middle" letterSpacing="0.8">APT</text>
                  </g>
                )}
              </g>
            );
          })}
        </svg>

        {/* Scanline overlay */}
        <div className="absolute inset-0 pointer-events-none opacity-[0.015]"
          style={{ background: "repeating-linear-gradient(0deg, transparent, transparent 3px, rgba(0,229,255,0.4) 3px, rgba(0,229,255,0.4) 4px)" }}
        />

        {/* Bottom legend */}
        <div className="absolute bottom-3 left-3 z-30 flex items-center gap-4 px-3 py-1.5 rounded-lg bg-black/50 border border-white/5 backdrop-blur-sm">
          <div className="flex items-center gap-1.5">
            <div className="w-2 h-2 rounded-full bg-red-500 shadow-[0_0_6px_rgba(255,50,50,0.6)]" />
            <span className="text-[9px] font-mono text-white/40">APT Attributed</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-2 h-2 rounded-full bg-cyan-400 shadow-[0_0_6px_rgba(0,229,255,0.6)]" />
            <span className="text-[9px] font-mono text-white/40">Infrastructure</span>
          </div>
          <div className="flex items-center gap-1.5">
            <svg width="16" height="6"><line x1="0" y1="3" x2="16" y2="3" stroke="rgba(255,60,60,0.5)" strokeWidth="1" strokeDasharray="3 2" /></svg>
            <span className="text-[9px] font-mono text-white/40">Attack Path</span>
          </div>
        </div>
      </div>
    </div>
  );
}
