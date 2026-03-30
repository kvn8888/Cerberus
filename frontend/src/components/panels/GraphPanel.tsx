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
  const [viewMode, setViewMode] = useState<"graph" | "map">("graph");
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
      <div className="absolute left-4 top-4 z-20 flex items-center gap-2">
        {(["graph", "map"] as const).map((mode) => (
          <button
            key={mode}
            type="button"
            onClick={() => setViewMode(mode)}
            className={cn(
              "rounded-full border px-3 py-1 text-[10px] font-mono uppercase tracking-[0.15em]",
              viewMode === mode
                ? "border-primary/40 bg-primary/15 text-primary"
                : "border-border bg-surface/80 text-muted-foreground"
            )}
          >
            {mode === "graph" ? "Threat Graph" : "Geo Map"}
          </button>
        ))}
      </div>

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

  /* Convert lat/lon to Mercator-projected SVG coordinates */
  const project = (lat: number, lon: number) => {
    const x = ((lon + 180) / 360) * 1000;
    const latRad = (lat * Math.PI) / 180;
    const mercY = Math.log(Math.tan(Math.PI / 4 + latRad / 2));
    const y = 250 - mercY * 160;
    return { x, y };
  };

  const handleWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    const next = Math.max(0.5, Math.min(4, zoom - e.deltaY * 0.002));
    setZoom(next);
  };

  /* Simplified world boundary paths — continents outlined */
  const continents = [
    /* North America */
    "M60 120 L120 80 L200 70 L240 90 L260 120 L250 160 L220 200 L180 220 L140 230 L100 240 L80 220 L60 200 Z",
    /* South America */
    "M160 260 L200 240 L230 260 L240 300 L230 360 L210 400 L180 420 L160 400 L150 350 L140 300 Z",
    /* Europe */
    "M440 80 L480 60 L530 70 L550 90 L540 120 L520 140 L490 150 L460 140 L440 120 Z",
    /* Africa */
    "M440 160 L500 150 L540 170 L560 210 L550 280 L530 340 L500 370 L470 360 L440 320 L430 260 L420 200 Z",
    /* Asia */
    "M550 60 L650 40 L750 50 L820 80 L850 120 L830 170 L790 200 L730 210 L670 190 L620 170 L580 150 L560 120 L550 90 Z",
    /* Oceania */
    "M760 300 L820 280 L870 290 L890 320 L870 360 L830 370 L790 350 L760 330 Z",
    /* Small landmasses */
    "M740 220 L770 210 L790 230 L780 250 L750 250 Z",
  ];

  /* Grid lines for longitude and latitude */
  const gridLons = [-120, -60, 0, 60, 120];
  const gridLats = [-40, 0, 40];

  return (
    <div className="absolute inset-0 p-4">
      <div
        className="relative h-full w-full overflow-hidden rounded-2xl border border-primary/10 bg-[radial-gradient(ellipse_at_center,rgba(0,229,255,0.04),transparent_70%)] cursor-grab active:cursor-grabbing"
        onWheel={handleWheel}
        onMouseDown={(e) => { setDragging(true); setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y }); }}
        onMouseMove={(e) => { if (dragging) setPan({ x: e.clientX - dragStart.x, y: e.clientY - dragStart.y }); }}
        onMouseUp={() => setDragging(false)}
        onMouseLeave={() => setDragging(false)}
      >
        {/* Zoom controls */}
        <div className="absolute top-3 right-3 z-30 flex flex-col gap-1">
          <button onClick={() => setZoom(Math.min(4, zoom + 0.3))} className="w-7 h-7 rounded bg-surface-raised/80 border border-border/40 text-muted-foreground hover:text-primary text-xs font-mono">+</button>
          <button onClick={() => setZoom(Math.max(0.5, zoom - 0.3))} className="w-7 h-7 rounded bg-surface-raised/80 border border-border/40 text-muted-foreground hover:text-primary text-xs font-mono">−</button>
          <button onClick={() => { setZoom(1); setPan({ x: 0, y: 0 }); }} className="w-7 h-7 rounded bg-surface-raised/80 border border-border/40 text-muted-foreground hover:text-primary text-[8px] font-mono">⟳</button>
        </div>

        {/* Stats overlay */}
        <div className="absolute top-3 left-3 z-30 flex items-center gap-3">
          <span className="px-2 py-1 rounded bg-surface-raised/60 border border-primary/15 text-[10px] font-mono text-primary">
            {points.length} THREAT NODES
          </span>
          <span className="px-2 py-1 rounded bg-surface-raised/60 border border-border/30 text-[10px] font-mono text-muted-foreground">
            {zoom.toFixed(1)}x
          </span>
        </div>

        <svg
          viewBox="0 0 1000 500"
          className="h-full w-full"
          style={{ transform: `scale(${zoom}) translate(${pan.x / zoom}px, ${pan.y / zoom}px)` }}
        >
          <defs>
            <radialGradient id="pointGlow" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#ff4444" stopOpacity="0.6" />
              <stop offset="100%" stopColor="#ff4444" stopOpacity="0" />
            </radialGradient>
            <radialGradient id="pointGlowCyan" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#00e5ff" stopOpacity="0.4" />
              <stop offset="100%" stopColor="#00e5ff" stopOpacity="0" />
            </radialGradient>
            <filter id="glow">
              <feGaussianBlur stdDeviation="2" result="blur" />
              <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
            </filter>
          </defs>

          {/* Grid lines */}
          {gridLons.map((lon) => {
            const { x } = project(0, lon);
            return <line key={`lon-${lon}`} x1={x} y1={0} x2={x} y2={500} stroke="rgba(0,229,255,0.04)" strokeWidth="0.5" />;
          })}
          {gridLats.map((lat) => {
            const { y } = project(lat, 0);
            return <line key={`lat-${lat}`} x1={0} y1={y} x2={1000} y2={y} stroke="rgba(0,229,255,0.04)" strokeWidth="0.5" />;
          })}

          {/* Continent silhouettes */}
          {continents.map((d, i) => (
            <path key={i} d={d} fill="rgba(100,140,180,0.07)" stroke="rgba(0,229,255,0.08)" strokeWidth="0.5" />
          ))}

          {/* Connection lines between threat points */}
          {points.length > 1 && points.slice(1).map((p, i) => {
            const from = project(points[0].lat, points[0].lon);
            const to = project(p.lat, p.lon);
            const midX = (from.x + to.x) / 2;
            const midY = Math.min(from.y, to.y) - 30;
            return (
              <path
                key={`conn-${i}`}
                d={`M${from.x},${from.y} Q${midX},${midY} ${to.x},${to.y}`}
                fill="none"
                stroke="rgba(255,68,68,0.2)"
                strokeWidth="1"
                strokeDasharray="4 4"
              >
                <animate attributeName="stroke-dashoffset" from="0" to="-8" dur="2s" repeatCount="indefinite" />
              </path>
            );
          })}

          {/* Threat points */}
          {points.map((point, idx) => {
            const { x, y } = project(point.lat, point.lon);
            const isHovered = hoveredIdx === idx;
            const isFirst = idx === 0;
            const color = isFirst ? "#ff4444" : "#00e5ff";
            return (
              <g
                key={`${point.ip}-${point.geo}`}
                onMouseEnter={() => setHoveredIdx(idx)}
                onMouseLeave={() => setHoveredIdx(null)}
                style={{ cursor: "pointer" }}
              >
                {/* Outer pulse ring */}
                <circle cx={x} cy={y} r="18" fill={isFirst ? "url(#pointGlow)" : "url(#pointGlowCyan)"}>
                  <animate attributeName="r" values="14;22;14" dur="3s" repeatCount="indefinite" />
                  <animate attributeName="opacity" values="0.6;0.15;0.6" dur="3s" repeatCount="indefinite" />
                </circle>
                {/* Sonar ring */}
                <circle cx={x} cy={y} r="8" fill="none" stroke={color} strokeWidth="0.5" opacity="0.3">
                  <animate attributeName="r" values="8;28" dur="4s" repeatCount="indefinite" begin={`${idx * 0.5}s`} />
                  <animate attributeName="opacity" values="0.4;0" dur="4s" repeatCount="indefinite" begin={`${idx * 0.5}s`} />
                </circle>
                {/* Core dot */}
                <circle cx={x} cy={y} r={isHovered ? 6 : 4} fill={color} filter="url(#glow)" className="transition-all duration-200" />
                {/* Inner bright core */}
                <circle cx={x} cy={y} r="1.5" fill="white" opacity="0.8" />

                {/* Label — always visible */}
                <rect x={x + 10} y={y - 22} width={Math.max(point.ip.length * 7.5, 90)} height={32} rx="4"
                  fill={isHovered ? "rgba(8,14,24,0.95)" : "rgba(8,14,24,0.75)"}
                  stroke={isHovered ? color : "rgba(0,229,255,0.15)"}
                  strokeWidth={isHovered ? 1 : 0.5}
                />
                <text x={x + 16} y={y - 8} fill={color} fontSize="11" fontFamily="monospace" fontWeight="600">
                  {point.ip}
                </text>
                <text x={x + 16} y={y + 5} fill="rgba(208,224,235,0.6)" fontSize="9" fontFamily="monospace">
                  {point.geo}{point.actors[0] ? ` · ${point.actors[0]}` : ""}
                </text>
              </g>
            );
          })}
        </svg>

        {/* Scanline effect */}
        <div className="absolute inset-0 pointer-events-none opacity-[0.02]"
          style={{ background: "repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,229,255,0.5) 2px, rgba(0,229,255,0.5) 3px)" }}
        />
      </div>
    </div>
  );
}
