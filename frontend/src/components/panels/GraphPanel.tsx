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
import { X } from "lucide-react";
import type { InvestigationState, EntityType, GraphNode } from "../../types/api";
import { cn } from "../../lib/utils";

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
  /* Ref for the container div — used to measure dimensions */
  const containerRef = useRef<HTMLDivElement>(null);
  /* Ref for the force graph instance */
  const graphRef = useRef<any>(null);
  /* Track container dimensions so the canvas fills all available space */
  const [containerSize, setContainerSize] = useState({ width: 800, height: 600 });
  /* Currently selected node — shown in the detail sidebar */
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

  /* ResizeObserver keeps the canvas size in sync with the container */
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

  /* New graph results invalidate prior node selections */
  useEffect(() => {
    setSelectedNode(null);
  }, [state.entity, state.entityType, state.status]);

  const hasGraph = graphData.nodes.length > 0;

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
      {hasGraph && (
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
          width={containerSize.width}
          height={containerSize.height}
          onNodeClick={(node: any) => setSelectedNode(node as GraphNode)}
          onBackgroundClick={() => setSelectedNode(null)}
        />
      )}

      {/* ── Idle / waiting state ─────────────────────────── */}
      {!hasGraph && (
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

      {/* ── Node detail sidebar (appears on click) ──────── */}
      {selectedNode && (
        <div className="absolute top-4 right-4 w-64 glass-panel rounded-lg p-4 z-20 animate-in slide-in-from-right-4 duration-200">
          {/* Header with close button */}
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <span
                className="node-dot flex-shrink-0"
                style={{
                  backgroundColor: NODE_COLORS[selectedNode.type] || "#666",
                  boxShadow: `0 0 6px ${(NODE_COLORS[selectedNode.type] || "#666")}40`,
                }}
              />
              <span className="text-xs font-mono uppercase tracking-wider text-muted-foreground">
                {selectedNode.type}
              </span>
            </div>
            <button
              type="button"
              onClick={() => setSelectedNode(null)}
              className="p-1 rounded hover:bg-surface-raised text-muted-foreground/60 hover:text-foreground transition-colors"
              aria-label="Close node details"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>

          {/* Node label / identifier */}
          <p className="text-sm font-mono text-foreground break-all mb-3 leading-relaxed">
            {selectedNode.label || selectedNode.id}
          </p>

          {/* Node properties table */}
          <div className="space-y-1.5 text-[10px] font-mono">
            <div className="flex justify-between text-muted-foreground/60 uppercase tracking-widest border-b border-border/30 pb-1">
              <span>Property</span>
              <span>Value</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground/80">id</span>
              <span className="text-foreground/80 max-w-[140px] truncate text-right">{selectedNode.id}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground/80">type</span>
              <span className="text-foreground/80">{selectedNode.type}</span>
            </div>
            {/* Render any extra properties from the Neo4j node */}
            {Object.entries(selectedNode)
              .filter(([key]) => !["id", "label", "type", "val", "x", "y", "vx", "vy", "fx", "fy", "index", "__indexColor"].includes(key))
              .map(([key, value]) => (
                <div key={key} className="flex justify-between">
                  <span className="text-muted-foreground/80">{key}</span>
                  <span className="text-foreground/80 max-w-[140px] truncate text-right">
                    {typeof value === "object" ? JSON.stringify(value) : String(value)}
                  </span>
                </div>
              ))}
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
