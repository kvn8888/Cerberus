/**
 * components/panels/GraphPanel.tsx — Force-directed graph visualization
 *
 * Renders the threat attack chain as an interactive force-directed graph.
 * Uses react-force-graph-2d for the visualization. Node colors follow
 * the design system's node-type palette.
 *
 * In the idle state, shows a placeholder with the graph legend.
 * When an investigation completes, it would render the traversal paths.
 *
 * Note: In this version, we generate a mock graph from the narrative
 * metadata since the backend SSE doesn't send graph node data directly.
 * A production version would add a /api/graph endpoint.
 */
import { useMemo, useRef, useCallback, useEffect } from "react";
import ForceGraph2D from "react-force-graph-2d";
import type { InvestigationState, EntityType } from "../../types/api";
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

  /* Generate graph data when investigation completes */
  const graphData = useMemo(() => {
    if (state.status === "complete" && state.pathsFound > 0) {
      return generateDemoGraph(state.entity, state.entityType);
    }
    return { nodes: [], links: [] };
  }, [state.status, state.pathsFound, state.entity, state.entityType]);

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

  const hasGraph = graphData.nodes.length > 0;

  return (
    <div
      ref={containerRef}
      className={cn(
        "relative h-full w-full overflow-hidden",
        "grid-bg"
      )}
    >
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
          width={containerRef.current?.clientWidth || 600}
          height={containerRef.current?.clientHeight || 400}
        />
      )}

      {/* ── Idle / waiting state ─────────────────────────── */}
      {!hasGraph && (
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="text-center px-8">
            {state.status === "running" ? (
              <div className="space-y-3">
                <div className="h-16 w-16 mx-auto rounded-full border-2 border-primary/30 border-t-primary animate-spin" />
                <p className="text-sm text-muted-foreground font-mono">
                  Traversing knowledge graph...
                </p>
              </div>
            ) : (
              <div className="space-y-3 opacity-40">
                <svg
                  className="h-24 w-24 mx-auto text-muted-foreground"
                  viewBox="0 0 100 100"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1"
                >
                  {/* Simple graph icon */}
                  <circle cx="50" cy="20" r="6" />
                  <circle cx="25" cy="55" r="6" />
                  <circle cx="75" cy="55" r="6" />
                  <circle cx="50" cy="85" r="6" />
                  <line x1="50" y1="26" x2="25" y2="49" />
                  <line x1="50" y1="26" x2="75" y2="49" />
                  <line x1="25" y1="61" x2="50" y2="79" />
                  <line x1="75" y1="61" x2="50" y2="79" />
                </svg>
                <p className="text-sm text-muted-foreground">
                  Graph visualization will appear here
                </p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Legend overlay ───────────────────────────────── */}
      <div
        className={cn(
          "absolute bottom-4 left-4 p-3 rounded-lg",
          "bg-surface/80 backdrop-blur-md border border-border/50",
          "text-[10px] font-mono"
        )}
      >
        <p className="text-muted-foreground uppercase tracking-wider mb-2 font-semibold">
          Node Types
        </p>
        <div className="grid grid-cols-2 gap-x-4 gap-y-1">
          {LEGEND_ITEMS.map((item) => (
            <div key={item.label} className="flex items-center gap-1.5">
              <span
                className="node-dot"
                style={{ backgroundColor: item.color }}
              />
              <span className="text-muted-foreground">{item.label}</span>
            </div>
          ))}
        </div>
        {hasGraph && (
          <div className="mt-2 pt-2 border-t border-border/50 flex items-center gap-1.5">
            <span className="w-4 border-t border-dashed border-threat-medium" />
            <span className="text-muted-foreground">Synthetic link</span>
          </div>
        )}
      </div>
    </div>
  );
}
