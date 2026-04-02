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
import { X, Search, Filter, ChevronLeft, ChevronRight, Route, MessageSquare, Send, Trash2, Eye } from "lucide-react";
import type { InvestigationState, EntityType, GraphNode } from "../../types/api";
import { cn } from "../../lib/utils";
import { GraphMinimap } from "./GraphMinimap";
import { buildAttackPathOrder } from "../../lib/attackPath";
import {
  listAnnotations, createAnnotation, deleteAnnotation, type Annotation,
  addToWatchlist,
} from "../../lib/api";

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
  /* Relationship type filter — togglable edge types */
  const [hiddenRelTypes, setHiddenRelTypes] = useState<Set<string>>(new Set());
  /* Node search — highlights matching nodes */
  const [searchQuery, setSearchQuery] = useState("");
  /* Show/hide the filter panel */
  const [showFilters, setShowFilters] = useState(false);
  /* Attack path stepper — walk the graph from the investigation root */
  const [attackStepIndex, setAttackStepIndex] = useState(0);

  /* ── Annotation state — notes on graph nodes ───────── */
  const [annotations, setAnnotations] = useState<Annotation[]>([]);
  const [annotationText, setAnnotationText] = useState("");
  const [annotationBusy, setAnnotationBusy] = useState(false);

  /* Fetch annotations when selected node changes */
  useEffect(() => {
    if (!selectedNode) { setAnnotations([]); return; }
    const entity = selectedNode.label || selectedNode.id;
    listAnnotations(entity).then(setAnnotations).catch(() => setAnnotations([]));
  }, [selectedNode?.id]);

  /* Create a new annotation on the selected node */
  const handleAddAnnotation = useCallback(async () => {
    if (!selectedNode || !annotationText.trim()) return;
    setAnnotationBusy(true);
    try {
      const ann = await createAnnotation(
        selectedNode.label || selectedNode.id,
        annotationText.trim()
      );
      setAnnotations((prev) => [ann, ...prev]);
      setAnnotationText("");
    } catch (err) {
      console.error("Create annotation failed:", err);
    } finally {
      setAnnotationBusy(false);
    }
  }, [selectedNode, annotationText]);

  /* Delete an annotation */
  const handleDeleteAnnotation = useCallback(async (id: string) => {
    try {
      await deleteAnnotation(id);
      setAnnotations((prev) => prev.filter((a) => a.id !== id));
    } catch (err) {
      console.error("Delete annotation failed:", err);
    }
  }, []);

  /* ── Watchlist — quick-watch a node ────────────────── */
  const [watchBusy, setWatchBusy] = useState(false);
  const [watchSuccess, setWatchSuccess] = useState<string | null>(null);

  const handleWatch = useCallback(async () => {
    if (!selectedNode) return;
    setWatchBusy(true);
    try {
      const typeMap: Record<string, string> = {
        Package: "package", CVE: "cve", IP: "ip",
        Domain: "domain", ThreatActor: "threatactor", FraudSignal: "fraudsignal",
      };
      const eType = typeMap[selectedNode.type] || "package";
      await addToWatchlist(selectedNode.label || selectedNode.id, eType);
      setWatchSuccess(selectedNode.label || selectedNode.id);
      setTimeout(() => setWatchSuccess(null), 2000);
    } catch (err) {
      console.error("Watch failed:", err);
    } finally {
      setWatchBusy(false);
    }
  }, [selectedNode]);

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

  /* Ordered walk from investigation root — for attack path stepper */
  const attackPathOrder = useMemo(() => {
    if (!graphData.nodes.length) return [] as string[];
    return buildAttackPathOrder(
      graphData.nodes as GraphNode[],
      graphData.links as any,
      state.entity
    );
  }, [graphData.nodes, graphData.links, state.entity]);

  /* Extract unique relationship types from links for the filter UI */
  const relTypes = useMemo(() => {
    const types = new Set<string>();
    graphData.links.forEach((link: any) => {
      if (link.type) types.add(link.type);
    });
    return Array.from(types).sort();
  }, [graphData.links]);

  /* Apply relationship type filter to graph data */
  const filteredGraphData = useMemo(() => {
    if (hiddenRelTypes.size === 0) return graphData;
    const filteredLinks = graphData.links.filter(
      (link: any) => !hiddenRelTypes.has(link.type || "")
    );
    /* Keep only nodes that appear in at least one visible link */
    const visibleNodeIds = new Set<string>();
    filteredLinks.forEach((link: any) => {
      const src = typeof link.source === "object" ? link.source.id : link.source;
      const tgt = typeof link.target === "object" ? link.target.id : link.target;
      visibleNodeIds.add(src);
      visibleNodeIds.add(tgt);
    });
    const filteredNodes = graphData.nodes.filter((n: any) => visibleNodeIds.has(n.id));
    return { nodes: filteredNodes, links: filteredLinks };
  }, [graphData, hiddenRelTypes]);

  /* Custom node rendering on the canvas — includes search highlight logic */
  const pathHighlightId =
    attackPathOrder.length > 0 ? attackPathOrder[Math.min(attackStepIndex, attackPathOrder.length - 1)] : null;

  const paintNode = useCallback(
    (node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const label = node.label || node.id;
      const fontSize = Math.max(10 / globalScale, 3);
      const nodeRadius = Math.max(node.val || 5, 3);
      const color = NODE_COLORS[node.type] || "#666";
      const isMatch = searchQuery && label.toLowerCase().includes(searchQuery.toLowerCase());
      const isPathStep = pathHighlightId && node.id === pathHighlightId;

      /* Glow effect — stronger for search matches */
      ctx.shadowColor = isMatch ? "#FFD700" : color;
      ctx.shadowBlur = isMatch ? 20 : 12;

      /* Attack path step — cyan ring */
      if (isPathStep && !isMatch) {
        ctx.beginPath();
        ctx.arc(node.x, node.y, nodeRadius + 5, 0, 2 * Math.PI);
        ctx.strokeStyle = "#00E5FF";
        ctx.lineWidth = 3;
        ctx.stroke();
      }

      /* Highlight ring for search matches */
      if (isMatch) {
        ctx.beginPath();
        ctx.arc(node.x, node.y, nodeRadius + 3, 0, 2 * Math.PI);
        ctx.strokeStyle = "#FFD700";
        ctx.lineWidth = 2;
        ctx.stroke();
      }

      /* Node circle */
      ctx.beginPath();
      ctx.arc(node.x, node.y, nodeRadius, 0, 2 * Math.PI);
      ctx.fillStyle = isMatch ? "#FFD700" : isPathStep ? "#00E5FF" : color;
      ctx.fill();

      /* Reset shadow for text */
      ctx.shadowBlur = 0;

      /* Label */
      ctx.font = `${fontSize}px "JetBrains Mono", monospace`;
      ctx.textAlign = "center";
      ctx.textBaseline = "top";
      ctx.fillStyle = isMatch ? "#FFD700" : "rgba(200, 210, 220, 0.9)";
      ctx.fillText(label, node.x, node.y + nodeRadius + 2);
    },
    [searchQuery, pathHighlightId]
  );

  /* Custom link rendering — dashed for synthetic edges */
  const paintLink = useCallback(
    (link: any, ctx: CanvasRenderingContext2D) => {
      const source = link.source;
      const target = link.target;
      const confidence = Math.max(0.2, Math.min(0.99, Number(link.confidence ?? 0.75)));
      const lineOpacity = 0.12 + confidence * 0.45;

      ctx.beginPath();

      if (link.dashed) {
        ctx.setLineDash([4, 4]);
        ctx.strokeStyle = `rgba(255, 200, 50, ${Math.min(0.75, lineOpacity + 0.1)})`;
      } else {
        ctx.setLineDash([]);
        ctx.strokeStyle = `rgba(0, 229, 255, ${lineOpacity})`;
      }

      ctx.lineWidth = 0.75 + confidence * 2.25;
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

  /* Auto-center the graph on the current attack-path step node when the
     user clicks next/prev so they don't have to hunt for the cyan ring. */
  useEffect(() => {
    if (!graphRef.current || !attackPathOrder.length) return;
    const nodeId = attackPathOrder[Math.min(attackStepIndex, attackPathOrder.length - 1)];
    const node = graphData.nodes.find((n: any) => n.id === nodeId) as any;
    if (node && typeof node.x === "number" && typeof node.y === "number") {
      graphRef.current.centerAt(node.x as number, node.y as number, 300);
      graphRef.current.zoom(3, 300);
    }
  }, [attackStepIndex, attackPathOrder, graphData.nodes]);

  /* Build a quick lookup from node ID → node object for the stepper label */
  const nodeById = useMemo(() => {
    const map = new Map<string, GraphNode>();
    for (const n of graphData.nodes as GraphNode[]) map.set(n.id, n);
    return map;
  }, [graphData.nodes]);

  /* New graph results invalidate prior node selections and reset filters */
  useEffect(() => {
    setSelectedNode(null);
    setSearchQuery("");
    setHiddenRelTypes(new Set());
    setShowFilters(false);
    setAttackStepIndex(0);
  }, [state.entity, state.entityType, state.status]);

  const hasGraph = graphData.nodes.length > 0;
  const hasFilteredGraph = filteredGraphData.nodes.length > 0;

  return (
    <div
      ref={containerRef}
      className={cn(
        "relative h-full w-full overflow-hidden",
        "grid-bg"
      )}
    >
      {/* View toggle is handled by the parent ViewNav component */}

      {/* ── Search + Filter toolbar ──────────────────────── */}
      {hasGraph && (
        <div className="absolute top-3 right-3 z-20 flex items-center gap-2">
          <div className="hidden sm:flex items-center gap-1 rounded-md border border-border/60 bg-surface/90 px-2 py-1 text-[10px] font-mono text-muted-foreground backdrop-blur-sm">
            <span className="h-1.5 w-1.5 rounded-full bg-primary/70" />
            confidence-weighted
          </div>
          {/* Node search */}
          <div className="relative">
            <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3 w-3 text-muted-foreground" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search nodes..."
              className="pl-7 pr-3 py-1.5 rounded-md text-[11px] font-mono bg-surface/90 backdrop-blur-sm border border-border/60 text-foreground placeholder:text-muted-foreground/40 focus:outline-none focus:border-primary/50 w-40"
            />
          </div>
          {/* Filter toggle */}
          <button
            onClick={() => setShowFilters(!showFilters)}
            className={cn(
              "p-1.5 rounded-md text-xs font-mono border transition-all",
              showFilters
                ? "bg-primary/15 text-primary border-primary/30"
                : "bg-surface/90 backdrop-blur-sm text-muted-foreground border-border/60 hover:text-foreground"
            )}
            title="Filter relationships"
          >
            <Filter className="h-3.5 w-3.5" />
          </button>
        </div>
      )}

      {/* ── Relationship type filter panel ───────────────── */}
      {hasGraph && showFilters && relTypes.length > 0 && (
        <div className="absolute top-12 right-3 z-20 glass-panel rounded-lg p-3 w-52 animate-in slide-in-from-top-2 duration-200">
          <p className="text-[10px] font-mono text-muted-foreground uppercase tracking-wider mb-2">
            Relationship Types
          </p>
          <div className="space-y-1.5">
            {relTypes.map((rt) => (
              <label key={rt} className="flex items-center gap-2 text-[11px] font-mono cursor-pointer group">
                <input
                  type="checkbox"
                  checked={!hiddenRelTypes.has(rt)}
                  onChange={() => {
                    setHiddenRelTypes((prev) => {
                      const next = new Set(prev);
                      if (next.has(rt)) next.delete(rt);
                      else next.add(rt);
                      return next;
                    });
                  }}
                  className="rounded border-border accent-primary h-3 w-3"
                />
                <span className="text-muted-foreground group-hover:text-foreground transition-colors">
                  {rt.replace(/_/g, " ")}
                </span>
              </label>
            ))}
          </div>
        </div>
      )}

      {/* ── Graph visualization ─────────────────────────── */}
      {hasFilteredGraph && (
        <ForceGraph2D
          ref={graphRef}
          graphData={filteredGraphData}
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

          {/* Watch button — adds this entity to the watchlist */}
          <button
            onClick={handleWatch}
            disabled={watchBusy}
            className={cn(
              "w-full mb-2 py-1 rounded text-[10px] font-mono flex items-center justify-center gap-1.5 transition-all",
              watchSuccess
                ? "bg-success/15 text-success border border-success/30"
                : "bg-surface-raised/50 text-muted-foreground border border-border/30 hover:border-primary/30 hover:text-primary"
            )}
          >
            <Eye className="h-3 w-3" />
            {watchSuccess ? "Watching!" : watchBusy ? "Adding..." : "Watch Entity"}
          </button>

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

          {/* ── Annotations section ──────────────────────── */}
          <div className="mt-3 pt-3 border-t border-border/30">
            <p className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest mb-2 flex items-center gap-1">
              <MessageSquare className="h-3 w-3" />
              Notes ({annotations.length})
            </p>

            {/* Existing annotations */}
            {annotations.length > 0 && (
              <div className="space-y-1.5 mb-2 max-h-32 overflow-y-auto">
                {annotations.map((ann) => (
                  <div key={ann.id} className="group p-1.5 rounded bg-surface-raised/40 border border-border/20">
                    <p className="text-[10px] text-foreground/80 leading-relaxed break-words">{ann.text}</p>
                    <div className="flex items-center justify-between mt-1">
                      <span className="text-[8px] text-muted-foreground/40">
                        {ann.author} · {new Date(ann.created_at).toLocaleDateString()}
                      </span>
                      <button
                        onClick={() => handleDeleteAnnotation(ann.id)}
                        className="opacity-0 group-hover:opacity-100 p-0.5 text-muted-foreground/40 hover:text-threat-high transition-all"
                      >
                        <Trash2 className="h-2.5 w-2.5" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Add annotation input */}
            <div className="flex gap-1">
              <input
                type="text"
                value={annotationText}
                onChange={(e) => setAnnotationText(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleAddAnnotation()}
                placeholder="Add a note..."
                className="flex-1 px-2 py-1 rounded text-[10px] font-mono bg-surface-raised border border-border/30 text-foreground placeholder:text-muted-foreground/30 focus:outline-none focus:border-primary/40"
              />
              <button
                onClick={handleAddAnnotation}
                disabled={!annotationText.trim() || annotationBusy}
                className="p-1 rounded text-muted-foreground hover:text-primary disabled:opacity-30 transition-colors"
              >
                <Send className="h-3 w-3" />
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Attack path stepper — walk the kill chain from the investigation root */}
      {hasGraph && attackPathOrder.length > 0 && (() => {
        const currentNodeId = attackPathOrder[Math.min(attackStepIndex, attackPathOrder.length - 1)];
        const currentNode = nodeById.get(currentNodeId);
        const nodeLabel = currentNode?.label || currentNodeId;
        const nodeType = currentNode?.type || "";
        /* Truncate long labels so the stepper doesn't blow out horizontally */
        const displayLabel = nodeLabel.length > 28 ? nodeLabel.slice(0, 26) + "…" : nodeLabel;
        return (
        <div className="absolute bottom-14 left-1/2 -translate-x-1/2 z-20 flex items-center gap-2 px-3 py-2 rounded-lg bg-surface/95 backdrop-blur-md border border-primary/25 shadow-lg max-w-[90%]">
          <Route className="h-3.5 w-3.5 text-primary flex-shrink-0" />
          <span className="text-[10px] font-mono text-muted-foreground uppercase">Attack path</span>
          <button
            type="button"
            disabled={attackStepIndex <= 0}
            onClick={() => setAttackStepIndex((i) => Math.max(0, i - 1))}
            className="p-1 rounded hover:bg-primary/10 disabled:opacity-30"
          >
            <ChevronLeft className="h-4 w-4" />
          </button>
          <div className="flex flex-col items-center min-w-[140px]">
            <span className="text-[11px] font-mono text-foreground truncate max-w-[200px]" title={nodeLabel}>
              {displayLabel}
            </span>
            <span className="text-[9px] font-mono text-muted-foreground">
              {nodeType && <span className="mr-1">{nodeType}</span>}
              {attackStepIndex + 1} / {attackPathOrder.length}
            </span>
          </div>
          <button
            type="button"
            disabled={attackStepIndex >= attackPathOrder.length - 1}
            onClick={() => setAttackStepIndex((i) => Math.min(attackPathOrder.length - 1, i + 1))}
            className="p-1 rounded hover:bg-primary/10 disabled:opacity-30"
          >
            <ChevronRight className="h-4 w-4" />
          </button>
        </div>
        );
      })()}

      {/* ── Minimap overview ────────────────────────────── */}
      {hasGraph && <GraphMinimap graphData={filteredGraphData} />}

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
