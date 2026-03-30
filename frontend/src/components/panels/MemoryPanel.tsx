/**
 * components/panels/MemoryPanel.tsx — Interactive memory graph with expand
 *
 * Shows memorized threat patterns as an interactive force-directed graph.
 * Starts with core entities only; clicking an expandable node (shown with
 * a "+" ring) fetches its hidden children (Techniques, etc.) and adds
 * them to the graph in place.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import ForceGraph2D, { type ForceGraphMethods } from "react-force-graph-2d";
import { Brain, RefreshCw, Zap } from "lucide-react";
import { fetchMemory, expandMemoryNode } from "../../lib/api";
import { cn } from "../../lib/utils";

interface MemoryNode {
  id: string;
  label: string;
  type: string;
  val: number;
  confirmed: boolean;
  expandable?: boolean;
  hidden_children?: number;
}

interface MemoryLink {
  source: string | MemoryNode;
  target: string | MemoryNode;
  type: string;
  confirmed_at?: number;
}

interface MemoryPanelProps {
  refreshKey: number;
  onCountChange?: (count: number) => void;
}

const NODE_COLORS: Record<string, string> = {
  Package: "#4D94FF",
  CVE: "#FF4D4D",
  IP: "#FF8C26",
  Domain: "#9966FF",
  ThreatActor: "#E64DCC",
  Technique: "#E6337A",
  Account: "#33CC80",
  FraudSignal: "#E6CC33",
};

export function MemoryPanel({ refreshKey, onCountChange }: MemoryPanelProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const fgRef = useRef<ForceGraphMethods | undefined>(undefined);
  const [graphData, setGraphData] = useState<{ nodes: MemoryNode[]; links: MemoryLink[] }>({ nodes: [], links: [] });
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [expanding, setExpanding] = useState<string | null>(null);
  const [lastSaved, setLastSaved] = useState<string | null>(null);
  const [dimensions, setDimensions] = useState({ w: 800, h: 600 });

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await fetchMemory();
      setGraphData({ nodes: data.nodes, links: data.links });
      setTotal(data.total_memorized);
      onCountChange?.(data.total_memorized);
      if (data.total_memorized > 0) {
        setLastSaved(new Date().toLocaleTimeString());
      }
    } catch (err) {
      console.error("Memory fetch failed:", err);
    } finally {
      setLoading(false);
    }
  }, [onCountChange]);

  useEffect(() => {
    load();
  }, [load, refreshKey]);

  // Tune forces based on node count — fewer nodes get more space,
  // many nodes get pulled tighter so the graph stays readable.
  useEffect(() => {
    const fg = fgRef.current;
    if (!fg) return;
    const n = graphData.nodes.length;
    const charge = n > 50 ? -80 : n > 20 ? -150 : -250;
    const dist = n > 50 ? 40 : n > 20 ? 60 : 80;
    fg.d3Force("charge")?.strength(charge);
    fg.d3Force("link")?.distance(dist);
    // Re-heat and zoom to fit after layout settles
    fg.d3ReheatSimulation();
    setTimeout(() => fg.zoomToFit(400, 50), 500);
  }, [graphData]);

  // Track container size
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const obs = new ResizeObserver(([entry]) => {
      setDimensions({ w: entry.contentRect.width, h: entry.contentRect.height });
    });
    obs.observe(el);
    return () => obs.disconnect();
  }, []);

  /** Click handler — expand a node to show its children */
  const handleNodeClick = useCallback(async (node: MemoryNode) => {
    if (!node.expandable || expanding) return;
    setExpanding(node.id);
    try {
      const data = await expandMemoryNode(node.id);
      if (data.nodes.length === 0) return;

      setGraphData((prev) => {
        const existingIds = new Set(prev.nodes.map((n) => n.id));
        const newNodes = data.nodes.filter((n) => !existingIds.has(n.id));
        const existingLinks = new Set(
          prev.links.map((l) => {
            const s = typeof l.source === "string" ? l.source : l.source.id;
            const t = typeof l.target === "string" ? l.target : l.target.id;
            return `${s}-${t}-${l.type}`;
          })
        );
        const newLinks = data.links.filter((l) => {
          const key = `${l.source}-${l.target}-${l.type}`;
          const keyRev = `${l.target}-${l.source}-${l.type}`;
          return !existingLinks.has(key) && !existingLinks.has(keyRev);
        });

        // Mark the expanded node as no longer expandable
        const updatedNodes = prev.nodes.map((n) =>
          n.id === node.id ? { ...n, expandable: false, hidden_children: 0 } : n
        );

        return {
          nodes: [...updatedNodes, ...newNodes],
          links: [...prev.links, ...newLinks],
        };
      });
    } catch (err) {
      console.error("Expand failed:", err);
    } finally {
      setExpanding(null);
    }
  }, [expanding]);

  /** Custom node renderer — glow + expandable ring indicator */
  const paintNode = useCallback((rawNode: object, ctx: CanvasRenderingContext2D) => {
    const node = rawNode as MemoryNode & { x: number; y: number };
    if (node.x == null || node.y == null) return;

    const color = NODE_COLORS[node.type] || "#888";
    const r = node.type === "Package" || node.type === "ThreatActor" ? 8 : 5;
    const isExpanding = expanding === node.id;

    // Outer glow
    const grad = ctx.createRadialGradient(node.x, node.y, 0, node.x, node.y, r * 3);
    grad.addColorStop(0, color + "50");
    grad.addColorStop(1, color + "00");
    ctx.beginPath();
    ctx.arc(node.x, node.y, r * 3, 0, Math.PI * 2);
    ctx.fillStyle = grad;
    ctx.fill();

    // Core circle
    ctx.beginPath();
    ctx.arc(node.x, node.y, r, 0, Math.PI * 2);
    ctx.fillStyle = color;
    ctx.fill();
    ctx.strokeStyle = color + "80";
    ctx.lineWidth = 1.5;
    ctx.stroke();

    // Expandable indicator — dashed ring + count badge
    if (node.expandable && node.hidden_children) {
      ctx.setLineDash(isExpanding ? [2, 2] : [4, 3]);
      ctx.beginPath();
      ctx.arc(node.x, node.y, r + 5, 0, Math.PI * 2);
      ctx.strokeStyle = isExpanding ? "#ffaa00" : "rgba(0, 255, 200, 0.6)";
      ctx.lineWidth = 1.5;
      ctx.stroke();
      ctx.setLineDash([]);

      // "+" count badge
      ctx.fillStyle = "rgba(0, 255, 200, 0.9)";
      ctx.font = "bold 8px 'JetBrains Mono', monospace";
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillText(`+${node.hidden_children}`, node.x + r + 8, node.y - r - 2);
    }

    // Label
    ctx.fillStyle = "rgba(255,255,255,0.8)";
    ctx.font = "10px 'JetBrains Mono', monospace";
    ctx.textAlign = "center";
    ctx.textBaseline = "top";
    const label = node.label.length > 20 ? node.label.slice(0, 18) + "..." : node.label;
    ctx.fillText(label, node.x, node.y + r + 6);

    // Type sub-label
    ctx.fillStyle = color + "aa";
    ctx.font = "8px 'JetBrains Mono', monospace";
    ctx.fillText(node.type, node.x, node.y + r + 18);
  }, [expanding]);

  /** Custom link renderer */
  const paintLink = useCallback((rawLink: object, ctx: CanvasRenderingContext2D) => {
    const link = rawLink as { source: { x: number; y: number }; target: { x: number; y: number } };
    if (!link.source?.x || !link.target?.x) return;

    ctx.beginPath();
    ctx.moveTo(link.source.x, link.source.y);
    ctx.lineTo(link.target.x, link.target.y);
    ctx.strokeStyle = "rgba(0, 255, 200, 0.15)";
    ctx.lineWidth = 1.2;
    ctx.stroke();
  }, []);

  return (
    <div className="relative w-full h-full bg-background" ref={containerRef}>
      {graphData.nodes.length > 0 && (
        <ForceGraph2D
          ref={fgRef as React.MutableRefObject<ForceGraphMethods | undefined>}
          width={dimensions.w}
          height={dimensions.h}
          graphData={graphData}
          backgroundColor="transparent"
          nodeCanvasObject={paintNode as (node: object, ctx: CanvasRenderingContext2D, globalScale: number) => void}
          nodePointerAreaPaint={(rawNode: object, color: string, ctx: CanvasRenderingContext2D) => {
            const n = rawNode as MemoryNode & { x: number; y: number };
            ctx.beginPath();
            ctx.arc(n.x, n.y, 14, 0, Math.PI * 2);
            ctx.fillStyle = color;
            ctx.fill();
          }}
          onNodeClick={(node) => handleNodeClick(node as unknown as MemoryNode)}
          linkCanvasObject={paintLink as (link: object, ctx: CanvasRenderingContext2D, globalScale: number) => void}
          linkDirectionalParticles={2}
          linkDirectionalParticleWidth={2}
          linkDirectionalParticleColor={() => "rgba(0, 255, 200, 0.4)"}
          linkDirectionalParticleSpeed={0.004}
          d3VelocityDecay={0.3}
          d3AlphaDecay={0.015}
          cooldownTime={4000}
          enableZoomInteraction={true}
          enablePanInteraction={true}
          enableNodeDrag={true}
        />
      )}

      {/* HUD — top right */}
      <div className="absolute top-3 right-3 z-10 flex items-center gap-2">
        {expanding && (
          <span className="px-2 py-1 rounded-md text-[10px] font-mono bg-yellow-500/15 text-yellow-400 border border-yellow-500/25 animate-pulse">
            Expanding {expanding}...
          </span>
        )}
        <button
          onClick={load}
          disabled={loading}
          className={cn(
            "flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[10px] font-mono",
            "border border-border/60 bg-surface/80 backdrop-blur-sm",
            "text-muted-foreground hover:text-foreground transition-colors",
            loading && "animate-pulse"
          )}
        >
          <RefreshCw className={cn("h-3 w-3", loading && "animate-spin")} />
          Refresh
        </button>
      </div>

      {/* Stats — bottom left */}
      <div className="absolute bottom-3 left-3 z-10 flex items-center gap-3">
        <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md border border-primary/20 bg-surface/80 backdrop-blur-sm">
          <Brain className="h-3.5 w-3.5 text-primary" />
          <span className="text-xs font-mono text-primary font-semibold">{total}</span>
          <span className="text-[10px] font-mono text-muted-foreground">memorized</span>
        </div>
        {lastSaved && (
          <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md border border-success/20 bg-surface/80 backdrop-blur-sm">
            <Zap className="h-3 w-3 text-success" />
            <span className="text-[10px] font-mono text-success/80">Last updated {lastSaved}</span>
          </div>
        )}
      </div>

      {/* Hint — bottom right */}
      {graphData.nodes.some((n) => n.expandable) && (
        <div className="absolute bottom-3 right-3 z-10 px-2.5 py-1.5 rounded-md border border-border/40 bg-surface/80 backdrop-blur-sm">
          <span className="text-[10px] font-mono text-muted-foreground/60">
            Click nodes with <span className="text-[rgb(0,255,200)]">+N</span> to expand
          </span>
        </div>
      )}

      {/* Empty state */}
      {!loading && graphData.nodes.length === 0 && (
        <div className="absolute inset-0 flex flex-col items-center justify-center z-10">
          <div className="relative mb-4">
            <Brain className="h-16 w-16 text-muted-foreground/20 animate-float" />
            <div className="absolute inset-0 blur-xl bg-primary/5 rounded-full" />
          </div>
          <p className="text-sm font-medium text-muted-foreground/50 mb-1">
            No memories yet
          </p>
          <p className="text-xs text-muted-foreground/30 max-w-[260px] text-center leading-relaxed">
            Investigate an entity and click &quot;Save to Memory&quot; to teach
            the system. Memorized patterns appear here and are recalled instantly
            on future queries.
          </p>
        </div>
      )}
    </div>
  );
}
