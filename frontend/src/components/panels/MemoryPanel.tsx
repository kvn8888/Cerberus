/**
 * components/panels/MemoryPanel.tsx — Interactive memory graph
 *
 * Visualizes all confirmed/memorized threat patterns using the same
 * force-directed graph library as the Threat Graph tab. Nodes are
 * draggable, the canvas is pannable and zoomable.
 *
 * Refreshes automatically when a new pattern is saved via "Save to Memory".
 */
import { useCallback, useEffect, useRef, useState } from "react";
import ForceGraph2D from "react-force-graph-2d";
import { Brain, RefreshCw, Zap } from "lucide-react";
import { fetchMemory } from "../../lib/api";
import { cn } from "../../lib/utils";

interface MemoryNode {
  id: string;
  label: string;
  type: string;
  val: number;
  confirmed: boolean;
}

interface MemoryLink {
  source: string;
  target: string;
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
  const [graphData, setGraphData] = useState<{ nodes: MemoryNode[]; links: MemoryLink[] }>({ nodes: [], links: [] });
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
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

  // Track container size for the force graph
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const obs = new ResizeObserver(([entry]) => {
      setDimensions({ w: entry.contentRect.width, h: entry.contentRect.height });
    });
    obs.observe(el);
    return () => obs.disconnect();
  }, []);

  /** Custom node renderer — glowing circles with labels */
  const paintNode = useCallback((node: MemoryNode, ctx: CanvasRenderingContext2D) => {
    const x = (node as MemoryNode & { x: number }).x;
    const y = (node as MemoryNode & { y: number }).y;
    if (x == null || y == null) return;

    const color = NODE_COLORS[node.type] || "#888";
    const r = node.type === "Package" || node.type === "ThreatActor" ? 7 : 5;

    // Outer glow
    const grad = ctx.createRadialGradient(x, y, 0, x, y, r * 3.5);
    grad.addColorStop(0, color + "50");
    grad.addColorStop(1, color + "00");
    ctx.beginPath();
    ctx.arc(x, y, r * 3.5, 0, Math.PI * 2);
    ctx.fillStyle = grad;
    ctx.fill();

    // Core circle
    ctx.beginPath();
    ctx.arc(x, y, r, 0, Math.PI * 2);
    ctx.fillStyle = color;
    ctx.fill();
    ctx.strokeStyle = color + "80";
    ctx.lineWidth = 1.5;
    ctx.stroke();

    // Label
    ctx.fillStyle = "rgba(255,255,255,0.8)";
    ctx.font = "10px 'JetBrains Mono', monospace";
    ctx.textAlign = "center";
    const label = node.label.length > 20 ? node.label.slice(0, 18) + "..." : node.label;
    ctx.fillText(label, x, y + r + 13);

    // Type sub-label
    ctx.fillStyle = color + "aa";
    ctx.font = "8px 'JetBrains Mono', monospace";
    ctx.fillText(node.type, x, y + r + 23);
  }, []);

  /** Custom link renderer — glowing teal connections */
  const paintLink = useCallback((link: MemoryLink, ctx: CanvasRenderingContext2D) => {
    const src = link.source as unknown as { x: number; y: number };
    const tgt = link.target as unknown as { x: number; y: number };
    if (!src?.x || !tgt?.x) return;

    ctx.beginPath();
    ctx.moveTo(src.x, src.y);
    ctx.lineTo(tgt.x, tgt.y);
    ctx.strokeStyle = "rgba(0, 255, 200, 0.18)";
    ctx.lineWidth = 1.5;
    ctx.stroke();
  }, []);

  return (
    <div className="relative w-full h-full bg-background" ref={containerRef}>
      {/* Force-directed graph — interactive with drag/pan/zoom */}
      {graphData.nodes.length > 0 && (
        <ForceGraph2D
          width={dimensions.w}
          height={dimensions.h}
          graphData={graphData}
          backgroundColor="transparent"
          nodeCanvasObject={paintNode as (node: object, ctx: CanvasRenderingContext2D, globalScale: number) => void}
          nodePointerAreaPaint={(node: object, color: string, ctx: CanvasRenderingContext2D) => {
            const n = node as MemoryNode & { x: number; y: number };
            ctx.beginPath();
            ctx.arc(n.x, n.y, 12, 0, Math.PI * 2);
            ctx.fillStyle = color;
            ctx.fill();
          }}
          linkCanvasObject={paintLink as (link: object, ctx: CanvasRenderingContext2D, globalScale: number) => void}
          linkDirectionalParticles={2}
          linkDirectionalParticleWidth={2}
          linkDirectionalParticleColor={() => "rgba(0, 255, 200, 0.5)"}
          linkDirectionalParticleSpeed={0.004}
          d3VelocityDecay={0.3}
          d3AlphaDecay={0.02}
          cooldownTime={3000}
          enableZoomInteraction={true}
          enablePanInteraction={true}
          enableNodeDrag={true}
        />
      )}

      {/* Overlay HUD — top right */}
      <div className="absolute top-3 right-3 z-10 flex items-center gap-2">
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

      {/* Stats overlay — bottom left */}
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
