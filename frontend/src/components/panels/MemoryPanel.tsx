/**
 * components/panels/MemoryPanel.tsx — Visualizes the system's learned memory
 *
 * Shows all confirmed/memorized threat patterns as an animated graph.
 * Each node represents an entity the system has "learned" — grouped by type
 * with pulsing connections. Refreshes automatically when a new pattern
 * is saved via the "Save to Memory" button.
 *
 * Uses canvas rendering for smooth animations of the neural-network aesthetic.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { Brain, RefreshCw, Zap } from "lucide-react";
import { fetchMemory } from "../../lib/api";
import { cn } from "../../lib/utils";

interface MemoryNode {
  id: string;
  label: string;
  type: string;
  val: number;
  confirmed: boolean;
  x?: number;
  y?: number;
  vx?: number;
  vy?: number;
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

/**
 * Simple force simulation that positions nodes in a radial layout
 * grouped by type, then applies a spring model for connected nodes.
 */
function layoutNodes(
  nodes: MemoryNode[],
  links: MemoryLink[],
  width: number,
  height: number,
): MemoryNode[] {
  const cx = width / 2;
  const cy = height / 2;

  const typeGroups = new Map<string, MemoryNode[]>();
  for (const n of nodes) {
    const group = typeGroups.get(n.type) || [];
    group.push(n);
    typeGroups.set(n.type, group);
  }

  const types = Array.from(typeGroups.keys());
  const radius = Math.min(width, height) * 0.32;

  types.forEach((type, ti) => {
    const angle = (ti / types.length) * Math.PI * 2 - Math.PI / 2;
    const group = typeGroups.get(type)!;
    group.forEach((node, ni) => {
      const spread = group.length > 1 ? (ni / (group.length - 1) - 0.5) * 0.6 : 0;
      const r = radius + spread * radius * 0.5;
      node.x = cx + Math.cos(angle + spread * 0.4) * r;
      node.y = cy + Math.sin(angle + spread * 0.4) * r;
    });
  });

  // Pull connected nodes slightly closer together
  for (let i = 0; i < 30; i++) {
    for (const link of links) {
      const src = nodes.find((n) => n.id === link.source);
      const tgt = nodes.find((n) => n.id === link.target);
      if (!src?.x || !tgt?.x || !src.y || !tgt.y) continue;
      const dx = tgt.x - src.x;
      const dy = tgt.y - src.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const force = (dist - 120) * 0.002;
      src.x += dx * force;
      src.y += dy * force;
      tgt.x -= dx * force;
      tgt.y -= dy * force;
    }
  }

  return nodes;
}

export function MemoryPanel({ refreshKey, onCountChange }: MemoryPanelProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [nodes, setNodes] = useState<MemoryNode[]>([]);
  const [links, setLinks] = useState<MemoryLink[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [lastSaved, setLastSaved] = useState<string | null>(null);
  const animFrameRef = useRef<number>(0);
  const timeRef = useRef(0);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await fetchMemory();
      setNodes(data.nodes);
      setLinks(data.links);
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
  }, []);

  useEffect(() => {
    load();
  }, [load, refreshKey]);

  // Canvas animation loop
  useEffect(() => {
    const canvas = canvasRef.current;
    const container = containerRef.current;
    if (!canvas || !container) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const resize = () => {
      const rect = container.getBoundingClientRect();
      canvas.width = rect.width * window.devicePixelRatio;
      canvas.height = rect.height * window.devicePixelRatio;
      canvas.style.width = `${rect.width}px`;
      canvas.style.height = `${rect.height}px`;
      ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
    };
    resize();

    const observer = new ResizeObserver(resize);
    observer.observe(container);

    const positioned = layoutNodes(
      [...nodes],
      links,
      container.getBoundingClientRect().width,
      container.getBoundingClientRect().height,
    );

    const draw = () => {
      const w = container.getBoundingClientRect().width;
      const h = container.getBoundingClientRect().height;
      timeRef.current += 0.016;
      const t = timeRef.current;

      ctx.clearRect(0, 0, w, h);

      // Background grid
      ctx.strokeStyle = "rgba(0, 255, 200, 0.03)";
      ctx.lineWidth = 0.5;
      for (let x = 0; x < w; x += 40) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, h);
        ctx.stroke();
      }
      for (let y = 0; y < h; y += 40) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(w, y);
        ctx.stroke();
      }

      if (positioned.length === 0) return;

      // Draw links with animated pulse
      for (const link of links) {
        const src = positioned.find((n) => n.id === link.source);
        const tgt = positioned.find((n) => n.id === link.target);
        if (!src?.x || !tgt?.x || !src.y || !tgt.y) continue;

        const pulse = 0.15 + Math.sin(t * 2 + links.indexOf(link) * 0.5) * 0.1;
        ctx.beginPath();
        ctx.moveTo(src.x, src.y);
        ctx.lineTo(tgt.x, tgt.y);
        ctx.strokeStyle = `rgba(0, 255, 200, ${pulse})`;
        ctx.lineWidth = 1.5;
        ctx.stroke();

        // Animated particle traveling along the link
        const particleT = ((t * 0.3 + links.indexOf(link) * 0.2) % 1);
        const px = src.x + (tgt.x - src.x) * particleT;
        const py = src.y + (tgt.y - src.y) * particleT;
        ctx.beginPath();
        ctx.arc(px, py, 2, 0, Math.PI * 2);
        ctx.fillStyle = "rgba(0, 255, 200, 0.6)";
        ctx.fill();
      }

      // Draw nodes
      for (const node of positioned) {
        if (!node.x || !node.y) continue;
        const color = NODE_COLORS[node.type] || "#888";
        const r = node.val * 1.2 + Math.sin(t * 1.5 + node.x * 0.01) * 1.5;

        // Outer glow
        const grad = ctx.createRadialGradient(node.x, node.y, 0, node.x, node.y, r * 3);
        grad.addColorStop(0, color + "40");
        grad.addColorStop(1, color + "00");
        ctx.beginPath();
        ctx.arc(node.x, node.y, r * 3, 0, Math.PI * 2);
        ctx.fillStyle = grad;
        ctx.fill();

        // Core
        ctx.beginPath();
        ctx.arc(node.x, node.y, r, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.fill();
        ctx.strokeStyle = color + "80";
        ctx.lineWidth = 1.5;
        ctx.stroke();

        // Label
        ctx.fillStyle = "rgba(255,255,255,0.75)";
        ctx.font = "10px 'JetBrains Mono', monospace";
        ctx.textAlign = "center";
        const label = node.label.length > 18 ? node.label.slice(0, 16) + "..." : node.label;
        ctx.fillText(label, node.x, node.y + r + 14);

        // Type badge
        ctx.fillStyle = color + "90";
        ctx.font = "8px 'JetBrains Mono', monospace";
        ctx.fillText(node.type, node.x, node.y + r + 24);
      }

      animFrameRef.current = requestAnimationFrame(draw);
    };

    animFrameRef.current = requestAnimationFrame(draw);

    return () => {
      cancelAnimationFrame(animFrameRef.current);
      observer.disconnect();
    };
  }, [nodes, links]);

  return (
    <div className="relative w-full h-full bg-background" ref={containerRef}>
      <canvas ref={canvasRef} className="absolute inset-0" />

      {/* Overlay HUD */}
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

      {/* Stats overlay */}
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
      {!loading && nodes.length === 0 && (
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
