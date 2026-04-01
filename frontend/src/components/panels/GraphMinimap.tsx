/**
 * components/panels/GraphMinimap.tsx — Miniature graph overview
 *
 * Renders a small (160×120) canvas preview of the full graph in the
 * bottom-right corner of GraphPanel. All nodes are shown as tiny
 * colored dots using the same palette as the main graph. Links are
 * drawn as thin gray lines. The viewport auto-fits all nodes.
 */
import { useRef, useEffect } from "react";
import type { GraphNode, GraphLink } from "../../types/api";
import { cn } from "../../lib/utils";

interface GraphMinimapProps {
  graphData: { nodes: GraphNode[]; links: GraphLink[] };
}

/** Same palette as GraphPanel — kept in sync with --node-* CSS tokens */
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

const WIDTH = 160;
const HEIGHT = 120;
const PADDING = 12;
const NODE_RADIUS = 2;

export function GraphMinimap({ graphData }: GraphMinimapProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const { nodes, links } = graphData;
    if (nodes.length === 0) return;

    ctx.clearRect(0, 0, WIDTH, HEIGHT);

    /* Build a lookup for node positions — react-force-graph mutates
       x/y onto the node objects after simulation stabilises. */
    const posMap = new Map<string, { x: number; y: number }>();
    let minX = Infinity,
      maxX = -Infinity,
      minY = Infinity,
      maxY = -Infinity;

    for (const n of nodes) {
      const x = (n as any).x ?? 0;
      const y = (n as any).y ?? 0;
      posMap.set(n.id, { x, y });
      if (x < minX) minX = x;
      if (x > maxX) maxX = x;
      if (y < minY) minY = y;
      if (y > maxY) maxY = y;
    }

    /* Scale factor to fit the graph into the minimap with padding */
    const rangeX = maxX - minX || 1;
    const rangeY = maxY - minY || 1;
    const scaleX = (WIDTH - PADDING * 2) / rangeX;
    const scaleY = (HEIGHT - PADDING * 2) / rangeY;
    const scale = Math.min(scaleX, scaleY);

    const offsetX = (WIDTH - rangeX * scale) / 2;
    const offsetY = (HEIGHT - rangeY * scale) / 2;

    /** Project a graph coordinate into minimap pixel space */
    const project = (gx: number, gy: number) => ({
      px: (gx - minX) * scale + offsetX,
      py: (gy - minY) * scale + offsetY,
    });

    /* Draw links */
    ctx.strokeStyle = "rgba(100, 116, 139, 0.35)";
    ctx.lineWidth = 0.5;
    for (const link of links) {
      const srcId =
        typeof link.source === "object"
          ? (link.source as any).id
          : link.source;
      const tgtId =
        typeof link.target === "object"
          ? (link.target as any).id
          : link.target;
      const src = posMap.get(srcId);
      const tgt = posMap.get(tgtId);
      if (!src || !tgt) continue;

      const a = project(src.x, src.y);
      const b = project(tgt.x, tgt.y);

      ctx.beginPath();
      ctx.moveTo(a.px, a.py);
      ctx.lineTo(b.px, b.py);
      ctx.stroke();
    }

    /* Draw nodes */
    for (const n of nodes) {
      const pos = posMap.get(n.id);
      if (!pos) continue;
      const { px, py } = project(pos.x, pos.y);
      const color = NODE_COLORS[n.type] || "#6B7280";

      ctx.beginPath();
      ctx.arc(px, py, NODE_RADIUS, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.fill();
    }
  }, [graphData]);

  return (
    <div
      className={cn(
        "absolute bottom-4 right-4 z-10",
        "glass-panel rounded-lg overflow-hidden",
        "flex flex-col"
      )}
      style={{ width: WIDTH, height: HEIGHT + 16 }}
    >
      {/* Label */}
      <span className="text-[8px] font-mono text-muted-foreground/60 uppercase tracking-widest px-2 pt-1.5 select-none">
        Minimap
      </span>
      <canvas
        ref={canvasRef}
        width={WIDTH}
        height={HEIGHT}
        className="block"
      />
    </div>
  );
}
