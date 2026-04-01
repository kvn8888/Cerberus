/**
 * components/panels/ThreatMap.tsx — Live geographic threat visualization
 *
 * Renders a real world map using Natural Earth topology data projected with
 * d3-geo's equirectangular projection. Animated threat nodes show active APT
 * groups, their geographic attribution, and attack connection flows.
 */
import { useState, useMemo, useCallback, useRef, useEffect } from "react";
import { Shield, Activity, AlertTriangle, Crosshair, X } from "lucide-react";
import { cn } from "../../lib/utils";
import { fetchGeoMap, fetchMemoryGeo } from "../../lib/api";
import type { InvestigationState } from "../../types/api";
import { geoEquirectangular, geoPath, type GeoPermissibleObjects } from "d3-geo";
import { feature } from "topojson-client";
import type { Topology, GeometryCollection } from "topojson-specification";
import type { FeatureCollection, Geometry } from "geojson";
import worldTopo from "world-atlas/countries-110m.json";

/* ════════════════════════════════════════════════════════════════════════
 * PROJECTION — Equirectangular projection fitted to a 1000×500 viewBox
 * ════════════════════════════════════════════════════════════════════════ */

const MAP_W = 1000;
const MAP_H = 500;

const projection = geoEquirectangular()
  .scale(160)
  .center([0, 15])
  .translate([MAP_W / 2, MAP_H / 2]);

const pathGen = geoPath().projection(projection);

/** Convert [longitude, latitude] to SVG [x, y] in the 1000×500 viewBox */
function project(lon: number, lat: number): [number, number] {
  const p = projection([lon, lat]);
  return p ? [p[0], p[1]] : [0, 0];
}

/* ════════════════════════════════════════════════════════════════════════
 * WORLD GEOGRAPHY — Convert Natural Earth TopoJSON to GeoJSON features
 * ════════════════════════════════════════════════════════════════════════ */

const worldGeo: FeatureCollection<Geometry> = feature(
  worldTopo as unknown as Topology<{ countries: GeometryCollection }>,
  (worldTopo as unknown as Topology<{ countries: GeometryCollection }>).objects.countries
) as FeatureCollection<Geometry>;

/* ════════════════════════════════════════════════════════════════════════
 * DATA MODEL
 * ════════════════════════════════════════════════════════════════════════ */

type ThreatSeverity = "critical" | "high" | "medium" | "low";

interface ThreatNode {
  id: string;
  name: string;
  type: "apt" | "infrastructure" | "c2" | "target";
  /** [longitude, latitude] */
  coordinates: [number, number];
  severity: ThreatSeverity;
  region: string;
  active: boolean;
  techniques?: string[];
}

interface ThreatConnection {
  from: string;
  to: string;
  active: boolean;
  type: "attack" | "c2" | "exfil" | "lateral";
}

/* ════════════════════════════════════════════════════════════════════════
 * STATIC THREAT DATA — Known APT groups and infrastructure
 * Coordinates are real-world [longitude, latitude].
 * ════════════════════════════════════════════════════════════════════════ */

const THREAT_NODES: ThreatNode[] = [
  {
    id: "apt28",
    name: "APT-28 (Fancy Bear)",
    type: "apt",
    coordinates: [37.6, 55.8],
    severity: "critical",
    region: "Eastern Europe",
    active: true,
    techniques: ["T1566", "T1078", "T1055"],
  },
  {
    id: "lazarus",
    name: "Lazarus Group",
    type: "apt",
    coordinates: [125.7, 39.0],
    severity: "critical",
    region: "East Asia",
    active: true,
    techniques: ["T1195", "T1059", "T1486"],
  },
  {
    id: "apt41",
    name: "APT-41 (Winnti)",
    type: "apt",
    coordinates: [116.4, 39.9],
    severity: "high",
    region: "East Asia",
    active: true,
    techniques: ["T1190", "T1505", "T1071"],
  },
  {
    id: "c2-eu",
    name: "C2 Server (NL)",
    type: "c2",
    coordinates: [4.9, 52.4],
    severity: "high",
    region: "Netherlands",
    active: true,
  },
  {
    id: "c2-us",
    name: "C2 Relay (US-East)",
    type: "c2",
    coordinates: [-74.0, 40.7],
    severity: "medium",
    region: "United States",
    active: false,
  },
  {
    id: "target-fin",
    name: "Financial Sector",
    type: "target",
    coordinates: [-73.9, 40.8],
    severity: "high",
    region: "North America",
    active: true,
  },
  {
    id: "target-tech",
    name: "Tech Infrastructure",
    type: "target",
    coordinates: [-122.4, 37.8],
    severity: "medium",
    region: "US West Coast",
    active: false,
  },
  {
    id: "infra-sea",
    name: "Proxy Network",
    type: "infrastructure",
    coordinates: [103.8, 1.4],
    severity: "medium",
    region: "Southeast Asia",
    active: true,
  },
  {
    id: "apt-sandworm",
    name: "Sandworm",
    type: "apt",
    coordinates: [30.5, 50.4],
    severity: "critical",
    region: "Eastern Europe",
    active: true,
    techniques: ["T1498", "T1485", "T1561"],
  },
  {
    id: "target-energy",
    name: "Energy Grid",
    type: "target",
    coordinates: [2.3, 48.9],
    severity: "critical",
    region: "Western Europe",
    active: true,
  },
];

const THREAT_CONNECTIONS: ThreatConnection[] = [
  { from: "apt28", to: "c2-eu", active: true, type: "c2" },
  { from: "c2-eu", to: "target-fin", active: true, type: "attack" },
  { from: "lazarus", to: "infra-sea", active: true, type: "c2" },
  { from: "infra-sea", to: "c2-us", active: false, type: "lateral" },
  { from: "c2-us", to: "target-tech", active: false, type: "attack" },
  { from: "apt41", to: "infra-sea", active: true, type: "c2" },
  { from: "apt41", to: "target-fin", active: true, type: "attack" },
  { from: "apt-sandworm", to: "c2-eu", active: true, type: "c2" },
  { from: "apt-sandworm", to: "target-energy", active: true, type: "attack" },
  { from: "lazarus", to: "target-fin", active: true, type: "exfil" },
];

/* ════════════════════════════════════════════════════════════════════════
 * COLOR MAPS
 * ════════════════════════════════════════════════════════════════════════ */

const SEVERITY_COLORS: Record<ThreatSeverity, string> = {
  critical: "text-threat-critical",
  high: "text-threat-high",
  medium: "text-threat-medium",
  low: "text-threat-low",
};

const SEVERITY_HEX: Record<ThreatSeverity, string> = {
  critical: "#E63946",
  high: "#E67326",
  medium: "#E6B833",
  low: "#82B366",
};

const NODE_TYPE_STYLES: Record<string, { glow: number; size: number }> = {
  apt: { glow: 1.0, size: 8 },
  c2: { glow: 0.7, size: 6 },
  infrastructure: { glow: 0.5, size: 5 },
  target: { glow: 0.8, size: 7 },
};

/* ════════════════════════════════════════════════════════════════════════
 * EXPORTS
 * ════════════════════════════════════════════════════════════════════════ */

export { type ThreatNode, type ThreatConnection, type ThreatSeverity };

/* ════════════════════════════════════════════════════════════════════════
 * THREAT MAP COMPONENT
 * ════════════════════════════════════════════════════════════════════════ */

interface ThreatMapProps {
  state: InvestigationState;
}

export function ThreatMap({ state }: ThreatMapProps) {
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const svgRef = useRef<SVGSVGElement>(null);

  const [liveNodes, setLiveNodes] = useState<ThreatNode[]>([]);
  const [liveConnections, setLiveConnections] = useState<ThreatConnection[]>([]);

  /* Memorized entities loaded on mount */
  const [memoryNodes, setMemoryNodes] = useState<ThreatNode[]>([]);
  const [memoryConns, setMemoryConns] = useState<ThreatConnection[]>([]);

  /* ── Zoom / Pan state ─────────────────────────────── */
  const [viewBox, setViewBox] = useState({ x: 0, y: 0, w: MAP_W, h: MAP_H });
  const isPanning = useRef(false);
  const panStart = useRef({ x: 0, y: 0, vx: 0, vy: 0 });

  /** Auto-zoom to fit all active nodes with padding when data changes */
  const zoomToFitNodes = useCallback((nodes: ThreatNode[]) => {
    if (nodes.length === 0) return;
    const projected = nodes.map((n) => project(n.coordinates[0], n.coordinates[1]));
    const xs = projected.map((p) => p[0]);
    const ys = projected.map((p) => p[1]);
    const minX = Math.min(...xs);
    const maxX = Math.max(...xs);
    const minY = Math.min(...ys);
    const maxY = Math.max(...ys);
    const pad = 80;
    const w = Math.max(maxX - minX + pad * 2, 200);
    const h = Math.max(maxY - minY + pad * 2, 100);
    const aspect = MAP_W / MAP_H;
    const fitW = Math.max(w, h * aspect);
    const fitH = fitW / aspect;
    const cx = (minX + maxX) / 2;
    const cy = (minY + maxY) / 2;
    setViewBox({ x: cx - fitW / 2, y: cy - fitH / 2, w: fitW, h: fitH });
  }, []);

  const handleWheel = useCallback((e: React.WheelEvent<SVGSVGElement>) => {
    e.preventDefault();
    const svg = svgRef.current;
    if (!svg) return;
    const rect = svg.getBoundingClientRect();
    // Cursor position as fraction of SVG element
    const fx = (e.clientX - rect.left) / rect.width;
    const fy = (e.clientY - rect.top) / rect.height;
    const zoomFactor = e.deltaY > 0 ? 1.12 : 0.88;

    setViewBox((vb) => {
      const newW = Math.max(100, Math.min(MAP_W * 2, vb.w * zoomFactor));
      const newH = Math.max(50, Math.min(MAP_H * 2, vb.h * zoomFactor));
      const newX = vb.x + (vb.w - newW) * fx;
      const newY = vb.y + (vb.h - newH) * fy;
      return { x: newX, y: newY, w: newW, h: newH };
    });
  }, []);

  const handleMouseDown = useCallback((e: React.MouseEvent<SVGSVGElement>) => {
    if (e.button !== 0) return;
    isPanning.current = true;
    panStart.current = { x: e.clientX, y: e.clientY, vx: viewBox.x, vy: viewBox.y };
  }, [viewBox.x, viewBox.y]);

  const handleMouseMove = useCallback((e: React.MouseEvent<SVGSVGElement>) => {
    if (!isPanning.current || !svgRef.current) return;
    const rect = svgRef.current.getBoundingClientRect();
    const dx = (e.clientX - panStart.current.x) / rect.width * viewBox.w;
    const dy = (e.clientY - panStart.current.y) / rect.height * viewBox.h;
    setViewBox((vb) => ({ ...vb, x: panStart.current.vx - dx, y: panStart.current.vy - dy }));
  }, [viewBox.w, viewBox.h]);

  const handleMouseUp = useCallback(() => { isPanning.current = false; }, []);

  /* Load memorized geo points on mount */
  useEffect(() => {
    fetchMemoryGeo()
      .then((data) => {
        if (!data.points?.length) return;
        const nodes: ThreatNode[] = [];
        const conns: ThreatConnection[] = [];
        const seenActors = new Set<string>();

        for (const pt of data.points) {
          const actors: string[] = pt.actors || [];
          const actorName = actors[0] || "";
          const ipId = `mem-ip-${pt.ip}`;

          nodes.push({
            id: ipId,
            name: pt.ip,
            type: "infrastructure",
            coordinates: [pt.lon ?? 0, pt.lat ?? 0],
            severity: actorName ? "high" : "medium",
            region: pt.geo || "Unknown",
            active: true,
          });

          for (const actor of actors) {
            if (!actor || seenActors.has(actor)) continue;
            seenActors.add(actor);
            const matchingStatic = THREAT_NODES.find(
              (n) => n.type === "apt" && n.name.toLowerCase().includes(actor.toLowerCase().split(" ")[0])
            );
            if (!matchingStatic) {
              const actorId = `mem-actor-${actor.replace(/\s+/g, "-").toLowerCase()}`;
              nodes.push({
                id: actorId,
                name: actor,
                type: "apt",
                coordinates: [(pt.lon ?? 0) + 1.5, (pt.lat ?? 0) + 1],
                severity: "critical",
                region: pt.geo || "Unknown",
                active: true,
              });
            }
          }

          if (actorName) {
            const matchStatic = THREAT_NODES.find(
              (n) => n.type === "apt" && n.name.toLowerCase().includes(actorName.toLowerCase().split(" ")[0])
            );
            const targetId = matchStatic
              ? matchStatic.id
              : `mem-actor-${actorName.replace(/\s+/g, "-").toLowerCase()}`;
            conns.push({ from: ipId, to: targetId, active: true, type: "c2" });
          }
        }
        setMemoryNodes(nodes);
        setMemoryConns(conns);
      })
      .catch((err) => console.error("Memory geo fetch failed:", err));
  }, []);

  /* Fetch geo data when an investigation completes */
  useEffect(() => {
    if (state.status !== "complete" || !state.entity) return;
    let cancelled = false;

    fetchGeoMap({ entity: state.entity, type: state.entityType })
      .then((data) => {
        if (cancelled || !data.points?.length) return;
        const newNodes: ThreatNode[] = [];
        const newConns: ThreatConnection[] = [];
        const seenActors = new Set<string>();

        for (const pt of data.points) {
          const actors: string[] = pt.actors || [];
          const actorName = actors[0] || "";

          // Actor-only points: plot the actor directly at their country
          if (pt.actor_only) {
            if (!actorName || seenActors.has(actorName)) continue;
            seenActors.add(actorName);
            const matchingStatic = THREAT_NODES.find(
              (n) => n.type === "apt" && n.name.toLowerCase().includes(actorName.toLowerCase().split(" ")[0])
            );
            if (!matchingStatic) {
              newNodes.push({
                id: `live-actor-${actorName.replace(/\s+/g, "-").toLowerCase()}`,
                name: actorName,
                type: "apt",
                coordinates: [pt.lon ?? 0, pt.lat ?? 0],
                severity: "critical",
                region: pt.geo || "Unknown",
                active: true,
              });
            }
            continue;
          }

          // IP-based points: infrastructure node + connected actor
          const ipId = `live-ip-${pt.ip}`;
          newNodes.push({
            id: ipId,
            name: pt.ip,
            type: "infrastructure",
            coordinates: [pt.lon ?? 0, pt.lat ?? 0],
            severity: actorName ? "critical" : "high",
            region: pt.geo || "Unknown",
            active: true,
          });

          for (const actor of actors) {
            if (!actor || seenActors.has(actor)) continue;
            seenActors.add(actor);
            const matchingStatic = THREAT_NODES.find(
              (n) => n.type === "apt" && n.name.toLowerCase().includes(actor.toLowerCase().split(" ")[0])
            );
            if (!matchingStatic) {
              const actorId = `live-actor-${actor.replace(/\s+/g, "-").toLowerCase()}`;
              newNodes.push({
                id: actorId,
                name: actor,
                type: "apt",
                coordinates: [(pt.lon ?? 0) + 1.5, (pt.lat ?? 0) + 1],
                severity: "critical",
                region: pt.geo || "Unknown",
                active: true,
              });
            }
          }

          if (actorName) {
            const matchStatic = THREAT_NODES.find(
              (n) => n.type === "apt" && n.name.toLowerCase().includes(actorName.toLowerCase().split(" ")[0])
            );
            const targetId = matchStatic
              ? matchStatic.id
              : `live-actor-${actorName.replace(/\s+/g, "-").toLowerCase()}`;
            newConns.push({ from: ipId, to: targetId, active: true, type: "c2" });
          }
        }
        setLiveNodes(newNodes);
        setLiveConnections(newConns);
        if (newNodes.length > 0) {
          zoomToFitNodes([...THREAT_NODES, ...newNodes]);
        }
      })
      .catch((err) => console.error("Geo map fetch failed:", err));

    return () => { cancelled = true; };
  }, [state.status, state.entity, state.entityType]);

  /* Deduplicate: memory + live → merge by IP/actor id */
  const allNodes = useMemo(() => {
    const seen = new Set<string>();
    const merged: ThreatNode[] = [];
    for (const n of [...THREAT_NODES, ...liveNodes, ...memoryNodes]) {
      if (!seen.has(n.id)) { seen.add(n.id); merged.push(n); }
    }
    return merged;
  }, [liveNodes, memoryNodes]);

  const allConnections = useMemo(() => [...THREAT_CONNECTIONS, ...liveConnections, ...memoryConns], [liveConnections, memoryConns]);

  const nodeMap = useMemo(() => {
    const map = new Map<string, ThreatNode>();
    allNodes.forEach((n) => map.set(n.id, n));
    return map;
  }, [allNodes]);

  const stats = useMemo(() => ({
    activeCount: allNodes.filter((n) => n.active).length,
    aptCount: allNodes.filter((n) => n.type === "apt").length,
    criticalCount: allNodes.filter((n) => n.severity === "critical").length,
  }), [allNodes]);

  const handleNodeClick = useCallback((nodeId: string) => {
    setSelectedNode((prev) => (prev === nodeId ? null : nodeId));
  }, []);

  const selectedNodeData = selectedNode ? nodeMap.get(selectedNode) : null;

  return (
    <div ref={containerRef} className="relative h-full w-full overflow-hidden grid-bg">
      {/* Stats header bar */}
      <div className="absolute top-3 right-3 z-20 flex flex-col items-end gap-1.5">
        <StatBadge icon={<Activity className="h-3 w-3" />} label="ACTIVE" value={stats.activeCount} color="text-primary" />
        <StatBadge icon={<Shield className="h-3 w-3" />} label="APT" value={stats.aptCount} color="text-threat-high" />
        <StatBadge icon={<AlertTriangle className="h-3 w-3" />} label="CRITICAL" value={stats.criticalCount} color="text-threat-critical" />
      </div>

      {/* Main SVG map — zoom with scroll, pan with drag */}
      <svg
        ref={svgRef}
        viewBox={`${viewBox.x} ${viewBox.y} ${viewBox.w} ${viewBox.h}`}
        className="absolute inset-0 w-full h-full"
        preserveAspectRatio="xMidYMid meet"
        onWheel={handleWheel}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
      >
        <defs>
          <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <filter id="glow-strong" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="6" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {/* Graticule grid lines */}
        {[-60, -30, 0, 30, 60].map((lat) => {
          const [, y] = project(0, lat);
          return <line key={`lat-${lat}`} x1="0" y1={y} x2={MAP_W} y2={y} stroke="hsl(var(--border))" strokeWidth="0.4" opacity="0.12" />;
        })}
        {[-120, -60, 0, 60, 120].map((lon) => {
          const [x] = project(lon, 0);
          return <line key={`lon-${lon}`} x1={x} y1="0" x2={x} y2={MAP_H} stroke="hsl(var(--border))" strokeWidth="0.4" opacity="0.12" />;
        })}

        {/* Real country outlines from Natural Earth */}
        {worldGeo.features.map((feat, i) => (
          <path
            key={i}
            d={pathGen(feat as GeoPermissibleObjects) || ""}
            fill="hsl(var(--surface-raised))"
            stroke="hsl(var(--border))"
            strokeWidth="0.5"
            opacity="0.55"
          />
        ))}

        {/* Connection lines between threat nodes */}
        {allConnections.map((conn, i) => {
          const fromNode = nodeMap.get(conn.from);
          const toNode = nodeMap.get(conn.to);
          if (!fromNode || !toNode) return null;

          const [x1, y1] = project(fromNode.coordinates[0], fromNode.coordinates[1]);
          const [x2, y2] = project(toNode.coordinates[0], toNode.coordinates[1]);
          const midX = (x1 + x2) / 2;
          const midY = (y1 + y2) / 2 - 20;
          const color = conn.active
            ? SEVERITY_HEX[fromNode.severity]
            : "hsl(var(--border))";

          return (
            <g key={`conn-${i}`}>
              <path
                d={`M ${x1} ${y1} Q ${midX} ${midY} ${x2} ${y2}`}
                fill="none"
                stroke={color}
                strokeWidth={conn.active ? 1.2 : 0.6}
                strokeDasharray={conn.active ? "6 4" : "3 6"}
                opacity={conn.active ? 0.5 : 0.15}
                className={conn.active ? "animate-shimmer" : ""}
              />
              {conn.active && (
                <circle r="2" fill={color} opacity="0.8">
                  <animateMotion
                    dur={`${3 + i * 0.5}s`}
                    repeatCount="indefinite"
                    path={`M ${x1} ${y1} Q ${midX} ${midY} ${x2} ${y2}`}
                  />
                </circle>
              )}
            </g>
          );
        })}

        {/* Threat nodes */}
        {allNodes.map((node) => {
          const [cx, cy] = project(node.coordinates[0], node.coordinates[1]);
          const style = NODE_TYPE_STYLES[node.type];
          const color = SEVERITY_HEX[node.severity];
          const isHovered = hoveredNode === node.id;
          const isSelected = selectedNode === node.id;

          return (
            <g
              key={node.id}
              className="cursor-pointer"
              onMouseEnter={() => setHoveredNode(node.id)}
              onMouseLeave={() => setHoveredNode(null)}
              onClick={() => handleNodeClick(node.id)}
            >
              {node.active && (
                <>
                  <circle cx={cx} cy={cy} r={style.size * 2.5} fill="none" stroke={color} strokeWidth="0.5" opacity="0.2">
                    <animate attributeName="r" values={`${style.size * 1.5};${style.size * 3};${style.size * 1.5}`} dur="3s" repeatCount="indefinite" />
                    <animate attributeName="opacity" values="0.3;0;0.3" dur="3s" repeatCount="indefinite" />
                  </circle>
                  <circle cx={cx} cy={cy} r={style.size * 2} fill="none" stroke={color} strokeWidth="0.3" opacity="0.15">
                    <animate attributeName="r" values={`${style.size};${style.size * 2.5};${style.size}`} dur="3s" begin="1.5s" repeatCount="indefinite" />
                    <animate attributeName="opacity" values="0.2;0;0.2" dur="3s" begin="1.5s" repeatCount="indefinite" />
                  </circle>
                </>
              )}

              {isSelected && (
                <circle cx={cx} cy={cy} r={style.size + 5} fill="none" stroke={color} strokeWidth="1.5" strokeDasharray="4 2" opacity="0.6">
                  <animateTransform attributeName="transform" type="rotate" from={`0 ${cx} ${cy}`} to={`360 ${cx} ${cy}`} dur="8s" repeatCount="indefinite" />
                </circle>
              )}

              <circle
                cx={cx} cy={cy}
                r={isHovered || isSelected ? style.size + 2 : style.size}
                fill={color}
                opacity={node.active ? style.glow : 0.3}
                filter={node.active && node.severity === "critical" ? "url(#glow-strong)" : node.active ? "url(#glow)" : undefined}
                className="transition-all duration-200"
              />

              <circle cx={cx} cy={cy} r={Math.max(style.size * 0.4, 2)} fill="white" opacity={node.active ? 0.6 : 0.15} />

              {node.type === "apt" && (
                <polygon
                  points={`${cx},${cy - style.size - 6} ${cx - 3},${cy - style.size - 2} ${cx + 3},${cy - style.size - 2}`}
                  fill={color}
                  opacity="0.8"
                />
              )}

              {(isHovered || isSelected) && (
                <g>
                  <rect
                    x={cx + style.size + 6}
                    y={cy - 10}
                    width={node.name.length * 5.5 + 16}
                    height="20"
                    rx="4"
                    fill="hsl(var(--surface))"
                    stroke={color}
                    strokeWidth="0.5"
                    opacity="0.95"
                  />
                  <text
                    x={cx + style.size + 14}
                    y={cy + 1}
                    fill="hsl(var(--foreground))"
                    fontSize="9"
                    fontFamily="'JetBrains Mono', monospace"
                    dominantBaseline="middle"
                  >
                    {node.name}
                  </text>
                </g>
              )}
            </g>
          );
        })}
      </svg>

      {/* APT Attribution Panel */}
      <AptAttributionPanel
        selectedNode={selectedNodeData}
        activeNodes={allNodes.filter((n) => n.active && n.type === "apt")}
        onSelect={(id) => setSelectedNode(id)}
        onClose={() => setSelectedNode(null)}
      />

      {/* Live feed indicator */}
      <div className="absolute bottom-3 right-3 z-20 flex items-center gap-2 px-2.5 py-1.5 rounded-md bg-surface/80 backdrop-blur-md border border-border/50">
        <div className="relative">
          <div className="w-2 h-2 rounded-full bg-threat-critical animate-pulse" />
          <div className="absolute inset-0 w-2 h-2 rounded-full bg-threat-critical animate-ping opacity-75" />
        </div>
        <span className="text-[9px] font-mono text-threat-critical uppercase tracking-wider">
          Live Threat Feed
        </span>
      </div>
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════════
 * SUB-COMPONENTS
 * ════════════════════════════════════════════════════════════════════════ */

function StatBadge({ icon, label, value, color }: { icon: React.ReactNode; label: string; value: number; color: string }) {
  return (
    <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md bg-surface/80 backdrop-blur-md border border-border/50">
      <span className={color}>{icon}</span>
      <span className="text-[9px] font-mono text-muted-foreground uppercase tracking-wider">{label}</span>
      <span className={cn("text-xs font-mono font-bold", color)}>{value}</span>
    </div>
  );
}

function AptAttributionPanel({
  selectedNode,
  activeNodes,
  onSelect,
  onClose,
}: {
  selectedNode: ThreatNode | null | undefined;
  activeNodes: ThreatNode[];
  onSelect: (id: string) => void;
  onClose: () => void;
}) {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <div className="absolute bottom-3 left-3 z-20 w-64">
      {selectedNode && !collapsed && (
        <div className="mb-2 p-3 rounded-lg bg-surface/90 backdrop-blur-md border border-border/60 animate-slide-up">
          <div className="flex items-center gap-2 mb-2">
            <div className="relative">
              <Crosshair className={cn("h-4 w-4", SEVERITY_COLORS[selectedNode.severity])} />
              <div className={cn(
                "absolute inset-0 blur-sm rounded-full opacity-40",
                selectedNode.severity === "critical" && "bg-threat-critical",
                selectedNode.severity === "high" && "bg-threat-high",
                selectedNode.severity === "medium" && "bg-threat-medium",
              )} />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-xs font-mono font-bold text-foreground truncate">{selectedNode.name}</p>
              <p className="text-[9px] font-mono text-muted-foreground uppercase">{selectedNode.region}</p>
            </div>
            <span className={cn(
              "px-1.5 py-0.5 rounded text-[8px] font-mono font-bold uppercase",
              selectedNode.severity === "critical" && "bg-threat-critical/15 text-threat-critical border border-threat-critical/30",
              selectedNode.severity === "high" && "bg-threat-high/15 text-threat-high border border-threat-high/30",
              selectedNode.severity === "medium" && "bg-threat-medium/15 text-threat-medium border border-threat-medium/30",
              selectedNode.severity === "low" && "bg-threat-low/15 text-threat-low border border-threat-low/30",
            )}>
              {selectedNode.severity}
            </span>
            <button type="button" onClick={onClose} className="ml-1 p-0.5 rounded hover:bg-muted-foreground/10 text-muted-foreground/50 hover:text-foreground transition-colors">
              <X className="h-3.5 w-3.5" />
            </button>
          </div>

          {selectedNode.techniques && selectedNode.techniques.length > 0 && (
            <div className="mt-2 pt-2 border-t border-border/30">
              <p className="text-[8px] font-mono text-muted-foreground/60 uppercase tracking-wider mb-1.5">MITRE ATT&CK Techniques</p>
              <div className="flex flex-wrap gap-1">
                {selectedNode.techniques.map((tech) => (
                  <span key={tech} className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-primary/10 text-primary border border-primary/20">{tech}</span>
                ))}
              </div>
            </div>
          )}

          <div className="mt-2 pt-2 border-t border-border/30 flex items-center justify-between">
            <span className="text-[8px] font-mono text-muted-foreground/60 uppercase">Type: {selectedNode.type.toUpperCase()}</span>
            <span className={cn("flex items-center gap-1 text-[8px] font-mono", selectedNode.active ? "text-threat-critical" : "text-muted-foreground/40")}>
              <span className={cn("w-1.5 h-1.5 rounded-full", selectedNode.active ? "bg-threat-critical animate-pulse" : "bg-muted-foreground/30")} />
              {selectedNode.active ? "ACTIVE" : "DORMANT"}
            </span>
          </div>
        </div>
      )}

      <div className="p-2.5 rounded-lg bg-surface/80 backdrop-blur-md border border-border/50">
        <button
          type="button"
          onClick={() => setCollapsed((c) => !c)}
          className="w-full flex items-center gap-1.5 px-1 cursor-pointer hover:opacity-80 transition-opacity"
        >
          <Shield className="h-3 w-3 text-threat-high" />
          <span className="text-[9px] font-mono font-bold text-foreground uppercase tracking-wider">APT Attribution</span>
          <span className="ml-auto text-[8px] font-mono text-muted-foreground/50">{activeNodes.length} ACTIVE</span>
          <svg className={cn("h-3 w-3 text-muted-foreground/50 transition-transform duration-200", collapsed && "-rotate-90")} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
            <path d="M6 9l6 6 6-6" />
          </svg>
        </button>

        {!collapsed && (
          <div className="space-y-1 mt-2 max-h-64 overflow-y-auto">
            {activeNodes.map((node) => (
              <button
                key={node.id}
                onClick={() => onSelect(node.id)}
                className={cn(
                  "w-full flex items-center gap-2 px-2 py-1.5 rounded-md text-left transition-all duration-150",
                  selectedNode?.id === node.id
                    ? "bg-primary/10 border border-primary/25"
                    : "hover:bg-surface-raised/60 border border-transparent"
                )}
              >
                <div className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: SEVERITY_HEX[node.severity] }} />
                <div className="flex-1 min-w-0">
                  <p className="text-[10px] font-mono font-medium text-foreground truncate">{node.name}</p>
                  <p className="text-[8px] font-mono text-muted-foreground/50">{node.region}</p>
                </div>
                {node.active && <div className="w-1.5 h-1.5 rounded-full bg-threat-critical animate-pulse flex-shrink-0" />}
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
