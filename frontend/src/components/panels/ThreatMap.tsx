/**
 * components/panels/ThreatMap.tsx — Live geographic threat visualization
 *
 * Renders a simplified world map SVG with animated threat nodes showing
 * active APT groups, their geographic attribution, and attack connections.
 * Nodes pulse to indicate active threats. Connection lines animate between
 * source and target locations to show attack flows.
 *
 * This is a self-contained visualization — no external map library needed.
 * The map uses a simplified equirectangular projection with hand-tuned
 * control points for continent shapes.
 */
import { useState, useMemo, useCallback, useRef, useEffect } from "react";
import { Shield, Activity, AlertTriangle, Crosshair, X } from "lucide-react";
import { cn } from "../../lib/utils";
import { fetchGeoMap } from "../../lib/api";
import type { InvestigationState } from "../../types/api";

/* ════════════════════════════════════════════════════════════════════════
 * DATA MODEL — Threat nodes, APT groups, and their geographic positions
 * ════════════════════════════════════════════════════════════════════════ */

/** A geographic point on the threat map (percent-based coordinates) */
interface GeoPoint {
  /** X position as percentage of map width (0-100) */
  x: number;
  /** Y position as percentage of map height (0-100) */
  y: number;
}

/** Severity level for visual color-coding */
type ThreatSeverity = "critical" | "high" | "medium" | "low";

/** A threat node that appears on the map */
interface ThreatNode {
  /** Unique identifier */
  id: string;
  /** Display name (e.g., "APT-28", "Lazarus Group") */
  name: string;
  /** Attribution category */
  type: "apt" | "infrastructure" | "c2" | "target";
  /** Geographic position on the map */
  position: GeoPoint;
  /** Threat severity determines the node's color */
  severity: ThreatSeverity;
  /** Country/region attribution */
  region: string;
  /** Whether this node is currently "active" (pulses) */
  active: boolean;
  /** Optional: MITRE technique IDs associated with this actor */
  techniques?: string[];
}

/** A connection between two threat nodes (attack flow) */
interface ThreatConnection {
  /** ID of the source node */
  from: string;
  /** ID of the target node */
  to: string;
  /** Whether this connection is actively being used */
  active: boolean;
  /** Type of relationship for styling */
  type: "attack" | "c2" | "exfil" | "lateral";
}

/* ════════════════════════════════════════════════════════════════════════
 * MOCK THREAT DATA — Simulates live threat intelligence feed
 * ════════════════════════════════════════════════════════════════════════ */

/** Pre-defined threat nodes representing known APT groups and infrastructure */
const THREAT_NODES: ThreatNode[] = [
  {
    id: "apt28",
    name: "APT-28 (Fancy Bear)",
    type: "apt",
    position: { x: 55, y: 28 },
    severity: "critical",
    region: "Eastern Europe",
    active: true,
    techniques: ["T1566", "T1078", "T1055"],
  },
  {
    id: "lazarus",
    name: "Lazarus Group",
    type: "apt",
    position: { x: 80, y: 36 },
    severity: "critical",
    region: "East Asia",
    active: true,
    techniques: ["T1195", "T1059", "T1486"],
  },
  {
    id: "apt41",
    name: "APT-41 (Winnti)",
    type: "apt",
    position: { x: 76, y: 38 },
    severity: "high",
    region: "East Asia",
    active: true,
    techniques: ["T1190", "T1505", "T1071"],
  },
  {
    id: "c2-eu",
    name: "C2 Server (NL)",
    type: "c2",
    position: { x: 50, y: 25 },
    severity: "high",
    region: "Netherlands",
    active: true,
  },
  {
    id: "c2-us",
    name: "C2 Relay (US-East)",
    type: "c2",
    position: { x: 25, y: 32 },
    severity: "medium",
    region: "United States",
    active: false,
  },
  {
    id: "target-fin",
    name: "Financial Sector",
    type: "target",
    position: { x: 22, y: 30 },
    severity: "high",
    region: "North America",
    active: true,
  },
  {
    id: "target-tech",
    name: "Tech Infrastructure",
    type: "target",
    position: { x: 16, y: 36 },
    severity: "medium",
    region: "US West Coast",
    active: false,
  },
  {
    id: "infra-sea",
    name: "Proxy Network",
    type: "infrastructure",
    position: { x: 72, y: 52 },
    severity: "medium",
    region: "Southeast Asia",
    active: true,
  },
  {
    id: "apt-sandworm",
    name: "Sandworm",
    type: "apt",
    position: { x: 57, y: 26 },
    severity: "critical",
    region: "Eastern Europe",
    active: true,
    techniques: ["T1498", "T1485", "T1561"],
  },
  {
    id: "target-energy",
    name: "Energy Grid",
    type: "target",
    position: { x: 51, y: 24 },
    severity: "critical",
    region: "Western Europe",
    active: true,
  },
];

/** Connections between threat nodes — represents attack flows */
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
 * COLOR MAPS — Severity and node type → color
 * ════════════════════════════════════════════════════════════════════════ */

/** Map severity to CSS color classes */
const SEVERITY_COLORS: Record<ThreatSeverity, string> = {
  critical: "text-threat-critical",
  high: "text-threat-high",
  medium: "text-threat-medium",
  low: "text-threat-low",
};

/** Map severity to hex for SVG rendering (canvas can't use CSS vars) */
const SEVERITY_HEX: Record<ThreatSeverity, string> = {
  critical: "#E63946",
  high: "#E67326",
  medium: "#E6B833",
  low: "#82B366",
};

/** Map node type to icon fill opacity and shape */
const NODE_TYPE_STYLES: Record<string, { glow: number; size: number }> = {
  apt: { glow: 1.0, size: 8 },
  c2: { glow: 0.7, size: 6 },
  infrastructure: { glow: 0.5, size: 5 },
  target: { glow: 0.8, size: 7 },
};

/* ════════════════════════════════════════════════════════════════════════
 * WORLD MAP SVG PATHS — Simplified continent outlines
 *
 * These paths represent simplified continent shapes in a 1000x500 viewBox.
 * Using an equirectangular-ish projection where x=longitude, y=latitude.
 * The shapes are intentionally low-detail for performance & aesthetic.
 * ════════════════════════════════════════════════════════════════════════ */

const CONTINENT_PATHS = [
  /* North America */
  "M80,80 L120,60 L180,55 L220,65 L260,80 L280,100 L290,130 L275,150 L260,160 L240,170 L220,180 L200,190 L190,200 L175,210 L160,200 L140,190 L120,180 L100,160 L90,140 L80,120 Z",
  /* South America */
  "M200,220 L220,210 L240,215 L260,230 L270,260 L275,290 L270,320 L260,350 L245,370 L230,380 L215,370 L205,350 L200,320 L195,290 L195,260 L197,240 Z",
  /* Europe */
  "M440,70 L460,65 L480,70 L510,75 L530,85 L540,100 L535,115 L520,120 L510,130 L495,135 L480,125 L465,120 L455,110 L445,95 L440,80 Z",
  /* Africa */
  "M440,150 L460,140 L490,145 L520,150 L540,165 L550,190 L555,220 L550,250 L540,280 L525,300 L510,310 L490,315 L470,305 L455,285 L445,260 L440,230 L438,200 L440,170 Z",
  /* Asia */
  "M540,60 L580,50 L640,45 L700,50 L750,55 L790,65 L810,80 L815,100 L810,120 L800,140 L780,150 L760,155 L740,150 L720,145 L700,140 L680,135 L660,140 L640,145 L620,140 L600,130 L580,120 L560,110 L545,95 L540,80 Z",
  /* Southeast Asia / Indonesia */
  "M700,170 L720,165 L740,170 L760,175 L780,180 L790,190 L785,200 L770,205 L750,200 L730,195 L715,190 L705,180 Z",
  /* Australia */
  "M740,270 L770,260 L800,265 L830,275 L845,290 L840,310 L825,325 L800,330 L775,325 L755,315 L745,300 L740,285 Z",
];

/* ════════════════════════════════════════════════════════════════════════
 * HELPER — Get a node's position given the lookup map
 * ════════════════════════════════════════════════════════════════════════ */

function getNodePos(nodeId: string, nodeMap: Map<string, ThreatNode>): GeoPoint | null {
  const node = nodeMap.get(nodeId);
  return node ? node.position : null;
}

export { type ThreatNode, type ThreatConnection, type ThreatSeverity };

/* ════════════════════════════════════════════════════════════════════════
 * THREAT MAP COMPONENT
 * ════════════════════════════════════════════════════════════════════════ */

/** Convert longitude (-180..180) to map X percentage (0..100) */
function latLonToX(lon: number): number {
  return ((lon + 180) / 360) * 100;
}

/** Convert latitude (-90..90) to map Y percentage (0..100) — inverted */
function latLonToY(lat: number): number {
  return ((90 - lat) / 180) * 100;
}

interface ThreatMapProps {
  state: InvestigationState;
}

export function ThreatMap({ state }: ThreatMapProps) {
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  // Dynamic nodes from real investigation data, merged with static ones
  const [liveNodes, setLiveNodes] = useState<ThreatNode[]>([]);
  const [liveConnections, setLiveConnections] = useState<ThreatConnection[]>([]);

  // Fetch geo data when an investigation completes
  useEffect(() => {
    if (state.status !== "complete" || !state.entity) return;
    let cancelled = false;

    fetchGeoMap({ entity: state.entity, type: state.entityType })
      .then((data) => {
        if (cancelled || !data.points?.length) return;
        const newNodes: ThreatNode[] = [];
        const newConns: ThreatConnection[] = [];

        for (const pt of data.points) {
          const actors: string[] = pt.actors || [];
          const actorName = actors[0] || "";
          const id = `live-${pt.ip || Math.random()}`;
          newNodes.push({
            id,
            name: actorName ? `${pt.ip} (${actorName})` : pt.ip,
            type: actorName ? "infrastructure" : "infrastructure",
            position: { x: latLonToX(pt.lon ?? 0), y: latLonToY(pt.lat ?? 0) },
            severity: actorName ? "critical" : "high",
            region: pt.geo || "Unknown",
            active: true,
          });
          // Connect live IP to any matching static APT node
          const matchingApt = THREAT_NODES.find(
            (n) => n.type === "apt" && actors.some((a: string) => n.name.toLowerCase().includes(a.toLowerCase().split(" ")[0]))
          );
          if (matchingApt) {
            newConns.push({ from: id, to: matchingApt.id, active: true, type: "c2" });
          }
        }
        setLiveNodes(newNodes);
        setLiveConnections(newConns);
      })
      .catch((err) => console.error("Geo map fetch failed:", err));

    return () => { cancelled = true; };
  }, [state.status, state.entity, state.entityType]);

  // Merge static + live nodes
  const allNodes = useMemo(() => [...THREAT_NODES, ...liveNodes], [liveNodes]);
  const allConnections = useMemo(() => [...THREAT_CONNECTIONS, ...liveConnections], [liveConnections]);

  const nodeMap = useMemo(() => {
    const map = new Map<string, ThreatNode>();
    allNodes.forEach((n) => map.set(n.id, n));
    return map;
  }, [allNodes]);

  const stats = useMemo(() => {
    const activeCount = allNodes.filter((n) => n.active).length;
    const aptCount = allNodes.filter((n) => n.type === "apt").length;
    const criticalCount = allNodes.filter((n) => n.severity === "critical").length;
    return { activeCount, aptCount, criticalCount };
  }, [allNodes]);

  /* Handle node click — toggles selection for APT detail */
  const handleNodeClick = useCallback((nodeId: string) => {
    setSelectedNode((prev) => (prev === nodeId ? null : nodeId));
  }, []);

  /* Get the currently selected node data */
  const selectedNodeData = selectedNode ? nodeMap.get(selectedNode) : null;

  return (
    <div
      ref={containerRef}
      className="relative h-full w-full overflow-hidden grid-bg"
    >
      {/* ── Stats header bar ─────────────────────────────── */}
      <div className="absolute top-3 right-3 z-20 flex items-center gap-2">
        <StatBadge
          icon={<Activity className="h-3 w-3" />}
          label="ACTIVE"
          value={stats.activeCount}
          color="text-primary"
        />
        <StatBadge
          icon={<Shield className="h-3 w-3" />}
          label="APT"
          value={stats.aptCount}
          color="text-threat-high"
        />
        <StatBadge
          icon={<AlertTriangle className="h-3 w-3" />}
          label="CRITICAL"
          value={stats.criticalCount}
          color="text-threat-critical"
        />
      </div>

      {/* ── Main SVG map ─────────────────────────────────── */}
      <svg
        viewBox="0 0 1000 500"
        className="absolute inset-0 w-full h-full"
        preserveAspectRatio="xMidYMid meet"
      >
        {/* Grid lines for depth */}
        <defs>
          {/* Glow filter for active nodes */}
          <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>

          {/* Stronger glow for critical nodes */}
          <filter id="glow-strong" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="6" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>

          {/* Animated dash pattern for active connections */}
          <pattern id="dash-pattern" patternUnits="userSpaceOnUse" width="12" height="1">
            <line x1="0" y1="0" x2="6" y2="0" stroke="currentColor" strokeWidth="1" />
          </pattern>
        </defs>

        {/* ── Latitude/longitude grid lines ───────────────── */}
        {[0, 100, 200, 300, 400, 500].map((y) => (
          <line
            key={`h-${y}`}
            x1="0" y1={y} x2="1000" y2={y}
            stroke="hsl(var(--border))"
            strokeWidth="0.5"
            opacity="0.15"
          />
        ))}
        {[0, 200, 400, 600, 800, 1000].map((x) => (
          <line
            key={`v-${x}`}
            x1={x} y1="0" x2={x} y2="500"
            stroke="hsl(var(--border))"
            strokeWidth="0.5"
            opacity="0.15"
          />
        ))}

        {/* ── Continent outlines ──────────────────────────── */}
        {CONTINENT_PATHS.map((path, i) => (
          <path
            key={i}
            d={path}
            fill="hsl(var(--surface-raised))"
            stroke="hsl(var(--border))"
            strokeWidth="0.8"
            opacity="0.5"
          />
        ))}

        {/* ── Connection lines between threat nodes ────────── */}
        {allConnections.map((conn, i) => {
          const from = getNodePos(conn.from, nodeMap);
          const to = getNodePos(conn.to, nodeMap);
          if (!from || !to) return null;

          /* Convert percentage positions to SVG coordinates */
          const x1 = from.x * 10;
          const y1 = from.y * 10;
          const x2 = to.x * 10;
          const y2 = to.y * 10;

          /* Curved path — control point offset for visual arc */
          const midX = (x1 + x2) / 2;
          const midY = (y1 + y2) / 2 - 20;

          return (
            <g key={`conn-${i}`}>
              {/* Base connection line */}
              <path
                d={`M ${x1} ${y1} Q ${midX} ${midY} ${x2} ${y2}`}
                fill="none"
                stroke={conn.active ? SEVERITY_HEX[nodeMap.get(conn.from)?.severity ?? "medium"] : "hsl(var(--border))"}
                strokeWidth={conn.active ? 1.2 : 0.6}
                strokeDasharray={conn.active ? "6 4" : "3 6"}
                opacity={conn.active ? 0.5 : 0.15}
                className={conn.active ? "animate-shimmer" : ""}
              />

              {/* Animated particle traveling along active connections */}
              {conn.active && (
                <circle r="2" fill={SEVERITY_HEX[nodeMap.get(conn.from)?.severity ?? "medium"]} opacity="0.8">
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

        {/* ── Threat nodes ────────────────────────────────── */}
        {allNodes.map((node) => {
          const cx = node.position.x * 10;
          const cy = node.position.y * 10;
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
              {/* Outer pulse ring — only for active nodes */}
              {node.active && (
                <>
                  <circle
                    cx={cx} cy={cy}
                    r={style.size * 2.5}
                    fill="none"
                    stroke={color}
                    strokeWidth="0.5"
                    opacity="0.2"
                  >
                    <animate
                      attributeName="r"
                      values={`${style.size * 1.5};${style.size * 3};${style.size * 1.5}`}
                      dur="3s"
                      repeatCount="indefinite"
                    />
                    <animate
                      attributeName="opacity"
                      values="0.3;0;0.3"
                      dur="3s"
                      repeatCount="indefinite"
                    />
                  </circle>
                  {/* Second pulse ring (offset) */}
                  <circle
                    cx={cx} cy={cy}
                    r={style.size * 2}
                    fill="none"
                    stroke={color}
                    strokeWidth="0.3"
                    opacity="0.15"
                  >
                    <animate
                      attributeName="r"
                      values={`${style.size};${style.size * 2.5};${style.size}`}
                      dur="3s"
                      begin="1.5s"
                      repeatCount="indefinite"
                    />
                    <animate
                      attributeName="opacity"
                      values="0.2;0;0.2"
                      dur="3s"
                      begin="1.5s"
                      repeatCount="indefinite"
                    />
                  </circle>
                </>
              )}

              {/* Selection ring */}
              {isSelected && (
                <circle
                  cx={cx} cy={cy}
                  r={style.size + 5}
                  fill="none"
                  stroke={color}
                  strokeWidth="1.5"
                  strokeDasharray="4 2"
                  opacity="0.6"
                >
                  <animateTransform
                    attributeName="transform"
                    type="rotate"
                    from={`0 ${cx} ${cy}`}
                    to={`360 ${cx} ${cy}`}
                    dur="8s"
                    repeatCount="indefinite"
                  />
                </circle>
              )}

              {/* Main node dot */}
              <circle
                cx={cx} cy={cy}
                r={isHovered || isSelected ? style.size + 2 : style.size}
                fill={color}
                opacity={node.active ? style.glow : 0.3}
                filter={node.active && node.severity === "critical" ? "url(#glow-strong)" : node.active ? "url(#glow)" : undefined}
                className="transition-all duration-200"
              />

              {/* Inner highlight dot */}
              <circle
                cx={cx} cy={cy}
                r={Math.max(style.size * 0.4, 2)}
                fill="white"
                opacity={node.active ? 0.6 : 0.15}
              />

              {/* Node type icon indicator — small shape at edge */}
              {node.type === "apt" && (
                <polygon
                  points={`${cx},${cy - style.size - 6} ${cx - 3},${cy - style.size - 2} ${cx + 3},${cy - style.size - 2}`}
                  fill={color}
                  opacity="0.8"
                />
              )}

              {/* Hover label */}
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

      {/* ── APT Attribution Panel (bottom-left overlay) ──── */}
      <AptAttributionPanel
        selectedNode={selectedNodeData}
        activeNodes={allNodes.filter((n) => n.active && n.type === "apt")}
        onSelect={(id) => setSelectedNode(id)}
        onClose={() => setSelectedNode(null)}
      />

      {/* ── Live feed indicator ──────────────────────────── */}
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

/**
 * StatBadge — Small status badge for the top-right stats bar.
 * Shows an icon, label, and numeric value.
 */
function StatBadge({
  icon,
  label,
  value,
  color,
}: {
  icon: React.ReactNode;
  label: string;
  value: number;
  color: string;
}) {
  return (
    <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md bg-surface/80 backdrop-blur-md border border-border/50">
      <span className={color}>{icon}</span>
      <span className="text-[9px] font-mono text-muted-foreground uppercase tracking-wider">
        {label}
      </span>
      <span className={cn("text-xs font-mono font-bold", color)}>
        {value}
      </span>
    </div>
  );
}

/**
 * AptAttributionPanel — Bottom-left overlay showing APT group details.
 *
 * Lists active APT groups as clickable cards. When a node is selected
 * on the map, shows expanded detail with MITRE techniques and region info.
 */
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
  return (
    <div className="absolute bottom-3 left-3 z-20 w-64">
      {/* ── Selected node detail card ─────────────────── */}
      {selectedNode && (
        <div className="mb-2 p-3 rounded-lg bg-surface/90 backdrop-blur-md border border-border/60 animate-slide-up">
          {/* Header with severity indicator + close button */}
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
              <p className="text-xs font-mono font-bold text-foreground truncate">
                {selectedNode.name}
              </p>
              <p className="text-[9px] font-mono text-muted-foreground uppercase">
                {selectedNode.region}
              </p>
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
            <button
              type="button"
              onClick={onClose}
              className="ml-1 p-0.5 rounded hover:bg-muted-foreground/10 text-muted-foreground/50 hover:text-foreground transition-colors"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>

          {/* MITRE techniques */}
          {selectedNode.techniques && selectedNode.techniques.length > 0 && (
            <div className="mt-2 pt-2 border-t border-border/30">
              <p className="text-[8px] font-mono text-muted-foreground/60 uppercase tracking-wider mb-1.5">
                MITRE ATT&CK Techniques
              </p>
              <div className="flex flex-wrap gap-1">
                {selectedNode.techniques.map((tech) => (
                  <span
                    key={tech}
                    className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-primary/10 text-primary border border-primary/20"
                  >
                    {tech}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Node type and status */}
          <div className="mt-2 pt-2 border-t border-border/30 flex items-center justify-between">
            <span className="text-[8px] font-mono text-muted-foreground/60 uppercase">
              Type: {selectedNode.type.toUpperCase()}
            </span>
            <span className={cn(
              "flex items-center gap-1 text-[8px] font-mono",
              selectedNode.active ? "text-threat-critical" : "text-muted-foreground/40"
            )}>
              <span className={cn(
                "w-1.5 h-1.5 rounded-full",
                selectedNode.active ? "bg-threat-critical animate-pulse" : "bg-muted-foreground/30"
              )} />
              {selectedNode.active ? "ACTIVE" : "DORMANT"}
            </span>
          </div>
        </div>
      )}

      {/* ── APT group listing ─────────────────────────── */}
      <div className="p-2.5 rounded-lg bg-surface/80 backdrop-blur-md border border-border/50">
        <div className="flex items-center gap-1.5 mb-2 px-1">
          <Shield className="h-3 w-3 text-threat-high" />
          <span className="text-[9px] font-mono font-bold text-foreground uppercase tracking-wider">
            APT Attribution
          </span>
          <span className="ml-auto text-[8px] font-mono text-muted-foreground/50">
            {activeNodes.length} ACTIVE
          </span>
        </div>

        <div className="space-y-1">
          {activeNodes.map((node) => (
            <button
              key={node.id}
              onClick={() => onSelect(node.id)}
              className={cn(
                "w-full flex items-center gap-2 px-2 py-1.5 rounded-md text-left",
                "transition-all duration-150",
                selectedNode?.id === node.id
                  ? "bg-primary/10 border border-primary/25"
                  : "hover:bg-surface-raised/60 border border-transparent"
              )}
            >
              {/* Severity dot */}
              <div
                className="w-2 h-2 rounded-full flex-shrink-0"
                style={{ backgroundColor: SEVERITY_HEX[node.severity] }}
              />
              {/* Name and region */}
              <div className="flex-1 min-w-0">
                <p className="text-[10px] font-mono font-medium text-foreground truncate">
                  {node.name}
                </p>
                <p className="text-[8px] font-mono text-muted-foreground/50">
                  {node.region}
                </p>
              </div>
              {/* Active indicator */}
              {node.active && (
                <div className="w-1.5 h-1.5 rounded-full bg-threat-critical animate-pulse flex-shrink-0" />
              )}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
