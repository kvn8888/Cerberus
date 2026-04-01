/**
 * components/panels/TimelinePanel.tsx — Session investigation timeline
 *
 * Renders a horizontal timeline scrubber at the bottom of the center panel.
 * Each dot represents a completed investigation, colored by severity.
 * Hovering shows entity details; clicking replays the investigation.
 */
import { useState } from "react";
import { Clock, History } from "lucide-react";
import type { InvestigationHistoryItem } from "../../types/api";
import { cn } from "../../lib/utils";

interface TimelinePanelProps {
  investigationHistory: InvestigationHistoryItem[];
  onReplay: (item: InvestigationHistoryItem) => void;
}

/** Map severity levels to dot colors */
const SEVERITY_COLORS: Record<string, string> = {
  critical: "#EF4444",
  high: "#F97316",
  medium: "#EAB308",
  low: "#22C55E",
  info: "#3B82F6",
};

/** Format a unix-ms timestamp as HH:MM */
function formatTime(ts: number): string {
  const d = new Date(ts);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

export function TimelinePanel({
  investigationHistory,
  onReplay,
}: TimelinePanelProps) {
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);

  if (investigationHistory.length === 0) return null;

  return (
    <div
      className={cn(
        "absolute bottom-4 left-16 right-16 z-20",
        "glass-panel rounded-lg px-4 py-3",
        "flex flex-col gap-2"
      )}
    >
      {/* Header */}
      <div className="flex items-center gap-2 text-[10px] font-mono text-muted-foreground uppercase tracking-wider">
        <History className="h-3 w-3" />
        <span>Session Timeline</span>
        <span className="ml-auto opacity-60">
          {investigationHistory.length} investigation
          {investigationHistory.length !== 1 ? "s" : ""}
        </span>
      </div>

      {/* Timeline bar with dots */}
      <div className="relative flex items-center w-full h-8">
        {/* Connecting line */}
        <div className="absolute top-1/2 left-0 right-0 h-px bg-border/50 -translate-y-1/2" />

        <div className="relative flex items-center justify-between w-full">
          {investigationHistory.map((item, i) => {
            const color =
              SEVERITY_COLORS[item.severity ?? ""] ?? "#6B7280";

            return (
              <div
                key={`${item.entity}-${item.timestamp}`}
                className="relative flex flex-col items-center"
              >
                {/* Tooltip on hover */}
                {hoveredIndex === i && (
                  <div
                    className={cn(
                      "absolute bottom-full mb-2 px-2.5 py-1.5 rounded-md",
                      "glass-panel text-[10px] font-mono whitespace-nowrap",
                      "animate-in fade-in slide-in-from-bottom-1 duration-150",
                      "z-30"
                    )}
                  >
                    <p className="text-foreground font-semibold">
                      {item.entity}
                    </p>
                    <p className="text-muted-foreground">
                      {item.entityType} &middot; {item.pathsFound} paths
                    </p>
                    <div className="flex items-center gap-1 text-muted-foreground/60 mt-0.5">
                      <Clock className="h-2.5 w-2.5" />
                      <span>{formatTime(item.timestamp)}</span>
                    </div>
                  </div>
                )}

                {/* Dot */}
                <button
                  type="button"
                  onClick={() => onReplay(item)}
                  onMouseEnter={() => setHoveredIndex(i)}
                  onMouseLeave={() => setHoveredIndex(null)}
                  className="relative z-10 w-3 h-3 rounded-full border-2 border-background transition-transform hover:scale-150 cursor-pointer"
                  style={{
                    backgroundColor: color,
                    boxShadow: `0 0 8px ${color}60`,
                  }}
                  aria-label={`Replay investigation: ${item.entity}`}
                />

                {/* Time label */}
                <span className="mt-1 text-[8px] font-mono text-muted-foreground/50">
                  {formatTime(item.timestamp)}
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
