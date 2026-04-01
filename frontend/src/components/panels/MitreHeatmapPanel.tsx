/**
 * MITRE ATT&CK tactic heatmap from Technique nodes in the current investigation graph.
 */
import { useMemo } from "react";
import { Grid3x3 } from "lucide-react";
import type { InvestigationState } from "../../types/api";
import { cn } from "../../lib/utils";
import {
  MITRE_TACTICS_ORDER,
  extractTechniqueId,
  tacticForTechniqueId,
} from "../../lib/mitreTactics";
import type { GraphNode } from "../../types/api";

function countTechniquesByTactic(nodes: GraphNode[]): Map<string, number> {
  const m = new Map<string, number>();
  for (const t of MITRE_TACTICS_ORDER) m.set(t, 0);
  for (const n of nodes) {
    if ((n.type || "").toLowerCase() !== "technique") continue;
    const raw = String((n as { mitre_id?: string }).mitre_id || n.label || n.id || "");
    const tid = extractTechniqueId(raw) || extractTechniqueId(String(n.label || n.id));
    if (!tid) continue;
    const tactic = tacticForTechniqueId(tid);
    m.set(tactic, (m.get(tactic) ?? 0) + 1);
  }
  return m;
}

export function MitreHeatmapPanel({ state }: { state: InvestigationState }) {
  const counts = useMemo(() => {
    const nodes = state.graphData?.nodes ?? [];
    return countTechniquesByTactic(nodes);
  }, [state.graphData]);

  const maxCount = useMemo(() => Math.max(1, ...Array.from(counts.values())), [counts]);
  const total = useMemo(() => Array.from(counts.values()).reduce((a, b) => a + b, 0), [counts]);

  const hasData = total > 0;

  return (
    <div className="relative h-full w-full overflow-hidden grid-bg flex flex-col">
      <div className="absolute top-3 left-3 z-20 flex items-center gap-2 px-3 py-2 rounded-lg border border-border/60 bg-surface/90">
        <Grid3x3 className="h-4 w-4 text-primary" />
        <div>
          <p className="text-xs font-semibold text-foreground uppercase tracking-wider">MITRE ATT&CK</p>
          <p className="text-[10px] font-mono text-muted-foreground">
            {hasData ? `${total} technique${total === 1 ? "" : "s"} mapped to tactics` : "Run an investigation with Technique nodes"}
          </p>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-4 pt-20">
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2 max-w-5xl mx-auto">
          {MITRE_TACTICS_ORDER.map((tactic) => {
            const c = counts.get(tactic) ?? 0;
            const intensity = c / maxCount;
            return (
              <div
                key={tactic}
                className={cn(
                  "rounded-lg border p-3 min-h-[72px] flex flex-col justify-between transition-colors",
                  c > 0
                    ? "border-primary/40 bg-primary/[0.06]"
                    : "border-border/40 bg-surface-raised/20 opacity-60"
                )}
              >
                <p className="text-[10px] font-mono text-muted-foreground leading-tight">{tactic}</p>
                <p
                  className={cn(
                    "text-2xl font-bold font-mono tabular-nums",
                    c > 0 ? "text-primary" : "text-muted-foreground/30"
                  )}
                  style={{
                    color:
                      c > 0
                        ? `hsl(var(--primary) / ${0.5 + intensity * 0.5})`
                        : undefined,
                  }}
                >
                  {c}
                </p>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
