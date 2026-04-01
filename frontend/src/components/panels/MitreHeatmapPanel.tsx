/**
 * MITRE ATT&CK tactic heatmap from Technique nodes in the current investigation graph.
 */
import { useMemo } from "react";
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

    /* Prefer the tactic field provided by the backend (from Neo4j).
       Fall back to the frontend T_TO_TACTIC lookup by technique ID. */
    const backendTactic = String((n as { tactic?: string }).tactic || "");
    const raw = String((n as { mitre_id?: string }).mitre_id || n.label || n.id || "");
    const tid = extractTechniqueId(raw) || extractTechniqueId(String(n.label || n.id));

    const tactic =
      (backendTactic && MITRE_TACTICS_ORDER.includes(backendTactic as any) ? backendTactic : null)
      || (tid ? tacticForTechniqueId(tid) : null)
      || "Discovery";

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

  return (
    <div className="relative h-full w-full overflow-hidden grid-bg flex flex-col">
      <div className="flex-1 overflow-y-auto p-4 pt-14">
        {total > 0 && (
          <p className="text-xs text-muted-foreground font-mono mb-3 text-right">
            {total} technique{total !== 1 ? "s" : ""} across {MITRE_TACTICS_ORDER.filter((t) => (counts.get(t) ?? 0) > 0).length} tactic{MITRE_TACTICS_ORDER.filter((t) => (counts.get(t) ?? 0) > 0).length !== 1 ? "s" : ""}
          </p>
        )}
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
