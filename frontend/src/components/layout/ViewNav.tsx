/**
 * components/layout/ViewNav.tsx — Tab navigation for center panel views
 *
 * Lets the user switch between "Threat Graph", "Geomap", and "Memory"
 * views. Renders as a floating pill bar overlaying the center panel.
 */
import { Network, Globe2, Brain, Box } from "lucide-react";
import { cn } from "../../lib/utils";

export type CenterView = "graph" | "graph3d" | "geomap" | "memory";

interface ViewNavProps {
  activeView: CenterView;
  onViewChange: (view: CenterView) => void;
  memoryCount?: number;
}

const TABS: { id: CenterView; label: string; icon: typeof Network }[] = [
  { id: "graph", label: "Threat Graph", icon: Network },
  { id: "graph3d", label: "3D Graph", icon: Box },
  { id: "geomap", label: "Geomap", icon: Globe2 },
  { id: "memory", label: "Memory", icon: Brain },
];

export function ViewNav({ activeView, onViewChange, memoryCount }: ViewNavProps) {
  return (
    <nav
      className={cn(
        "absolute top-3 left-3 z-30 flex items-center gap-0.5",
        "rounded-lg border border-border/60 bg-surface backdrop-blur-none",
        "p-0.5 shadow-lg"
      )}
    >
      {TABS.map((tab) => {
        const Icon = tab.icon;
        const isActive = activeView === tab.id;

        return (
          <button
            key={tab.id}
            onClick={() => onViewChange(tab.id)}
            className={cn(
              "flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium",
              "transition-all duration-200",
              isActive
                ? "bg-primary/15 text-primary border border-primary/30 shadow-glow"
                : "text-muted-foreground hover:text-foreground hover:bg-surface-raised/60"
            )}
          >
            <Icon className="h-3.5 w-3.5" />
            {tab.label}

            {/* Memory count badge */}
            {tab.id === "memory" && memoryCount !== undefined && memoryCount > 0 && (
              <span className="ml-0.5 px-1.5 py-0.5 rounded-full text-[9px] font-mono bg-success/15 text-success border border-success/25">
                {memoryCount}
              </span>
            )}

            {isActive && (
              <span className="w-1.5 h-1.5 rounded-full bg-primary pulse-dot ml-0.5" />
            )}
          </button>
        );
      })}
    </nav>
  );
}
