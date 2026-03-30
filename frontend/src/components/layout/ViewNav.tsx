/**
 * components/layout/ViewNav.tsx — Tab navigation for center panel views
 *
 * Lets the user switch between "Threat Graph" (force-directed) and
 * "Geomap" (world threat map) views. Renders as a floating pill bar
 * overlaying the center panel's top-left corner.
 */
import { Network, Globe2 } from "lucide-react";
import { cn } from "../../lib/utils";

/** The two available center-panel views */
export type CenterView = "graph" | "geomap";

interface ViewNavProps {
  /** Currently active view */
  activeView: CenterView;
  /** Callback when user clicks a view tab */
  onViewChange: (view: CenterView) => void;
}

/** Tab configuration — icon, label, and description for each view */
const TABS: { id: CenterView; label: string; icon: typeof Network }[] = [
  { id: "graph", label: "Threat Graph", icon: Network },
  { id: "geomap", label: "Geomap", icon: Globe2 },
];

export function ViewNav({ activeView, onViewChange }: ViewNavProps) {
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

            {/* Active dot indicator */}
            {isActive && (
              <span className="w-1.5 h-1.5 rounded-full bg-primary pulse-dot ml-0.5" />
            )}
          </button>
        );
      })}
    </nav>
  );
}
