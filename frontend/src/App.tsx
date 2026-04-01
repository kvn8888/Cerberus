/**
 * App.tsx — Root layout for the Cerberus threat intelligence dashboard
 *
 * Three-column layout:
 *   Left:   QueryPanel  — entity input + type selector + examples
 *   Center: GraphPanel / ThreatMap / MemoryPanel — toggled via ViewNav tabs
 *   Right:  NarrativePanel — streaming AI threat narrative + memory save
 *
 * The PipelineStages bar sits between the header and main content,
 * showing the agent's progress through each investigation stage.
 */
import { lazy, startTransition, Suspense, useCallback, useState } from "react";
import { Header } from "./components/layout/Header";
import { ViewNav, type CenterView } from "./components/layout/ViewNav";
import { QueryPanel } from "./components/panels/QueryPanel";
import { PipelineStages } from "./components/panels/PipelineStages";
import { NarrativePanel } from "./components/panels/NarrativePanel";
import { TimelinePanel } from "./components/panels/TimelinePanel";
import { useInvestigation } from "./hooks/useInvestigation";
import { cn } from "./lib/utils";

/* Lazy-load heavy visualization panels — only the active tab's chunk loads.
   GraphPanel, ThreatMap, MitreHeatmap, and MemoryPanel each pull in large
   dependencies (d3-force, d3-geo, Three.js references, etc.) that would
   otherwise bloat the initial bundle. */
const GraphPanel = lazy(() => import("./components/panels/GraphPanel").then(m => ({ default: m.GraphPanel })));
const ThreatMap = lazy(() => import("./components/panels/ThreatMap").then(m => ({ default: m.ThreatMap })));
const MitreHeatmapPanel = lazy(() => import("./components/panels/MitreHeatmapPanel").then(m => ({ default: m.MitreHeatmapPanel })));
const MemoryPanel = lazy(() => import("./components/panels/MemoryPanel").then(m => ({ default: m.MemoryPanel })));

function App() {
  const { state, investigate, history } = useInvestigation();
  const [centerView, setCenterView] = useState<CenterView>("geomap");

  /* Bumped by NarrativePanel after a successful "Save to Memory" so
     the MemoryPanel re-fetches from the backend automatically. */
  const [memoryRefreshKey, setMemoryRefreshKey] = useState(0);
  const [memoryCount, setMemoryCount] = useState(0);
  const [narrativeCollapsed, setNarrativeCollapsed] = useState(false);

  const onMemorySaved = useCallback(() => {
    setMemoryRefreshKey((k) => k + 1);
  }, []);

  const handleViewChange = useCallback((view: CenterView) => {
    startTransition(() => {
      setCenterView(view);
    });
  }, []);

  return (
    <div className="flex flex-col h-screen overflow-hidden">
      <Header />

      <PipelineStages
        currentStage={state.currentStage}
        isRunning={state.status === "running"}
        routeInfo={state.routeInfo}
      />

      <main className="flex-1 flex overflow-hidden">
        <aside className="w-72 flex-shrink-0 border-r border-border bg-surface/40 backdrop-blur-sm overflow-y-auto">
          <QueryPanel
            onInvestigate={investigate}
            isRunning={state.status === "running"}
            investigationState={state}
          />
        </aside>

        <section className="flex-1 relative">
          <ViewNav
            activeView={centerView}
            onViewChange={handleViewChange}
            memoryCount={memoryCount}
          />

          {/* Suspense wraps lazy-loaded visualization panels so the rest
              of the UI renders immediately while the active tab's chunk loads */}
          <Suspense fallback={<div className="flex items-center justify-center h-full text-muted-foreground text-sm">Loading view…</div>}>
            {centerView === "graph" && <GraphPanel state={state} />}
            {centerView === "geomap" && <ThreatMap state={state} />}
            {centerView === "mitre" && <MitreHeatmapPanel state={state} />}
            {centerView === "memory" && (
              <MemoryPanel
                refreshKey={memoryRefreshKey}
                onCountChange={setMemoryCount}
              />
            )}
          </Suspense>

          <TimelinePanel
            investigationHistory={history}
            onReplay={(item) => investigate(item.entity, item.entityType)}
          />
        </section>

        <aside className={cn(
          "flex-shrink-0 border-l border-border bg-surface/40 backdrop-blur-sm overflow-x-hidden flex flex-col transition-all duration-300",
          narrativeCollapsed ? "w-12" : "w-96"
        )}>
          <NarrativePanel
            state={state}
            onMemorySaved={onMemorySaved}
            onInvestigate={investigate}
            collapsed={narrativeCollapsed}
            onToggleCollapse={() => setNarrativeCollapsed((c) => !c)}
          />
        </aside>
      </main>
    </div>
  );
}

export default App
