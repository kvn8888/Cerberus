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
import { useCallback, useState } from "react";
import { Header } from "./components/layout/Header";
import { ViewNav, type CenterView } from "./components/layout/ViewNav";
import { QueryPanel } from "./components/panels/QueryPanel";
import { PipelineStages } from "./components/panels/PipelineStages";
import { GraphPanel } from "./components/panels/GraphPanel";
import { ThreatMap } from "./components/panels/ThreatMap";
import { MemoryPanel } from "./components/panels/MemoryPanel";
import { NarrativePanel } from "./components/panels/NarrativePanel";
import { useInvestigation } from "./hooks/useInvestigation";

function App() {
  const { state, investigate, setAudienceMode } = useInvestigation();
  const [centerView, setCenterView] = useState<CenterView>("geomap");

  /* Bumped by NarrativePanel after a successful "Save to Memory" so
     the MemoryPanel re-fetches from the backend automatically. */
  const [memoryRefreshKey, setMemoryRefreshKey] = useState(0);
  const [memoryCount, setMemoryCount] = useState(0);

  const onMemorySaved = useCallback(() => {
    setMemoryRefreshKey((k) => k + 1);
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
            onViewChange={setCenterView}
            memoryCount={memoryCount}
          />

          {centerView === "graph" && <GraphPanel state={state} />}
          {centerView === "geomap" && <ThreatMap state={state} />}
          {centerView === "memory" && (
            <MemoryPanel
              refreshKey={memoryRefreshKey}
              onCountChange={setMemoryCount}
            />
          )}
        </section>

        <aside className="w-96 flex-shrink-0 border-l border-border bg-surface/40 backdrop-blur-sm overflow-hidden">
          <NarrativePanel
            state={state}
            onMemorySaved={onMemorySaved}
            onInvestigate={investigate}
            onAudienceModeChange={setAudienceMode}
          />
        </aside>
      </main>
    </div>
  );
}

export default App
