/**
 * App.tsx — Root layout for the Cerberus threat intelligence dashboard
 *
 * Three-column layout:
 *   Left:   QueryPanel  — entity input + type selector + examples
 *   Center: GraphPanel  — force-directed attack chain visualization
 *   Right:  NarrativePanel — streaming AI threat narrative + confirm
 *
 * The PipelineStages bar sits between the header and main content,
 * showing the agent's progress through each investigation stage.
 */
import { Header } from "./components/layout/Header";
import { QueryPanel } from "./components/panels/QueryPanel";
import { PipelineStages } from "./components/panels/PipelineStages";
import { GraphPanel } from "./components/panels/GraphPanel";
import { NarrativePanel } from "./components/panels/NarrativePanel";
import { useInvestigation } from "./hooks/useInvestigation";

function App() {
  /* Central investigation state machine */
  const { state, investigate } = useInvestigation();

  return (
    <div className="flex flex-col h-screen overflow-hidden">
      {/* ── Top bar: brand + connection status ─────────────── */}
      <Header />

      {/* ── Pipeline progress bar ──────────────────────────── */}
      <PipelineStages
        currentStage={state.currentStage}
        isRunning={state.status === "running"}
      />

      {/* ── Main three-column layout ───────────────────────── */}
      <main className="flex-1 flex overflow-hidden">
        {/* Left panel: investigation input */}
        <aside className="w-72 flex-shrink-0 border-r border-border bg-surface/40 backdrop-blur-sm overflow-y-auto">
          <QueryPanel
            onInvestigate={investigate}
            isRunning={state.status === "running"}
          />
        </aside>

        {/* Center: graph visualization */}
        <section className="flex-1 relative">
          <GraphPanel state={state} />
        </section>

        {/* Right panel: streaming narrative + confirm */}
        <aside className="w-96 flex-shrink-0 border-l border-border bg-surface/40 backdrop-blur-sm overflow-hidden">
          <NarrativePanel state={state} />
        </aside>
      </main>
    </div>
  );
}

export default App
