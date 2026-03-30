/**
 * components/panels/NarrativePanel.tsx — Streaming threat narrative display
 *
 * The right-side panel that shows the AI-generated threat narrative
 * as it streams in via SSE. Includes metadata badges (cache hit,
 * paths found) and the confirm button for analyst feedback.
 *
 * Implements US-4 (streaming narrative) and US-7 (analyst confirmation).
 */
import { useEffect, useMemo, useState } from "react";
import ReactMarkdown from "react-markdown";
import { pdf } from "@react-pdf/renderer";
import {
  FileText,
  Zap,
  Database,
  Brain,
  CheckCircle2,
  AlertTriangle,
  Shield,
  Download,
} from "lucide-react";
import type { InvestigationState } from "../../types/api";
import { confirmEntity, fetchReport } from "../../lib/api";
import { cn } from "../../lib/utils";
import { ThreatReportPdf } from "../report/ThreatReportPdf";

interface NarrativePanelProps {
  state: InvestigationState;
  onMemorySaved?: () => void;
}

export function NarrativePanel({ state, onMemorySaved }: NarrativePanelProps) {
  const [confirmed, setConfirmed] = useState(false);
  const [confirming, setConfirming] = useState(false);
  useEffect(() => {
    setConfirmed(false);
  }, [state.entity]);

  const canExport = useMemo(
    () => state.status === "complete" && !!state.entity,
    [state.status, state.entity]
  );

  /**
   * Handle analyst confirmation — sends a POST /api/confirm
   * to mark this threat pattern for cache acceleration.
   */
  const handleConfirm = async () => {
    if (confirmed || confirming) return;
    setConfirming(true);
    try {
      await confirmEntity({
        entity: state.entity,
        type: state.entityType,
      });
      setConfirmed(true);
      onMemorySaved?.();
    } catch (err) {
      console.error("Confirm failed:", err);
    } finally {
      setConfirming(false);
    }
  };

  const [pdfBusy, setPdfBusy] = useState(false);

  const handleExportPdf = async () => {
    if (!canExport || pdfBusy) return;
    setPdfBusy(true);
    try {
      // Fetch the report data from the backend
      const report = await fetchReport({ entity: state.entity, type: state.entityType });
      // Render the React-PDF document to a blob (all client-side, no popups)
      const blob = await pdf(<ThreatReportPdf report={report} />).toBlob();
      // Create a temporary download link and trigger the save dialog
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `cerberus-report-${report.entity}-${Date.now()}.pdf`;
      document.body.appendChild(a);
      a.click();
      // Clean up the object URL and temporary link element
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Export failed:", err);
      alert("Report generation failed — check the console for details.");
    } finally {
      setPdfBusy(false);
    }
  };

  return (
    <div className="flex flex-col h-full">
      {/* ── Section header ─────────────────────────────────── */}
      <div className="px-4 py-3 border-b border-border flex items-center justify-between">
        <h2 className="text-sm font-semibold text-foreground uppercase tracking-wider flex items-center gap-2">
          <FileText className="h-4 w-4 text-primary" />
          Threat Narrative
        </h2>

        {/* Metadata badges — only shown when we have results */}
        {state.status === "complete" && (
          <div className="flex items-center gap-2">
            {state.fromCache && (
              <span className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono bg-success/10 text-success border border-success/20">
                <Brain className="h-3 w-3" />
                FROM MEMORY
              </span>
            )}
            <span className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono bg-accent text-accent-foreground border border-primary/20">
              <Database className="h-3 w-3" />
              {state.pathsFound} PATHS
            </span>
          </div>
        )}
      </div>

      <div className="px-4 pt-3 flex flex-col gap-2">
        <button
          type="button"
          disabled={!canExport || pdfBusy}
          onClick={handleExportPdf}
          className={cn(
            "w-full rounded-lg border px-3 py-2 text-xs font-mono transition-all",
            canExport && !pdfBusy
              ? "border-primary/25 bg-primary/10 text-primary hover:bg-primary/15"
              : "border-border bg-surface-raised text-muted-foreground"
          )}
        >
          <span className="flex items-center justify-center gap-2">
            <Download className="h-3.5 w-3.5" />
            {pdfBusy ? "Generating PDF..." : "Export PDF Report"}
          </span>
        </button>

      </div>

      {/* ── Narrative body ─────────────────────────────────── */}
      <div className="flex-1 overflow-y-auto p-4">
        {state.status === "idle" && (
          <IdleState />
        )}

        {(state.status === "running" || state.status === "complete") &&
          state.narrative && (
            <div className="space-y-4 animate-fade-in">
              {/* Entity header card */}
              <div className="flex items-center gap-2.5 p-3 rounded-lg bg-surface-raised/50 border border-border/50">
                <div className="relative">
                  <Shield className="h-5 w-5 text-primary relative z-10" />
                  <div className="absolute inset-0 blur-md bg-primary/20 rounded-full" />
                </div>
                <div>
                  <span className="font-mono text-sm font-semibold text-primary block">
                    {state.entity}
                  </span>
                  <span className="text-[9px] font-mono uppercase text-muted-foreground tracking-wider">
                    {state.entityType} investigation
                  </span>
                </div>
                {state.fromCache && (
                  <span className="ml-auto flex items-center gap-1 px-2 py-0.5 rounded-full text-[9px] font-mono bg-success/10 text-success border border-success/20 animate-fade-in">
                    <Zap className="h-2.5 w-2.5" />
                    RECALLED INSTANTLY
                  </span>
                )}
              </div>

              {/* Narrative text with markdown rendering */}
              <div className="relative">
                <div className="absolute left-0 top-0 bottom-0 w-px bg-primary/15" />

                <div
                  className={cn(
                    "pl-4 font-mono text-[13px] leading-[1.8] text-foreground/85",
                    "selection:bg-primary/20",
                    "prose prose-invert prose-sm max-w-none",
                    "prose-headings:text-primary prose-headings:font-mono prose-headings:text-sm prose-headings:mt-3 prose-headings:mb-1",
                    "prose-strong:text-primary prose-strong:font-semibold",
                    "prose-p:mb-2 prose-p:leading-[1.8]",
                    "prose-ul:my-1 prose-li:my-0.5 prose-li:marker:text-primary/40",
                    "prose-code:text-primary prose-code:bg-primary/10 prose-code:px-1 prose-code:py-0.5 prose-code:rounded prose-code:text-xs",
                  )}
                >
                  <ReactMarkdown>{state.narrative}</ReactMarkdown>

                  {state.status === "running" && (
                    <span className="inline-flex items-center gap-1 text-primary">
                      <span className="w-1.5 h-4 bg-primary animate-pulse" />
                    </span>
                  )}
                </div>
              </div>
            </div>
          )}

        {state.status === "error" && (
          <div className="flex items-start gap-3 p-4 rounded-lg bg-threat-critical/10 border border-threat-critical/20">
            <AlertTriangle className="h-5 w-5 text-threat-critical flex-shrink-0 mt-0.5" />
            <div>
              <p className="text-sm font-medium text-threat-critical">
                Investigation Failed
              </p>
              <p className="text-xs text-muted-foreground mt-1 font-mono">
                {state.error}
              </p>
            </div>
          </div>
        )}

      </div>

      {/* ── Memory save — shown when complete with paths, hidden if already memorized ── */}
      {state.status === "complete" && state.pathsFound > 0 && (
        <div className="p-4 border-t border-border">
          <div className="flex items-center justify-center gap-2 mb-3">
            <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-mono bg-accent/50 text-accent-foreground border border-primary/15">
              <Database className="h-3 w-3" />
              {state.pathsFound} threat {state.pathsFound === 1 ? "path" : "paths"} discovered
            </span>
          </div>

          {state.fromCache ? (
            /* Already memorized — show static "already in memory" state */
            <>
              <div className="w-full py-2.5 rounded-lg text-sm font-bold tracking-wide bg-success/15 text-success border border-success/30 flex items-center justify-center gap-2 shadow-[0_0_16px_hsl(var(--success)/0.15)]">
                <CheckCircle2 className="h-4 w-4" />
                Already Memorized
              </div>
              <p className="text-[10px] text-success/60 mt-2 text-center font-mono">
                This pattern was recalled from memory — no need to save again
              </p>
            </>
          ) : (
            /* Not yet memorized — show save button */
            <>
              <button
                onClick={handleConfirm}
                disabled={confirmed || confirming}
                className={cn(
                  "group w-full py-2.5 rounded-lg text-sm font-bold tracking-wide",
                  "transition-all duration-500 flex items-center justify-center gap-2",
                  confirmed
                    ? "bg-success/15 text-success border border-success/30 cursor-default shadow-[0_0_16px_hsl(var(--success)/0.15)]"
                    : confirming
                      ? "bg-muted text-muted-foreground cursor-wait"
                      : "bg-surface-raised text-foreground border border-primary/30 hover:bg-primary/10 hover:border-primary/50 hover:shadow-glow active:scale-[0.98]"
                )}
              >
                {confirmed ? (
                  <>
                    <CheckCircle2 className="h-4 w-4 animate-fade-in" />
                    Memorized
                  </>
                ) : confirming ? (
                  <>
                    <Brain className="h-4 w-4 animate-pulse" />
                    Saving to Memory...
                  </>
                ) : (
                  <>
                    <Brain className="h-4 w-4 group-hover:animate-pulse" />
                    Save to Memory
                  </>
                )}
              </button>
              {confirmed ? (
                <p className="text-[10px] text-success/60 mt-2 text-center font-mono animate-fade-in">
                  This pattern will be recognized instantly next time
                </p>
              ) : (
                <p className="text-[10px] text-muted-foreground/40 mt-2 text-center font-mono">
                  Teach the system to recognize this threat pattern instantly
                </p>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}

/**
 * Idle state content — shown before any investigation is started.
 * Provides an atmospheric hint about capabilities.
 */
function IdleState() {
  return (
    <div className="flex flex-col items-center justify-center h-full text-center px-6">
      {/* Animated shield with layered glow */}
      <div className="relative mb-6">
        <Shield className="h-16 w-16 text-muted-foreground/20 animate-float" />
        <div className="absolute inset-0 blur-xl bg-primary/5 rounded-full" />
      </div>

      <p className="text-sm font-medium text-muted-foreground/60 mb-2">
        No active investigation
      </p>
      <p className="text-xs text-muted-foreground/40 max-w-[240px] leading-relaxed">
        Select an entity type and enter a target to begin cross-domain
        threat analysis. The agent will traverse the knowledge graph,
        reason about attack chains, and generate a narrative.
      </p>

      {/* Decorative divider */}
      <div className="mt-6 flex items-center gap-2">
        <div className="w-8 h-px bg-border/50" />
        <div className="w-1.5 h-1.5 rounded-full bg-muted-foreground/15" />
        <div className="w-8 h-px bg-border/50" />
      </div>

      {/* Capability hints */}
      <div className="mt-4 space-y-2 text-[10px] text-muted-foreground/30 font-mono">
        <p>Package supply-chain analysis</p>
        <p>IP/domain infrastructure mapping</p>
        <p>MITRE ATT&CK technique correlation</p>
      </div>
    </div>
  );
}
