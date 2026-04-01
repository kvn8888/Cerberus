/**
 * components/panels/NarrativePanel.tsx — Streaming threat narrative display
 *
 * The right-side panel that shows the AI-generated threat narrative
 * as it streams in via SSE. Includes metadata badges (cache hit,
 * paths found) and the confirm button for analyst feedback.
 *
 * Implements US-4 (streaming narrative) and US-7 (analyst confirmation).
 */
import { useDeferredValue, useEffect, useMemo, useState } from "react";
import ReactMarkdown from "react-markdown";
import {
  FileText,
  Zap,
  Database,
  Brain,
  CheckCircle2,
  AlertTriangle,
  Shield,
  Download,
  Target,
  Crosshair,
  ArrowRight,
  Users,
  Copy,
  Table2,
  PanelRightClose,
  PanelRightOpen,
} from "lucide-react";
import type { InvestigationState, EntityType } from "../../types/api";
import { confirmEntity, fetchReport } from "../../lib/api";
import { cn } from "../../lib/utils";
import { mergeIOCs, iocsToCsv } from "../../lib/iocExtract";
/* ThreatReportPdf and @react-pdf/renderer are dynamically imported in
   handleExportPdf so the 518KB vendor-pdf chunk only loads on click. */

const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-threat-critical bg-threat-critical/10 border-threat-critical/30",
  high: "text-threat-high bg-threat-high/10 border-threat-high/30",
  medium: "text-threat-medium bg-threat-medium/10 border-threat-medium/30",
  low: "text-success bg-success/10 border-success/30",
  info: "text-muted-foreground bg-muted/10 border-border",
};

const SEVERITY_SCORE_COLORS: Record<string, string> = {
  critical: "text-threat-critical",
  high: "text-threat-high",
  medium: "text-threat-medium",
  low: "text-success",
  info: "text-muted-foreground",
};

interface NarrativePanelProps {
  state: InvestigationState;
  onMemorySaved?: () => void;
  onInvestigate?: (entity: string, type: EntityType) => void;
  collapsed?: boolean;
  onToggleCollapse?: () => void;
}

/**
 * Extract a short executive summary from the full narrative.
 * Pulls the first meaningful paragraph and trims to ~2 sentences.
 */
function buildExecutiveSummary(narrative: string): string {
  const lines = narrative
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#") && !l.startsWith("---") && !l.startsWith("|") && !l.startsWith("```"));
  const meaningful = lines.filter((l) => l.length > 40);
  if (meaningful.length === 0) return lines.slice(0, 2).join(" ");
  return meaningful.slice(0, 2).join(" ");
}

export function NarrativePanel({ state, onMemorySaved, onInvestigate, collapsed, onToggleCollapse }: NarrativePanelProps) {
  const [confirmed, setConfirmed] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [viewMode, setViewMode] = useState<"technical" | "executive">("technical");
  const deferredNarrative = useDeferredValue(state.narrative);
  useEffect(() => {
    setConfirmed(false);
  }, [state.entity]);

  const extractedIocs = useMemo(
    () => mergeIOCs(state.graphData, deferredNarrative || ""),
    [state.graphData, deferredNarrative]
  );

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
      // Dynamic imports: @react-pdf/renderer (518KB) loads only on click
      const [{ pdf }, { ThreatReportPdf }] = await Promise.all([
        import("@react-pdf/renderer"),
        import("../report/ThreatReportPdf"),
      ]);
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
      <div className="px-4 py-3 border-b border-border flex items-start justify-between gap-2">
        <h2 className="text-sm font-semibold text-foreground uppercase tracking-wider flex items-center gap-2 flex-shrink-0">
          <FileText className="h-4 w-4 text-primary" />
          {!collapsed && "Threat Narrative"}
        </h2>

        <div className="flex items-center gap-1.5 flex-wrap justify-end">
          {/* Metadata badges — only shown when we have results and panel is open */}
          {!collapsed && state.status === "complete" && (
            <>
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
              {state.threatScore && (
                <span className={cn(
                  "flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono border",
                  SEVERITY_COLORS[state.threatScore.severity]
                )}>
                  <Target className="h-3 w-3" />
                  {state.threatScore.score}/100
                </span>
              )}
              {state.blastRadius && (
                <span className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono bg-threat-high/10 text-threat-high border border-threat-high/20">
                  <Crosshair className="h-3 w-3" />
                  {state.blastRadius.total} AFFECTED
                </span>
              )}
            </>
          )}

          {/* Collapse / expand toggle */}
          {onToggleCollapse && (
            <button
              type="button"
              onClick={onToggleCollapse}
              className="p-1 rounded-md text-muted-foreground hover:text-foreground hover:bg-surface-raised transition-colors"
              title={collapsed ? "Expand narrative panel" : "Collapse narrative panel"}
            >
              {collapsed ? <PanelRightOpen className="h-4 w-4" /> : <PanelRightClose className="h-4 w-4" />}
            </button>
          )}
        </div>
      </div>

      {collapsed ? null : <>
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

        {/* Audience mode toggle — switches between full technical detail and executive summary */}
        <div className="flex items-center gap-1 rounded-lg border border-border/60 bg-surface-raised/30 p-0.5">
          <button
            type="button"
            onClick={() => setViewMode("technical")}
            className={cn(
              "flex-1 px-3 py-1.5 rounded-md text-[10px] font-mono transition-all",
              viewMode === "technical"
                ? "bg-primary/15 text-primary border border-primary/25"
                : "text-muted-foreground hover:text-foreground"
            )}
          >
            Technical
          </button>
          <button
            type="button"
            onClick={() => setViewMode("executive")}
            className={cn(
              "flex-1 px-3 py-1.5 rounded-md text-[10px] font-mono transition-all",
              viewMode === "executive"
                ? "bg-primary/15 text-primary border border-primary/25"
                : "text-muted-foreground hover:text-foreground"
            )}
          >
            <span className="flex items-center justify-center gap-1">
              <Users className="h-3 w-3" />
              Executive
            </span>
          </button>
        </div>
      </div>

      {/* ── Narrative body ─────────────────────────────────── */}
      <div className="flex-1 overflow-y-auto p-4">
        {state.status === "idle" && (
          <IdleState />
        )}

        {(state.status === "running" || state.status === "complete") &&
          deferredNarrative && (
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

              {/* Extracted IOCs — copy / CSV for firewalls & SIEM */}
              {state.status === "complete" && extractedIocs.length > 0 && (
                <div className="p-3 rounded-lg bg-surface-raised/40 border border-border/50">
                  <div className="flex items-center justify-between mb-2">
                    <p className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                      <Table2 className="h-3 w-3 text-primary" />
                      Extracted IOCs ({extractedIocs.length})
                    </p>
                    <div className="flex gap-1">
                      <button
                        type="button"
                        onClick={() => {
                          const lines = extractedIocs.map((r) => r.value);
                          void navigator.clipboard.writeText(lines.join("\n"));
                        }}
                        className="px-2 py-0.5 rounded text-[9px] font-mono border border-border/60 hover:bg-primary/10 hover:border-primary/30 transition-colors flex items-center gap-1"
                      >
                        <Copy className="h-2.5 w-2.5" /> Copy all
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          const blob = new Blob([iocsToCsv(extractedIocs)], { type: "text/csv" });
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement("a");
                          a.href = url;
                          a.download = `cerberus-iocs-${state.entity}-${Date.now()}.csv`;
                          a.click();
                          URL.revokeObjectURL(url);
                        }}
                        className="px-2 py-0.5 rounded text-[9px] font-mono border border-border/60 hover:bg-primary/10 hover:border-primary/30 transition-colors"
                      >
                        CSV
                      </button>
                    </div>
                  </div>
                  <div className="max-h-36 overflow-y-auto space-y-1">
                    {extractedIocs.map((row, i) => (
                      <div
                        key={`${row.type}-${row.value}-${i}`}
                        className="flex items-center justify-between gap-2 text-[10px] font-mono px-2 py-1 rounded bg-surface/50 border border-border/30"
                      >
                        <span className="text-muted-foreground/70 uppercase w-14 flex-shrink-0">{row.type}</span>
                        <span className="text-foreground truncate flex-1">{row.value}</span>
                        <span className="text-muted-foreground/40 w-16 text-right flex-shrink-0">{row.source}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {viewMode === "executive" ? (
                /* ── EXECUTIVE VIEW — clean summary for leadership ── */
                <div className="space-y-4">
                  {/* Risk verdict */}
                  {state.threatScore && (
                    <div className={cn(
                      "p-4 rounded-lg border text-center",
                      SEVERITY_COLORS[state.threatScore.severity]
                    )}>
                      <p className="text-[10px] font-mono uppercase tracking-wider opacity-70 mb-1">Risk Level</p>
                      <p className="text-2xl font-bold font-mono uppercase">
                        {state.threatScore.severity}
                      </p>
                      <p className="text-3xl font-bold font-mono mt-1">
                        {state.threatScore.score}/100
                      </p>
                    </div>
                  )}

                  {/* Key finding */}
                  <div className="p-4 rounded-lg bg-surface-raised/40 border border-border/50">
                    <p className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
                      <FileText className="h-3 w-3 text-primary" />
                      Key Finding
                    </p>
                    <div className={cn(
                      "text-sm leading-relaxed text-foreground/90",
                      "prose prose-invert prose-sm max-w-none",
                      "prose-headings:text-primary prose-headings:font-mono prose-headings:text-sm prose-headings:mt-3 prose-headings:mb-1",
                      "prose-strong:text-primary prose-strong:font-semibold",
                      "prose-p:mb-2 prose-p:leading-relaxed",
                      "prose-ul:my-1 prose-li:my-0.5 prose-li:marker:text-primary/40",
                      "prose-code:text-primary prose-code:bg-primary/10 prose-code:px-1 prose-code:py-0.5 prose-code:rounded prose-code:text-xs",
                    )}>
                      <ReactMarkdown>{buildExecutiveSummary(deferredNarrative)}</ReactMarkdown>
                    </div>
                  </div>

                  {/* Impact numbers */}
                  <div className="grid grid-cols-2 gap-2">
                    <div className="p-3 rounded-lg bg-surface-raised/30 border border-border/50 text-center">
                      <p className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-1">Threat Paths</p>
                      <p className="text-xl font-bold font-mono text-primary">{state.pathsFound}</p>
                    </div>
                    <div className="p-3 rounded-lg bg-surface-raised/30 border border-border/50 text-center">
                      <p className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-1">Blast Radius</p>
                      <p className="text-xl font-bold font-mono text-threat-high">{state.blastRadius?.total ?? 0}</p>
                    </div>
                  </div>

                  {/* Recommended action */}
                  <div className="p-4 rounded-lg bg-primary/5 border border-primary/20">
                    <p className="text-[10px] font-mono uppercase tracking-wider text-primary mb-2 flex items-center gap-1.5">
                      <Shield className="h-3 w-3" />
                      Recommended Action
                    </p>
                    <p className="text-sm text-foreground/80 leading-relaxed">
                      {state.threatScore && state.threatScore.score >= 70
                        ? `Immediate investigation required. ${state.entity} is linked to active threat infrastructure with ${state.pathsFound} confirmed attack path${state.pathsFound === 1 ? "" : "s"}. Escalate to incident response.`
                        : state.threatScore && state.threatScore.score >= 40
                          ? `Monitor closely. ${state.entity} shows indicators of compromise but threat level is moderate. Add to watchlist and review in 24 hours.`
                          : `Low risk. ${state.entity} shows minimal threat indicators. Continue standard monitoring.`
                      }
                    </p>
                  </div>
                </div>
              ) : (
                /* ── TECHNICAL VIEW — full detail for analysts ── */
                <>
                  {/* Threat Score detail card */}
                  {state.threatScore && (
                    <div className="p-3 rounded-lg bg-surface-raised/30 border border-border/50">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">Threat Score</span>
                        <span className={cn("text-lg font-bold font-mono", SEVERITY_SCORE_COLORS[state.threatScore.severity])}>
                          {state.threatScore.score}
                        </span>
                      </div>
                      <div className="w-full h-1.5 rounded-full bg-surface-raised overflow-hidden mb-2">
                        <div
                          className={cn("h-full rounded-full transition-all duration-1000", {
                            "bg-threat-critical": state.threatScore.severity === "critical",
                            "bg-threat-high": state.threatScore.severity === "high",
                            "bg-threat-medium": state.threatScore.severity === "medium",
                            "bg-success": state.threatScore.severity === "low",
                            "bg-muted-foreground": state.threatScore.severity === "info",
                          })}
                          style={{ width: `${state.threatScore.score}%` }}
                        />
                      </div>
                      <div className="space-y-1">
                        {state.threatScore.factors.slice(0, 4).map((f, i) => (
                          <p key={i} className="text-[10px] font-mono text-muted-foreground/70 flex items-center gap-1.5">
                            <span className="w-1 h-1 rounded-full bg-primary/40" />
                            {f}
                          </p>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Blast Radius breakdown */}
                  {state.blastRadius && state.blastRadius.total > 0 && (
                    <div className="p-3 rounded-lg bg-surface-raised/30 border border-border/50">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                          <Crosshair className="h-3 w-3 text-threat-high" />
                          Blast Radius
                        </span>
                        <span className="text-sm font-bold font-mono text-threat-high">{state.blastRadius.total} entities</span>
                      </div>
                      <div className="flex flex-wrap gap-1.5">
                        {Object.entries(state.blastRadius.by_type).map(([type, count]) => (
                          <span key={type} className="px-2 py-0.5 rounded-full text-[9px] font-mono bg-surface-raised border border-border/40 text-muted-foreground">
                            {type}: {count}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

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
                      <ReactMarkdown>{deferredNarrative}</ReactMarkdown>
                      {state.status === "running" && (
                        <span className="inline-flex items-center gap-1 text-primary">
                          <span className="w-1.5 h-4 bg-primary animate-pulse" />
                        </span>
                      )}
                    </div>
                  </div>
                </>
              )}
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

        {/* ── Investigate Next suggestions (inside scroll area so
             they flow naturally after the narrative instead of
             covering it as a fixed footer) ────────────────────── */}
        {state.status === "complete" && state.suggestions && state.suggestions.length > 0 && (
          <div className="mt-4 pt-3 border-t border-border/50">
            <p className="text-[10px] font-mono text-muted-foreground uppercase tracking-wider pb-2 flex items-center gap-1.5">
              <ArrowRight className="h-3 w-3 text-primary" />
              Investigate Next
            </p>
            <div className="space-y-1">
              {state.suggestions.map((s, i) => (
                <button
                  key={i}
                  onClick={() => onInvestigate?.(s.entity, s.type as EntityType)}
                  className="w-full text-left px-3 py-2 rounded-md text-xs font-mono group bg-surface-raised/30 hover:bg-primary/8 hover:text-primary border border-transparent hover:border-primary/15 transition-all duration-200"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-foreground/80 group-hover:text-primary transition-colors truncate">
                      {s.entity}
                    </span>
                    <span className="text-[9px] text-muted-foreground/50 ml-2 flex-shrink-0">
                      {s.connections} links
                    </span>
                  </div>
                  <span className="text-muted-foreground/40 text-[10px] block mt-0.5">
                    {s.reason}
                  </span>
                </button>
              ))}
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
      </>}
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
