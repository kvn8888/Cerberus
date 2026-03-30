/**
 * components/panels/NarrativePanel.tsx — Streaming threat narrative display
 *
 * The right-side panel that shows the AI-generated threat narrative
 * as it streams in via SSE. Includes metadata badges (cache hit,
 * paths found) and the confirm button for analyst feedback.
 *
 * Implements US-4 (streaming narrative) and US-7 (analyst confirmation).
 */
import { useMemo, useState } from "react";
import {
  FileText,
  Zap,
  Database,
  CheckCircle2,
  AlertTriangle,
  Shield,
  Download,
  GitCompareArrows,
} from "lucide-react";
import type { InvestigationState } from "../../types/api";
import { compareEntities, confirmEntity, fetchReport } from "../../lib/api";
import { cn } from "../../lib/utils";

interface NarrativePanelProps {
  state: InvestigationState;
}

export function NarrativePanel({ state }: NarrativePanelProps) {
  const [confirmed, setConfirmed] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [compareText, setCompareText] = useState("ua-parser-js:package\n203.0.113.42:ip");
  const [compareBusy, setCompareBusy] = useState(false);
  const [compareError, setCompareError] = useState("");
  const [compareResults, setCompareResults] = useState<Array<{
    entity: string;
    entity_type: string;
    paths_found: number;
    from_cache: boolean;
    risk_level: string;
    summary: string;
  }>>([]);

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
    } catch (err) {
      console.error("Confirm failed:", err);
    } finally {
      setConfirming(false);
    }
  };

  const handleExportPdf = async () => {
    if (!canExport) return;
    try {
      const report = await fetchReport({ entity: state.entity, type: state.entityType });
      const popup = window.open("", "_blank", "width=900,height=700");
      if (!popup) {
        throw new Error("Popup blocked");
      }
      popup.document.write(`
        <html>
          <head>
            <title>Cerberus Report - ${report.entity}</title>
            <style>
              body { font-family: Arial, sans-serif; margin: 40px; color: #0f172a; }
              h1, h2 { margin-bottom: 8px; }
              .meta { color: #475569; margin-bottom: 24px; }
              .card { border: 1px solid #cbd5e1; border-radius: 12px; padding: 16px; margin: 16px 0; }
              .pill { display: inline-block; padding: 4px 8px; border-radius: 999px; background: #e2e8f0; margin-right: 8px; font-size: 12px; }
              table { width: 100%; border-collapse: collapse; margin-top: 12px; }
              th, td { text-align: left; padding: 10px; border-bottom: 1px solid #e2e8f0; }
            </style>
          </head>
          <body>
            <h1>Cerberus Threat Report</h1>
            <div class="meta">
              <div><strong>Entity:</strong> ${report.entity}</div>
              <div><strong>Type:</strong> ${report.entity_type}</div>
              <div><strong>Generated:</strong> ${new Date(report.generated_at).toLocaleString()}</div>
            </div>
            <div class="card">
              <span class="pill">Paths Found: ${report.paths_found}</span>
              <span class="pill">Cache: ${report.from_cache ? "Yes" : "No"}</span>
              <span class="pill">Fraud Signals: ${report.juspay_summary.signals}</span>
              <p>${report.summary}</p>
            </div>
            <div class="card">
              <h2>Narrative</h2>
              <p>${(report.narrative || "No cached narrative available yet.").replace(/\n/g, "<br/>")}</p>
            </div>
            <div class="card">
              <h2>Cross-Domain Connections</h2>
              <table>
                <thead><tr><th>Fields</th><th>Values</th></tr></thead>
                <tbody>
                  ${report.cross_domain.map((row: Record<string, unknown>) => `
                    <tr>
                      <td>${Object.keys(row).join(", ")}</td>
                      <td>${Object.values(row).map((value) => Array.isArray(value) ? value.join(", ") : String(value ?? "")).join(" | ")}</td>
                    </tr>`).join("") || '<tr><td colspan="2">No cross-domain rows.</td></tr>'}
                </tbody>
              </table>
            </div>
          </body>
        </html>
      `);
      popup.document.close();
      popup.focus();
      popup.print();
    } catch (err) {
      console.error("Export failed:", err);
    }
  };

  const handleCompare = async () => {
    setCompareBusy(true);
    setCompareError("");
    try {
      const queries = compareText
        .split("\n")
        .map((line) => line.trim())
        .filter(Boolean)
        .map((line) => {
          const [entity, type = "package"] = line.split(":");
          return {
            entity: entity.trim(),
            type: type.trim() as InvestigationState["entityType"],
          };
        });
      const data = await compareEntities(queries);
      setCompareResults(data.results);
    } catch (err) {
      setCompareError(err instanceof Error ? err.message : "Compare failed");
    } finally {
      setCompareBusy(false);
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
                <Zap className="h-3 w-3" />
                CACHED
              </span>
            )}
            <span className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono bg-accent text-accent-foreground border border-primary/20">
              <Database className="h-3 w-3" />
              {state.pathsFound} PATHS
            </span>
          </div>
        )}
      </div>

      <div className="px-4 pt-3">
        <button
          type="button"
          disabled={!canExport}
          onClick={handleExportPdf}
          className={cn(
            "w-full rounded-lg border px-3 py-2 text-xs font-mono transition-all",
            canExport
              ? "border-primary/25 bg-primary/10 text-primary hover:bg-primary/15"
              : "border-border bg-surface-raised text-muted-foreground"
          )}
        >
          <span className="flex items-center justify-center gap-2">
            <Download className="h-3.5 w-3.5" />
            Export PDF Report
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
                    INSTANT
                  </span>
                )}
              </div>

              {/* Narrative text with terminal-style rendering */}
              <div className="relative">
                {/* Vertical accent line */}
                <div className="absolute left-0 top-0 bottom-0 w-px bg-primary/15" />

                <div
                  className={cn(
                    "pl-4 font-mono text-[13px] leading-[1.8] text-foreground/85",
                    "selection:bg-primary/20"
                  )}
                >
                  {state.narrative.split("\n").map((line, i) => (
                    <p
                      key={i}
                      className="animate-text-reveal mb-2"
                      style={{ animationDelay: `${i * 0.03}s` }}
                    >
                      {line || "\u00A0"}
                    </p>
                  ))}

                {/* Animated cursor while streaming */}
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

        <div className="mt-6 rounded-lg border border-border bg-surface-raised/35 p-3">
          <div className="mb-2 flex items-center gap-2 text-[10px] font-mono uppercase tracking-[0.15em] text-muted-foreground">
            <GitCompareArrows className="h-3.5 w-3.5 text-primary" />
            Multi-Entity Comparison
          </div>
          <textarea
            value={compareText}
            onChange={(e) => setCompareText(e.target.value)}
            rows={4}
            className="w-full rounded-lg border border-border bg-surface px-3 py-2 text-xs font-mono text-foreground focus:outline-none focus:border-primary/40"
          />
          <button
            type="button"
            onClick={handleCompare}
            disabled={compareBusy}
            className="mt-2 w-full rounded-lg border border-primary/25 bg-primary/10 px-3 py-2 text-xs font-semibold text-primary hover:bg-primary/15 disabled:opacity-50"
          >
            {compareBusy ? "Comparing..." : "Compare Entities"}
          </button>
          {compareError && (
            <p className="mt-2 text-[10px] font-mono text-threat-high">{compareError}</p>
          )}
          {compareResults.length > 0 && (
            <div className="mt-3 space-y-2">
              {compareResults.map((result) => (
                <div key={`${result.entity}-${result.entity_type}`} className="rounded-md border border-border/70 bg-surface/70 p-3">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-xs text-primary">{result.entity}</span>
                    <span className="text-[10px] font-mono text-muted-foreground">{result.risk_level}</span>
                  </div>
                  <p className="mt-1 text-[11px] text-muted-foreground">
                    {result.entity_type} • {result.paths_found} paths • {result.from_cache ? "cached" : "fresh"}
                  </p>
                  <p className="mt-2 text-xs leading-relaxed text-foreground/85">{result.summary}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* ── Confirm button — only shown when investigation is complete ── */}
      {state.status === "complete" && state.pathsFound > 0 && (
        <div className="p-4 border-t border-border">
          {/* Path count badge */}
          <div className="flex items-center justify-center gap-2 mb-3">
            <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-mono bg-accent/50 text-accent-foreground border border-primary/15">
              <Database className="h-3 w-3" />
              {state.pathsFound} threat {state.pathsFound === 1 ? "path" : "paths"} discovered
            </span>
          </div>

          <button
            onClick={handleConfirm}
            disabled={confirmed || confirming}
            className={cn(
              "w-full py-2.5 rounded-lg text-sm font-bold tracking-wide",
              "transition-all duration-500 flex items-center justify-center gap-2",
              confirmed
                ? "bg-success/15 text-success border border-success/30 cursor-default"
                : confirming
                  ? "bg-muted text-muted-foreground cursor-wait"
                  : "bg-surface-raised text-foreground border border-primary/30 hover:bg-primary/10 hover:border-primary/50 hover:shadow-glow active:scale-[0.98]"
            )}
          >
            <CheckCircle2 className={cn("h-4 w-4", confirmed && "animate-fade-in")} />
            {confirmed
              ? "Pattern Confirmed"
              : confirming
                ? "Confirming..."
                : "Confirm Threat Pattern"}
          </button>
          {confirmed ? (
            <p className="text-[10px] text-success/60 mt-2 text-center font-mono animate-fade-in">
              Future queries for this entity will skip LLM — instant cached response
            </p>
          ) : (
            <p className="text-[10px] text-muted-foreground/40 mt-2 text-center font-mono">
              Validates this pattern for the self-improvement cache
            </p>
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
