/**
 * components/panels/NarrativePanel.tsx — Streaming threat narrative display
 *
 * The right-side panel that shows the AI-generated threat narrative
 * as it streams in via SSE. Includes metadata badges (cache hit,
 * paths found) and the confirm button for analyst feedback.
 *
 * Implements US-4 (streaming narrative) and US-7 (analyst confirmation).
 */
import { useState } from "react";
import {
  FileText,
  Zap,
  Database,
  CheckCircle2,
  AlertTriangle,
  Shield,
} from "lucide-react";
import type { InvestigationState } from "../../types/api";
import { confirmEntity } from "../../lib/api";
import { cn } from "../../lib/utils";

interface NarrativePanelProps {
  state: InvestigationState;
}

export function NarrativePanel({ state }: NarrativePanelProps) {
  const [confirmed, setConfirmed] = useState(false);
  const [confirming, setConfirming] = useState(false);

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

      {/* ── Narrative body ─────────────────────────────────── */}
      <div className="flex-1 overflow-y-auto p-4">
        {state.status === "idle" && (
          <IdleState />
        )}

        {(state.status === "running" || state.status === "complete") &&
          state.narrative && (
            <div className="space-y-4 animate-fade-in">
              {/* Entity being investigated */}
              <div className="flex items-center gap-2 mb-3">
                <Shield className="h-4 w-4 text-primary" />
                <span className="font-mono text-sm text-primary">
                  {state.entity}
                </span>
                <span className="text-[10px] font-mono uppercase text-muted-foreground px-1.5 py-0.5 rounded bg-surface-raised">
                  {state.entityType}
                </span>
              </div>

              {/* Narrative text — formatted with monospace for that terminal feel */}
              <div
                className={cn(
                  "prose prose-invert prose-sm max-w-none",
                  "font-mono text-sm leading-relaxed text-foreground/90",
                  "[&_p]:mb-3"
                )}
              >
                {state.narrative.split("\n").map((line, i) => (
                  <p key={i} className="animate-fade-in" style={{ animationDelay: `${i * 0.02}s` }}>
                    {line || "\u00A0"}
                  </p>
                ))}

                {/* Blinking cursor while streaming */}
                {state.status === "running" && (
                  <span className="inline-block w-2 h-4 bg-primary animate-pulse ml-0.5" />
                )}
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

      {/* ── Confirm button — only shown when investigation is complete ── */}
      {state.status === "complete" && state.pathsFound > 0 && (
        <div className="p-4 border-t border-border">
          <button
            onClick={handleConfirm}
            disabled={confirmed || confirming}
            className={cn(
              "w-full py-2.5 rounded-lg text-sm font-semibold",
              "transition-all duration-300 flex items-center justify-center gap-2",
              confirmed
                ? "bg-success/15 text-success border border-success/30 cursor-default"
                : confirming
                  ? "bg-muted text-muted-foreground cursor-wait"
                  : "bg-surface-raised text-foreground border border-primary/30 hover:bg-primary/10 hover:border-primary/50 hover:shadow-glow"
            )}
          >
            <CheckCircle2 className="h-4 w-4" />
            {confirmed
              ? "Pattern Confirmed — Future queries will be instant"
              : confirming
                ? "Confirming..."
                : "Confirm Threat Pattern"}
          </button>
          <p className="text-[10px] text-muted-foreground mt-2 text-center font-mono">
            Confirms this pattern for cache acceleration (self-improvement loop)
          </p>
        </div>
      )}
    </div>
  );
}

/**
 * Idle state content — shown before any investigation is started.
 * Provides a hint about what the tool does.
 */
function IdleState() {
  return (
    <div className="flex flex-col items-center justify-center h-full text-center px-6 opacity-60">
      <Shield className="h-12 w-12 text-muted-foreground mb-4" />
      <p className="text-sm text-muted-foreground mb-1">
        No active investigation
      </p>
      <p className="text-xs text-muted-foreground/70 max-w-xs">
        Select an entity type and enter a target to begin cross-domain
        threat analysis. The AI agent will traverse the knowledge graph
        and generate a threat narrative.
      </p>
    </div>
  );
}
