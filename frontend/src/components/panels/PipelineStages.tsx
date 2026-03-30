/**
 * components/panels/PipelineStages.tsx — Visual pipeline progression
 *
 * Shows each stage of the Cerberus investigation pipeline as a
 * horizontal chain of nodes. Stages light up sequentially as the
 * agent progresses: input → NER → classify → route → traverse →
 * analyze → narrate → complete.
 *
 * This implements US-5 (pipeline stage visibility) and US-6
 * (route decision visibility) from the spec.
 */
import {
  Terminal,
  ScanSearch,
  Tag,
  GitFork,
  Network,
  CloudDownload,
  Brain,
  FileText,
  CheckCircle2,
} from "lucide-react";
import type { PipelineStage } from "../../types/api";
import { cn } from "../../lib/utils";

/** Configuration for each pipeline stage — icon, label, description */
const STAGES: {
  id: PipelineStage;
  label: string;
  icon: typeof Terminal;
  description: string;
}[] = [
  {
    id: "input",
    label: "INPUT",
    icon: Terminal,
    description: "Receive entity",
  },
  {
    id: "ner",
    label: "NER",
    icon: ScanSearch,
    description: "Extract entities",
  },
  {
    id: "classify",
    label: "CLASSIFY",
    icon: Tag,
    description: "Threat classification",
  },
  {
    id: "route",
    label: "ROUTE",
    icon: GitFork,
    description: "Choose traversal",
  },
  {
    id: "traverse",
    label: "TRAVERSE",
    icon: Network,
    description: "Graph walk",
  },
  {
    id: "enrich",
    label: "ENRICH",
    icon: CloudDownload,
    description: "Live threat intel",
  },
  {
    id: "analyze",
    label: "ANALYZE",
    icon: Brain,
    description: "LLM reasoning",
  },
  {
    id: "narrate",
    label: "NARRATE",
    icon: FileText,
    description: "Generate report",
  },
  {
    id: "complete",
    label: "DONE",
    icon: CheckCircle2,
    description: "Investigation complete",
  },
];

/** Ordered stage IDs for index-based comparison */
const STAGE_ORDER: PipelineStage[] = STAGES.map((s) => s.id);

interface PipelineStagesProps {
  currentStage: PipelineStage;
  isRunning: boolean;
}

export function PipelineStages({
  currentStage,
  isRunning,
}: PipelineStagesProps) {
  const currentIdx = STAGE_ORDER.indexOf(currentStage);

  return (
    <div className="px-6 py-3 border-b border-border bg-surface/50 backdrop-blur-sm relative overflow-hidden">
      {/* Subtle ambient glow behind active area */}
      {isRunning && (
        <div
          className="absolute inset-0 pointer-events-none transition-opacity duration-1000"
          style={{
            background: `radial-gradient(ellipse at ${(currentIdx / (STAGES.length - 1)) * 100}% 50%, hsl(var(--primary) / 0.06) 0%, transparent 70%)`,
          }}
        />
      )}

      <div className="flex items-center justify-between max-w-5xl mx-auto relative z-10">
        {STAGES.map((stage, idx) => {
          const Icon = stage.icon;
          const isComplete = idx < currentIdx;
          const isActive = idx === currentIdx && isRunning;
          const isPending = idx > currentIdx;

          return (
            <div key={stage.id} className="flex items-center">
              {/* ── Stage node ─────────────────────────────── */}
              <div className="flex flex-col items-center gap-1 relative">
                {/* Outer glow ring for active stage */}
                {isActive && (
                  <div className="absolute -inset-2 rounded-full bg-primary/10 blur-md animate-pulse-slow" />
                )}
                <div
                  className={cn(
                    "flex items-center justify-center w-8 h-8 rounded-full relative z-10",
                    "transition-all duration-500",
                    isComplete &&
                      "bg-primary/20 border border-primary/50 text-primary",
                    isActive &&
                      "bg-primary/30 border-2 border-primary text-primary shadow-glow animate-glow-pulse scale-110",
                    isPending &&
                      "bg-surface-raised border border-border text-muted-foreground/40",
                    !isRunning &&
                      currentStage === "input" &&
                      "bg-surface-raised border border-border text-muted-foreground/40"
                  )}
                >
                  <Icon className={cn(
                    "h-3.5 w-3.5 transition-transform duration-300",
                    isActive && "scale-110",
                    isComplete && "scale-100"
                  )} />
                  {/* Checkmark overlay for completed stages */}
                  {isComplete && (
                    <div className="absolute -top-0.5 -right-0.5 w-2.5 h-2.5 rounded-full bg-primary flex items-center justify-center">
                      <svg className="w-1.5 h-1.5 text-primary-foreground" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="3">
                        <path d="M2 6l3 3 5-5" />
                      </svg>
                    </div>
                  )}
                </div>
                <span
                  className={cn(
                    "text-[8px] font-mono uppercase tracking-wider transition-all duration-300",
                    isComplete && "text-primary/80",
                    isActive && "text-primary font-bold",
                    isPending && "text-muted-foreground/30",
                    !isRunning &&
                      currentStage === "input" &&
                      "text-muted-foreground/30"
                  )}
                >
                  {stage.label}
                </span>
              </div>

              {/* ── Connector line with fill animation ─────── */}
              {idx < STAGES.length - 1 && (
                <div className="w-8 mx-0.5 relative h-0.5">
                  {/* Background track */}
                  <div className="absolute inset-0 bg-border/50 rounded-full" />
                  {/* Filled portion */}
                  <div
                    className={cn(
                      "absolute inset-y-0 left-0 rounded-full transition-all duration-700 ease-out",
                      idx < currentIdx ? "bg-primary/50 w-full" : "bg-transparent w-0"
                    )}
                  />
                  {/* Moving particle on active connector */}
                  {idx === currentIdx - 1 && isRunning && (
                    <div className="absolute top-1/2 -translate-y-1/2 w-1.5 h-1.5 rounded-full bg-primary shadow-glow animate-shimmer" />
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
