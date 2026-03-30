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
    <div className="px-6 py-3 border-b border-border bg-surface/50 backdrop-blur-sm">
      <div className="flex items-center justify-between max-w-5xl mx-auto">
        {STAGES.map((stage, idx) => {
          const Icon = stage.icon;
          /* Determine visual state: completed, active, or pending */
          const isComplete = idx < currentIdx;
          const isActive = idx === currentIdx && isRunning;
          const isPending = idx > currentIdx;

          return (
            <div key={stage.id} className="flex items-center">
              {/* ── Stage node ─────────────────────────────── */}
              <div className="flex flex-col items-center gap-1">
                <div
                  className={cn(
                    "flex items-center justify-center w-8 h-8 rounded-full",
                    "transition-all duration-500",
                    isComplete &&
                      "bg-primary/20 border border-primary/40 text-primary",
                    isActive &&
                      "bg-primary/30 border border-primary text-primary shadow-glow animate-glow-pulse",
                    isPending &&
                      "bg-surface-raised border border-border text-muted-foreground",
                    !isRunning &&
                      currentStage === "input" &&
                      "bg-surface-raised border border-border text-muted-foreground"
                  )}
                >
                  <Icon className="h-3.5 w-3.5" />
                </div>
                <span
                  className={cn(
                    "text-[9px] font-mono uppercase tracking-wider",
                    isComplete && "text-primary",
                    isActive && "text-primary font-bold",
                    isPending && "text-muted-foreground/50",
                    !isRunning &&
                      currentStage === "input" &&
                      "text-muted-foreground/50"
                  )}
                >
                  {stage.label}
                </span>
              </div>

              {/* ── Connector line between stages ──────────── */}
              {idx < STAGES.length - 1 && (
                <div
                  className={cn(
                    "w-6 h-px mx-1",
                    "transition-all duration-500",
                    idx < currentIdx
                      ? "bg-primary/40"
                      : "bg-border"
                  )}
                />
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
