/**
 * hooks/useInvestigation.ts — Core state machine for running investigations
 *
 * Manages the full lifecycle: idle → streaming SSE → complete/error.
 * Simulates pipeline stage progression for visual feedback.
 * Exposes the narrative text, metadata, and stage for the UI.
 */
import { useState, useCallback, useRef } from "react";
import type {
  EntityType,
  PipelineStage,
  InvestigationState,
} from "../types/api";
import { queryEntityStream } from "../lib/api";

/** The ordered pipeline stages displayed in the UI */
const PIPELINE_STAGES: PipelineStage[] = [
  "input",
  "ner",
  "classify",
  "route",
  "traverse",
  "analyze",
  "narrate",
  "complete",
];

/** Default idle state before any investigation */
const IDLE_STATE: InvestigationState = {
  status: "idle",
  entity: "",
  entityType: "package",
  currentStage: "input",
  narrative: "",
  pathsFound: 0,
  fromCache: false,
};

/**
 * Custom hook that drives the investigation flow.
 *
 * Returns:
 * - state: current investigation state (status, narrative, stage, etc.)
 * - investigate: trigger function — pass entity + type to start
 * - reset: clear back to idle
 */
export function useInvestigation() {
  const [state, setState] = useState<InvestigationState>(IDLE_STATE);
  /* Ref to allow cancellation if user starts a new query mid-stream */
  const abortRef = useRef<AbortController | null>(null);

  /**
   * Advance through pipeline stages on a timer to give
   * visual feedback while waiting for SSE data.
   * Each stage lights up for ~600ms before advancing.
   */
  const simulateStages = useCallback(
    (upTo: PipelineStage) => {
      const targetIdx = PIPELINE_STAGES.indexOf(upTo);
      let current = 0;

      const interval = setInterval(() => {
        if (current >= targetIdx) {
          clearInterval(interval);
          return;
        }
        current++;
        setState((prev) => ({
          ...prev,
          currentStage: PIPELINE_STAGES[current],
        }));
      }, 600);

      return () => clearInterval(interval);
    },
    []
  );

  /**
   * Start an investigation for the given entity.
   * Opens an SSE stream and accumulates narrative text.
   */
  const investigate = useCallback(
    async (entity: string, entityType: EntityType) => {
      /* Cancel any in-flight investigation */
      abortRef.current?.abort();
      const controller = new AbortController();
      abortRef.current = controller;

      /* Reset state and mark as running */
      setState({
        status: "running",
        entity,
        entityType,
        currentStage: "input",
        narrative: "",
        pathsFound: 0,
        fromCache: false,
      });

      /* Start visual stage progression */
      const cleanup = simulateStages("analyze");

      try {
        const res = await queryEntityStream({ entity, type: entityType });

        if (!res.body) {
          throw new Error("No response body — SSE not supported");
        }

        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let accumulated = "";

        /* Read the SSE stream chunk by chunk */
        while (true) {
          if (controller.signal.aborted) break;

          const { done, value } = await reader.read();
          if (done) break;

          const text = decoder.decode(value, { stream: true });
          /* SSE format: "data: {json}\n\n" — split on double newline */
          const lines = text.split("\n");

          for (const line of lines) {
            if (!line.startsWith("data: ")) continue;
            const payload = line.slice(6).trim();

            /* Terminal marker */
            if (payload === "[DONE]") {
              setState((prev) => ({
                ...prev,
                status: "complete",
                currentStage: "complete",
              }));
              cleanup();
              return;
            }

            /* Parse JSON chunk */
            try {
              const chunk = JSON.parse(payload);

              if ("from_cache" in chunk && "paths_found" in chunk) {
                /* Metadata chunk with path count */
                setState((prev) => ({
                  ...prev,
                  pathsFound: chunk.paths_found,
                  fromCache: chunk.from_cache,
                  currentStage: "narrate",
                }));
              } else if ("from_cache" in chunk) {
                /* Cache-hit indicator */
                setState((prev) => ({
                  ...prev,
                  fromCache: chunk.from_cache,
                  currentStage: "narrate",
                }));
              } else if ("text" in chunk) {
                /* Narrative text fragment — append */
                accumulated += chunk.text;
                setState((prev) => ({
                  ...prev,
                  narrative: accumulated,
                  currentStage: "narrate",
                }));
              }
            } catch {
              /* Skip malformed JSON chunks */
            }
          }
        }

        /* If stream ended without [DONE], still mark complete */
        setState((prev) => ({
          ...prev,
          status: "complete",
          currentStage: "complete",
        }));
      } catch (err) {
        if (controller.signal.aborted) return;
        setState((prev) => ({
          ...prev,
          status: "error",
          error:
            err instanceof Error ? err.message : "Unknown error occurred",
        }));
      } finally {
        cleanup();
      }
    },
    [simulateStages]
  );

  /** Reset everything back to idle */
  const reset = useCallback(() => {
    abortRef.current?.abort();
    setState(IDLE_STATE);
  }, []);

  return { state, investigate, reset };
}
