/**
 * hooks/useInvestigation.ts — Core state machine for running investigations
 *
 * Manages the full lifecycle: idle → streaming SSE → complete/error.
 * Pipeline stage progression is driven by real {"stage": "..."} events from
 * the backend SSE stream. No simulation timers needed.
 * Exposes the narrative text, metadata, and stage for the UI.
 *
 * SSE event contract (emitted by GET /api/query/stream):
 *   {"stage": "input"|"ner"|"classify"|"route"|"traverse"|"analyze"|"narrate"|"complete"}
 *   {"route_info": {"strategy": string, "path": string[], "reason": string}}
 *   {"paths_found": number, "from_cache": boolean}
 *   {"text": string}   — narrative chunk, may arrive many times
 *   "[DONE]"           — terminal string (not JSON)
 */
import { useState, useCallback, useRef } from "react";
import type {
  EntityType,
  PipelineStage,
  InvestigationState,
} from "../types/api";
import { queryEntityStream, fetchGraph } from "../lib/api";

/** Default idle state before any investigation */
const IDLE_STATE: InvestigationState = {
  status: "idle",
  entity: "",
  entityType: "package",
  currentStage: "input",
  routeInfo: undefined,
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
   * Finish the investigation: fetch graph data then mark complete.
   * Called on both normal [DONE] and early-exit paths.
   */
  const finalize = useCallback(
    async (entity: string, entityType: EntityType) => {
      try {
        const graph = await fetchGraph({ entity, type: entityType });
        setState((prev) => ({
          ...prev,
          status: "complete",
          currentStage: "complete",
          graphData: graph.nodes.length > 0 ? graph : undefined,
        }));
      } catch {
        /* Graph fetch failed — still mark complete, GraphPanel falls back to demo */
        setState((prev) => ({
          ...prev,
          status: "complete",
          currentStage: "complete",
        }));
      }
    },
    []
  );

  /**
   * Start an investigation for the given entity.
   * Opens an SSE stream and processes events as they arrive.
   * Stage transitions come from the backend — no timers needed.
   */
  const investigate = useCallback(
    async (entity: string, entityType: EntityType) => {
      /* Cancel any in-flight investigation */
      abortRef.current?.abort();
      const controller = new AbortController();
      abortRef.current = controller;

      /* Full reset — wipe everything from the previous investigation */
      setState({
        status: "running",
        entity,
        entityType,
        currentStage: "input",
        routeInfo: undefined,
        narrative: "",
        pathsFound: 0,
        fromCache: false,
        graphData: undefined,
      });

      try {
        const res = await queryEntityStream({ entity, type: entityType });

        if (!res.body) {
          throw new Error("No response body — SSE not supported");
        }

        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let accumulated = "";
        /* Buffer for partial SSE lines split across chunks */
        let buffer = "";

        /* Read the SSE stream chunk by chunk */
        while (true) {
          if (controller.signal.aborted) break;

          const { done, value } = await reader.read();
          if (done) break;

          /* Append to buffer and split on newlines */
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split("\n");
          /* Keep last (possibly incomplete) line in buffer */
          buffer = lines.pop() ?? "";

          for (const line of lines) {
            if (!line.startsWith("data: ")) continue;
            const payload = line.slice(6).trim();

            /* Terminal marker — fetch graph then done */
            if (payload === "[DONE]") {
              await finalize(entity, entityType);
              return;
            }

            /* Parse JSON event */
            try {
              const chunk = JSON.parse(payload);

              if ("stage" in chunk) {
                /* Real pipeline stage transition from backend */
                setState((prev) => ({
                  ...prev,
                  currentStage: chunk.stage as PipelineStage,
                }));
              } else if ("route_info" in chunk) {
                /* Route selection details from backend reasoning */
                setState((prev) => ({
                  ...prev,
                  routeInfo: chunk.route_info,
                }));
              } else if ("paths_found" in chunk) {
                /* Metadata: path count + cache status */
                setState((prev) => ({
                  ...prev,
                  pathsFound: chunk.paths_found,
                  fromCache: chunk.from_cache ?? false,
                }));
              } else if ("text" in chunk) {
                /* Narrative text fragment — append to accumulated narrative */
                accumulated += chunk.text;
                setState((prev) => ({
                  ...prev,
                  narrative: accumulated,
                }));
              }
            } catch {
              /* Skip malformed JSON chunks */
            }
          }
        }

        /* Stream ended without [DONE] — still finalize */
        await finalize(entity, entityType);
      } catch (err) {
        if (controller.signal.aborted) return;
        setState((prev) => ({
          ...prev,
          status: "error",
          error:
            err instanceof Error ? err.message : "Unknown error occurred",
        }));
      }
    },
    [finalize]
  );

  /** Reset everything back to idle */
  const reset = useCallback(() => {
    abortRef.current?.abort();
    setState(IDLE_STATE);
  }, []);

  return { state, investigate, reset };
}
