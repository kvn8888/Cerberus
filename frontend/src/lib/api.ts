/**
 * lib/api.ts — HTTP client for the Cerberus FastAPI backend
 *
 * All API calls go through these functions, which handle base URL
 * construction, JSON parsing, and error propagation.
 * The base URL defaults to localhost:8000 for development.
 */
import type {
  QueryRequest,
  QueryResponse,
  ConfirmRequest,
  ConfirmResponse,
  SchemaResponse,
  GraphResponse,
} from "../types/api";

/** Base URL for the Cerberus backend — no trailing slash */
const API_BASE = "http://localhost:8000";

/**
 * Submit an entity for investigation (non-streaming).
 * Returns the full narrative + metadata in one response.
 */
export async function queryEntity(
  req: QueryRequest
): Promise<QueryResponse> {
  const res = await fetch(`${API_BASE}/api/query`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(req),
  });
  if (!res.ok) {
    throw new Error(`Query failed: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

/**
 * Open an SSE stream for real-time narrative generation.
 * Returns the raw Response so the caller can read the event stream.
 *
 * Usage:
 *   const res = await queryEntityStream({ entity: "ua-parser-js", type: "package" });
 *   const reader = res.body.getReader();
 *   // ... read chunks
 */
export async function queryEntityStream(
  req: QueryRequest
): Promise<Response> {
  const params = new URLSearchParams({
    entity: req.entity,
    type: req.type,
  });
  const res = await fetch(`${API_BASE}/api/query/stream?${params}`);
  if (!res.ok) {
    throw new Error(`Stream failed: ${res.status} ${res.statusText}`);
  }
  return res;
}

/**
 * Confirm a threat pattern — analyst validation that triggers
 * the self-improvement cache write-back.
 */
export async function confirmEntity(
  req: ConfirmRequest
): Promise<ConfirmResponse> {
  const res = await fetch(`${API_BASE}/api/confirm`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(req),
  });
  if (!res.ok) {
    throw new Error(`Confirm failed: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

/**
 * Fetch the graph traversal result as nodes + links for the
 * force-directed visualization in GraphPanel.
 */
export async function fetchGraph(
  req: QueryRequest
): Promise<GraphResponse> {
  const params = new URLSearchParams({
    entity: req.entity,
    type: req.type,
  });
  const res = await fetch(`${API_BASE}/api/query/graph?${params}`);
  if (!res.ok) {
    throw new Error(`Graph fetch failed: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

/**
 * Fetch the live graph schema (node labels, relationship types, counts).
 * Used to populate the schema sidebar.
 */
export async function fetchSchema(): Promise<SchemaResponse> {
  const res = await fetch(`${API_BASE}/api/schema`);
  if (!res.ok) {
    throw new Error(`Schema failed: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

/**
 * Health check — returns true if the backend is reachable.
 */
export async function healthCheck(): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE}/health`);
    return res.ok;
  } catch {
    return false;
  }
}
