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
  NaturalLanguageResponse,
  ComparisonResponse,
  FeedResponse,
  MapResponse,
  ReportResponse,
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

/**
 * RocketRide health check — returns true if the RocketRide pipeline
 * service is reachable (proxied through the backend).
 */
export async function rocketrideHealthCheck(): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE}/api/rocketride/health`);
    if (!res.ok) return false;
    const data = await res.json();
    return data.available === true;
  } catch {
    return false;
  }
}

export async function parseNaturalLanguage(
  message: string
): Promise<NaturalLanguageResponse> {
  const res = await fetch(`${API_BASE}/api/demo/natural`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message }),
  });
  if (!res.ok) {
    throw new Error(`Natural-language parse failed: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

export async function compareEntities(
  queries: QueryRequest[]
): Promise<ComparisonResponse> {
  const res = await fetch(`${API_BASE}/api/demo/compare`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ queries }),
  });
  if (!res.ok) {
    throw new Error(`Compare failed: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

export async function fetchLiveFeed(limit = 6): Promise<FeedResponse> {
  const res = await fetch(`${API_BASE}/api/demo/feed?limit=${limit}`);
  if (!res.ok) {
    throw new Error(`Live feed failed: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

export async function ingestFeedEvent(event: {
  juspay_id: string;
  fraud_type: string;
  amount: number;
  currency: string;
  ip_address: string;
  merchant_id?: string;
}): Promise<{ success: boolean; ingested: number }> {
  const res = await fetch(`${API_BASE}/api/demo/feed/ingest`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(event),
  });
  if (!res.ok) {
    throw new Error(`Feed ingest failed: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

export async function fetchGeoMap(
  req: QueryRequest
): Promise<MapResponse> {
  const params = new URLSearchParams({
    entity: req.entity,
    type: req.type,
  });
  const res = await fetch(`${API_BASE}/api/demo/map?${params}`);
  if (!res.ok) {
    throw new Error(`Map fetch failed: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

export async function fetchReport(
  req: QueryRequest
): Promise<ReportResponse> {
  const params = new URLSearchParams({
    entity: req.entity,
    type: req.type,
  });
  const res = await fetch(`${API_BASE}/api/demo/report?${params}`);
  if (!res.ok) {
    throw new Error(`Report failed: ${res.status} ${res.statusText}`);
  }
  return res.json();
}
