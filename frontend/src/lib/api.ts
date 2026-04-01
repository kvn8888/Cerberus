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
  MapResponse,
  ReportResponse,
  ThreatScore,
  BlastRadius,
  Suggestion,
} from "../types/api";

/** Base URL for the Cerberus backend — no trailing slash.
 *  Uses VITE_API_URL env var if set (baked in at build time).
 *  When empty string (unified container), uses relative URLs (same origin).
 *  Falls back to localhost:8000 for local dev. */
const API_BASE =
  import.meta.env.VITE_API_URL !== undefined
    ? import.meta.env.VITE_API_URL
    : "http://localhost:8000";

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
  req: QueryRequest,
  options?: { signal?: AbortSignal }
): Promise<Response> {
  const params = new URLSearchParams({
    entity: req.entity,
    type: req.type,
  });
  const res = await fetch(`${API_BASE}/api/query/stream?${params}`, {
    signal: options?.signal,
  });
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
  req: QueryRequest,
  options?: { signal?: AbortSignal }
): Promise<GraphResponse> {
  const params = new URLSearchParams({
    entity: req.entity,
    type: req.type,
  });
  const res = await fetch(`${API_BASE}/api/query/graph?${params}`, {
    signal: options?.signal,
  });
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

/** Fetch geo-plottable points from all memorized/confirmed entities. */
export async function fetchMemoryGeo(): Promise<MapResponse> {
  const res = await fetch(`${API_BASE}/api/memory/geo`);
  if (!res.ok) {
    throw new Error(`Memory geo failed: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

/** Fetch all memorized entities and their confirmed connections. */
export async function fetchMemory(): Promise<{
  nodes: Array<{ id: string; label: string; type: string; val: number; confirmed: boolean }>;
  links: Array<{ source: string; target: string; type: string; confirmed_at?: number }>;
  total_memorized: number;
}> {
  const res = await fetch(`${API_BASE}/api/memory`);
  if (!res.ok) {
    throw new Error(`Memory fetch failed: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

/** Expand a node in the memory graph to reveal its hidden children. */
export async function expandMemoryNode(nodeId: string): Promise<{
  nodes: Array<{ id: string; label: string; type: string; val: number; confirmed: boolean; expandable: boolean; hidden_children: number }>;
  links: Array<{ source: string; target: string; type: string }>;
}> {
  const params = new URLSearchParams({ node: nodeId });
  const res = await fetch(`${API_BASE}/api/memory/expand?${params}`);
  if (!res.ok) {
    throw new Error(`Memory expand failed: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

/** Fetch threat score for an entity */
export async function fetchThreatScore(
  req: QueryRequest
): Promise<ThreatScore> {
  const params = new URLSearchParams({ entity: req.entity, type: req.type });
  const res = await fetch(`${API_BASE}/api/threat-score?${params}`);
  if (!res.ok) throw new Error(`Threat score failed: ${res.status}`);
  return res.json();
}

/** Fetch blast radius for an entity */
export async function fetchBlastRadius(
  req: QueryRequest
): Promise<BlastRadius> {
  const params = new URLSearchParams({ entity: req.entity, type: req.type });
  const res = await fetch(`${API_BASE}/api/blast-radius?${params}`);
  if (!res.ok) throw new Error(`Blast radius failed: ${res.status}`);
  return res.json();
}

/** Find shortest path between two entities */
export async function fetchShortestPath(
  from: QueryRequest,
  to: QueryRequest
): Promise<GraphResponse & { hops: number }> {
  const params = new URLSearchParams({
    from_entity: from.entity, from_type: from.type,
    to_entity: to.entity, to_type: to.type,
  });
  const res = await fetch(`${API_BASE}/api/shortest-path?${params}`);
  if (!res.ok) throw new Error(`Shortest path failed: ${res.status}`);
  return res.json();
}

/** Fetch investigation suggestions */
export async function fetchSuggestions(
  req: QueryRequest
): Promise<Suggestion[]> {
  const params = new URLSearchParams({ entity: req.entity, type: req.type });
  const res = await fetch(`${API_BASE}/api/suggestions?${params}`);
  if (!res.ok) throw new Error(`Suggestions failed: ${res.status}`);
  return res.json();
}

/** Fetch the STIX 2.1 bundle JSON for a given entity investigation.
 *  Returns the raw bundle object — caller handles download. */
export async function fetchStixBundle(
  req: QueryRequest
): Promise<Record<string, unknown>> {
  const params = new URLSearchParams({ entity: req.entity, type: req.type });
  const res = await fetch(`${API_BASE}/api/stix/bundle?${params}`);
  if (!res.ok) throw new Error(`STIX export failed: ${res.status}`);
  return res.json();
}

/** Enrichment summary for the current entity (VirusTotal + HIBP + general). */
export async function fetchEnrichmentSummary(
  req: QueryRequest
): Promise<Record<string, unknown>> {
  const params = new URLSearchParams({ entity: req.entity, type: req.type });
  const res = await fetch(`${API_BASE}/api/enrich/summary?${params}`);
  if (!res.ok) throw new Error(`Enrichment failed: ${res.status}`);
  return res.json();
}
