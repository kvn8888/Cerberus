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
  DetectionRuleSet,
  TlpLevel,
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
  req: QueryRequest,
  tlp?: TlpLevel
): Promise<ReportResponse> {
  const params = new URLSearchParams({
    entity: req.entity,
    type: req.type,
  });
  if (tlp) params.set("tlp", tlp);
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

/** Fetch geo-plottable points for ALL IPs and ThreatActors in Neo4j (not just confirmed).
 *  Used to pre-populate the geomap on first load with real data. */
export async function fetchAllGeo(): Promise<MapResponse> {
  const res = await fetch(`${API_BASE}/api/geomap/all`);
  if (!res.ok) {
    throw new Error(`All-geo fetch failed: ${res.status} ${res.statusText}`);
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
  req: QueryRequest,
  tlp?: TlpLevel
): Promise<Record<string, unknown>> {
  const params = new URLSearchParams({ entity: req.entity, type: req.type });
  if (tlp) params.set("tlp", tlp);
  const res = await fetch(`${API_BASE}/api/stix/bundle?${params}`);
  if (!res.ok) throw new Error(`STIX export failed: ${res.status}`);
  return res.json();
}

export async function generateDetectionRules(payload: {
  entity: string;
  entityType: string;
  iocs: Array<{ type: string; value: string }>;
  techniques: string[];
  narrative: string;
  tlp: TlpLevel;
}): Promise<DetectionRuleSet> {
  const res = await fetch(`${API_BASE}/api/detect/rules`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(`Detection rules failed: ${res.status}`);
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

/** Natural language → entity extraction via backend NER.
 *  Returns the primary entity and all extracted entities. */
export async function parseNaturalLanguage(
  message: string
): Promise<{
  message: string;
  primary_entity: { type: string; value: string };
  entities: { type: string; value: string }[];
}> {
  const res = await fetch(`${API_BASE}/api/demo/natural`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message }),
  });
  if (!res.ok) throw new Error(`NLP parse failed: ${res.status}`);
  return res.json();
}

/** Compare two entity graphs — returns shared/exclusive nodes, links, overlap score. */
export async function compareEntities(
  entityA: string,
  typeA: string,
  entityB: string,
  typeB: string
): Promise<{
  shared_nodes: Record<string, unknown>[];
  only_a: Record<string, unknown>[];
  only_b: Record<string, unknown>[];
  overlap_score: number;
  summary: {
    total_unique_nodes: number;
    shared_count: number;
    only_a_count: number;
    only_b_count: number;
  };
}> {
  const res = await fetch(`${API_BASE}/api/diff/compare`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      entity_a: entityA,
      type_a: typeA,
      entity_b: entityB,
      type_b: typeB,
    }),
  });
  if (!res.ok) throw new Error(`Comparison failed: ${res.status}`);
  return res.json();
}

/* ── Annotation CRUD ─────────────────────────────────────────────── */

export interface Annotation {
  id: string;
  entity: string;
  text: string;
  author: string;
  created_at: number;
}

/** List annotations for a given entity. */
export async function listAnnotations(entity: string): Promise<Annotation[]> {
  const params = new URLSearchParams({ entity });
  const res = await fetch(`${API_BASE}/api/annotations?${params}`);
  if (!res.ok) throw new Error(`Annotations fetch failed: ${res.status}`);
  return res.json();
}

/** Create a new annotation on an entity. */
export async function createAnnotation(
  entity: string,
  text: string,
  author?: string
): Promise<Annotation> {
  const res = await fetch(`${API_BASE}/api/annotations`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ entity, text, author: author ?? "analyst" }),
  });
  if (!res.ok) throw new Error(`Create annotation failed: ${res.status}`);
  return res.json();
}

/** Delete an annotation by ID. */
export async function deleteAnnotation(id: string): Promise<void> {
  const res = await fetch(`${API_BASE}/api/annotations/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
  if (!res.ok) throw new Error(`Delete annotation failed: ${res.status}`);
}

/* ── Watchlist CRUD ────────────────────────────────────────────────── */

export interface WatchedEntity {
  entity: string;
  entity_type: string;
  added_at: number;
  last_checked: number;
}

export interface WatchlistAlert {
  entity: string;
  entity_type: string;
  new_connections: number;
  neighbor_types: string[];
  since: number;
}

/** List all watched entities. */
export async function getWatchlist(): Promise<WatchedEntity[]> {
  const res = await fetch(`${API_BASE}/api/watchlist`);
  if (!res.ok) throw new Error(`Watchlist fetch failed: ${res.status}`);
  return res.json();
}

/** Add an entity to the watchlist. */
export async function addToWatchlist(
  entity: string,
  entityType: string
): Promise<WatchedEntity> {
  const res = await fetch(`${API_BASE}/api/watchlist`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ entity, entity_type: entityType }),
  });
  if (!res.ok) throw new Error(`Watchlist add failed: ${res.status}`);
  return res.json();
}

/** Remove an entity from the watchlist. */
export async function removeFromWatchlist(entity: string): Promise<void> {
  const res = await fetch(
    `${API_BASE}/api/watchlist/${encodeURIComponent(entity)}`,
    { method: "DELETE" }
  );
  if (!res.ok) throw new Error(`Watchlist remove failed: ${res.status}`);
}

/** Check all watched entities for new connections. */
export async function checkWatchlist(): Promise<{
  digest_since?: number;
  checked_at: number;
  watched_count: number;
  alerts: WatchlistAlert[];
}> {
  const res = await fetch(`${API_BASE}/api/watchlist/check`);
  if (!res.ok) throw new Error(`Watchlist check failed: ${res.status}`);
  return res.json();
}

export async function checkWatchlistSince(since: number): Promise<{
  digest_since?: number;
  checked_at: number;
  watched_count: number;
  alerts: WatchlistAlert[];
}> {
  const params = new URLSearchParams({ since: String(since) });
  const res = await fetch(`${API_BASE}/api/watchlist/check?${params}`);
  if (!res.ok) throw new Error(`Watchlist check failed: ${res.status}`);
  return res.json();
}

/* ── Ingest (RocketRide document/text ingestion) ──────────────────── */

/** Response shape from the ingest endpoints */
export interface IngestResponse {
  entities_found: number;
  entities: Array<{
    type: string;
    value: string;
    threat_domain?: string;
    confidence?: string;
    context?: string;
  }>;
  written_to_graph: number;
  pipeline: string;
  filename?: string;
}

/** Check whether the RocketRide ingest pipeline is loaded and ready. */
export async function checkIngestStatus(): Promise<{
  ready: boolean;
  reason?: string;
  pipeline?: string;
}> {
  const res = await fetch(`${API_BASE}/api/ingest/status`);
  if (!res.ok) throw new Error(`Ingest status check failed: ${res.status}`);
  return res.json();
}

/** Submit raw text for threat entity extraction via the ingest pipeline. */
export async function ingestText(
  text: string,
  writeToGraph: boolean = true
): Promise<IngestResponse> {
  const res = await fetch(`${API_BASE}/api/ingest/text`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text, write_to_graph: writeToGraph }),
  });
  if (!res.ok) {
    const detail = await res.text().catch(() => res.statusText);
    throw new Error(`Ingest text failed: ${detail}`);
  }
  return res.json();
}

/** Upload a file (PDF, image, text doc) for entity extraction via the ingest pipeline. */
export async function ingestFile(
  file: File,
  writeToGraph: boolean = true
): Promise<IngestResponse> {
  const form = new FormData();
  form.append("file", file);
  form.append("write_to_graph", String(writeToGraph));
  const res = await fetch(`${API_BASE}/api/ingest/file`, {
    method: "POST",
    body: form,
  });
  if (!res.ok) {
    const detail = await res.text().catch(() => res.statusText);
    throw new Error(`Ingest file failed: ${detail}`);
  }
  return res.json();
}
