/**
 * types/api.ts — TypeScript interfaces for the Cerberus backend API
 *
 * These mirror the JSON shapes returned by the FastAPI endpoints so
 * we get full type safety when consuming API responses.
 */

/** The entity types the backend supports for investigation */
export type EntityType =
  | "package"
  | "ip"
  | "domain"
  | "cve"
  | "threatactor"
  | "fraudsignal";

export type TlpLevel =
  | "clear"
  | "green"
  | "amber"
  | "amber+strict"
  | "red";

/** POST /api/query request body */
export interface QueryRequest {
  entity: string;
  type: EntityType;
}

/** POST /api/query response */
export interface QueryResponse {
  entity: string;
  entity_type: EntityType;
  paths_found: number;
  from_cache: boolean;
  llm_called: boolean;
  narrative: string;
  cross_domain: string[];
}

/** POST /api/confirm request body */
export interface ConfirmRequest {
  entity: string;
  type: EntityType;
}

/** POST /api/confirm response */
export interface ConfirmResponse {
  success: boolean;
  entity: string;
  entity_type: EntityType;
  relationships_confirmed: number;
  message: string;
}

/** GET /api/schema response */
export interface SchemaResponse {
  labels: string[];
  relationship_types: string[];
  counts: Array<{ label: string; count: number }>;
}

/** A single node in the graph visualization */
export interface GraphNode {
  id: string;
  label: string;
  type: string;
  val: number;
  [key: string]: unknown;
}

/** A single link (edge) in the graph visualization */
export interface GraphLink {
  source: string;
  target: string;
  type?: string;
  dashed?: boolean;
  confidence?: number;
  source_reliability?: number;
  last_seen?: number;
}

/** GET /api/query/graph response — nodes + links for force-directed graph */
export interface GraphResponse {
  nodes: GraphNode[];
  links: GraphLink[];
}

/** SSE stream chunk shapes from GET /api/query/stream */
export type StreamChunk =
  | { text: string }
  | { from_cache: boolean }
  | { paths_found: number; from_cache: boolean }
  | { route_info: RouteInfo }
  | { threat_score: ThreatScore }
  | { blast_radius: BlastRadius }
  | { suggestions: Suggestion[] }
  | { agent_activity: AgentActivity };

/** Route decision metadata emitted during the ROUTE stage */
export interface RouteInfo {
  strategy: string;
  path: string[];
  reason: string;
}

/** Agent activity events from RocketRide wave-planning agent.
 *  Emitted during the ANALYZE stage when the agent pipeline is active. */
export interface AgentActivity {
  status: "started" | "completed";
  pipeline?: string;
  tools?: string[];
  description: string;
  tool_call_count?: number;
  metadata?: Record<string, unknown>;
}

/**
 * Pipeline stages the UI shows during investigation.
 * Each stage lights up as the agent progresses.
 */
export type PipelineStage =
  | "input"
  | "ner"
  | "classify"
  | "route"
  | "traverse"
  | "enrich"
  | "analyze"
  | "narrate"
  | "complete";

/** Threat score breakdown from /api/threat-score */
export interface ThreatScore {
  score: number;
  factors: string[];
  severity: "critical" | "high" | "medium" | "low" | "info";
}

/** Blast radius from /api/blast-radius */
export interface BlastRadius {
  total: number;
  by_type: Record<string, number>;
}

/** Investigation suggestion from /api/suggestions */
export interface Suggestion {
  entity: string;
  type: string;
  reason: string;
  connections: number;
}

/** Saved investigation for history */
export interface InvestigationHistoryItem {
  entity: string;
  entityType: EntityType;
  timestamp: number;
  threatScore?: number;
  severity?: string;
  pathsFound: number;
}

/** Tracks the overall state of an investigation */
export interface InvestigationState {
  status: "idle" | "running" | "complete" | "error";
  entity: string;
  entityType: EntityType;
  tlp: TlpLevel;
  currentStage: PipelineStage;
  routeInfo?: RouteInfo;
  narrative: string;
  pathsFound: number;
  fromCache: boolean;
  error?: string;
  graphData?: GraphResponse;
  threatScore?: ThreatScore;
  blastRadius?: BlastRadius;
  suggestions?: Suggestion[];
  agentActivity?: AgentActivity;
  audienceMode: "analyst" | "executive";
}

export interface NaturalLanguageResponse {
  message: string;
  primary_entity: {
    type: EntityType;
    value: string;
  };
  entities: Array<{
    type: EntityType;
    value: string;
  }>;
}

export interface ComparisonItem {
  entity: string;
  entity_type: EntityType;
  from_cache: boolean;
  paths_found: number;
  risk_level: string;
  summary: string;
  cross_domain_count?: number;
}

export interface ComparisonResponse {
  results: ComparisonItem[];
}

export interface FeedEvent {
  juspay_id: string;
  fraud_type: string;
  amount: number;
  currency: string;
  ip_address: string;
  merchant_id?: string;
  timestamp: number;
}

export interface FeedResponse {
  events: FeedEvent[];
}

export interface GeoPoint {
  ip: string;
  geo: string;
  lat: number;
  lon: number;
  actors: string[];
  actor_only?: boolean;
}

export interface MapResponse {
  entity: string;
  entity_type: EntityType;
  points: GeoPoint[];
}

export interface ReportResponse {
  entity: string;
  entity_type: EntityType;
  tlp: TlpLevel;
  generated_at: number;
  from_cache: boolean;
  paths_found: number;
  cross_domain: Array<Record<string, unknown>>;
  graph: GraphResponse;
  juspay_summary: {
    signals: number;
    linked_ips: number;
    total_amount: number;
  };
  narrative: string;
  summary: string;
}

export interface DetectionRuleSet {
  sigma: string;
  yara: string;
  notes: string[];
  tlp: TlpLevel;
}
