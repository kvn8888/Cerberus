/**
 * components/panels/ComparePanel.tsx — Side-by-side entity comparison
 *
 * Lets users pick two entities (with type selectors) and compare their
 * investigation graphs. Shows overlap score, shared infrastructure,
 * and exclusive nodes for each entity. Uses the POST /api/diff/compare
 * endpoint which does set-level graph diffing.
 */
import { useState } from "react";
import {
  GitCompareArrows,
  Search,
  Loader2,
  Share2,
  AlertTriangle,
} from "lucide-react";
import { compareEntities } from "../../lib/api";
import { cn } from "../../lib/utils";

/** The entity types supported by the backend EntityType enum */
const ENTITY_TYPES = [
  { value: "package", label: "Package" },
  { value: "ip", label: "IP" },
  { value: "domain", label: "Domain" },
  { value: "cve", label: "CVE" },
  { value: "threatactor", label: "Threat Actor" },
  { value: "fraudsignal", label: "Fraud Signal" },
] as const;

/** Shape of the comparison result from the backend */
interface CompareResult {
  shared_nodes: { id?: string; label?: string; type?: string }[];
  only_a: { id?: string; label?: string; type?: string }[];
  only_b: { id?: string; label?: string; type?: string }[];
  overlap_score: number;
  summary: {
    total_unique_nodes: number;
    shared_count: number;
    only_a_count: number;
    only_b_count: number;
  };
}

export function ComparePanel() {
  /* ── Input state for two entities ─────────────────────── */
  const [entityA, setEntityA] = useState("");
  const [typeA, setTypeA] = useState("package");
  const [entityB, setEntityB] = useState("");
  const [typeB, setTypeB] = useState("package");

  /* ── Result state ──────────────────────────────────────── */
  const [result, setResult] = useState<CompareResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  /** Run the comparison against the backend diff endpoint */
  const handleCompare = async () => {
    if (!entityA.trim() || !entityB.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const data = await compareEntities(
        entityA.trim(),
        typeA,
        entityB.trim(),
        typeB
      );
      setResult(data as CompareResult);
    } catch (err: any) {
      setError(err.message || "Comparison failed");
    } finally {
      setLoading(false);
    }
  };

  /** Render a list of nodes (shared, only_a, or only_b) */
  const renderNodeList = (
    nodes: { id?: string; label?: string; type?: string }[],
    emptyMsg: string
  ) => {
    if (nodes.length === 0) {
      return (
        <p className="text-[10px] text-muted-foreground/50 italic">{emptyMsg}</p>
      );
    }
    return (
      <div className="space-y-1 max-h-36 overflow-y-auto">
        {nodes.slice(0, 30).map((n) => (
          <div
            key={n.id ?? n.label}
            className="flex items-center gap-2 px-2 py-1 rounded bg-surface-raised/30 text-[10px] font-mono"
          >
            <span className="text-primary/60">{n.type}</span>
            <span className="text-foreground truncate">{n.label ?? n.id}</span>
          </div>
        ))}
        {nodes.length > 30 && (
          <p className="text-[10px] text-muted-foreground/40">
            +{nodes.length - 30} more
          </p>
        )}
      </div>
    );
  };

  /** Color the overlap score bar — green=high overlap, yellow=some, red=none */
  const scoreColor =
    !result
      ? "bg-muted"
      : result.overlap_score > 0.3
        ? "bg-success"
        : result.overlap_score > 0.05
          ? "bg-yellow-500"
          : "bg-threat-high";

  return (
    <div className="flex flex-col h-full">
      {/* ── Header ───────────────────────────────────────── */}
      <div className="px-4 py-3 border-b border-border relative">
        <h2 className="text-sm font-semibold text-foreground uppercase tracking-wider flex items-center gap-2">
          <GitCompareArrows className="h-4 w-4 text-primary" />
          Compare Entities
        </h2>
        <div className="absolute left-0 top-2 bottom-2 w-0.5 bg-primary/40 rounded-full" />
      </div>

      {/* ── Inputs ───────────────────────────────────────── */}
      <div className="p-4 space-y-3 border-b border-border/50">
        {/* Entity A */}
        <div>
          <label className="text-[10px] font-mono text-muted-foreground uppercase tracking-[0.15em] mb-1 block">
            Entity A
          </label>
          <div className="flex gap-2">
            <input
              type="text"
              value={entityA}
              onChange={(e) => setEntityA(e.target.value)}
              placeholder="e.g. ua-parser-js"
              className={cn(
                "flex-1 px-3 py-2 rounded-md text-xs font-mono",
                "bg-surface-raised border border-border",
                "text-foreground placeholder:text-muted-foreground/40",
                "focus:outline-none focus:border-primary/50"
              )}
            />
            <select
              value={typeA}
              onChange={(e) => setTypeA(e.target.value)}
              className="px-2 py-2 rounded-md text-[10px] font-mono bg-surface-raised border border-border text-foreground"
            >
              {ENTITY_TYPES.map((t) => (
                <option key={t.value} value={t.value}>
                  {t.label}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Entity B */}
        <div>
          <label className="text-[10px] font-mono text-muted-foreground uppercase tracking-[0.15em] mb-1 block">
            Entity B
          </label>
          <div className="flex gap-2">
            <input
              type="text"
              value={entityB}
              onChange={(e) => setEntityB(e.target.value)}
              placeholder="e.g. event-stream"
              className={cn(
                "flex-1 px-3 py-2 rounded-md text-xs font-mono",
                "bg-surface-raised border border-border",
                "text-foreground placeholder:text-muted-foreground/40",
                "focus:outline-none focus:border-primary/50"
              )}
            />
            <select
              value={typeB}
              onChange={(e) => setTypeB(e.target.value)}
              className="px-2 py-2 rounded-md text-[10px] font-mono bg-surface-raised border border-border text-foreground"
            >
              {ENTITY_TYPES.map((t) => (
                <option key={t.value} value={t.value}>
                  {t.label}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Compare button */}
        <button
          onClick={handleCompare}
          disabled={!entityA.trim() || !entityB.trim() || loading}
          className={cn(
            "w-full py-2 rounded-lg text-xs font-bold tracking-wide transition-all",
            !entityA.trim() || !entityB.trim() || loading
              ? "bg-muted text-muted-foreground cursor-not-allowed"
              : "bg-primary text-primary-foreground hover:shadow-glow-lg active:scale-[0.97]"
          )}
        >
          {loading ? (
            <span className="flex items-center justify-center gap-2">
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
              Comparing...
            </span>
          ) : (
            <span className="flex items-center justify-center gap-2">
              <Search className="h-3.5 w-3.5" />
              COMPARE
            </span>
          )}
        </button>

        {error && (
          <div className="flex items-center gap-2 text-threat-high text-[10px] font-mono">
            <AlertTriangle className="h-3 w-3" />
            {error}
          </div>
        )}
      </div>

      {/* ── Results ──────────────────────────────────────── */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {result && (
          <>
            {/* Overlap score */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono text-muted-foreground uppercase tracking-[0.15em]">
                  Overlap Score
                </span>
                <span className="text-sm font-bold text-foreground">
                  {(result.overlap_score * 100).toFixed(1)}%
                </span>
              </div>
              <div className="w-full h-2 rounded-full bg-surface-raised overflow-hidden">
                <div
                  className={cn("h-full rounded-full transition-all duration-700", scoreColor)}
                  style={{ width: `${Math.max(result.overlap_score * 100, 2)}%` }}
                />
              </div>
            </div>

            {/* Summary stats */}
            <div className="grid grid-cols-3 gap-2">
              <div className="text-center p-2 rounded-md bg-surface-raised/40 border border-border/30">
                <p className="text-lg font-bold text-primary">
                  {result.summary.shared_count}
                </p>
                <p className="text-[9px] font-mono text-muted-foreground">Shared</p>
              </div>
              <div className="text-center p-2 rounded-md bg-surface-raised/40 border border-border/30">
                <p className="text-lg font-bold text-blue-400">
                  {result.summary.only_a_count}
                </p>
                <p className="text-[9px] font-mono text-muted-foreground truncate">
                  Only {entityA.slice(0, 10)}
                </p>
              </div>
              <div className="text-center p-2 rounded-md bg-surface-raised/40 border border-border/30">
                <p className="text-lg font-bold text-purple-400">
                  {result.summary.only_b_count}
                </p>
                <p className="text-[9px] font-mono text-muted-foreground truncate">
                  Only {entityB.slice(0, 10)}
                </p>
              </div>
            </div>

            {/* Shared nodes */}
            <div>
              <p className="text-[10px] font-mono text-muted-foreground uppercase tracking-[0.15em] mb-1.5 flex items-center gap-1.5">
                <Share2 className="h-3 w-3 text-primary" />
                Shared Infrastructure
              </p>
              {renderNodeList(result.shared_nodes, "No shared nodes")}
            </div>

            {/* Only A */}
            <div>
              <p className="text-[10px] font-mono text-muted-foreground uppercase tracking-[0.15em] mb-1.5">
                Exclusive to <span className="text-blue-400">{entityA || "A"}</span>
              </p>
              {renderNodeList(result.only_a, "No exclusive nodes")}
            </div>

            {/* Only B */}
            <div>
              <p className="text-[10px] font-mono text-muted-foreground uppercase tracking-[0.15em] mb-1.5">
                Exclusive to <span className="text-purple-400">{entityB || "B"}</span>
              </p>
              {renderNodeList(result.only_b, "No exclusive nodes")}
            </div>
          </>
        )}

        {/* Empty state */}
        {!result && !loading && (
          <div className="flex flex-col items-center justify-center h-full text-center">
            <GitCompareArrows className="h-12 w-12 text-muted-foreground/15 mb-3" />
            <p className="text-xs text-muted-foreground/40 max-w-[220px] leading-relaxed">
              Enter two entities above to compare their threat graphs.
              Shared infrastructure reveals hidden connections between
              seemingly unrelated threats.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
