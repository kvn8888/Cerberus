/**
 * components/panels/QueryPanel.tsx — Left sidebar input panel
 *
 * Where analysts type an entity (package name, IP, domain, etc.)
 * and select its type before launching an investigation.
 * Also shows quick-access example entities for demo purposes.
 */
import { useEffect, useState } from "react";
import {
  Search,
  Package,
  Globe,
  Server,
  Bug,
  UserX,
  Zap,
  ChevronRight,
  Languages,
  Radio,
  Download,
} from "lucide-react";
import type { EntityType } from "../../types/api";
import type { FeedEvent } from "../../types/api";
import { cn } from "../../lib/utils";
import {
  fetchLiveFeed,
  ingestFeedEvent,
  parseNaturalLanguage,
} from "../../lib/api";

/** Props: the parent provides the investigate callback */
interface QueryPanelProps {
  onInvestigate: (entity: string, type: EntityType) => void;
  isRunning: boolean;
}

/**
 * Entity type options with their icon and label.
 * These map to the backend's supported entity types.
 */
const ENTITY_TYPES: { value: EntityType; label: string; icon: typeof Package }[] = [
  { value: "package", label: "Package", icon: Package },
  { value: "ip", label: "IP Address", icon: Server },
  { value: "domain", label: "Domain", icon: Globe },
  { value: "cve", label: "CVE", icon: Bug },
  { value: "threatactor", label: "Threat Actor", icon: UserX },
  { value: "fraudsignal", label: "Fraud Signal", icon: Zap },
];

/**
 * Quick-access demo entities — let the user click to auto-fill.
 * These are known to produce interesting results against the seed data.
 */
const EXAMPLES = [
  { entity: "ua-parser-js", type: "package" as EntityType, label: "ua-parser-js" },
  { entity: "colors", type: "package" as EntityType, label: "colors" },
  { entity: "event-stream", type: "package" as EntityType, label: "event-stream" },
  { entity: "CVE-2021-27292", type: "cve" as EntityType, label: "CVE-2021-27292" },
  { entity: "Lazarus Group", type: "threatactor" as EntityType, label: "Lazarus Group" },
  { entity: "203.0.113.42", type: "ip" as EntityType, label: "203.0.113.42" },
];

export function QueryPanel({ onInvestigate, isRunning }: QueryPanelProps) {
  const [entity, setEntity] = useState("");
  const [entityType, setEntityType] = useState<EntityType>("package");
  const [naturalText, setNaturalText] = useState("");
  const [nlError, setNlError] = useState("");
  const [nlBusy, setNlBusy] = useState(false);
  const [feed, setFeed] = useState<FeedEvent[]>([]);
  const [feedError, setFeedError] = useState("");
  const [ingestingId, setIngestingId] = useState("");

  useEffect(() => {
    const load = async () => {
      try {
        const data = await fetchLiveFeed(4);
        setFeed(data.events);
        setFeedError("");
      } catch (err) {
        setFeedError(err instanceof Error ? err.message : "Feed unavailable");
      }
    };
    void load();
    const id = setInterval(() => {
      void load();
    }, 15000);
    return () => clearInterval(id);
  }, []);

  /* Fire investigation when user submits */
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!entity.trim() || isRunning) return;
    onInvestigate(entity.trim(), entityType);
  };

  /* Click a demo entity to auto-fill and run */
  const handleExample = (ex: (typeof EXAMPLES)[0]) => {
    setEntity(ex.entity);
    setEntityType(ex.type);
    if (!isRunning) {
      onInvestigate(ex.entity, ex.type);
    }
  };

  const handleNaturalInvestigate = async () => {
    if (!naturalText.trim() || isRunning || nlBusy) return;
    setNlBusy(true);
    setNlError("");
    try {
      const parsed = await parseNaturalLanguage(naturalText.trim());
      setEntity(parsed.primary_entity.value);
      setEntityType(parsed.primary_entity.type);
      onInvestigate(parsed.primary_entity.value, parsed.primary_entity.type);
    } catch (err) {
      setNlError(err instanceof Error ? err.message : "Unable to parse prompt");
    } finally {
      setNlBusy(false);
    }
  };

  const handleFeedIngest = async (event: FeedEvent) => {
    if (ingestingId) return;
    setIngestingId(event.juspay_id);
    try {
      await ingestFeedEvent(event);
      onInvestigate(event.ip_address, "ip");
      setFeedError("");
    } catch (err) {
      setFeedError(err instanceof Error ? err.message : "Ingest failed");
    } finally {
      setIngestingId("");
    }
  };

  return (
    <div className="flex flex-col h-full">
      {/* ── Section header with decorative accent ──────────── */}
      <div className="px-4 py-3 border-b border-border relative">
        <h2 className="text-sm font-semibold text-foreground uppercase tracking-wider flex items-center gap-2">
          <Zap className="h-4 w-4 text-primary" />
          Investigation
        </h2>
        {/* Subtle left edge accent */}
        <div className="absolute left-0 top-2 bottom-2 w-0.5 bg-primary/40 rounded-full" />
      </div>

      {/* ── Input form ─────────────────────────────────────── */}
      <form onSubmit={handleSubmit} className="p-4 space-y-4">
        <div className="rounded-lg border border-primary/15 bg-primary/5 p-3">
          <label className="text-[10px] font-mono text-primary uppercase tracking-[0.15em] mb-2 block">
            Natural Language
          </label>
          <textarea
            value={naturalText}
            onChange={(e) => setNaturalText(e.target.value)}
            placeholder='e.g. "Compare ua-parser-js with 203.0.113.42" or "Investigate Lazarus Group"'
            rows={3}
            className={cn(
              "w-full rounded-lg border border-primary/20 bg-surface px-3 py-2 text-xs",
              "text-foreground placeholder:text-muted-foreground/40",
              "focus:outline-none focus:border-primary/50 focus:ring-2 focus:ring-primary/15"
            )}
          />
          <button
            type="button"
            disabled={!naturalText.trim() || isRunning || nlBusy}
            onClick={handleNaturalInvestigate}
            className={cn(
              "mt-2 w-full rounded-lg px-3 py-2 text-xs font-semibold",
              !naturalText.trim() || isRunning || nlBusy
                ? "bg-muted text-muted-foreground"
                : "bg-primary/15 text-primary border border-primary/25 hover:bg-primary/20"
            )}
          >
            <span className="flex items-center justify-center gap-2">
              <Languages className="h-3.5 w-3.5" />
              {nlBusy ? "Parsing prompt..." : "Parse & Investigate"}
            </span>
          </button>
          {nlError && (
            <p className="mt-2 text-[10px] font-mono text-threat-high">{nlError}</p>
          )}
        </div>

        {/* Entity type selector — pill buttons with glow on active */}
        <div>
          <label className="text-[10px] font-mono text-muted-foreground uppercase tracking-[0.15em] mb-2 block">
            Entity Type
          </label>
          <div className="flex flex-wrap gap-1.5">
            {ENTITY_TYPES.map((t) => {
              const Icon = t.icon;
              const active = entityType === t.value;
              return (
                <button
                  key={t.value}
                  type="button"
                  onClick={() => setEntityType(t.value)}
                  className={cn(
                    "flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs font-medium",
                    "transition-all duration-300 hover-lift",
                    active
                      ? "bg-primary/15 text-primary border border-primary/40 shadow-glow"
                      : "bg-surface-raised text-muted-foreground border border-border hover:text-foreground hover:border-primary/20 hover:bg-primary/5"
                  )}
                >
                  <Icon className={cn("h-3 w-3 transition-transform duration-200", active && "scale-110")} />
                  {t.label}
                </button>
              );
            })}
          </div>
        </div>

        {/* Entity name input with enhanced focus states */}
        <div>
          <label className="text-[10px] font-mono text-muted-foreground uppercase tracking-[0.15em] mb-2 block">
            Entity
          </label>
          <div className="relative group">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground transition-colors group-focus-within:text-primary" />
            <input
              type="text"
              value={entity}
              onChange={(e) => setEntity(e.target.value)}
              placeholder="e.g. ua-parser-js, 185.220.101.1"
              className={cn(
                "w-full pl-10 pr-4 py-2.5 rounded-lg text-sm font-mono",
                "bg-surface-raised border border-border",
                "text-foreground placeholder:text-muted-foreground/40",
                "focus:outline-none focus:border-primary/50 focus:ring-2 focus:ring-primary/15 focus:shadow-glow",
                "transition-all duration-300"
              )}
            />
          </div>
        </div>

        {/* Submit button with gradient and hover effects */}
        <button
          type="submit"
          disabled={!entity.trim() || isRunning}
          className={cn(
            "w-full py-2.5 rounded-lg text-sm font-bold tracking-wide",
            "transition-all duration-300 relative overflow-hidden",
            !entity.trim() || isRunning
              ? "bg-muted text-muted-foreground cursor-not-allowed"
              : "bg-primary text-primary-foreground hover:shadow-glow-lg active:scale-[0.97] hover:tracking-wider"
          )}
        >
          {isRunning ? (
            <span className="flex items-center justify-center gap-2">
              <span className="h-3.5 w-3.5 rounded-full border-2 border-primary-foreground/60 border-t-transparent animate-spin" />
              <span className="animate-pulse">Investigating...</span>
            </span>
          ) : (
            "INVESTIGATE"
          )}
        </button>
      </form>

      <div className="px-4 pb-4">
        <p className="text-[10px] font-mono text-muted-foreground uppercase tracking-[0.15em] mb-2.5 flex items-center gap-1.5">
          <Radio className="h-3 w-3 text-primary" />
          Live Feed Ingestion
        </p>
        <div className="space-y-2">
          {feed.map((event) => (
            <div
              key={event.juspay_id}
              className="rounded-lg border border-border bg-surface-raised/50 p-3"
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-[10px] font-mono text-primary">{event.juspay_id}</span>
                <span className="text-[10px] font-mono text-muted-foreground">{event.ip_address}</span>
              </div>
              <p className="mt-1 text-xs text-foreground">{event.fraud_type}</p>
              <p className="text-[10px] text-muted-foreground">
                {event.currency} {event.amount.toLocaleString()}
              </p>
              <div className="mt-2 flex gap-2">
                <button
                  type="button"
                  disabled={!!ingestingId}
                  onClick={() => handleFeedIngest(event)}
                  className="flex-1 rounded-md border border-primary/25 bg-primary/10 px-2 py-1.5 text-[10px] font-mono text-primary hover:bg-primary/15 disabled:opacity-50"
                >
                  <span className="flex items-center justify-center gap-1">
                    <Download className="h-3 w-3" />
                    {ingestingId === event.juspay_id ? "Ingesting" : "Ingest"}
                  </span>
                </button>
                <button
                  type="button"
                  disabled={isRunning}
                  onClick={() => onInvestigate(event.ip_address, "ip")}
                  className="rounded-md border border-border px-2 py-1.5 text-[10px] font-mono text-muted-foreground hover:text-foreground"
                >
                  Investigate
                </button>
              </div>
            </div>
          ))}
          {feedError && (
            <p className="text-[10px] font-mono text-threat-high">{feedError}</p>
          )}
        </div>
      </div>

      {/* ── Quick examples with staggered animation ────────── */}
      <div className="px-4 pb-4 mt-auto">
        <p className="text-[10px] font-mono text-muted-foreground uppercase tracking-[0.15em] mb-2.5 flex items-center gap-1.5">
          <span className="w-3 h-px bg-muted-foreground/30" />
          Quick Start
          <span className="flex-1 h-px bg-muted-foreground/10" />
        </p>
        <div className="space-y-1">
          {EXAMPLES.map((ex, i) => (
            <button
              key={ex.entity}
              onClick={() => handleExample(ex)}
              disabled={isRunning}
              className={cn(
                "w-full text-left px-3 py-2 rounded-md text-xs font-mono group",
                "bg-surface-raised/30 text-muted-foreground",
                "hover:bg-primary/8 hover:text-primary",
                "border border-transparent hover:border-primary/15",
                "transition-all duration-300",
                "disabled:opacity-40 disabled:cursor-not-allowed"
              )}
              style={{ animationDelay: `${i * 0.05}s` }}
            >
              <span className="text-accent-foreground group-hover:text-primary transition-colors">
                {ex.label}
              </span>
              <span className="text-muted-foreground/40 ml-2 text-[10px]">
                {ex.type}
              </span>
              {/* Hover arrow indicator */}
              <ChevronRight className="h-3 w-3 inline-block ml-auto opacity-0 group-hover:opacity-100 transition-all duration-200 -translate-x-1 group-hover:translate-x-0" />
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
