/**
 * components/panels/QueryPanel.tsx — Left sidebar input panel
 *
 * Two tabs with clearly distinct purposes:
 *  1. Investigate — entity search (auto-detects type) + natural language fallback
 *  2. Live Feed   — real-time fraud alerts you can investigate with one click
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
  Crosshair,
  Rss,
  MessageSquareText,
} from "lucide-react";
import type { EntityType } from "../../types/api";
import type { FeedEvent } from "../../types/api";
import { cn } from "../../lib/utils";
import {
  fetchLiveFeed,
  ingestFeedEvent,
  parseNaturalLanguage,
} from "../../lib/api";

interface QueryPanelProps {
  onInvestigate: (entity: string, type: EntityType) => void;
  isRunning: boolean;
}

/**
 * Auto-detect entity type from user input using simple pattern matching.
 * Falls back to "package" if nothing else matches.
 */
function detectEntityType(input: string): { type: EntityType; label: string } {
  const trimmed = input.trim();
  if (/^CVE-\d{4}-\d{4,7}$/i.test(trimmed))
    return { type: "cve", label: "CVE" };
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(trimmed))
    return { type: "ip", label: "IP Address" };
  if (/^[a-zA-Z0-9]([a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}$/.test(trimmed))
    return { type: "domain", label: "Domain" };
  if (/^JS-/i.test(trimmed))
    return { type: "fraudsignal", label: "Fraud Signal" };
  // Known threat actor patterns: multi-word with capitals, or contains "Group", "Spider", etc.
  if (/\b(group|spider|bear|panda|apt\d+|lazarus|fin\d+|wizard|velvet|dragonfly)\b/i.test(trimmed))
    return { type: "threatactor", label: "Threat Actor" };
  return { type: "package", label: "Package" };
}

/** Icon for each entity type — used in the detected type badge */
const TYPE_ICONS: Record<EntityType, typeof Package> = {
  package: Package,
  ip: Server,
  domain: Globe,
  cve: Bug,
  threatactor: UserX,
  fraudsignal: Zap,
};

const EXAMPLES = [
  { entity: "ua-parser-js", type: "package" as EntityType, desc: "Hijacked npm package — full attack chain" },
  { entity: "203.0.113.42", type: "ip" as EntityType, desc: "Malicious IP — APT41 infrastructure" },
  { entity: "Lazarus Group", type: "threatactor" as EntityType, desc: "North Korean APT — techniques & IPs" },
  { entity: "CVE-2021-27292", type: "cve" as EntityType, desc: "ReDoS vulnerability in ua-parser-js" },
  { entity: "colors", type: "package" as EntityType, desc: "Sabotaged npm package" },
  { entity: "event-stream", type: "package" as EntityType, desc: "Supply chain compromise" },
];

type Tab = "investigate" | "livefeed";

export function QueryPanel({ onInvestigate, isRunning }: QueryPanelProps) {
  const [tab, setTab] = useState<Tab>("investigate");
  const [query, setQuery] = useState("");
  const [naturalText, setNaturalText] = useState("");
  const [nlError, setNlError] = useState("");
  const [nlBusy, setNlBusy] = useState(false);
  const [feed, setFeed] = useState<FeedEvent[]>([]);
  const [feedError, setFeedError] = useState("");
  const [ingestingId, setIngestingId] = useState("");

  /* Auto-detect entity type as user types */
  const detected = detectEntityType(query);
  const DetectedIcon = TYPE_ICONS[detected.type];

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
    const id = setInterval(() => { void load(); }, 15000);
    return () => clearInterval(id);
  }, []);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!query.trim() || isRunning) return;
    onInvestigate(query.trim(), detected.type);
  };

  const handleExample = (ex: (typeof EXAMPLES)[0]) => {
    setQuery(ex.entity);
    if (!isRunning) onInvestigate(ex.entity, ex.type);
  };

  const handleNaturalInvestigate = async () => {
    if (!naturalText.trim() || isRunning || nlBusy) return;
    setNlBusy(true);
    setNlError("");
    try {
      const parsed = await parseNaturalLanguage(naturalText.trim());
      setQuery(parsed.primary_entity.value);
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
      {/* ── Header ──────────────────────────────────────────── */}
      <div className="px-4 py-3 border-b border-border relative">
        <h2 className="text-sm font-semibold text-foreground uppercase tracking-wider flex items-center gap-2">
          <Zap className="h-4 w-4 text-primary" />
          Investigation
        </h2>
        <div className="absolute left-0 top-2 bottom-2 w-0.5 bg-primary/40 rounded-full" />
      </div>

      {/* ── Tab switcher ────────────────────────────────────── */}
      <div className="flex border-b border-border">
        <button
          type="button"
          onClick={() => setTab("investigate")}
          className={cn(
            "flex-1 flex items-center justify-center gap-1.5 px-3 py-2.5 text-[11px] font-mono uppercase tracking-wider transition-all",
            tab === "investigate"
              ? "text-primary border-b-2 border-primary bg-primary/5"
              : "text-muted-foreground hover:text-foreground"
          )}
        >
          <Crosshair className="h-3 w-3" />
          Investigate
        </button>
        <button
          type="button"
          onClick={() => setTab("livefeed")}
          className={cn(
            "flex-1 flex items-center justify-center gap-1.5 px-3 py-2.5 text-[11px] font-mono uppercase tracking-wider transition-all relative",
            tab === "livefeed"
              ? "text-primary border-b-2 border-primary bg-primary/5"
              : "text-muted-foreground hover:text-foreground"
          )}
        >
          <Rss className="h-3 w-3" />
          Live Feed
          {feed.length > 0 && tab !== "livefeed" && (
            <span className="absolute top-1.5 right-3 w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
          )}
        </button>
      </div>

      {/* ── Tab content ─────────────────────────────────────── */}
      <div className="flex-1 overflow-y-auto">
        {tab === "investigate" && (
          <form onSubmit={handleSubmit} className="p-4 space-y-4 flex flex-col h-full">
            {/* Single search box */}
            <div>
              <label className="text-[10px] font-mono text-muted-foreground uppercase tracking-[0.15em] mb-2 block">
                Search anything
              </label>
              <div className="relative group">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground transition-colors group-focus-within:text-primary" />
                <input
                  type="text"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Package, IP, CVE, domain, threat actor..."
                  className={cn(
                    "w-full pl-10 pr-4 py-3 rounded-lg text-sm font-mono",
                    "bg-surface-raised border border-border",
                    "text-foreground placeholder:text-muted-foreground/40",
                    "focus:outline-none focus:border-primary/50 focus:ring-2 focus:ring-primary/15 focus:shadow-glow",
                    "transition-all duration-300"
                  )}
                />
              </div>
              {/* Auto-detected type badge — shows what Cerberus thinks you typed */}
              {query.trim() && (
                <div className="mt-2 flex items-center gap-2 animate-fade-in">
                  <span className="text-[10px] font-mono text-muted-foreground/60">Detected:</span>
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono bg-primary/10 text-primary border border-primary/20">
                    <DetectedIcon className="h-2.5 w-2.5" />
                    {detected.label}
                  </span>
                </div>
              )}
            </div>

            {/* Submit */}
            <button
              type="submit"
              disabled={!query.trim() || isRunning}
              className={cn(
                "w-full py-2.5 rounded-lg text-sm font-bold tracking-wide",
                "transition-all duration-300 relative overflow-hidden",
                !query.trim() || isRunning
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

            {/* Quick start examples — with descriptions */}
            <div className="mt-auto pt-4">
              <p className="text-[10px] font-mono text-muted-foreground uppercase tracking-[0.15em] mb-2.5 flex items-center gap-1.5">
                <span className="w-3 h-px bg-muted-foreground/30" />
                Try these
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
                    <div className="flex items-center justify-between">
                      <span className="text-accent-foreground group-hover:text-primary transition-colors">
                        {ex.entity}
                      </span>
                      <ChevronRight className="h-3 w-3 opacity-0 group-hover:opacity-100 transition-all duration-200 -translate-x-1 group-hover:translate-x-0" />
                    </div>
                    <span className="text-muted-foreground/40 text-[10px] block mt-0.5">
                      {ex.desc}
                    </span>
                  </button>
                ))}
              </div>
            </div>
          </form>
        )}

        {tab === "livefeed" && (
          <div className="p-4 space-y-4">
            {/* Natural language input */}
            <div className="rounded-lg border border-primary/15 bg-primary/5 p-3">
              <label className="text-[10px] font-mono text-primary uppercase tracking-[0.15em] mb-2 block flex items-center gap-1.5">
                <Languages className="h-3 w-3" />
                Ask a question
              </label>
              <textarea
                value={naturalText}
                onChange={(e) => setNaturalText(e.target.value)}
                placeholder='e.g. "What attacks involve ua-parser-js?" or "Who is behind 203.0.113.42?"'
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
                  {nlBusy ? "Parsing..." : "Investigate"}
                </span>
              </button>
              {nlError && (
                <p className="mt-2 text-[10px] font-mono text-threat-high">{nlError}</p>
              )}
            </div>

            {/* Fraud feed cards */}
            <div>
              <p className="text-[10px] font-mono text-muted-foreground uppercase tracking-[0.15em] mb-1.5 flex items-center gap-1.5">
                <Radio className="h-3 w-3 text-primary animate-pulse" />
                Recent suspicious activity
              </p>
              <p className="text-[10px] text-muted-foreground/50 mb-2.5">
                Click Investigate to trace the full attack chain for any alert.
              </p>
              <div className="space-y-2">
                {feed.map((event) => (
                  <div
                    key={event.juspay_id}
                    className="rounded-lg border border-border bg-surface-raised/50 p-3"
                  >
                    <p className="text-xs text-foreground font-medium">
                      {event.fraud_type.replace(/_/g, " ")}
                    </p>
                    <div className="mt-1 flex items-center justify-between gap-2">
                      <span className="text-[10px] font-mono text-muted-foreground">
                        IP: {event.ip_address}
                      </span>
                      <span className="text-[10px] font-mono text-yellow-400/80">
                        {event.currency} {event.amount.toLocaleString()}
                      </span>
                    </div>
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
                {feed.length === 0 && !feedError && (
                  <p className="text-xs text-muted-foreground/50 text-center py-4">Loading feed...</p>
                )}
                {feedError && (
                  <p className="text-[10px] font-mono text-threat-high">{feedError}</p>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
