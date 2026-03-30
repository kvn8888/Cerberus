/**
 * components/panels/QueryPanel.tsx — Left sidebar input panel
 *
 * Single-panel layout: one search bar, auto-detects entity type,
 * optional NLP expansion, quick-start examples.
 */
import { useState } from "react";
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
  MessageSquareText,
} from "lucide-react";
import type { EntityType } from "../../types/api";
import { cn } from "../../lib/utils";
import { parseNaturalLanguage } from "../../lib/api";

interface QueryPanelProps {
  onInvestigate: (entity: string, type: EntityType) => void;
  isRunning: boolean;
}

/**
 * Auto-detect entity type from user input using pattern matching.
 * Handles both raw entities ("CVE-2021-27292") and natural language
 * ("What is CVE-2021-27292?") by extracting known patterns from anywhere
 * in the input. Returns the cleaned entity value alongside the type so
 * the caller can submit the actual entity, not the full sentence.
 */
function detectEntityType(input: string): {
  type: EntityType;
  label: string;
  extracted: string;
} {
  const trimmed = input.trim();

  const cveMatch = trimmed.match(/CVE-\d{4}-\d{4,7}/i);
  if (cveMatch) return { type: "cve", label: "CVE", extracted: cveMatch[0].toUpperCase() };

  const ipMatch = trimmed.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
  if (ipMatch) return { type: "ip", label: "IP Address", extracted: ipMatch[1] };

  const jsMatch = trimmed.match(/\b(JS-\d{4}-\d{4})\b/i);
  if (jsMatch) return { type: "fraudsignal", label: "Fraud Signal", extracted: jsMatch[1].toUpperCase() };

  if (/^[a-zA-Z0-9]([a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}$/.test(trimmed))
    return { type: "domain", label: "Domain", extracted: trimmed };

  const actorPattern = /\b(apt\d+|lazarus\s+group|fin\d+|fancy\s+bear|cozy\s+bear|hafnium|sandworm\s+team|cl0p|wizard\s+spider|mummy\s+spider)\b/i;
  const actorMatch = trimmed.match(actorPattern);
  if (actorMatch) return { type: "threatactor", label: "Threat Actor", extracted: actorMatch[1] };

  if (/\b(group|spider|bear|panda)\b/i.test(trimmed) && trimmed.includes(" "))
    return { type: "threatactor", label: "Threat Actor", extracted: trimmed };

  let entity = trimmed;
  const unwrapped = trimmed
    .replace(/^(what|who|where|how|why|show|tell|find|is|are|investigate|check|look\s+up|search)\s+(is|are|me|for|about|up)?\s*/i, "")
    .replace(/[?.!]+$/, "")
    .trim();
  if (unwrapped && unwrapped !== trimmed) entity = unwrapped;

  return { type: "package", label: "Package", extracted: entity };
}

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

export function QueryPanel({ onInvestigate, isRunning }: QueryPanelProps) {
  const [query, setQuery] = useState("");
  const [showNl, setShowNl] = useState(false);
  const [naturalText, setNaturalText] = useState("");
  const [nlError, setNlError] = useState("");
  const [nlBusy, setNlBusy] = useState(false);

  const detected = detectEntityType(query);
  const DetectedIcon = TYPE_ICONS[detected.type];

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!query.trim() || isRunning) return;
    onInvestigate(detected.extracted, detected.type);
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

      {/* ── Single panel ──────────────────────────────────────── */}
      <div className="flex-1 overflow-y-auto">
        <form onSubmit={handleSubmit} className="p-4 space-y-4 flex flex-col h-full">
          {/* Search bar */}
          <div>
            <label className="text-[10px] font-mono text-muted-foreground uppercase tracking-[0.15em] mb-2 block">
              Enter an entity
            </label>
            <div className="relative group">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground transition-colors group-focus-within:text-primary" />
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="e.g. ua-parser-js, 203.0.113.42, CVE-2021-44228"
                className={cn(
                  "w-full pl-10 pr-4 py-3 rounded-lg text-sm font-mono",
                  "bg-surface-raised border border-border",
                  "text-foreground placeholder:text-muted-foreground/40",
                  "focus:outline-none focus:border-primary/50 focus:ring-2 focus:ring-primary/15 focus:shadow-glow",
                  "transition-all duration-300"
                )}
              />
            </div>
            {query.trim() && (
              <div className="mt-2 flex items-center gap-2 animate-fade-in flex-wrap">
                <span className="text-[10px] font-mono text-muted-foreground/60">Detected:</span>
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono bg-primary/10 text-primary border border-primary/20">
                  <DetectedIcon className="h-2.5 w-2.5" />
                  {detected.label}
                </span>
                {detected.extracted !== query.trim() && (
                  <span className="text-[10px] font-mono text-primary/70">
                    → {detected.extracted}
                  </span>
                )}
              </div>
            )}
          </div>

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

          {/* NLP expansion — collapsible */}
          <div>
            <button
              type="button"
              onClick={() => setShowNl(!showNl)}
              className="flex items-center gap-1.5 text-[10px] font-mono text-muted-foreground/60 hover:text-muted-foreground transition-colors"
            >
              <MessageSquareText className="h-3 w-3" />
              <span>{showNl ? "Hide" : "Or describe what you're looking for"}</span>
              <ChevronRight className={cn("h-3 w-3 transition-transform", showNl && "rotate-90")} />
            </button>
            {showNl && (
              <div className="mt-2 rounded-lg border border-primary/15 bg-primary/5 p-3 animate-fade-in">
                <textarea
                  value={naturalText}
                  onChange={(e) => setNaturalText(e.target.value)}
                  placeholder='e.g. "What attacks use ua-parser-js?" or "Show threats linked to 203.0.113.42"'
                  rows={2}
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
            )}
          </div>

          {/* Quick start examples */}
          <div className="mt-auto pt-4">
            <p className="text-[10px] font-mono text-muted-foreground uppercase tracking-[0.15em] mb-2.5 flex items-center gap-1.5">
              <span className="w-3 h-px bg-muted-foreground/30" />
              Quick start
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
      </div>
    </div>
  );
}
