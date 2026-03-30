/**
 * components/panels/QueryPanel.tsx — Left sidebar input panel
 *
 * Single-panel layout: one search bar, auto-detects entity type,
 * optional NLP expansion, quick-start examples.
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
} from "lucide-react";
import type { EntityType } from "../../types/api";
import { cn } from "../../lib/utils";

interface QueryPanelProps {
  onInvestigate: (entity: string, type: EntityType) => void;
  isRunning: boolean;
}

/**
 * Alias dictionary — maps common vulnerability/malware/campaign nicknames
 * to their canonical identifier + correct entity type.  This lets users
 * type "log4shell" and have the system resolve it to CVE-2021-44228.
 */
const ENTITY_ALIASES: Record<string, { canonical: string; type: EntityType; label: string }> = {
  // Major CVE nicknames
  "log4shell":     { canonical: "CVE-2021-44228",  type: "cve", label: "CVE" },
  "log4j":         { canonical: "CVE-2021-44228",  type: "cve", label: "CVE" },
  "spring4shell":  { canonical: "CVE-2022-22965",  type: "cve", label: "CVE" },
  "springshell":   { canonical: "CVE-2022-22965",  type: "cve", label: "CVE" },
  "heartbleed":    { canonical: "CVE-2014-0160",   type: "cve", label: "CVE" },
  "shellshock":    { canonical: "CVE-2014-6271",   type: "cve", label: "CVE" },
  "eternalblue":   { canonical: "CVE-2017-0144",   type: "cve", label: "CVE" },
  "bluekeep":      { canonical: "CVE-2019-0708",   type: "cve", label: "CVE" },
  "zerologon":     { canonical: "CVE-2020-1472",   type: "cve", label: "CVE" },
  "proxylogon":    { canonical: "CVE-2021-26855",  type: "cve", label: "CVE" },
  "proxyshell":    { canonical: "CVE-2021-34473",  type: "cve", label: "CVE" },
  "proxynotshell": { canonical: "CVE-2022-41040",  type: "cve", label: "CVE" },
  "dirty pipe":    { canonical: "CVE-2022-0847",   type: "cve", label: "CVE" },
  "dirtypipe":     { canonical: "CVE-2022-0847",   type: "cve", label: "CVE" },
  "dirty cow":     { canonical: "CVE-2016-5195",   type: "cve", label: "CVE" },
  "dirtycow":      { canonical: "CVE-2016-5195",   type: "cve", label: "CVE" },
  "poodle":        { canonical: "CVE-2014-3566",   type: "cve", label: "CVE" },
  "spectre":       { canonical: "CVE-2017-5753",   type: "cve", label: "CVE" },
  "meltdown":      { canonical: "CVE-2017-5754",   type: "cve", label: "CVE" },
  "krack":         { canonical: "CVE-2017-13077",  type: "cve", label: "CVE" },
  "printnightmare":{ canonical: "CVE-2021-34527",  type: "cve", label: "CVE" },
  "follina":       { canonical: "CVE-2022-30190",  type: "cve", label: "CVE" },
  "citrixbleed":   { canonical: "CVE-2023-4966",   type: "cve", label: "CVE" },
  "moveit":        { canonical: "CVE-2023-34362",  type: "cve", label: "CVE" },
  "regresshion":   { canonical: "CVE-2024-6387",   type: "cve", label: "CVE" },

  // Malware / campaign → threat actor mapping
  "wannacry":      { canonical: "Lazarus Group",    type: "threatactor", label: "Threat Actor" },
  "notpetya":      { canonical: "Sandworm Team",    type: "threatactor", label: "Threat Actor" },
  "stuxnet":       { canonical: "Equation",         type: "threatactor", label: "Threat Actor" },
  "solarwinds":    { canonical: "APT29",            type: "threatactor", label: "Threat Actor" },
  "sunburst":      { canonical: "APT29",            type: "threatactor", label: "Threat Actor" },
  "hafnium":       { canonical: "HAFNIUM",          type: "threatactor", label: "Threat Actor" },
  "revil":         { canonical: "REvil",            type: "threatactor", label: "Threat Actor" },
  "darkside":      { canonical: "DarkSide",         type: "threatactor", label: "Threat Actor" },
  "conti":         { canonical: "Wizard Spider",    type: "threatactor", label: "Threat Actor" },
  "emotet":        { canonical: "Mummy Spider",     type: "threatactor", label: "Threat Actor" },
  "trickbot":      { canonical: "Wizard Spider",    type: "threatactor", label: "Threat Actor" },
  "ryuk":          { canonical: "Wizard Spider",    type: "threatactor", label: "Threat Actor" },
  "lockbit":       { canonical: "LockBit",          type: "threatactor", label: "Threat Actor" },
  "cl0p":          { canonical: "FIN11",            type: "threatactor", label: "Threat Actor" },
  "clop":          { canonical: "FIN11",            type: "threatactor", label: "Threat Actor" },
};

/**
 * Auto-detect entity type from user input using pattern matching.
 * First checks the alias dictionary for common nicknames, then falls
 * back to regex-based detection. Returns the cleaned entity value
 * alongside the type so the caller can submit the canonical entity.
 */
function detectEntityType(input: string): {
  type: EntityType;
  label: string;
  extracted: string;
} {
  const trimmed = input.trim();

  // Strip natural-language wrapper first so aliases match bare terms
  let core = trimmed;
  const unwrapped = trimmed
    .replace(/^(what|who|where|how|why|show|tell|find|is|are|investigate|check|look\s+up|search)\s+(is|are|me|for|about|up)?\s*/i, "")
    .replace(/[?.!]+$/, "")
    .trim();
  if (unwrapped && unwrapped !== trimmed) core = unwrapped;

  // Check alias dictionary (case-insensitive)
  const alias = ENTITY_ALIASES[core.toLowerCase()];
  if (alias) return { type: alias.type, label: alias.label, extracted: alias.canonical };

  // Standard regex detection on original input
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

  return { type: "package", label: "Package", extracted: core };
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

type FeedSource = "juspay" | "demo";
const FEED_SOURCE_KEY = "cerberus.feedSource";

function getInitialFeedSource(): FeedSource {
  if (typeof window === "undefined") return "juspay";
  const saved = window.localStorage.getItem(FEED_SOURCE_KEY);
  return saved === "demo" ? "demo" : "juspay";
}

export function QueryPanel({ onInvestigate, isRunning }: QueryPanelProps) {
  const [query, setQuery] = useState("");
  const [feedSource, setFeedSource] = useState<FeedSource>(getInitialFeedSource);

  useEffect(() => {
    if (typeof window === "undefined") return;
    window.localStorage.setItem(FEED_SOURCE_KEY, feedSource);
  }, [feedSource]);

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
            <div className="mb-3">
              <p className="text-[10px] font-mono text-muted-foreground uppercase tracking-[0.15em] mb-2">
                Fraud feed source
              </p>
              <div className="grid grid-cols-2 gap-1.5">
                <button
                  type="button"
                  onClick={() => setFeedSource("juspay")}
                  className={cn(
                    "rounded-md px-2 py-1.5 text-[10px] font-mono border transition-all",
                    feedSource === "juspay"
                      ? "border-primary/35 bg-primary/15 text-primary"
                      : "border-border bg-surface-raised text-muted-foreground"
                  )}
                >
                  Juspay API
                </button>
                <button
                  type="button"
                  onClick={() => setFeedSource("demo")}
                  className={cn(
                    "rounded-md px-2 py-1.5 text-[10px] font-mono border transition-all",
                    feedSource === "demo"
                      ? "border-primary/35 bg-primary/15 text-primary"
                      : "border-border bg-surface-raised text-muted-foreground"
                  )}
                >
                  Demo Feed
                </button>
              </div>
            </div>

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
