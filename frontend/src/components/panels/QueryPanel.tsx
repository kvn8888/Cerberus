/**
 * components/panels/QueryPanel.tsx — Left sidebar input panel
 *
 * Where analysts type an entity (package name, IP, domain, etc.)
 * and select its type before launching an investigation.
 * Also shows quick-access example entities for demo purposes.
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
} from "lucide-react";
import type { EntityType } from "../../types/api";
import { cn } from "../../lib/utils";

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
];

export function QueryPanel({ onInvestigate, isRunning }: QueryPanelProps) {
  const [entity, setEntity] = useState("");
  const [entityType, setEntityType] = useState<EntityType>("package");

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
