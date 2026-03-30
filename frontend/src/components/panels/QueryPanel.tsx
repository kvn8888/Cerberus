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
      {/* ── Section header ─────────────────────────────────── */}
      <div className="px-4 py-3 border-b border-border">
        <h2 className="text-sm font-semibold text-foreground uppercase tracking-wider flex items-center gap-2">
          <Zap className="h-4 w-4 text-primary" />
          Investigation
        </h2>
      </div>

      {/* ── Input form ─────────────────────────────────────── */}
      <form onSubmit={handleSubmit} className="p-4 space-y-4">
        {/* Entity type selector — pill buttons */}
        <div>
          <label className="text-xs font-mono text-muted-foreground uppercase tracking-wider mb-2 block">
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
                    "transition-all duration-200",
                    active
                      ? "bg-primary/15 text-primary border border-primary/30"
                      : "bg-surface-raised text-muted-foreground border border-border hover:text-foreground hover:border-muted-foreground/30"
                  )}
                >
                  <Icon className="h-3 w-3" />
                  {t.label}
                </button>
              );
            })}
          </div>
        </div>

        {/* Entity name input */}
        <div>
          <label className="text-xs font-mono text-muted-foreground uppercase tracking-wider mb-2 block">
            Entity
          </label>
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <input
              type="text"
              value={entity}
              onChange={(e) => setEntity(e.target.value)}
              placeholder="e.g. ua-parser-js, 185.220.101.1"
              className={cn(
                "w-full pl-10 pr-4 py-2.5 rounded-lg text-sm font-mono",
                "bg-surface-raised border border-border",
                "text-foreground placeholder:text-muted-foreground/50",
                "focus:outline-none focus:border-primary/50 focus:ring-1 focus:ring-primary/20",
                "transition-all duration-200"
              )}
            />
          </div>
        </div>

        {/* Submit button */}
        <button
          type="submit"
          disabled={!entity.trim() || isRunning}
          className={cn(
            "w-full py-2.5 rounded-lg text-sm font-semibold",
            "transition-all duration-300",
            !entity.trim() || isRunning
              ? "bg-muted text-muted-foreground cursor-not-allowed"
              : "bg-primary text-primary-foreground hover:shadow-glow active:scale-[0.98]"
          )}
        >
          {isRunning ? (
            <span className="flex items-center justify-center gap-2">
              <span className="h-3 w-3 rounded-full border-2 border-primary-foreground border-t-transparent animate-spin" />
              Investigating...
            </span>
          ) : (
            "Investigate"
          )}
        </button>
      </form>

      {/* ── Quick examples ─────────────────────────────────── */}
      <div className="px-4 pb-4 mt-auto">
        <p className="text-xs font-mono text-muted-foreground uppercase tracking-wider mb-2">
          Quick Start
        </p>
        <div className="space-y-1">
          {EXAMPLES.map((ex) => (
            <button
              key={ex.entity}
              onClick={() => handleExample(ex)}
              disabled={isRunning}
              className={cn(
                "w-full text-left px-3 py-2 rounded-md text-xs font-mono",
                "bg-surface-raised/50 text-muted-foreground",
                "hover:bg-primary/10 hover:text-primary",
                "border border-transparent hover:border-primary/20",
                "transition-all duration-200",
                "disabled:opacity-50 disabled:cursor-not-allowed"
              )}
            >
              <span className="text-accent-foreground">{ex.label}</span>
              <span className="text-muted-foreground/50 ml-2">
                ({ex.type})
              </span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
