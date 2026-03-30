/**
 * components/layout/Header.tsx — Top navigation bar
 *
 * Displays the Cerberus brand, connection status indicator,
 * and a minimal nav. The three-headed dog motif is referenced
 * through the triple-dot icon next to the name.
 */
import { useEffect, useState } from "react";
import { Shield, Wifi, WifiOff } from "lucide-react";
import { healthCheck } from "../../lib/api";
import { cn } from "../../lib/utils";

export function Header() {
  /* Track whether the backend is reachable */
  const [online, setOnline] = useState(false);

  useEffect(() => {
    /* Check health on mount and every 30 seconds */
    const check = () => healthCheck().then(setOnline);
    check();
    const id = setInterval(check, 30_000);
    return () => clearInterval(id);
  }, []);

  return (
    <header
      className={cn(
        "flex items-center justify-between px-6 py-3",
        "border-b border-border bg-surface/80 backdrop-blur-md",
        "sticky top-0 z-50"
      )}
    >
      {/* ── Brand ──────────────────────────────────────────── */}
      <div className="flex items-center gap-3">
        {/* Shield icon — represents the guardian aspect */}
        <div className="relative">
          <Shield className="h-7 w-7 text-primary" />
          {/* Glow effect behind the icon */}
          <div className="absolute inset-0 blur-md bg-primary/20 rounded-full" />
        </div>
        <div>
          <h1 className="text-lg font-bold tracking-tight text-foreground">
            CERBERUS
          </h1>
          <p className="text-[10px] font-mono uppercase tracking-[0.2em] text-muted-foreground">
            Cross-Domain Threat Intelligence
          </p>
        </div>
      </div>

      {/* ── Status indicator ────────────────────────────────── */}
      <div
        className={cn(
          "flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-mono",
          online
            ? "bg-success/10 text-success border border-success/20"
            : "bg-threat-critical/10 text-threat-critical border border-threat-critical/20"
        )}
      >
        {online ? (
          <Wifi className="h-3.5 w-3.5" />
        ) : (
          <WifiOff className="h-3.5 w-3.5" />
        )}
        {online ? "CONNECTED" : "OFFLINE"}
      </div>
    </header>
  );
}
