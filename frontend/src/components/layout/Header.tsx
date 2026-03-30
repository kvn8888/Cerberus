/**
 * components/layout/Header.tsx — Top navigation bar
 *
 * Displays the Cerberus brand with an animated shield icon,
 * a subtle gradient bottom border, and live backend connection
 * status with a pulsing indicator dot.
 */
import { useEffect, useState } from "react";
import { Shield, Wifi, WifiOff, Activity, Cpu } from "lucide-react";
import { healthCheck, rocketrideHealthCheck } from "../../lib/api";
import { cn } from "../../lib/utils";

export function Header() {
  /* Track whether the backend is reachable */
  const [online, setOnline] = useState(false);
  /* Track whether RocketRide pipeline service is reachable */
  const [rocketrideOnline, setRocketrideOnline] = useState(false);

  useEffect(() => {
    const check = () => {
      healthCheck().then(setOnline);
      rocketrideHealthCheck().then(setRocketrideOnline);
    };
    check();
    const id = setInterval(check, 10_000);
    return () => clearInterval(id);
  }, []);

  return (
    <header className="relative sticky top-0 z-50">
      {/* Main header content */}
      <div
        className={cn(
          "flex items-center justify-between px-6 py-3",
          "bg-surface/90 backdrop-blur-xl"
        )}
      >
        {/* ── Brand ──────────────────────────────────────────── */}
        <div className="flex items-center gap-3.5">
          {/* Animated shield icon with layered glow */}
          <div className="relative group">
            <Shield className="h-8 w-8 text-primary relative z-10 transition-transform duration-300 group-hover:scale-110" />
            {/* Primary glow ring */}
            <div className="absolute inset-0 blur-lg bg-primary/25 rounded-full animate-pulse-slow" />
            {/* Secondary subtle ring */}
            <div className="absolute -inset-1 blur-xl bg-primary/10 rounded-full" />
          </div>
          <div>
            <h1 className="text-lg font-extrabold tracking-[0.08em] text-foreground">
              CERBERUS
            </h1>
            <p className="text-[10px] font-mono uppercase tracking-[0.25em] text-muted-foreground">
              Cross-Domain Threat Intel
            </p>
          </div>
        </div>

        {/* ── Center — subtle activity pulse ───────────────── */}
        <div className="hidden md:flex items-center gap-1.5 text-muted-foreground/30">
          <Activity className="h-3.5 w-3.5" />
          <div className="flex gap-0.5">
            {[0, 1, 2, 3, 4].map((i) => (
              <div
                key={i}
                className="w-0.5 bg-primary/20 rounded-full"
                style={{
                  height: `${8 + Math.sin(i * 1.2) * 6}px`,
                  animation: `float ${2 + i * 0.3}s ease-in-out infinite`,
                  animationDelay: `${i * 0.15}s`,
                }}
              />
            ))}
          </div>
        </div>

        {/* ── Status indicators ─────────────────────────────── */}
        <div className="flex items-center gap-2">
          {/* Backend status */}
          <div
            className={cn(
              "flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-mono",
              "transition-all duration-500",
              online
                ? "bg-success/10 text-success border border-success/20"
                : "bg-threat-critical/10 text-threat-critical border border-threat-critical/20"
            )}
          >
            <span className="relative flex h-2 w-2">
              <span
                className={cn(
                  "absolute inline-flex h-full w-full rounded-full opacity-75",
                  online ? "bg-success animate-ping" : "bg-threat-critical animate-ping"
                )}
                style={{ animationDuration: "2s" }}
              />
              <span
                className={cn(
                  "relative inline-flex h-2 w-2 rounded-full",
                  online ? "bg-success" : "bg-threat-critical"
                )}
              />
            </span>
            {online ? <Wifi className="h-3 w-3" /> : <WifiOff className="h-3 w-3" />}
            <span className="hidden sm:inline">
              {online ? "NEO4J" : "OFFLINE"}
            </span>
          </div>

          {/* RocketRide pipeline status */}
          <div
            className={cn(
              "flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-mono",
              "transition-all duration-500",
              rocketrideOnline
                ? "bg-success/10 text-success border border-success/20"
                : "bg-muted/20 text-muted-foreground border border-muted/20"
            )}
          >
            <span className="relative flex h-2 w-2">
              {rocketrideOnline && (
                <span
                  className="absolute inline-flex h-full w-full rounded-full bg-success opacity-75 animate-ping"
                  style={{ animationDuration: "2s" }}
                />
              )}
              <span
                className={cn(
                  "relative inline-flex h-2 w-2 rounded-full",
                  rocketrideOnline ? "bg-success" : "bg-muted-foreground/40"
                )}
              />
            </span>
            <Cpu className="h-3 w-3" />
            <span className="hidden sm:inline">
              {rocketrideOnline ? "ROCKETRIDE" : "PIPELINE"}
            </span>
          </div>
        </div>
      </div>

      {/* Gradient bottom border — subtle cyan accent line */}
      <div
        className="h-px w-full"
        style={{
          background:
            "linear-gradient(90deg, transparent 0%, hsl(var(--primary) / 0.4) 30%, hsl(var(--primary) / 0.6) 50%, hsl(var(--primary) / 0.4) 70%, transparent 100%)",
        }}
      />
    </header>
  );
}
