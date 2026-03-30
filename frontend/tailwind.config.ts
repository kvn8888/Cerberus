/**
 * tailwind.config.ts — Cerberus Design System
 *
 * Dark, tactical cybersecurity aesthetic.
 * All semantic tokens reference HSL CSS variables defined in index.css.
 * Components should ONLY use these tokens — never raw colors.
 */
import type { Config } from "tailwindcss";

const config: Config = {
  /* Scan all React/TS source files for class usage */
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],

  theme: {
    extend: {
      /* ── Color tokens ─────────────────────────────────────────────── */
      colors: {
        /* Surface hierarchy (darkest → lightest) */
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        surface: {
          DEFAULT: "hsl(var(--surface))",
          raised: "hsl(var(--surface-raised))",
          overlay: "hsl(var(--surface-overlay))",
        },
        /* Brand / primary action */
        primary: {
          DEFAULT: "hsl(var(--primary))",
          foreground: "hsl(var(--primary-foreground))",
          glow: "hsl(var(--primary-glow))",
          muted: "hsl(var(--primary-muted))",
        },
        /* Threat severity */
        threat: {
          critical: "hsl(var(--threat-critical))",
          high: "hsl(var(--threat-high))",
          medium: "hsl(var(--threat-medium))",
          low: "hsl(var(--threat-low))",
          info: "hsl(var(--threat-info))",
        },
        /* Node-type colors (graph visualization) */
        node: {
          package: "hsl(var(--node-package))",
          cve: "hsl(var(--node-cve))",
          ip: "hsl(var(--node-ip))",
          domain: "hsl(var(--node-domain))",
          actor: "hsl(var(--node-actor))",
          technique: "hsl(var(--node-technique))",
          account: "hsl(var(--node-account))",
          fraud: "hsl(var(--node-fraud))",
        },
        /* Utility / muted text and borders */
        muted: {
          DEFAULT: "hsl(var(--muted))",
          foreground: "hsl(var(--muted-foreground))",
        },
        border: "hsl(var(--border))",
        ring: "hsl(var(--ring))",
        accent: {
          DEFAULT: "hsl(var(--accent))",
          foreground: "hsl(var(--accent-foreground))",
        },
        success: "hsl(var(--success))",
      },

      /* ── Typography ───────────────────────────────────────────────── */
      fontFamily: {
        sans: ['"Plus Jakarta Sans"', "system-ui", "sans-serif"],
        mono: ['"JetBrains Mono"', '"Fira Code"', "monospace"],
      },

      /* ── Shadows ──────────────────────────────────────────────────── */
      boxShadow: {
        glow: "0 0 20px hsl(var(--primary) / 0.3)",
        "glow-lg": "0 0 40px hsl(var(--primary) / 0.4)",
        "glow-threat": "0 0 20px hsl(var(--threat-critical) / 0.3)",
        panel: "0 4px 24px hsl(var(--background) / 0.5)",
      },

      /* ── Animations ───────────────────────────────────────────────── */
      animation: {
        "pulse-slow": "pulse 3s ease-in-out infinite",
        "scan-line": "scanLine 4s linear infinite",
        "fade-in": "fadeIn 0.5s ease-out forwards",
        "slide-up": "slideUp 0.4s ease-out forwards",
        "slide-in-left": "slideInLeft 0.3s ease-out forwards",
        "slide-in-right": "slideInRight 0.3s ease-out forwards",
        "glow-pulse": "glowPulse 2s ease-in-out infinite",
        "border-glow": "borderGlow 3s ease-in-out infinite",
        "float": "float 6s ease-in-out infinite",
        "shimmer": "shimmer 2s linear infinite",
        "radar-sweep": "radarSweep 3s linear infinite",
        "text-reveal": "textReveal 0.5s ease-out forwards",
      },
      keyframes: {
        scanLine: {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(100vh)" },
        },
        fadeIn: {
          "0%": { opacity: "0" },
          "100%": { opacity: "1" },
        },
        slideUp: {
          "0%": { opacity: "0", transform: "translateY(12px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        slideInLeft: {
          "0%": { opacity: "0", transform: "translateX(-16px)" },
          "100%": { opacity: "1", transform: "translateX(0)" },
        },
        slideInRight: {
          "0%": { opacity: "0", transform: "translateX(16px)" },
          "100%": { opacity: "1", transform: "translateX(0)" },
        },
        glowPulse: {
          "0%, 100%": { boxShadow: "0 0 8px hsl(var(--primary) / 0.3)" },
          "50%": { boxShadow: "0 0 24px hsl(var(--primary) / 0.6)" },
        },
        borderGlow: {
          "0%, 100%": { borderColor: "hsl(var(--primary) / 0.2)" },
          "50%": { borderColor: "hsl(var(--primary) / 0.5)" },
        },
        float: {
          "0%, 100%": { transform: "translateY(0)" },
          "50%": { transform: "translateY(-8px)" },
        },
        shimmer: {
          "0%": { backgroundPosition: "-200% 0" },
          "100%": { backgroundPosition: "200% 0" },
        },
        radarSweep: {
          "0%": { transform: "rotate(0deg)" },
          "100%": { transform: "rotate(360deg)" },
        },
        textReveal: {
          "0%": { opacity: "0", transform: "translateY(4px)", filter: "blur(4px)" },
          "100%": { opacity: "1", transform: "translateY(0)", filter: "blur(0)" },
        },
      },

      /* ── Border radius ────────────────────────────────────────────── */
      borderRadius: {
        panel: "12px",
      },
    },
  },
  plugins: [require("@tailwindcss/typography")],
};

export default config;
