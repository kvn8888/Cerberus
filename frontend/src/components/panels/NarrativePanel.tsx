/**
 * components/panels/NarrativePanel.tsx — Streaming threat narrative display
 *
 * The right-side panel that shows the AI-generated threat narrative
 * as it streams in via SSE. Includes metadata badges (cache hit,
 * paths found) and the confirm button for analyst feedback.
 *
 * Implements US-4 (streaming narrative) and US-7 (analyst confirmation).
 */
import { useDeferredValue, useEffect, useMemo, useRef, useState } from "react";
import ReactMarkdown from "react-markdown";
import {
  FileText,
  Zap,
  Database,
  Brain,
  CheckCircle2,
  AlertTriangle,
  Shield,
  Download,
  Target,
  Crosshair,
  ArrowRight,
  Users,
  Copy,
  Table2,
  PanelRightClose,
  PanelRightOpen,
  Globe,
  Server,
  Link2,
  FileCode2,
  ShieldCheck,
  Maximize2,
  Minimize2,
} from "lucide-react";
import type {
  InvestigationState,
  EntityType,
  DetectionRuleSet,
  TlpLevel,
} from "../../types/api";
import {
  confirmEntity,
  fetchReport,
  fetchStixBundle,
  fetchEnrichmentSummary,
  generateDetectionRules,
} from "../../lib/api";
import { cn } from "../../lib/utils";
import {
  mergeIOCs,
  iocsToCsv,
  defangRows,
  defangText,
} from "../../lib/iocExtract";

const API_BASE =
  import.meta.env.VITE_API_URL !== undefined
    ? import.meta.env.VITE_API_URL
    : "http://localhost:8000";
/* ThreatReportPdf and @react-pdf/renderer are dynamically imported in
   handleExportPdf so the 518KB vendor-pdf chunk only loads on click. */

const SEVERITY_COLORS: Record<string, string> = {
  critical:
    "text-threat-critical bg-threat-critical/10 border-threat-critical/30",
  high: "text-threat-high bg-threat-high/10 border-threat-high/30",
  medium: "text-threat-medium bg-threat-medium/10 border-threat-medium/30",
  low: "text-success bg-success/10 border-success/30",
  info: "text-muted-foreground bg-muted/10 border-border",
};

const SEVERITY_SCORE_COLORS: Record<string, string> = {
  critical: "text-threat-critical",
  high: "text-threat-high",
  medium: "text-threat-medium",
  low: "text-success",
  info: "text-muted-foreground",
};

interface NarrativePanelProps {
  state: InvestigationState;
  onTlpChange?: (tlp: TlpLevel) => void;
  onMemorySaved?: () => void;
  onInvestigate?: (entity: string, type: EntityType) => void;
  collapsed?: boolean;
  onToggleCollapse?: () => void;
  expanded?: boolean;
  onToggleExpanded?: () => void;
}

const TLP_LABELS: Record<TlpLevel, string> = {
  clear: "TLP:CLEAR",
  green: "TLP:GREEN",
  amber: "TLP:AMBER",
  "amber+strict": "TLP:AMBER+STRICT",
  red: "TLP:RED",
};

function buildInvestigationMarkdown(args: {
  state: InvestigationState;
  iocs: Array<{ type: string; value: string }>;
  techniques: string[];
  narrative: string;
}): string {
  const { state, iocs, techniques, narrative } = args;
  const lines = [
    `## Investigation: ${state.entity} (${state.entityType})`,
    `**TLP:** ${TLP_LABELS[state.tlp]}`,
  ];

  if (state.threatScore) {
    lines.push(
      `**Threat Score:** ${state.threatScore.score}/100 (${state.threatScore.severity.toUpperCase()})`,
    );
  }

  if (state.blastRadius) {
    const blast = Object.entries(state.blastRadius.by_type)
      .map(([type, count]) => `${count} ${type}`)
      .join(", ");
    lines.push(
      `**Blast Radius:** ${state.blastRadius.total} entities${blast ? `, ${blast}` : ""}`,
    );
  }

  lines.push("", "### Narrative", narrative || "No narrative available.");

  if (iocs.length > 0) {
    lines.push("", "### IOCs");
    iocs.forEach((ioc) => lines.push(`- ${ioc.value} (${ioc.type})`));
  }

  if (techniques.length > 0) {
    lines.push("", "### MITRE Techniques");
    techniques.forEach((technique) => lines.push(`- ${technique}`));
  }

  if (state.suggestions?.length) {
    lines.push("", "### Investigate Next");
    state.suggestions.forEach((suggestion) => {
      lines.push(
        `- ${suggestion.entity} (${suggestion.type}) — ${suggestion.reason}`,
      );
    });
  }

  return lines.join("\n");
}

/**
 * Build a plain-English executive summary from the technical narrative.
 * Strips graph jargon, relationship terms, and technical identifiers so
 * non-technical readers can understand the risk without security expertise.
 */
function buildExecutiveSummary(narrative: string): string {
  if (!narrative) return "";

  const lines = narrative
    .split("\n")
    .map((l) => l.trim())
    .filter(
      (l) =>
        l &&
        !l.startsWith("#") &&
        !l.startsWith("---") &&
        !l.startsWith("|") &&
        !l.startsWith("```") &&
        !l.startsWith("*") &&
        l.length > 40,
    );

  if (lines.length === 0) return "";

  // Replace graph/technical jargon with plain language
  const plain = lines
    .slice(0, 8)
    .map((line) =>
      line
        // Graph relationship terms
        .replace(/\bHAS_VULNERABILITY\b/g, "contains a vulnerability")
        .replace(/\bEXPLOITED_BY\b/g, "is being exploited by")
        .replace(/\bOPERATES\b/g, "controls")
        .replace(/\bUSES\b/g, "uses")
        .replace(/\bCONTROLS\b/g, "controls")
        .replace(/\bHOSTS\b/g, "hosts")
        .replace(/\bLINKED_TO\b/g, "is linked to")
        .replace(/\bASSOCIATED_WITH\b/g, "is associated with")
        .replace(/\bDEPENDS_ON\b/g, "depends on")
        .replace(/\bPUBLISHED_BY\b/g, "was published by")
        // Node type labels
        .replace(/\b(the )?Package node\b/gi, "the software package")
        .replace(/\bPackage node\b/gi, "software package")
        .replace(/\bThreatActor\b/g, "hacking group")
        .replace(/\bThreatActors\b/g, "hacking groups")
        .replace(/\bthreat actor\b/gi, "hacking group")
        .replace(/\bthreat actors\b/gi, "hacking groups")
        .replace(/\bCVE-\d{4}-\d+/g, (m) => `security vulnerability ${m}`)
        .replace(/\bT\d{4}(?:\.\d{3})?\b/g, (m) => `attack technique ${m}`)
        // Technical phrases
        .replace(/\bcross-domain boundary crossing\b/gi, "the attack spread across multiple systems")
        .replace(/\bsoftware supply.chain domain\b/gi, "software supply chain")
        .replace(/\binfrastructure\/operational security\b/gi, "network infrastructure")
        .replace(/\battribution confidence\b/gi, "confidence level")
        .replace(/\bTTP[s]?\b/g, "attack methods")
        .replace(/\bIOC[s]?\b/g, "threat indicators")
        .replace(/\blast resort\b/gi, "fallback")
        // Markdown bold/italic cleanup
        .replace(/\*\*(.+?)\*\*/g, "$1")
        .replace(/\*(.+?)\*/g, "$1")
        .replace(/`(.+?)`/g, "$1")
    )
    .join("\n\n");

  return plain;
}

export function NarrativePanel({
  state,
  onTlpChange,
  onMemorySaved,
  onInvestigate,
  collapsed,
  onToggleCollapse,
  expanded,
  onToggleExpanded,
}: NarrativePanelProps) {
  const [confirmed, setConfirmed] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [viewMode, setViewMode] = useState<"technical" | "executive">(
    "technical",
  );
  const deferredNarrative = useDeferredValue(state.narrative);
  useEffect(() => {
    setConfirmed(false);
  }, [state.entity]);

  const extractedIocs = useMemo(
    () => mergeIOCs(state.graphData, deferredNarrative || ""),
    [state.graphData, deferredNarrative],
  );
  const [defangedCopy, setDefangedCopy] = useState(true);
  const [copiedAction, setCopiedAction] = useState<string | null>(null);
  const [rulesBusy, setRulesBusy] = useState(false);
  const [detectionRules, setDetectionRules] = useState<DetectionRuleSet | null>(
    null,
  );

  const displayedIocs = useMemo(
    () => (defangedCopy ? defangRows(extractedIocs) : extractedIocs),
    [defangedCopy, extractedIocs],
  );
  const techniqueIds = useMemo(() => {
    if (!state.graphData?.nodes?.length) return [] as string[];
    return state.graphData.nodes
      .filter((node) => node.type === "Technique")
      .map((node) => String(node.mitre_id || node.id || "").trim())
      .filter(Boolean);
  }, [state.graphData]);

  const canExport = useMemo(
    () => state.status === "complete" && !!state.entity,
    [state.status, state.entity],
  );

  /* Memoized executive summary — avoids re-processing large narrative on every render */
  const executiveSummary = useMemo(
    () => buildExecutiveSummary(deferredNarrative || ""),
    [deferredNarrative],
  );

  /* Enrichment intel — auto-fetches from VirusTotal / HIBP when investigation completes */
  const [enrichments, setEnrichments] = useState<
    { source: string; simulated: boolean; highlights: string[] }[]
  >([]);
  const [enrichLoading, setEnrichLoading] = useState(false);

  /* Cross-domain fraud overlap — IPs in this graph that also appear in fraud signals */
  const [crossDomainHits, setCrossDomainHits] = useState<
    { juspay_id: string; type: string; amount: number; ip_address: string }[]
  >([]);
  /* Track last entity we fetched for, to avoid re-fetching on cache hits */
  const crossDomainFetchedFor = useRef<string | null>(null);

  useEffect(() => {
    if (state.status !== "complete" || !state.graphData?.nodes) {
      if (state.status !== "complete") {
        setCrossDomainHits([]);
        crossDomainFetchedFor.current = null;
      }
      return;
    }
    /* Skip re-fetch if we already have results for this entity */
    if (crossDomainFetchedFor.current === state.entity) return;
    const ipNodes = new Set(
      state.graphData.nodes
        .filter((n) => (n.type || "").toLowerCase() === "ip")
        .map((n) => n.label || n.id),
    );
    if (ipNodes.size === 0) {
      crossDomainFetchedFor.current = state.entity;
      return;
    }
    crossDomainFetchedFor.current = state.entity;
    fetch(`${API_BASE}/api/juspay/signals?limit=50`)
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        if (!data) return;
        const hits = (data.recent_signals ?? []).filter((s: any) =>
          ipNodes.has(s.ip_address),
        );
        setCrossDomainHits(hits);
      })
      .catch(() => {});
  }, [state.status, state.entity, state.graphData]);

  useEffect(() => {
    if (state.status !== "complete" || !state.entity) {
      setEnrichments([]);
      return;
    }
    let cancelled = false;
    setEnrichLoading(true);
    fetchEnrichmentSummary({ entity: state.entity, type: state.entityType })
      .then((data: any) => {
        if (!cancelled) setEnrichments(data.enrichments ?? []);
      })
      .catch(() => {
        if (!cancelled) setEnrichments([]);
      })
      .finally(() => {
        if (!cancelled) setEnrichLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [state.status, state.entity, state.entityType]);

  useEffect(() => {
    setDetectionRules(null);
    setCopiedAction(null);
  }, [state.entity]);

  /**
   * Handle analyst confirmation — sends a POST /api/confirm
   * to mark this threat pattern for cache acceleration.
   */
  const handleConfirm = async () => {
    if (confirmed || confirming) return;
    setConfirming(true);
    try {
      await confirmEntity({
        entity: state.entity,
        type: state.entityType,
      });
      setConfirmed(true);
      onMemorySaved?.();
    } catch (err) {
      console.error("Confirm failed:", err);
    } finally {
      setConfirming(false);
    }
  };

  const [pdfBusy, setPdfBusy] = useState(false);
  const [stixBusy, setStixBusy] = useState(false);

  const flashCopied = (label: string) => {
    setCopiedAction(label);
    window.setTimeout(
      () => setCopiedAction((current) => (current === label ? null : current)),
      1400,
    );
  };

  const handleExportPdf = async () => {
    if (!canExport || pdfBusy) return;
    setPdfBusy(true);
    try {
      // Dynamic imports: @react-pdf/renderer (518KB) loads only on click
      const [{ pdf }, { ThreatReportPdf }] = await Promise.all([
        import("@react-pdf/renderer"),
        import("../report/ThreatReportPdf"),
      ]);
      // Fetch the report data from the backend
      const report = await fetchReport(
        {
          entity: state.entity,
          type: state.entityType,
        },
        state.tlp,
      );
      // Render the React-PDF document to a blob (all client-side, no popups)
      const blob = await pdf(<ThreatReportPdf report={report} />).toBlob();
      // Create a temporary download link and trigger the save dialog
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `cerberus-report-${report.entity}-${Date.now()}.pdf`;
      document.body.appendChild(a);
      a.click();
      // Clean up the object URL and temporary link element
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Export failed:", err);
      alert("Report generation failed — check the console for details.");
    } finally {
      setPdfBusy(false);
    }
  };

  /** Download the investigation as a STIX 2.1 JSON bundle, for import
   *  into MISP, OpenCTI, or other threat-intel platforms. */
  const handleExportStix = async () => {
    if (!canExport || stixBusy) return;
    setStixBusy(true);
    try {
      const bundle = await fetchStixBundle(
        {
          entity: state.entity,
          type: state.entityType,
        },
        state.tlp,
      );
      const json = JSON.stringify(bundle, null, 2);
      const blob = new Blob([json], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `cerberus-stix-${state.entity}-${Date.now()}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error("STIX export failed:", err);
    } finally {
      setStixBusy(false);
    }
  };

  const handleCopyMarkdown = async () => {
    if (!canExport) return;
    const markdown = buildInvestigationMarkdown({
      state,
      iocs: displayedIocs,
      techniques: techniqueIds,
      narrative: defangedCopy
        ? defangText(deferredNarrative || "")
        : deferredNarrative || "",
    });
    await navigator.clipboard.writeText(markdown);
    flashCopied("markdown");
  };

  const handleCopyPermalink = async () => {
    if (!state.entity || typeof window === "undefined") return;
    const url = new URL(window.location.href);
    url.searchParams.set("entity", state.entity);
    url.searchParams.set("type", state.entityType);
    await navigator.clipboard.writeText(url.toString());
    flashCopied("permalink");
  };

  const handleGenerateRules = async () => {
    if (!canExport || rulesBusy) return;
    setRulesBusy(true);
    try {
      const rules = await generateDetectionRules({
        entity: state.entity,
        entityType: state.entityType,
        iocs: extractedIocs.map((ioc) => ({
          type: ioc.type,
          value: ioc.value,
        })),
        techniques: techniqueIds,
        narrative: deferredNarrative || "",
        tlp: state.tlp,
      });
      setDetectionRules(rules);
    } catch (err) {
      console.error("Detection rule generation failed:", err);
    } finally {
      setRulesBusy(false);
    }
  };

  return (
    <div className="flex min-h-full flex-col">
      {/* ── Section header ─────────────────────────────────── */}
      {collapsed ? (
        /* Collapsed: just a centred toggle button, no overflow */
        <div className="flex items-center justify-center py-3 border-b border-border">
          {onToggleCollapse && (
            <button
              type="button"
              onClick={onToggleCollapse}
              className="p-1 rounded-md text-muted-foreground hover:text-foreground hover:bg-surface-raised transition-colors"
              title="Expand narrative panel"
            >
              <PanelRightOpen className="h-4 w-4" />
            </button>
          )}
        </div>
      ) : (
        <div className="px-4 py-3 border-b border-border flex items-start justify-between gap-2">
          <h2 className="text-sm font-semibold text-foreground uppercase tracking-wider flex items-center gap-2 flex-shrink-0">
            <FileText className="h-4 w-4 text-primary" />
            Threat Narrative
          </h2>

          <div className="flex items-center gap-1.5 flex-wrap justify-end">
            {/* Metadata badges */}
            {state.status === "complete" && (
              <>
                {state.fromCache && (
                  <span className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono bg-success/10 text-success border border-success/20">
                    <Brain className="h-3 w-3" />
                    FROM MEMORY
                  </span>
                )}
                <span className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono bg-accent text-accent-foreground border border-primary/20">
                  <Database className="h-3 w-3" />
                  {state.pathsFound} PATHS
                </span>
                {state.threatScore && (
                  <span
                    className={cn(
                      "flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono border",
                      SEVERITY_COLORS[state.threatScore.severity],
                    )}
                  >
                    <Target className="h-3 w-3" />
                    {state.threatScore.score}/100
                  </span>
                )}
                {state.blastRadius && (
                  <span className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono bg-threat-high/10 text-threat-high border border-threat-high/20">
                    <Crosshair className="h-3 w-3" />
                    {state.blastRadius.total} AFFECTED
                  </span>
                )}
                <span className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono bg-surface-raised text-muted-foreground border border-border/60">
                  <ShieldCheck className="h-3 w-3" />
                  {TLP_LABELS[state.tlp]}
                </span>
              </>
            )}

            {/* Expand / collapse toggles */}
            {onToggleExpanded && (
              <button
                type="button"
                onClick={onToggleExpanded}
                className="p-1 rounded-md text-muted-foreground hover:text-foreground hover:bg-surface-raised transition-colors"
                title={expanded ? "Restore panel size" : "Expand to full width"}
              >
                {expanded ? (
                  <Minimize2 className="h-4 w-4" />
                ) : (
                  <Maximize2 className="h-4 w-4" />
                )}
              </button>
            )}
            {onToggleCollapse && (
              <button
                type="button"
                onClick={onToggleCollapse}
                className="p-1 rounded-md text-muted-foreground hover:text-foreground hover:bg-surface-raised transition-colors"
                title="Collapse narrative panel"
              >
                <PanelRightClose className="h-4 w-4" />
              </button>
            )}
          </div>
        </div>
      )}

      {!collapsed && (
        <div className="flex flex-col animate-fade-in pb-4">
          <div className="px-4 pt-3 flex flex-col gap-2">
            <div className="flex items-center gap-2 rounded-lg border border-border/60 bg-surface-raised/30 px-3 py-2">
              <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
                Export TLP
              </span>
              <select
                value={state.tlp}
                onChange={(event) =>
                  onTlpChange?.(event.target.value as TlpLevel)
                }
                className="ml-auto rounded-md border border-border/60 bg-surface px-2 py-1 text-[10px] font-mono text-foreground focus:outline-none focus:border-primary/40"
              >
                {Object.entries(TLP_LABELS).map(([value, label]) => (
                  <option key={value} value={value}>
                    {label}
                  </option>
                ))}
              </select>
            </div>

            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                disabled={!canExport || pdfBusy}
                onClick={handleExportPdf}
                className={cn(
                  "flex-1 rounded-lg border px-3 py-2 text-xs font-mono transition-all",
                  canExport && !pdfBusy
                    ? "border-primary/25 bg-primary/10 text-primary hover:bg-primary/15"
                    : "border-border bg-surface-raised text-muted-foreground",
                )}
              >
                <span className="flex items-center justify-center gap-2">
                  <Download className="h-3.5 w-3.5" />
                  {pdfBusy ? "Generating..." : "PDF Report"}
                </span>
              </button>
              <button
                type="button"
                disabled={!canExport || stixBusy}
                onClick={handleExportStix}
                className={cn(
                  "flex-1 rounded-lg border px-3 py-2 text-xs font-mono transition-all",
                  canExport && !stixBusy
                    ? "border-primary/25 bg-primary/10 text-primary hover:bg-primary/15"
                    : "border-border bg-surface-raised text-muted-foreground",
                )}
              >
                <span className="flex items-center justify-center gap-2">
                  <Shield className="h-3.5 w-3.5" />
                  {stixBusy ? "Exporting..." : "STIX Bundle"}
                </span>
              </button>
              <button
                type="button"
                disabled={!canExport}
                onClick={() => void handleCopyMarkdown()}
                className={cn(
                  "rounded-lg border px-3 py-2 text-xs font-mono transition-all",
                  canExport
                    ? "border-primary/25 bg-primary/10 text-primary hover:bg-primary/15"
                    : "border-border bg-surface-raised text-muted-foreground",
                )}
              >
                <span className="flex items-center justify-center gap-2">
                  <Copy className="h-3.5 w-3.5" />
                  {copiedAction === "markdown" ? "Copied" : "Markdown"}
                </span>
              </button>
              <button
                type="button"
                disabled={!canExport}
                onClick={() => void handleCopyPermalink()}
                className={cn(
                  "rounded-lg border px-3 py-2 text-xs font-mono transition-all",
                  canExport
                    ? "border-primary/25 bg-primary/10 text-primary hover:bg-primary/15"
                    : "border-border bg-surface-raised text-muted-foreground",
                )}
              >
                <span className="flex items-center justify-center gap-2">
                  <Link2 className="h-3.5 w-3.5" />
                  {copiedAction === "permalink" ? "Copied" : "Permalink"}
                </span>
              </button>
            </div>

            <button
              type="button"
              disabled={!canExport || rulesBusy}
              onClick={() => void handleGenerateRules()}
              className={cn(
                "w-full rounded-lg border px-3 py-2 text-xs font-mono transition-all",
                canExport && !rulesBusy
                  ? "border-threat-high/30 bg-threat-high/10 text-threat-high hover:bg-threat-high/15"
                  : "border-border bg-surface-raised text-muted-foreground",
              )}
            >
              <span className="flex items-center justify-center gap-2">
                <FileCode2 className="h-3.5 w-3.5" />
                {rulesBusy
                  ? "Drafting detection rules..."
                  : "Generate Detection Rules"}
              </span>
            </button>

            {/* Audience mode toggle — switches between full technical detail and executive summary */}
            <div className="flex items-center gap-1 rounded-lg border border-border/60 bg-surface-raised/30 p-0.5">
              <button
                type="button"
                onClick={() => setViewMode("technical")}
                className={cn(
                  "flex-1 px-3 py-1.5 rounded-md text-[10px] font-mono transition-all",
                  viewMode === "technical"
                    ? "bg-primary/15 text-primary border border-primary/25"
                    : "text-muted-foreground hover:text-foreground",
                )}
              >
                Technical
              </button>
              <button
                type="button"
                onClick={() => setViewMode("executive")}
                className={cn(
                  "flex-1 px-3 py-1.5 rounded-md text-[10px] font-mono transition-all",
                  viewMode === "executive"
                    ? "bg-primary/15 text-primary border border-primary/25"
                    : "text-muted-foreground hover:text-foreground",
                )}
              >
                <span className="flex items-center justify-center gap-1">
                  <Users className="h-3 w-3" />
                  Executive
                </span>
              </button>
            </div>
          </div>

          {/* ── Narrative body ─────────────────────────────────── */}
          <div className="p-4">
            {state.status === "idle" && <IdleState />}

            {(state.status === "running" || state.status === "complete") &&
              deferredNarrative && (
                <div className="space-y-4 animate-fade-in">
                  {/* Entity header card */}
                  <div className="flex items-center gap-2.5 p-3 rounded-lg bg-surface-raised/50 border border-border/50">
                    <div className="relative">
                      <Shield className="h-5 w-5 text-primary relative z-10" />
                      <div className="absolute inset-0 blur-md bg-primary/20 rounded-full" />
                    </div>
                    <div>
                      <span className="font-mono text-sm font-semibold text-primary block">
                        {state.entity}
                      </span>
                      <span className="text-[9px] font-mono uppercase text-muted-foreground tracking-wider">
                        {state.entityType} investigation
                      </span>
                    </div>
                    {state.fromCache && (
                      <span className="ml-auto flex items-center gap-1 px-2 py-0.5 rounded-full text-[9px] font-mono bg-success/10 text-success border border-success/20 animate-fade-in">
                        <Zap className="h-2.5 w-2.5" />
                        RECALLED INSTANTLY
                      </span>
                    )}
                  </div>

                  {/* Extracted IOCs — copy / CSV for firewalls & SIEM */}
                  {state.status === "complete" && extractedIocs.length > 0 && (
                    <div className="p-3 rounded-lg bg-surface-raised/40 border border-border/50">
                      <div className="flex items-center justify-between mb-2">
                        <p className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                          <Table2 className="h-3 w-3 text-primary" />
                          Extracted IOCs ({extractedIocs.length})
                        </p>
                        <div className="flex gap-1">
                          <button
                            type="button"
                            onClick={() =>
                              setDefangedCopy((current) => !current)
                            }
                            className={cn(
                              "px-2 py-0.5 rounded text-[9px] font-mono border transition-colors",
                              defangedCopy
                                ? "border-primary/30 bg-primary/10 text-primary"
                                : "border-border/60 hover:bg-primary/10 hover:border-primary/30",
                            )}
                          >
                            {defangedCopy ? "Defanged" : "Raw"}
                          </button>
                          <button
                            type="button"
                            onClick={() => {
                              const lines = displayedIocs.map((r) => r.value);
                              void navigator.clipboard.writeText(
                                lines.join("\n"),
                              );
                              flashCopied("ioc-copy");
                            }}
                            className="px-2 py-0.5 rounded text-[9px] font-mono border border-border/60 hover:bg-primary/10 hover:border-primary/30 transition-colors flex items-center gap-1"
                          >
                            <Copy className="h-2.5 w-2.5" />
                            {copiedAction === "ioc-copy"
                              ? "Copied!"
                              : "Copy all"}
                          </button>
                          <button
                            type="button"
                            onClick={() => {
                              const blob = new Blob(
                                [iocsToCsv(displayedIocs)],
                                { type: "text/csv" },
                              );
                              const url = URL.createObjectURL(blob);
                              const a = document.createElement("a");
                              a.href = url;
                              a.download = `cerberus-iocs-${state.entity}-${Date.now()}.csv`;
                              a.click();
                              URL.revokeObjectURL(url);
                              flashCopied("ioc-csv");
                            }}
                            className="px-2 py-0.5 rounded text-[9px] font-mono border border-border/60 hover:bg-primary/10 hover:border-primary/30 transition-colors"
                          >
                            {copiedAction === "ioc-csv" ? "Saved!" : "CSV"}
                          </button>
                        </div>
                      </div>
                      <div className="space-y-1">
                        {displayedIocs.map((row, i) => {
                          const investigableType =
                            row.type === "ip"
                              ? "ip"
                              : row.type === "domain"
                                ? "domain"
                                : row.type === "package"
                                  ? "package"
                                  : null;
                          /* Use the raw (non-defanged) value for investigation */
                          const rawValue = extractedIocs[i]?.value ?? row.value;
                          return (
                            <div
                              key={`${row.type}-${row.value}-${i}`}
                              className="flex items-center justify-between gap-2 text-[10px] font-mono px-2 py-1 rounded bg-surface/50 border border-border/30"
                            >
                              <span className="text-muted-foreground/70 uppercase w-14 flex-shrink-0">
                                {row.type}
                              </span>
                              <span className="text-foreground truncate flex-1">
                                {row.value}
                              </span>
                              {investigableType ? (
                                <button
                                  type="button"
                                  onClick={() =>
                                    onInvestigate?.(
                                      rawValue,
                                      investigableType as EntityType,
                                    )
                                  }
                                  className="text-[9px] font-mono text-primary/50 hover:text-primary transition-colors flex-shrink-0 w-16 text-right"
                                  title={`Investigate ${rawValue}`}
                                >
                                  → graph
                                </button>
                              ) : (
                                <span className="w-16" />
                              )}
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}

                  {detectionRules && (
                    <div className="p-3 rounded-lg bg-surface-raised/40 border border-border/50 space-y-3">
                      <div className="flex items-center justify-between gap-2">
                        <p className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                          <FileCode2 className="h-3 w-3 text-threat-high" />
                          Detection Rule Sketches
                        </p>
                        <span className="px-2 py-0.5 rounded-full text-[9px] font-mono bg-threat-high/10 text-threat-high border border-threat-high/20">
                          {TLP_LABELS[detectionRules.tlp]}
                        </span>
                      </div>

                      <div className="space-y-2">
                        <div>
                          <div className="mb-1 flex items-center justify-between">
                            <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
                              Sigma
                            </span>
                            <button
                              type="button"
                              onClick={() =>
                                void navigator.clipboard.writeText(
                                  detectionRules.sigma,
                                )
                              }
                              className="px-2 py-0.5 rounded text-[9px] font-mono border border-border/60 hover:bg-primary/10 hover:border-primary/30 transition-colors"
                            >
                              Copy
                            </button>
                          </div>
                          <pre className="overflow-x-auto rounded-lg border border-border/50 bg-surface/70 p-3 text-[10px] leading-relaxed text-foreground/85">
                            <code>{detectionRules.sigma}</code>
                          </pre>
                        </div>

                        <div>
                          <div className="mb-1 flex items-center justify-between">
                            <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
                              YARA
                            </span>
                            <button
                              type="button"
                              onClick={() =>
                                void navigator.clipboard.writeText(
                                  detectionRules.yara,
                                )
                              }
                              className="px-2 py-0.5 rounded text-[9px] font-mono border border-border/60 hover:bg-primary/10 hover:border-primary/30 transition-colors"
                            >
                              Copy
                            </button>
                          </div>
                          <pre className="overflow-x-auto rounded-lg border border-border/50 bg-surface/70 p-3 text-[10px] leading-relaxed text-foreground/85">
                            <code>{detectionRules.yara}</code>
                          </pre>
                        </div>
                      </div>

                      {detectionRules.notes.length > 0 && (
                        <div className="space-y-1">
                          {detectionRules.notes.map((note, index) => (
                            <p
                              key={index}
                              className="text-[10px] font-mono text-muted-foreground/75 flex items-start gap-1.5"
                            >
                              <span className="mt-1 h-1 w-1 rounded-full bg-threat-high/50" />
                              {note}
                            </p>
                          ))}
                        </div>
                      )}
                    </div>
                  )}

                  {/* External enrichment intel — VirusTotal / HIBP highlights */}
                  {state.status === "complete" &&
                    (enrichLoading || enrichments.length > 0) && (
                      <div className="p-3 rounded-lg bg-surface-raised/40 border border-border/50">
                        <p className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground flex items-center gap-1.5 mb-2">
                          <Globe className="h-3 w-3 text-primary" />
                          External Intelligence
                        </p>
                        {enrichLoading ? (
                          <p className="text-[11px] font-mono text-muted-foreground animate-pulse">
                            Querying threat feeds...
                          </p>
                        ) : (
                          enrichments.map((e) => (
                            <div key={e.source} className="mb-2 last:mb-0">
                              <p className="text-[10px] font-mono text-primary/70 uppercase mb-1 flex items-center gap-1">
                                {e.source}
                                {e.simulated && (
                                  <span
                                    title="Demo enrichment data — connect live VirusTotal/HIBP API keys for real results"
                                    className="text-[8px] px-1 py-0.5 rounded bg-muted/30 text-muted-foreground/50 normal-case cursor-help border border-border/40"
                                  >
                                    demo
                                  </span>
                                )}
                              </p>
                              <ul className="space-y-0.5">
                                {e.highlights.map((h, i) => (
                                  <li
                                    key={i}
                                    className="text-[11px] font-mono text-foreground/80 flex items-start gap-1.5"
                                  >
                                    <span className="text-primary/40 mt-0.5">
                                      ▸
                                    </span>
                                    {h}
                                  </li>
                                ))}
                              </ul>
                            </div>
                          ))
                        )}
                      </div>
                    )}

                  {/* Cross-domain fraud overlap — only shown when IPs in this graph match fraud signals */}
                  {state.status === "complete" &&
                    crossDomainHits.length > 0 && (
                      <div className="p-3 rounded-lg bg-threat-high/5 border border-threat-high/20 animate-fade-in">
                        <p className="text-[10px] font-mono uppercase tracking-wider text-threat-high flex items-center gap-1.5 mb-2">
                          <AlertTriangle className="h-3 w-3" />
                          Cross-Domain Hit — Financial Fraud Overlap
                        </p>
                        <div className="space-y-1">
                          {crossDomainHits.map((hit) => (
                            <div
                              key={hit.juspay_id}
                              className="flex items-center justify-between text-[10px] font-mono px-2 py-1.5 rounded bg-threat-high/8 border border-threat-high/15"
                            >
                              <span className="text-foreground/80 flex items-center gap-1.5">
                                <Server className="h-2.5 w-2.5 text-threat-high/60" />
                                {hit.ip_address}
                              </span>
                              <div className="text-right">
                                <span className="text-threat-high">
                                  ${hit.amount.toLocaleString()}
                                </span>
                                <span className="text-muted-foreground/40 block text-[9px]">
                                  {hit.type.replace(/_/g, " ")}
                                </span>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                  {viewMode === "executive" ? (
                    /* ── EXECUTIVE VIEW — plain-English summary for non-technical leadership ── */
                    <div className="space-y-4">
                      {/* Risk verdict with explanation */}
                      {state.threatScore && (
                        <div
                          className={cn(
                            "p-4 rounded-lg border",
                            SEVERITY_COLORS[state.threatScore.severity],
                          )}
                        >
                          <div className="text-center mb-3">
                            <p className="text-[10px] font-mono uppercase tracking-wider opacity-70 mb-1">
                              Risk Level
                            </p>
                            <p className="text-2xl font-bold font-mono uppercase">
                              {state.threatScore.severity}
                            </p>
                            <p className="text-3xl font-bold font-mono mt-1">
                              {state.threatScore.score}/100
                            </p>
                          </div>
                          <p className="text-[11px] leading-relaxed opacity-80 text-center">
                            {state.threatScore.score >= 70
                              ? "This software package is connected to known criminal hacking groups and dangerous infrastructure. Your team needs to act on this now."
                              : state.threatScore.score >= 40
                                ? "This software package has some suspicious connections worth watching. It has not been confirmed as actively dangerous yet, but it should be monitored."
                                : "This software package has minimal connections to known threats. No immediate action is needed, but routine monitoring should continue."}
                          </p>
                        </div>
                      )}

                      {/* What happened — plain English summary */}
                      <div className="p-4 rounded-lg bg-surface-raised/40 border border-border/50">
                        <p className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
                          <FileText className="h-3 w-3 text-primary" />
                          What We Found
                        </p>
                        <div className="space-y-2">
                          {executiveSummary.split("\n\n").filter(Boolean).map((para, i) => (
                            <p key={i} className="text-[12px] leading-relaxed text-foreground/80">
                              {para}
                            </p>
                          ))}
                        </div>
                      </div>

                      {/* Impact numbers with plain-English descriptions */}
                      <div className="space-y-2">
                        <div className="p-3 rounded-lg bg-surface-raised/30 border border-border/50">
                          <div className="flex items-center justify-between mb-1">
                            <p className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
                              Attack Paths Found
                            </p>
                            <p className="text-xl font-bold font-mono text-primary">
                              {state.pathsFound}
                            </p>
                          </div>
                          <p className="text-[11px] text-muted-foreground/70 leading-relaxed">
                            {state.pathsFound === 0
                              ? "No direct attack routes were discovered connecting this entity to known threats. This is a good sign."
                              : state.pathsFound === 1
                                ? `We found 1 route that an attacker could use (or has used) to move from ${state.entity} toward your systems or data. Think of it as a chain of connections — each link represents a relationship between a piece of malware, a server, a vulnerability, or a hacking group.`
                                : `We found ${state.pathsFound} different routes that attackers could use (or have used) to move from ${state.entity} toward your systems or data. Each path is a chain of connections — linking malware, servers, vulnerabilities, and hacking groups together. More paths means more exposure.`}
                          </p>
                        </div>
                        <div className="p-3 rounded-lg bg-surface-raised/30 border border-border/50">
                          <div className="flex items-center justify-between mb-1">
                            <p className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
                              Blast Radius
                            </p>
                            <p className="text-xl font-bold font-mono text-threat-high">
                              {state.blastRadius?.total ?? 0} entities
                            </p>
                          </div>
                          <p className="text-[11px] text-muted-foreground/70 leading-relaxed">
                            {(state.blastRadius?.total ?? 0) === 0
                              ? "No other systems, accounts, or assets appear to be connected to this threat. The impact is contained."
                              : `If this threat is exploited, ${state.blastRadius?.total ?? 0} other systems, accounts, IP addresses, or digital assets in our network could be affected. This is the "blast radius" — the total number of things connected to this threat that could be compromised. ${(state.blastRadius?.total ?? 0) >= 100 ? "This is a very large blast radius, meaning the potential damage from this threat is widespread across the organization." : (state.blastRadius?.total ?? 0) >= 20 ? "This is a significant blast radius that warrants close monitoring." : "This is a contained blast radius."}`}
                          </p>
                        </div>
                      </div>

                      {/* Cross-domain fraud overlap — executive explanation */}
                      {crossDomainHits.length > 0 && (
                        <div className="p-4 rounded-lg bg-threat-high/5 border border-threat-high/20">
                          <p className="text-[10px] font-mono uppercase tracking-wider text-threat-high mb-2 flex items-center gap-1.5">
                            <AlertTriangle className="h-3 w-3" />
                            Financial Fraud Connection Detected
                          </p>
                          <p className="text-[11px] text-foreground/80 leading-relaxed mb-3">
                            This is a critical finding. The IP address
                            {crossDomainHits.length > 1 ? "es" : ""} involved in
                            this cyber threat{" "}
                            {crossDomainHits.length > 1 ? "are" : "is"} also
                            connected to financial fraud activity — meaning the
                            same infrastructure used for hacking is also being
                            used to steal money. This suggests a well-organized
                            criminal operation that operates across both
                            cybersecurity and financial crime.
                          </p>
                          <div className="space-y-1.5">
                            {crossDomainHits.map((hit) => (
                              <div
                                key={hit.juspay_id}
                                className="flex items-center justify-between text-[11px] px-2.5 py-2 rounded bg-threat-high/8 border border-threat-high/15"
                              >
                                <span className="text-foreground/80 flex items-center gap-1.5">
                                  <Server className="h-2.5 w-2.5 text-threat-high/60" />
                                  {hit.ip_address}
                                </span>
                                <div className="text-right">
                                  <span className="text-threat-high font-semibold">
                                    ${hit.amount.toLocaleString()}
                                  </span>
                                  <span className="text-muted-foreground/50 block text-[9px]">
                                    {hit.type.replace(/_/g, " ")} fraud
                                  </span>
                                </div>
                              </div>
                            ))}
                          </div>
                          <p className="text-[10px] text-muted-foreground/50 mt-2 leading-relaxed">
                            Total fraud exposure: $
                            {crossDomainHits
                              .reduce((sum, h) => sum + h.amount, 0)
                              .toLocaleString()}{" "}
                            across {crossDomainHits.length} transaction
                            {crossDomainHits.length > 1 ? "s" : ""}.
                          </p>
                        </div>
                      )}

                      {/* Recommended action — detailed for executives */}
                      <div className="p-4 rounded-lg bg-primary/5 border border-primary/20">
                        <p className="text-[10px] font-mono uppercase tracking-wider text-primary mb-2 flex items-center gap-1.5">
                          <Shield className="h-3 w-3" />
                          What Should We Do
                        </p>
                        <div className="text-sm text-foreground/80 leading-relaxed space-y-2">
                          {state.threatScore &&
                          state.threatScore.score >= 70 ? (
                            <>
                              <p>
                                <strong className="text-primary">
                                  Immediate action is required.
                                </strong>{" "}
                                Our investigation found that{" "}
                                <strong className="text-foreground">
                                  {state.entity}
                                </strong>{" "}
                                is directly connected to active, dangerous
                                threat infrastructure — meaning attackers are
                                actively using these systems right now.
                              </p>
                              <p>
                                We discovered {state.pathsFound} confirmed
                                attack path{state.pathsFound === 1 ? "" : "s"}{" "}
                                and {state.blastRadius?.total ?? 0} connected
                                entities that could be affected.{" "}
                                {crossDomainHits.length > 0
                                  ? `Additionally, this threat overlaps with $${crossDomainHits.reduce((s, h) => s + h.amount, 0).toLocaleString()} in financial fraud activity, suggesting organized criminal operations.`
                                  : ""}
                              </p>
                              <p>
                                <strong className="text-primary">
                                  Recommended next steps:
                                </strong>{" "}
                                Escalate to your incident response team
                                immediately. Block the associated IP addresses
                                at the firewall. Notify affected business units.
                                If financial fraud overlap was detected,
                                coordinate with your fraud prevention and legal
                                teams.
                              </p>
                            </>
                          ) : state.threatScore &&
                            state.threatScore.score >= 40 ? (
                            <>
                              <p>
                                <strong className="text-primary">
                                  This warrants close monitoring.
                                </strong>{" "}
                                Our investigation found that{" "}
                                <strong className="text-foreground">
                                  {state.entity}
                                </strong>{" "}
                                shows indicators of compromise — meaning there
                                are suspicious connections or activity, but we
                                have not confirmed active exploitation yet.
                              </p>
                              <p>
                                We found {state.pathsFound} potential attack
                                path{state.pathsFound === 1 ? "" : "s"} and{" "}
                                {state.blastRadius?.total ?? 0} entities that
                                could be impacted if this threat escalates.
                              </p>
                              <p>
                                <strong className="text-primary">
                                  Recommended next steps:
                                </strong>{" "}
                                Add this entity to your active watchlist. Have
                                your security team review in 24 hours. Prepare
                                containment procedures in case the threat level
                                increases. Brief your IT team on what to look
                                for.
                              </p>
                            </>
                          ) : (
                            <>
                              <p>
                                <strong className="text-primary">
                                  No immediate action needed.
                                </strong>{" "}
                                Our investigation found that{" "}
                                <strong className="text-foreground">
                                  {state.entity}
                                </strong>{" "}
                                shows minimal connections to known threats.
                                While it did appear in our threat intelligence
                                database, the risk level is low.
                              </p>
                              <p>
                                <strong className="text-primary">
                                  Recommended next steps:
                                </strong>{" "}
                                Continue standard security monitoring. No
                                escalation is necessary at this time. Our system
                                will continue to track this entity and alert you
                                if the risk level changes.
                              </p>
                            </>
                          )}
                        </div>
                      </div>
                    </div>
                  ) : (
                    /* ── TECHNICAL VIEW — full detail for analysts ── */
                    <>
                      {/* Threat Score detail card */}
                      {state.threatScore && (
                        <div className="p-3 rounded-lg bg-surface-raised/30 border border-border/50">
                          <div className="flex items-center justify-between mb-2">
                            <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
                              Threat Score
                            </span>
                            <span
                              className={cn(
                                "text-lg font-bold font-mono",
                                SEVERITY_SCORE_COLORS[
                                  state.threatScore.severity
                                ],
                              )}
                            >
                              {state.threatScore.score}
                            </span>
                          </div>
                          <div className="w-full h-1.5 rounded-full bg-surface-raised overflow-hidden mb-2">
                            <div
                              className={cn(
                                "h-full rounded-full transition-all duration-1000",
                                {
                                  "bg-threat-critical":
                                    state.threatScore.severity === "critical",
                                  "bg-threat-high":
                                    state.threatScore.severity === "high",
                                  "bg-threat-medium":
                                    state.threatScore.severity === "medium",
                                  "bg-success":
                                    state.threatScore.severity === "low",
                                  "bg-muted-foreground":
                                    state.threatScore.severity === "info",
                                },
                              )}
                              style={{ width: `${state.threatScore.score}%` }}
                            />
                          </div>
                          <div className="space-y-1">
                            {state.threatScore.factors
                              .slice(0, 4)
                              .map((f, i) => (
                                <p
                                  key={i}
                                  className="text-[10px] font-mono text-muted-foreground/70 flex items-center gap-1.5"
                                >
                                  <span className="w-1 h-1 rounded-full bg-primary/40" />
                                  {f}
                                </p>
                              ))}
                          </div>
                        </div>
                      )}

                      {/* Blast Radius breakdown */}
                      {state.blastRadius && state.blastRadius.total > 0 && (
                        <div className="p-3 rounded-lg bg-surface-raised/30 border border-border/50">
                          <div className="flex items-center justify-between mb-2">
                            <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                              <Crosshair className="h-3 w-3 text-threat-high" />
                              Blast Radius
                            </span>
                            <span className="text-sm font-bold font-mono text-threat-high">
                              {state.blastRadius.total} entities
                            </span>
                          </div>
                          <div className="flex flex-wrap gap-1.5">
                            {Object.entries(state.blastRadius.by_type).map(
                              ([type, count]) => (
                                <span
                                  key={type}
                                  className="px-2 py-0.5 rounded-full text-[9px] font-mono bg-surface-raised border border-border/40 text-muted-foreground"
                                >
                                  {type}: {count}
                                </span>
                              ),
                            )}
                          </div>
                        </div>
                      )}

                      {/* Narrative text with markdown rendering */}
                      <div className="relative">
                        <div className="absolute left-0 top-0 bottom-0 w-px bg-primary/15" />
                        <div
                          className={cn(
                            "pl-4 font-mono text-[13px] leading-[1.8] text-foreground/85",
                            "selection:bg-primary/20",
                            "prose prose-invert prose-sm max-w-none",
                            "prose-headings:text-primary prose-headings:font-mono prose-headings:text-sm prose-headings:mt-3 prose-headings:mb-1",
                            "prose-strong:text-primary prose-strong:font-semibold",
                            "prose-p:mb-2 prose-p:leading-[1.8]",
                            "prose-ul:my-1 prose-li:my-0.5 prose-li:marker:text-primary/40",
                            "prose-code:text-primary prose-code:bg-primary/10 prose-code:px-1 prose-code:py-0.5 prose-code:rounded prose-code:text-xs",
                          )}
                        >
                          <ReactMarkdown>{deferredNarrative}</ReactMarkdown>
                          {state.status === "running" && (
                            <span className="inline-flex items-center gap-1 text-primary">
                              <span className="w-1.5 h-4 bg-primary animate-pulse" />
                            </span>
                          )}
                        </div>
                      </div>
                    </>
                  )}
                </div>
              )}

            {state.status === "error" && (
              <div className="flex items-start gap-3 p-4 rounded-lg bg-threat-critical/10 border border-threat-critical/20">
                <AlertTriangle className="h-5 w-5 text-threat-critical flex-shrink-0 mt-0.5" />
                <div>
                  <p className="text-sm font-medium text-threat-critical">
                    Investigation Failed
                  </p>
                  <p className="text-xs text-muted-foreground mt-1 font-mono">
                    {state.error}
                  </p>
                </div>
              </div>
            )}

            {/* ── Investigate Next suggestions (inside scroll area so
             they flow naturally after the narrative instead of
             covering it as a fixed footer) ────────────────────── */}
            {state.status === "complete" &&
              state.suggestions &&
              state.suggestions.length > 0 && (
                <div className="mt-4 pt-3 border-t border-border/50">
                  <p className="text-[10px] font-mono text-muted-foreground uppercase tracking-wider pb-2 flex items-center gap-1.5">
                    <ArrowRight className="h-3 w-3 text-primary" />
                    Investigate Next
                  </p>
                  <div className="space-y-1">
                    {state.suggestions.map((s, i) => (
                      <button
                        key={i}
                        onClick={() =>
                          onInvestigate?.(s.entity, s.type as EntityType)
                        }
                        className="w-full text-left px-3 py-2 rounded-md text-xs font-mono group bg-surface-raised/30 hover:bg-primary/8 hover:text-primary border border-transparent hover:border-primary/15 transition-all duration-200"
                      >
                        <div className="flex items-center justify-between">
                          <span className="text-foreground/80 group-hover:text-primary transition-colors truncate">
                            {s.entity}
                          </span>
                          <span className="text-[9px] text-muted-foreground/50 ml-2 flex-shrink-0">
                            {s.connections} links
                          </span>
                        </div>
                        <span className="text-muted-foreground/40 text-[10px] block mt-0.5">
                          {s.reason}
                        </span>
                      </button>
                    ))}
                  </div>
                </div>
              )}
          </div>

          {/* ── Memory save — shown when complete with paths, hidden if already memorized ── */}
          {state.status === "complete" && state.pathsFound > 0 && (
            <div className="p-4 border-t border-border">
              <div className="flex items-center justify-center gap-2 mb-3">
                <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-mono bg-accent/50 text-accent-foreground border border-primary/15">
                  <Database className="h-3 w-3" />
                  {state.pathsFound} threat{" "}
                  {state.pathsFound === 1 ? "path" : "paths"} discovered
                </span>
              </div>

              {state.fromCache ? (
                /* Already memorized — show static "already in memory" state */
                <>
                  <div className="w-full py-2.5 rounded-lg text-sm font-bold tracking-wide bg-success/15 text-success border border-success/30 flex items-center justify-center gap-2 shadow-[0_0_16px_hsl(var(--success)/0.15)]">
                    <CheckCircle2 className="h-4 w-4" />
                    Already Memorized
                  </div>
                  <p className="text-[10px] text-success/60 mt-2 text-center font-mono">
                    This pattern was recalled from memory — no need to save
                    again
                  </p>
                </>
              ) : (
                /* Not yet memorized — show save button */
                <>
                  <button
                    onClick={handleConfirm}
                    disabled={confirmed || confirming}
                    className={cn(
                      "group w-full py-2.5 rounded-lg text-sm font-bold tracking-wide",
                      "transition-all duration-500 flex items-center justify-center gap-2",
                      confirmed
                        ? "bg-success/15 text-success border border-success/30 cursor-default shadow-[0_0_16px_hsl(var(--success)/0.15)]"
                        : confirming
                          ? "bg-muted text-muted-foreground cursor-wait"
                          : "bg-surface-raised text-foreground border border-primary/30 hover:bg-primary/10 hover:border-primary/50 hover:shadow-glow active:scale-[0.98]",
                    )}
                  >
                    {confirmed ? (
                      <>
                        <CheckCircle2 className="h-4 w-4 animate-fade-in" />
                        Memorized
                      </>
                    ) : confirming ? (
                      <>
                        <Brain className="h-4 w-4 animate-pulse" />
                        Saving to Memory...
                      </>
                    ) : (
                      <>
                        <Brain className="h-4 w-4 group-hover:animate-pulse" />
                        Save to Memory
                      </>
                    )}
                  </button>
                  {confirmed ? (
                    <p className="text-[10px] text-success/60 mt-2 text-center font-mono animate-fade-in">
                      This pattern will be recognized instantly next time
                    </p>
                  ) : (
                    <p className="text-[10px] text-muted-foreground/40 mt-2 text-center font-mono">
                      Teach the system to recognize this threat pattern
                      instantly
                    </p>
                  )}
                </>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/**
 * Idle state content — shown before any investigation is started.
 * Provides an atmospheric hint about capabilities.
 */
function IdleState() {
  return (
    <div className="flex flex-col items-center justify-center h-full text-center px-6">
      {/* Animated shield with layered glow */}
      <div className="relative mb-6">
        <Shield className="h-16 w-16 text-muted-foreground/20 animate-float" />
        <div className="absolute inset-0 blur-xl bg-primary/5 rounded-full" />
      </div>

      <p className="text-sm font-medium text-muted-foreground/60 mb-2">
        No active investigation
      </p>
      <p className="text-xs text-muted-foreground/40 max-w-[240px] leading-relaxed">
        Select an entity type and enter a target to begin cross-domain threat
        analysis. The agent will traverse the knowledge graph, reason about
        attack chains, and generate a narrative.
      </p>

      {/* Decorative divider */}
      <div className="mt-6 flex items-center gap-2">
        <div className="w-8 h-px bg-border/50" />
        <div className="w-1.5 h-1.5 rounded-full bg-muted-foreground/15" />
        <div className="w-8 h-px bg-border/50" />
      </div>

      {/* Capability hints */}
      <div className="mt-4 space-y-2 text-[10px] text-muted-foreground/30 font-mono">
        <p>Package supply-chain analysis</p>
        <p>IP/domain infrastructure mapping</p>
        <p>MITRE ATT&CK technique correlation</p>
      </div>
    </div>
  );
}
