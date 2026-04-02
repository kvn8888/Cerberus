/**
 * components/panels/IngestPanel.tsx — Document & text ingestion panel
 *
 * Lets users paste threat report text or drag-drop files (PDFs, images)
 * into the RocketRide ingest pipeline. The pipeline runs:
 *   webhook → parse → OCR (images) → extract_data → LLM (Haiku) → entities
 *
 * Extracted entities are displayed in a table and optionally written
 * to the Neo4j graph for cross-domain investigation.
 *
 * This panel connects the cerberus-ingest.pipe pipeline to the frontend,
 * making document ingestion visible and interactive for the demo.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import {
  Upload,
  FileText,
  AlertCircle,
  CheckCircle2,
  Loader2,
  Trash2,
  Database,
  Search,
  Package,
  Globe,
  Server,
  Bug,
  UserX,
  Shield,
  X,
} from "lucide-react";
import { cn } from "../../lib/utils";
import {
  checkIngestStatus,
  ingestText,
  ingestFile,
  type IngestResponse,
} from "../../lib/api";

/** Props — onInvestigate allows clicking an extracted entity to investigate it */
interface IngestPanelProps {
  onInvestigate?: (entity: string, type: string) => void;
}

/** Icon lookup for entity types in the results table */
const TYPE_ICONS: Record<string, typeof Package> = {
  Package: Package,
  IP: Server,
  Domain: Globe,
  CVE: Bug,
  ThreatActor: UserX,
  Technique: Shield,
};

/** Color classes for entity type badges */
const TYPE_COLORS: Record<string, string> = {
  Package: "bg-blue-500/15 text-blue-400 border-blue-500/25",
  IP: "bg-orange-500/15 text-orange-400 border-orange-500/25",
  Domain: "bg-purple-500/15 text-purple-400 border-purple-500/25",
  CVE: "bg-red-500/15 text-red-400 border-red-500/25",
  ThreatActor: "bg-pink-500/15 text-pink-400 border-pink-500/25",
  Technique: "bg-rose-500/15 text-rose-400 border-rose-500/25",
};

/** Confidence level badge styling */
const CONFIDENCE_COLORS: Record<string, string> = {
  high: "text-green-400",
  medium: "text-yellow-400",
  low: "text-red-400",
};

export function IngestPanel({ onInvestigate }: IngestPanelProps) {
  /* ── State ────────────────────────────────────────────────────────── */

  // Pipeline readiness — checked on mount
  const [pipelineReady, setPipelineReady] = useState<boolean | null>(null);

  // Input mode: user can paste text or upload a file
  const [mode, setMode] = useState<"text" | "file">("text");

  // Text input state
  const [text, setText] = useState("");

  // File input state
  const [selectedFile, setSelectedFile] = useState<File | null>(null);

  // Whether to auto-write extracted entities to the graph
  const [writeToGraph, setWriteToGraph] = useState(true);

  // Processing state
  const [processing, setProcessing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Results from the ingest pipeline
  const [result, setResult] = useState<IngestResponse | null>(null);

  // Drag state for the file drop zone
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  /* ── Check pipeline readiness on mount ────────────────────────────── */
  useEffect(() => {
    checkIngestStatus()
      .then((status) => setPipelineReady(status.ready))
      .catch(() => setPipelineReady(false));
  }, []);

  /* ── File drag-and-drop handlers ──────────────────────────────────── */
  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOver(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOver(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      setSelectedFile(file);
      setMode("file");
      setResult(null);
      setError(null);
    }
  }, []);

  const handleFileSelect = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) {
        setSelectedFile(file);
        setMode("file");
        setResult(null);
        setError(null);
      }
    },
    []
  );

  /* ── Submit handler — routes to text or file ingest ───────────────── */
  const handleSubmit = useCallback(async () => {
    setProcessing(true);
    setError(null);
    setResult(null);

    try {
      let response: IngestResponse;

      if (mode === "file" && selectedFile) {
        // File ingestion — uses RocketRide's webhook → parse → OCR pipeline
        response = await ingestFile(selectedFile, writeToGraph);
      } else if (mode === "text" && text.trim()) {
        // Text ingestion — sends raw text through extract_data → LLM
        response = await ingestText(text.trim(), writeToGraph);
      } else {
        throw new Error("No content to ingest");
      }

      setResult(response);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ingestion failed");
    } finally {
      setProcessing(false);
    }
  }, [mode, selectedFile, text, writeToGraph]);

  /* ── Clear / reset ────────────────────────────────────────────────── */
  const handleClear = useCallback(() => {
    setText("");
    setSelectedFile(null);
    setResult(null);
    setError(null);
  }, []);

  /* ── Map entity type string to investigation EntityType ───────────── */
  const mapToEntityType = (type: string): string | null => {
    const mapping: Record<string, string> = {
      Package: "package",
      IP: "ip",
      Domain: "domain",
      CVE: "cve",
      ThreatActor: "threatactor",
    };
    return mapping[type] || null;
  };

  /* ── Render ───────────────────────────────────────────────────────── */
  return (
    <div className="h-full flex flex-col bg-background">
      {/* Header bar */}
      <div className="flex items-center gap-2 px-4 py-3 border-b border-border">
        <Upload className="h-4 w-4 text-primary" />
        <h2 className="text-sm font-semibold text-foreground">
          Threat Intel Ingestion
        </h2>

        {/* Pipeline status indicator */}
        <div className="ml-auto flex items-center gap-1.5">
          {pipelineReady === null ? (
            <Loader2 className="h-3 w-3 animate-spin text-muted-foreground" />
          ) : pipelineReady ? (
            <>
              <span className="h-2 w-2 rounded-full bg-green-500 animate-pulse" />
              <span className="text-[10px] text-muted-foreground">
                Pipeline Ready
              </span>
            </>
          ) : (
            <>
              <span className="h-2 w-2 rounded-full bg-red-500" />
              <span className="text-[10px] text-muted-foreground">
                Pipeline Offline
              </span>
            </>
          )}
        </div>
      </div>

      {/* Mode toggle — Text vs File */}
      <div className="flex gap-1 px-4 pt-3 pb-2">
        <button
          onClick={() => {
            setMode("text");
            setResult(null);
            setError(null);
          }}
          className={cn(
            "flex-1 flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all",
            mode === "text"
              ? "bg-primary/15 text-primary border border-primary/30"
              : "text-muted-foreground hover:text-foreground hover:bg-surface-raised/60"
          )}
        >
          <FileText className="h-3.5 w-3.5" />
          Paste Text
        </button>
        <button
          onClick={() => {
            setMode("file");
            setResult(null);
            setError(null);
          }}
          className={cn(
            "flex-1 flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all",
            mode === "file"
              ? "bg-primary/15 text-primary border border-primary/30"
              : "text-muted-foreground hover:text-foreground hover:bg-surface-raised/60"
          )}
        >
          <Upload className="h-3.5 w-3.5" />
          Upload File
        </button>
      </div>

      {/* Input area — scrollable */}
      <div className="flex-1 overflow-y-auto px-4 pb-4">
        {mode === "text" ? (
          /* ── Text input mode ──────────────────────────────────────── */
          <div className="space-y-3">
            <textarea
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder={
                "Paste threat report text, IOC list, or vulnerability advisory here...\n\n" +
                "Example:\n" +
                "CVE-2021-44228 (Log4Shell) affects Apache Log4j 2.x.\n" +
                "Threat actor APT29 has been observed exploiting this vulnerability\n" +
                "via IP 45.77.65.211 to deploy backdoors on targets using\n" +
                "the ua-parser-js npm package as an initial vector."
              }
              className={cn(
                "w-full h-48 px-3 py-2 rounded-lg text-sm font-mono",
                "bg-surface border border-border",
                "text-foreground placeholder:text-muted-foreground/50",
                "focus:outline-none focus:ring-1 focus:ring-primary/50",
                "resize-none"
              )}
              disabled={processing}
            />
            <div className="flex items-center justify-between text-[10px] text-muted-foreground">
              <span>{text.length} characters</span>
              {text.length > 0 && (
                <button
                  onClick={() => setText("")}
                  className="flex items-center gap-1 hover:text-foreground transition-colors"
                >
                  <X className="h-3 w-3" />
                  Clear
                </button>
              )}
            </div>
          </div>
        ) : (
          /* ── File upload mode (drag-and-drop zone) ────────────────── */
          <div
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={cn(
              "h-48 rounded-lg border-2 border-dashed cursor-pointer",
              "flex flex-col items-center justify-center gap-3",
              "transition-all duration-200",
              dragOver
                ? "border-primary bg-primary/5 scale-[1.02]"
                : selectedFile
                  ? "border-success/40 bg-success/5"
                  : "border-border hover:border-primary/40 hover:bg-surface"
            )}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".pdf,.txt,.png,.jpg,.jpeg,.gif,.doc,.docx,.csv,.json"
              onChange={handleFileSelect}
              className="hidden"
            />
            {selectedFile ? (
              <>
                <CheckCircle2 className="h-8 w-8 text-success" />
                <div className="text-center">
                  <p className="text-sm font-medium text-foreground">
                    {selectedFile.name}
                  </p>
                  <p className="text-[10px] text-muted-foreground">
                    {(selectedFile.size / 1024).toFixed(1)} KB •{" "}
                    {selectedFile.type || "unknown type"}
                  </p>
                </div>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    setSelectedFile(null);
                  }}
                  className="text-[10px] text-muted-foreground hover:text-red-400 flex items-center gap-1"
                >
                  <Trash2 className="h-3 w-3" />
                  Remove
                </button>
              </>
            ) : (
              <>
                <Upload
                  className={cn(
                    "h-8 w-8",
                    dragOver ? "text-primary" : "text-muted-foreground"
                  )}
                />
                <div className="text-center">
                  <p className="text-sm text-muted-foreground">
                    Drop a file here or{" "}
                    <span className="text-primary">browse</span>
                  </p>
                  <p className="text-[10px] text-muted-foreground/60 mt-1">
                    PDF, images, text files • Max 10MB
                  </p>
                </div>
              </>
            )}
          </div>
        )}

        {/* Write to Graph toggle */}
        <div className="flex items-center gap-2 mt-3">
          <button
            onClick={() => setWriteToGraph(!writeToGraph)}
            className={cn(
              "relative inline-flex h-5 w-9 items-center rounded-full transition-colors",
              writeToGraph ? "bg-primary/60" : "bg-muted"
            )}
          >
            <span
              className={cn(
                "inline-block h-3.5 w-3.5 rounded-full bg-white transition-transform",
                writeToGraph ? "translate-x-[18px]" : "translate-x-[3px]"
              )}
            />
          </button>
          <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <Database className="h-3 w-3" />
            Write extracted entities to graph
          </span>
        </div>

        {/* Submit button */}
        <button
          onClick={handleSubmit}
          disabled={
            processing ||
            pipelineReady === false ||
            (mode === "text" ? !text.trim() : !selectedFile)
          }
          className={cn(
            "w-full mt-3 py-2 rounded-lg text-sm font-medium",
            "flex items-center justify-center gap-2",
            "transition-all duration-200",
            processing || pipelineReady === false
              ? "bg-muted text-muted-foreground cursor-not-allowed"
              : "bg-primary/15 text-primary border border-primary/30 hover:bg-primary/25 active:scale-[0.98]"
          )}
        >
          {processing ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" />
              Extracting entities…
            </>
          ) : (
            <>
              <Search className="h-4 w-4" />
              Extract Entities
            </>
          )}
        </button>

        {/* Pipeline info note */}
        {processing && (
          <div className="mt-2 px-3 py-2 rounded-lg bg-surface border border-border">
            <p className="text-[10px] text-muted-foreground leading-relaxed">
              <span className="text-primary font-medium">RocketRide Pipeline:</span>{" "}
              {mode === "file"
                ? "webhook → parse → OCR → extract_data → LLM (Haiku) → entities"
                : "extract_data → LLM (Haiku) → entities"}
            </p>
          </div>
        )}

        {/* Error display */}
        {error && (
          <div className="mt-3 px-3 py-2 rounded-lg bg-red-500/10 border border-red-500/25">
            <div className="flex items-start gap-2">
              <AlertCircle className="h-4 w-4 text-red-400 mt-0.5 flex-shrink-0" />
              <p className="text-xs text-red-400">{error}</p>
            </div>
          </div>
        )}

        {/* ── Results table ────────────────────────────────────────── */}
        {result && (
          <div className="mt-4 space-y-3">
            {/* Summary bar */}
            <div className="flex items-center gap-3 px-3 py-2 rounded-lg bg-surface border border-border">
              <CheckCircle2 className="h-4 w-4 text-success flex-shrink-0" />
              <div className="flex-1">
                <p className="text-xs text-foreground font-medium">
                  {result.entities_found} entities extracted
                </p>
                <p className="text-[10px] text-muted-foreground">
                  {result.written_to_graph} written to graph •{" "}
                  {result.pipeline}
                </p>
              </div>
            </div>

            {/* Entity table */}
            {result.entities.length > 0 && (
              <div className="rounded-lg border border-border overflow-hidden">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="bg-surface-raised/60 border-b border-border">
                      <th className="px-3 py-2 text-left text-muted-foreground font-medium">
                        Type
                      </th>
                      <th className="px-3 py-2 text-left text-muted-foreground font-medium">
                        Value
                      </th>
                      <th className="px-3 py-2 text-left text-muted-foreground font-medium">
                        Confidence
                      </th>
                      <th className="px-3 py-2 text-right text-muted-foreground font-medium">
                        Action
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.entities.map((entity, i) => {
                      const TypeIcon = TYPE_ICONS[entity.type] || Shield;
                      const colorClass =
                        TYPE_COLORS[entity.type] ||
                        "bg-muted text-muted-foreground border-border";
                      const canInvestigate =
                        onInvestigate && mapToEntityType(entity.type);

                      return (
                        <tr
                          key={`${entity.type}-${entity.value}-${i}`}
                          className="border-b border-border/50 last:border-0 hover:bg-surface/60 transition-colors"
                        >
                          {/* Type badge */}
                          <td className="px-3 py-2">
                            <span
                              className={cn(
                                "inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium border",
                                colorClass
                              )}
                            >
                              <TypeIcon className="h-3 w-3" />
                              {entity.type}
                            </span>
                          </td>

                          {/* Entity value */}
                          <td className="px-3 py-2">
                            <span className="font-mono text-foreground">
                              {entity.value}
                            </span>
                            {entity.context && (
                              <p className="text-[10px] text-muted-foreground mt-0.5 line-clamp-1">
                                {entity.context}
                              </p>
                            )}
                          </td>

                          {/* Confidence level */}
                          <td className="px-3 py-2">
                            <span
                              className={cn(
                                "text-[10px] font-medium uppercase",
                                CONFIDENCE_COLORS[
                                  entity.confidence || "medium"
                                ] || "text-muted-foreground"
                              )}
                            >
                              {entity.confidence || "—"}
                            </span>
                          </td>

                          {/* Investigate button */}
                          <td className="px-3 py-2 text-right">
                            {canInvestigate && (
                              <button
                                onClick={() =>
                                  onInvestigate(
                                    entity.value,
                                    mapToEntityType(entity.type)!
                                  )
                                }
                                className="text-[10px] text-primary hover:text-primary-foreground hover:bg-primary/20 px-2 py-0.5 rounded transition-colors"
                              >
                                Investigate →
                              </button>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}

            {/* Clear results */}
            <button
              onClick={handleClear}
              className="w-full py-1.5 text-[10px] text-muted-foreground hover:text-foreground transition-colors"
            >
              Clear results
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
