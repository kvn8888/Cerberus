/**
 * components/report/ThreatReportPdf.tsx — PDF report using @react-pdf/renderer
 *
 * Generates a professional Cerberus Threat Report as a real PDF document.
 * Uses @react-pdf/renderer to build the PDF from React components —
 * no DOM hacking, no popups, no print dialogs. The PDF is generated
 * as a blob and downloaded directly.
 *
 * Usage:
 *   const blob = await pdf(<ThreatReportPdf report={data} />).toBlob();
 *   // trigger download with the blob
 */
import {
  Document,
  Page,
  Text,
  View,
  StyleSheet,
} from "@react-pdf/renderer";
import type { ReportResponse } from "../../types/api";

// ── Color palette matching the Cerberus dark UI ─────────────
const colors = {
  bg: "#0f172a",          // slate-900 — page background
  cardBg: "#1e293b",      // slate-800 — card/section background
  border: "#334155",      // slate-700 — borders
  text: "#e2e8f0",        // slate-200 — primary text
  muted: "#94a3b8",       // slate-400 — secondary text
  accent: "#38bdf8",      // sky-400  — accent/brand color
  success: "#4ade80",     // green-400 — cache hit badge
  warning: "#fbbf24",     // amber-400 — fraud signals
  headerBg: "#020617",    // slate-950 — header bar
};

const tlpColors: Record<string, { bg: string; text: string }> = {
  clear: { bg: "#dbeafe", text: "#1e3a8a" },
  green: { bg: "#dcfce7", text: "#166534" },
  amber: { bg: "#fef3c7", text: "#92400e" },
  "amber+strict": { bg: "#fde68a", text: "#78350f" },
  red: { bg: "#fee2e2", text: "#991b1b" },
};

// ── PDF stylesheet ──────────────────────────────────────────
const styles = StyleSheet.create({
  // Page-level layout: dark background, consistent padding
  page: {
    backgroundColor: colors.bg,
    padding: 40,
    fontFamily: "Helvetica",
    color: colors.text,
    fontSize: 10,
  },

  // ── Header section (title + metadata) ─────────────────
  header: {
    backgroundColor: colors.headerBg,
    borderRadius: 8,
    padding: 20,
    marginBottom: 20,
    borderBottom: `2px solid ${colors.accent}`,
  },
  title: {
    fontSize: 22,
    fontFamily: "Helvetica-Bold",
    color: colors.accent,
    marginBottom: 4,
  },
  subtitle: {
    fontSize: 9,
    color: colors.muted,
    letterSpacing: 2,
    textTransform: "uppercase" as const,
  },
  tlpBanner: {
    marginTop: 12,
    borderRadius: 6,
    paddingHorizontal: 10,
    paddingVertical: 6,
    alignSelf: "flex-start" as const,
  },
  tlpBannerText: {
    fontSize: 9,
    fontFamily: "Helvetica-Bold",
    letterSpacing: 1,
  },

  // ── Metadata row (entity, type, timestamp) ────────────
  metaRow: {
    flexDirection: "row" as const,
    justifyContent: "space-between" as const,
    marginTop: 12,
    gap: 8,
  },
  metaItem: {
    flex: 1,
  },
  metaLabel: {
    fontSize: 8,
    color: colors.muted,
    textTransform: "uppercase" as const,
    letterSpacing: 1,
    marginBottom: 2,
  },
  metaValue: {
    fontSize: 11,
    fontFamily: "Helvetica-Bold",
    color: colors.text,
  },

  // ── Badge row (paths, cache, fraud signals) ───────────
  badgeRow: {
    flexDirection: "row" as const,
    gap: 8,
    marginBottom: 20,
  },
  badge: {
    paddingHorizontal: 10,
    paddingVertical: 4,
    borderRadius: 12,
    fontSize: 9,
    fontFamily: "Helvetica-Bold",
  },

  // ── Content cards (narrative, cross-domain, etc.) ─────
  card: {
    backgroundColor: colors.cardBg,
    borderRadius: 8,
    padding: 16,
    marginBottom: 16,
    border: `1px solid ${colors.border}`,
  },
  cardTitle: {
    fontSize: 13,
    fontFamily: "Helvetica-Bold",
    color: colors.accent,
    marginBottom: 10,
    paddingBottom: 6,
    borderBottom: `1px solid ${colors.border}`,
  },
  bodyText: {
    fontSize: 10,
    lineHeight: 1.6,
    color: colors.text,
  },

  // ── Table styles for cross-domain connections ─────────
  table: {
    marginTop: 4,
  },
  tableHeader: {
    flexDirection: "row" as const,
    backgroundColor: colors.headerBg,
    borderRadius: 4,
    paddingVertical: 6,
    paddingHorizontal: 8,
    marginBottom: 2,
  },
  tableHeaderCell: {
    fontSize: 8,
    fontFamily: "Helvetica-Bold",
    color: colors.accent,
    textTransform: "uppercase" as const,
    letterSpacing: 1,
  },
  tableRow: {
    flexDirection: "row" as const,
    paddingVertical: 5,
    paddingHorizontal: 8,
    borderBottom: `1px solid ${colors.border}`,
  },
  tableCell: {
    fontSize: 9,
    color: colors.text,
  },
  tableCellMuted: {
    fontSize: 9,
    color: colors.muted,
  },

  // ── Footer ────────────────────────────────────────────
  footer: {
    position: "absolute" as const,
    bottom: 20,
    left: 40,
    right: 40,
    flexDirection: "row" as const,
    justifyContent: "space-between" as const,
    borderTop: `1px solid ${colors.border}`,
    paddingTop: 8,
  },
  footerText: {
    fontSize: 7,
    color: colors.muted,
  },
});

// ── Props ───────────────────────────────────────────────────
interface ThreatReportPdfProps {
  report: ReportResponse;
}

/**
 * ThreatReportPdf — The full PDF document component.
 *
 * @react-pdf/renderer compiles this into a real PDF with vector text,
 * proper pagination, and small file size. No screenshots or canvas.
 */
export function ThreatReportPdf({ report }: ThreatReportPdfProps) {
  // Format the generation timestamp for display
  const generatedDate = new Date(report.generated_at).toLocaleString();
  const tlp = report.tlp || "amber";
  const tlpStyle = tlpColors[tlp] || tlpColors.amber;
  const tlpLabel = tlp === "amber+strict" ? "TLP:AMBER+STRICT" : `TLP:${tlp.toUpperCase()}`;

  return (
    <Document>
      <Page size="A4" style={styles.page}>
        {/* ── Report Header ──────────────────────────────── */}
        <View style={styles.header}>
          <Text style={styles.title}>Cerberus Threat Report</Text>
          <Text style={styles.subtitle}>
            Cross-Domain Threat Intelligence Analysis
          </Text>
          <View style={[styles.tlpBanner, { backgroundColor: tlpStyle.bg }]}> 
            <Text style={[styles.tlpBannerText, { color: tlpStyle.text }]}>{tlpLabel}</Text>
          </View>

          {/* Entity metadata row */}
          <View style={styles.metaRow}>
            <View style={styles.metaItem}>
              <Text style={styles.metaLabel}>Entity</Text>
              <Text style={styles.metaValue}>{report.entity}</Text>
            </View>
            <View style={styles.metaItem}>
              <Text style={styles.metaLabel}>Type</Text>
              <Text style={styles.metaValue}>{report.entity_type}</Text>
            </View>
            <View style={styles.metaItem}>
              <Text style={styles.metaLabel}>Generated</Text>
              <Text style={styles.metaValue}>{generatedDate}</Text>
            </View>
          </View>
        </View>

        {/* ── Status Badges ──────────────────────────────── */}
        <View style={styles.badgeRow}>
          <Text
            style={[
              styles.badge,
              {
                backgroundColor: `${colors.accent}22`,
                color: colors.accent,
              },
            ]}
          >
            Paths Found: {report.paths_found}
          </Text>
          <Text
            style={[
              styles.badge,
              {
                backgroundColor: report.from_cache
                  ? `${colors.success}22`
                  : `${colors.border}`,
                color: report.from_cache ? colors.success : colors.muted,
              },
            ]}
          >
            Cache: {report.from_cache ? "HIT" : "MISS"}
          </Text>
          <Text
            style={[
              styles.badge,
              {
                backgroundColor: `${colors.warning}22`,
                color: colors.warning,
              },
            ]}
          >
            Fraud Signals: {report.juspay_summary.signals}
          </Text>
        </View>

        {/* ── Summary Card ───────────────────────────────── */}
        <View style={styles.card}>
          <Text style={styles.cardTitle}>Executive Summary</Text>
          <Text style={styles.bodyText}>{report.summary}</Text>
        </View>

        {/* ── Narrative Card ─────────────────────────────── */}
        <View style={styles.card}>
          <Text style={styles.cardTitle}>Threat Narrative</Text>
          <Text style={styles.bodyText}>
            {report.narrative || "No cached narrative available yet."}
          </Text>
        </View>

        {/* ── Cross-Domain Connections Table ──────────────── */}
        <View style={styles.card} wrap={true}>
          <Text style={styles.cardTitle}>Cross-Domain Connections</Text>

          {report.cross_domain.length === 0 ? (
            <Text style={styles.tableCellMuted}>
              No cross-domain connections found.
            </Text>
          ) : (
            <View style={styles.table}>
              {/* Table header */}
              <View style={styles.tableHeader}>
                <Text style={[styles.tableHeaderCell, { flex: 1 }]}>
                  Fields
                </Text>
                <Text style={[styles.tableHeaderCell, { flex: 2 }]}>
                  Values
                </Text>
              </View>

              {/* Table rows — one per cross-domain connection */}
              {report.cross_domain.map(
                (row: Record<string, unknown>, idx: number) => (
                  <View key={idx} style={styles.tableRow} wrap={false}>
                    <Text style={[styles.tableCellMuted, { flex: 1 }]}>
                      {Object.keys(row).join(", ")}
                    </Text>
                    <Text style={[styles.tableCell, { flex: 2 }]}>
                      {Object.values(row)
                        .map((v) =>
                          Array.isArray(v) ? v.join(", ") : String(v ?? "")
                        )
                        .join(" | ")}
                    </Text>
                  </View>
                )
              )}
            </View>
          )}
        </View>

        {/* ── Juspay Fraud Summary ───────────────────────── */}
        <View style={styles.card}>
          <Text style={styles.cardTitle}>Fraud Intelligence (Juspay)</Text>
          <View style={styles.metaRow}>
            <View style={styles.metaItem}>
              <Text style={styles.metaLabel}>Signals</Text>
              <Text style={styles.metaValue}>
                {report.juspay_summary.signals}
              </Text>
            </View>
            <View style={styles.metaItem}>
              <Text style={styles.metaLabel}>Linked IPs</Text>
              <Text style={styles.metaValue}>
                {report.juspay_summary.linked_ips}
              </Text>
            </View>
            <View style={styles.metaItem}>
              <Text style={styles.metaLabel}>Total Amount</Text>
              <Text style={styles.metaValue}>
                ${report.juspay_summary.total_amount.toLocaleString()}
              </Text>
            </View>
          </View>
        </View>

        {/* ── Footer ─────────────────────────────────────── */}
        <View style={styles.footer} fixed>
          <Text style={styles.footerText}>
            Cerberus Threat Intelligence Platform
          </Text>
          <Text style={styles.footerText}>
            Generated {generatedDate} • CONFIDENTIAL
          </Text>
        </View>
      </Page>
    </Document>
  );
}
