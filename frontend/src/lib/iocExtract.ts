/**
 * Extract IOCs from graph nodes and narrative text for analyst copy/export.
 */
import type { GraphNode, GraphResponse } from "../types/api";

export type IocType = "ip" | "domain" | "cve" | "package" | "hash" | "other";

export interface IocRow {
  type: IocType;
  value: string;
  source: "graph" | "narrative";
}

const IPV4 = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
const CVE = /\bCVE-\d{4}-\d{4,7}\b/gi;
const DOMAIN =
  /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g;
const HASH = /\b[a-fA-F0-9]{32,64}\b/g;

function typeFromGraphNode(n: GraphNode): IocType | null {
  const t = (n.type || "").toLowerCase();
  if (t === "ip") return "ip";
  if (t === "domain") return "domain";
  if (t === "cve") return "cve";
  if (t === "package") return "package";
  if (t === "threatactor" || t === "technique" || t === "account" || t === "fraudsignal")
    return "other";
  return null;
}

function pushUnique(rows: IocRow[], type: IocType, value: string, source: IocRow["source"]) {
  const v = value.trim();
  if (!v || v.length > 512) return;
  if (rows.some((r) => r.value === v && r.type === type)) return;
  rows.push({ type, value: v, source });
}

export function extractIOCsFromGraph(graph: GraphResponse | undefined): IocRow[] {
  if (!graph?.nodes?.length) return [];
  const rows: IocRow[] = [];
  for (const n of graph.nodes) {
    const label = String(n.label || n.id || "");
    const t = typeFromGraphNode(n);
    if (t && t !== "other") pushUnique(rows, t, label, "graph");
    else if (n.type === "ThreatActor" || n.type === "threatactor")
      pushUnique(rows, "other", label, "graph");
  }
  return rows;
}

export function extractIOCsFromNarrative(text: string): IocRow[] {
  if (!text) return [];
  const rows: IocRow[] = [];
  let m: RegExpExecArray | null;
  /* Must use 'g' flag so exec() advances lastIndex on each match —
     without it, exec() returns the same first match forever (infinite loop). */
  const ipRe = new RegExp(IPV4.source, "g");
  while ((m = ipRe.exec(text)) !== null) pushUnique(rows, "ip", m[0], "narrative");
  const cveRe = new RegExp(CVE.source, "gi");
  while ((m = cveRe.exec(text)) !== null) pushUnique(rows, "cve", m[0].toUpperCase(), "narrative");
  const hashRe = new RegExp(HASH.source, "g");
  while ((m = hashRe.exec(text)) !== null) pushUnique(rows, "hash", m[0], "narrative");
  const domRe = new RegExp(DOMAIN.source, "g");
  while ((m = domRe.exec(text)) !== null) {
    const d = m[0];
    if (/^localhost$/i.test(d) || d.length < 4) continue;
    pushUnique(rows, "domain", d, "narrative");
  }
  return rows;
}

export function mergeIOCs(
  graph: GraphResponse | undefined,
  narrative: string
): IocRow[] {
  const g = extractIOCsFromGraph(graph);
  const n = extractIOCsFromNarrative(narrative);
  const out: IocRow[] = [...g];
  for (const row of n) {
    if (!out.some((r) => r.value === row.value && r.type === row.type)) out.push(row);
  }
  return out.sort((a, b) => a.type.localeCompare(b.type) || a.value.localeCompare(b.value));
}

export function iocsToCsv(rows: IocRow[]): string {
  const header = "type,value,source";
  const lines = rows.map((r) => `${r.type},"${r.value.replace(/"/g, '""')}",${r.source}`);
  return [header, ...lines].join("\n");
}

export function defangValue(value: string, type?: IocType): string {
  let next = value.trim();
  if (!next) return next;

  next = next
    .replace(/^https:/i, "hxxps:")
    .replace(/^http:/i, "hxxp:")
    .replace(/^ftp:/i, "fxp:");

  if (type === "ip" || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(next)) {
    return next.replace(/\./g, "[.]");
  }

  if (type === "domain" || /[a-z0-9-]+\.[a-z]{2,}/i.test(next)) {
    return next.replace(/\./g, "[.]");
  }

  return next;
}

export function defangRows(rows: IocRow[]): IocRow[] {
  return rows.map((row) => ({
    ...row,
    value: defangValue(row.value, row.type),
  }));
}

export function defangText(text: string): string {
  return text
    .replace(/https:\/\//gi, "hxxps://")
    .replace(/http:\/\//gi, "hxxp://")
    .replace(IPV4, (match) => defangValue(match, "ip"))
    .replace(DOMAIN, (match) => defangValue(match, "domain"));
}
