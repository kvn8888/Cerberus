/**
 * Build an ordered attack-path walk from the investigation root through the graph (BFS).
 */
import type { GraphLink, GraphNode } from "../types/api";

function linkEndpoints(link: GraphLink & { source?: unknown; target?: unknown }): [string, string] {
  const s = typeof link.source === "object" && link.source && "id" in link.source
    ? String((link.source as { id: string }).id)
    : String(link.source);
  const t = typeof link.target === "object" && link.target && "id" in link.target
    ? String((link.target as { id: string }).id)
    : String(link.target);
  return [s, t];
}

export function buildAttackPathOrder(
  nodes: GraphNode[],
  links: Array<GraphLink & { source?: unknown; target?: unknown }>,
  rootEntity: string
): string[] {
  if (!nodes.length) return [];
  const root =
    nodes.find((n) => n.id === rootEntity || n.label === rootEntity) ||
    nodes.reduce((a, b) => ((a.val ?? 0) >= (b.val ?? 0) ? a : b));
  const adj = new Map<string, Set<string>>();
  for (const l of links) {
    const [a, b] = linkEndpoints(l);
    if (!adj.has(a)) adj.set(a, new Set());
    if (!adj.has(b)) adj.set(b, new Set());
    adj.get(a)!.add(b);
    adj.get(b)!.add(a);
  }
  const visited = new Set<string>();
  const order: string[] = [];
  const q: string[] = [];
  q.push(root.id);
  visited.add(root.id);
  while (q.length) {
    const u = q.shift()!;
    order.push(u);
    for (const v of adj.get(u) || []) {
      if (!visited.has(v)) {
        visited.add(v);
        q.push(v);
      }
    }
  }
  for (const n of nodes) {
    if (!visited.has(n.id)) order.push(n.id);
  }
  return order;
}
