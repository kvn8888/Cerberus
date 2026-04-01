/**
 * Build an ordered attack-path walk from the investigation root through the graph.
 *
 * Uses iterative DFS so each step follows a continuous chain (parent → child →
 * grandchild …) instead of BFS's level-by-level order which visually jumps
 * between unrelated parts of the graph.
 */
import type { GraphLink, GraphNode } from "../types/api";

/** Extract the two endpoint IDs from a link, handling both raw IDs and
 *  d3-force's object-reference format where source/target are nodes. */
function linkEndpoints(link: GraphLink & { source?: unknown; target?: unknown }): [string, string] {
  const s = typeof link.source === "object" && link.source && "id" in link.source
    ? String((link.source as { id: string }).id)
    : String(link.source);
  const t = typeof link.target === "object" && link.target && "id" in link.target
    ? String((link.target as { id: string }).id)
    : String(link.target);
  return [s, t];
}

/**
 * Walk the graph from `rootEntity` using DFS.  The returned array contains
 * node IDs in the order they would be visited by following one chain as far
 * as possible before backtracking — so consecutive IDs are always neighbors
 * in the graph.
 */
export function buildAttackPathOrder(
  nodes: GraphNode[],
  links: Array<GraphLink & { source?: unknown; target?: unknown }>,
  rootEntity: string
): string[] {
  if (!nodes.length) return [];

  /* Identify the root node — prefer exact id match, fallback to label,
     then fall back to the highest-value (most connected) node. */
  const root =
    nodes.find((n) => n.id === rootEntity || n.label === rootEntity) ||
    nodes.reduce((a, b) => ((a.val ?? 0) >= (b.val ?? 0) ? a : b));

  /* Build undirected adjacency list */
  const adj = new Map<string, Set<string>>();
  for (const l of links) {
    const [a, b] = linkEndpoints(l);
    if (!adj.has(a)) adj.set(a, new Set());
    if (!adj.has(b)) adj.set(b, new Set());
    adj.get(a)!.add(b);
    adj.get(b)!.add(a);
  }

  /* Iterative DFS — produces a path-like ordering where each consecutive
     pair of nodes shares an edge in the graph. */
  const visited = new Set<string>();
  const order: string[] = [];
  const stack: string[] = [root.id];

  while (stack.length) {
    const u = stack.pop()!;
    if (visited.has(u)) continue;
    visited.add(u);
    order.push(u);

    /* Push neighbors in reverse so the first neighbor is processed next
       (stack is LIFO). */
    const neighbors = Array.from(adj.get(u) || []);
    for (let i = neighbors.length - 1; i >= 0; i--) {
      if (!visited.has(neighbors[i])) {
        stack.push(neighbors[i]);
      }
    }
  }

  /* Append any disconnected nodes not reached by DFS */
  for (const n of nodes) {
    if (!visited.has(n.id)) order.push(n.id);
  }
  return order;
}
