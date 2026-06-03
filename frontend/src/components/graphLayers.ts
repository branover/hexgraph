// Shared vocab + state model for the Phase-5 layer panel, filter chip rail, and the
// complementary Table / Matrix views (design-graph-presentation §2.2 / §2.3 / §6).
//
// These are the ORTHOGONAL levers the design calls out: LAYERS show/hide whole
// CLASSES of element (node type, edge class); FILTERS subtract by VALUE (severity,
// target, finding-type) and are FADE-FIRST (dim before hide, so context isn't lost).
// Color (D8) is NEVER touched here — layers/filters change visibility/opacity only.

import { NODE_T, KIND } from "./GraphView";

export type GroupBy = "target" | "type" | "finding" | "none";

// ── Node-type layers (the full conceptual vocab + the three "kinds" of bytes target
//    that read as node fills, plus findings) ────────────────────────────────────────
// Each toggle shows/hides every element of that node type. The defaults preserve
// today's policy, generalized: symbol/string/param OFF by default; everything else ON.
// (function is special-cased by the skeleton/expand logic in GraphView, kept ON here.)
export const NODE_TYPE_LAYERS: { key: string; label: string }[] = [
  { key: "function", label: "function" },
  { key: "symbol", label: "symbol" },
  { key: "string", label: "string" },
  { key: "struct", label: "struct" },
  { key: "endpoint", label: "endpoint" },
  { key: "socket", label: "socket" },
  { key: "param", label: "param" },
  { key: "input", label: "input" },
  { key: "sink", label: "sink" },
  { key: "hypothesis", label: "hypothesis" },
  { key: "pattern", label: "pattern" },
  { key: "source_file", label: "source file" },
  { key: "harness", label: "harness" },
  { key: "finding", label: "finding" },
];
// source_file nodes are TRUSTED source we possess (often materialized in bulk when a tree is
// imported) — like symbol/string they're high-volume scaffolding, so they're OFF by default and
// the user opts them in via the layer panel (issue 4).
export const NODE_LAYER_DEFAULT_OFF = new Set(["symbol", "string", "param", "source_file"]);

// ── Edge-class layers (the single biggest density lever — edges are the dominant ink).
// Each class groups the real EDGE_C vocab; toggling a class hides every edge in it.
export const EDGE_CLASSES: { key: string; label: string; types: string[] }[] = [
  { key: "structural", label: "structural", types: ["contains", "located_in", "references", "links_against", "built_from", "about"] },
  { key: "call", label: "call graph", types: ["calls"] },
  { key: "semantic", label: "semantic / security", types: ["taints", "bypasses", "routes_to", "listens_on", "connects_to", "related_to", "instance_of_pattern", "similar_to"] },
  { key: "provenance", label: "provenance", types: ["produced_artifact", "instrumented_build_of", "fuzzed_by", "derived_from"] },
];
// type → edge-class lookup (for hiding/scoping by class). Anything unlisted → "semantic".
export const EDGE_TYPE_CLASS: Record<string, string> = (() => {
  const m: Record<string, string> = {};
  for (const c of EDGE_CLASSES) for (const t of c.types) m[t] = c.key;
  return m;
})();
export const edgeClassOf = (t: string): string => EDGE_TYPE_CLASS[t] || "semantic";

// Layer visibility state: which node types / edge classes are ON. Missing key ⇒ default.
export interface LayerState {
  nodes: Record<string, boolean>;   // node_type/kind/"finding" → visible
  edges: Record<string, boolean>;   // edge-class key → visible
}

export function defaultLayers(): LayerState {
  const nodes: Record<string, boolean> = {};
  for (const l of NODE_TYPE_LAYERS) nodes[l.key] = !NODE_LAYER_DEFAULT_OFF.has(l.key);
  const edges: Record<string, boolean> = {};
  for (const c of EDGE_CLASSES) edges[c.key] = true;
  return { nodes, edges };
}

export const nodeLayerOn = (layers: LayerState, key: string): boolean =>
  layers.nodes[key] !== false;
export const edgeClassOn = (layers: LayerState, type: string): boolean =>
  layers.edges[edgeClassOf(type)] !== false;

// ── Filter chip rail (value facets) — FADE-FIRST. A filtered-out element first fades
//    to context opacity; only a second explicit "hide" toggle fully removes it. So the
//    user never silently loses information (the no-loss constraint).
export interface FilterState {
  severity: string | null;            // minimum severity (info→critical), null = off
  targets: string[];                  // target-id multiselect; empty = all
  findingType: string | null;         // finding_type facet; null = off
  mode: "fade" | "hide";              // fade-first (default) vs hard hide
}
export function defaultFilters(): FilterState {
  return { severity: null, targets: [], findingType: null, mode: "fade" };
}
export const SEV_THRESHOLD = ["info", "low", "medium", "high", "critical"];
export const sevRank = (s: string): number => Math.max(0, SEV_THRESHOLD.indexOf(s));

export const anyFilterActive = (f: FilterState): boolean =>
  !!f.severity || f.targets.length > 0 || !!f.findingType;

// The color for a node-type legend swatch (shared by Table/Matrix). Findings are red.
export const nodeColor = (type: string, kind?: string, nodeType?: string): string => {
  if (type === "finding") return "#ff5d6c";
  if (type === "target") return KIND[kind || ""] || "#7d8799";
  return NODE_T[nodeType || ""] || "#7d8799";
};
