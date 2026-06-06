import { useEffect, useMemo, useRef, useState } from "react";
import cytoscape from "cytoscape";
import dagre from "cytoscape-dagre";
import edgehandles from "cytoscape-edgehandles";
import fcose from "cytoscape-fcose";
import { Graph } from "../api";
import { Icon } from "./Icon";
import {
  LayerState, FilterState, defaultLayers, defaultFilters,
  nodeLayerOn, edgeClassOn, sevRank, anyFilterActive,
  NODE_TYPE_LAYERS, EDGE_CLASSES, NODE_LAYER_DEFAULT_OFF,
} from "./graphLayers";

cytoscape.use(dagre);
cytoscape.use(edgehandles);
cytoscape.use(fcose);
// NOTE: cytoscape-expand-collapse was registered here in Phase 3 but never used — our
// expand/collapse is React-state-driven (the `expandedRooms` set re-derives the element
// list + scoped layout), not the extension's imperative collapse API. Phase 4 drops the
// dead dependency rather than retrofit a second, conflicting collapse model.

export const SEV: Record<string, string> = { info: "#7d8799", low: "#3fb950", medium: "#e3b341", high: "#f0883e", critical: "#ff5d6c" };
// Target-kind colors. (red is reserved for severity/findings — never a node fill.)
export const KIND: Record<string, string> = { firmware_image: "#a371f7", executable: "#6aa3ff", shared_library: "#39c5cf", web_app: "#2dd4bf", service: "#34d399", remote: "#f0883e", unknown: "#7d8799" };
// Sub-file/conceptual node colors — each visually distinct (no two near-identical hues).
export const NODE_T: Record<string, string> = {
  function: "#7ee787", symbol: "#d2a8ff", string: "#79c0ff", struct: "#ffa657",
  hypothesis: "#e3b341", pattern: "#bc8cff",
  input: "#58a6ff", sink: "#db6d28", socket: "#f778ba", endpoint: "#2dd4bf", param: "#a5d6ff",
  source_file: "#9ba3b4", harness: "#56d4dd",
};
// Per-node-type shape, so types are distinguishable independent of color (a redundant
// channel: color + shape, so types stay tellable apart when nodes shrink below
// hue-resolution and for low-contrast/colorblind viewers — color is never weakened).
// Phase-1 extension: every conceptual type is now shape-distinct.
export const NODE_SHAPE: Record<string, string> = {
  socket: "hexagon", endpoint: "tag", param: "ellipse", input: "triangle", sink: "vee",
  struct: "barrel", hypothesis: "pentagon", pattern: "diamond",
  string: "round-tag", symbol: "round-diamond",
  source_file: "round-rectangle", harness: "rhomboid",
};
export const EDGE_C: Record<string, string> = {
  contains: "#46506a", calls: "#6aa3ff", about: "#3b4458", related_to: "#f0883e",
  instance_of_pattern: "#f0883e", links_against: "#39c5cf", similar_to: "#8b5cf6",
  taints: "#ff7b72", bypasses: "#ff5d6c", listens_on: "#f778ba", connects_to: "#f0a0d0",
  routes_to: "#2dd4bf", references: "#46506a", derived_from: "#8b5cf6",
};
// Semantic edges whose type/attrs are the point — always labelled, not just on hover.
const ALWAYS_LABEL = new Set(["taints", "bypasses", "listens_on", "connects_to", "routes_to"]);
// Structural / scaffolding edges (the gray cobweb): recede hardest at rest so the colored
// semantic edges separate out. (containment, location, references, build provenance.)
const STRUCTURAL = new Set([
  "contains", "about", "references", "located_in", "built_from",
  "produced_artifact", "instrumented_build_of", "derived_from",
]);
// Semantic / security edges carry the finding — sit a touch stronger at rest.
const SEMANTIC = new Set([
  "calls", "taints", "bypasses", "routes_to", "listens_on", "connects_to",
  "links_against", "similar_to", "related_to", "instance_of_pattern", "fuzzed_by",
]);
const RESOLVED = new Set(["confirmed", "dismissed", "reported"]);
// Severity rank for the per-room rollup (worst finding inside a collapsed room).
const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const SEV_NAME = ["info", "low", "medium", "high", "critical"];
// Monochrome anchor glyphs (a third redundant channel, on the prominent anchors only) —
// simple geometric marks that render reliably as SVG text across browsers (no emoji).
const KIND_GLYPH: Record<string, string> = {
  firmware_image: "▣",   // ▣ chip
  executable: "▶",       // ▶ run/terminal
  shared_library: "⧉",   // ⧉ stacked (library)
  web_app: "⊕",          // ⊕ globe-ish
  service: "⇄",          // ⇄ socket/duplex
  remote: "↗",           // ↗ remote
};
// Render an anchor's glyph char as a small monochrome SVG data URI so Cytoscape can lay it
// on the node as a background-image (a color-independent channel on the prominent anchors).
function glyphDataUri(ch: string): string {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="40" height="40">`
    + `<text x="20" y="21" font-size="24" font-family="sans-serif" text-anchor="middle" `
    + `dominant-baseline="central" fill="#0a0c12">${ch}</text></svg>`;
  return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`;
}

// ── Phase 4: semantic-zoom (level-of-detail) thresholds ────────────────────────────────
// The headline Phase-4 fix: at the DEFAULT full-pane zoom of a LARGE/PATHOLOGICAL graph
// (~0.5–0.6) the room cards must be READABLE, and the interior clutter must stay hidden.
// A debounced zoom handler toggles a container LOD class; styles keyed on it switch detail.
//   FAR  (z < LOD_MID): islands only — readable room cards, no interior labels, no edge labels.
//   MID  (LOD_MID ≤ z < LOD_NEAR): structure — node shapes + hub/anchor labels, semantic-edge labels.
//   NEAR (z ≥ LOD_NEAR): full detail — every label, edge labels, attr hints (today's behaviour).
const LOD_MID = 0.5;
// NEAR was 1.35 — far too high: across the whole MID band (z≈0.5–1.35) leaf nodes are already
// large and clearly individuated (a single binary's call graph at z≈0.7–1.0) yet ALL their
// labels were suppressed, so a zoomed-in graph read as anonymous dots while only findings
// stayed labelled (issue 6). Drop NEAR so full per-node detail returns once nodes are
// resolvable; MID is now a narrow transitional band, not a label dead-zone.
const LOD_NEAR = 0.85;
// Above this many direct child rooms, a container (e.g. a firmware with hundreds of
// child binaries) does NOT auto-expand its children on open — it stays a single card so
// the default frame is a handful of countable rooms, never a grid of hundreds of cards.
// The user expands it explicitly to drill into the child-binary list. (Real firmware
// scale: ~250 children → collapsed; a 12-binary firmware → auto-expanded, as before.)
const ROOM_AUTO_EXPAND_CEILING = 40;
function lodClass(z: number): "lod-far" | "lod-mid" | "lod-near" {
  if (z < LOD_MID) return "lod-far";
  if (z < LOD_NEAR) return "lod-mid";
  return "lod-near";
}

// A committed focus: the anchor node + the hop radius of neighborhood it pulls into focus.
export interface FocusSpec { id: string; hop: number }
// Phase-3 grouping facet (how the canvas is organized into compound rooms).
export type GroupBy = "target" | "type" | "finding" | "none";

// Human label for a grouping room parent.
function typeLabel(t: string): string {
  if (t === "firmware_image") return "firmware";
  if (t === "shared_library") return "library";
  return t;
}

export default function GraphView({
  graph, onSelect, onEdgeSelect, onDrawEdge, selectedId, isolateType,
  focus, onFocus, onClearFocus,
  groupBy: groupByProp, onGroupBy, layers: layersProp, onLayers,
  filters: filtersProp, onFilters, findings: findingsProp, onFindings, scope,
  skeletonMode, onRoomExpand, roomLoading, mapMode, onRoomDrill,
}: {
  graph: Graph;
  onSelect: (id: string, type: string) => void;
  onEdgeSelect?: (edge: Graph["edges"][number] | null) => void;
  onDrawEdge?: (srcId: string, dstId: string) => void;
  selectedId?: string;
  isolateType?: string | null;
  // Phase 2 focus model: the committed focus (anchor + hop) is owned by the host (so it can
  // serialize to the URL + drive the breadcrumb). GraphView renders it onto the live cy
  // instance via .focus/.context classes + a scoped auto-frame, and reports focus intents up.
  focus?: FocusSpec | null;
  onFocus?: (id: string, hop?: number) => void;
  onClearFocus?: () => void;
  // ── Phase 5: layers / filters / grouping are CONTROLLED by the host (Workspace) so a
  // Saved Lens can capture + restore the full view state, and the Table/Matrix views share
  // the same facets. All optional: GraphView falls back to its own state when uncontrolled.
  groupBy?: GroupBy;
  onGroupBy?: (g: GroupBy) => void;
  layers?: LayerState;
  onLayers?: (l: LayerState) => void;
  filters?: FilterState;
  onFilters?: (f: FilterState) => void;
  findings?: "all" | "unresolved" | "none";
  onFindings?: (f: "all" | "unresolved" | "none") => void;
  // panels-drive-scope (§6.3): a target id the view is scoped to. When set, that target's
  // room is soloed/framed (others fade) — the side panels drive what the center shows.
  scope?: string | null;
  // ── Skeleton-first loading (real-firmware scale, ~13k nodes) ─────────────────────────
  // When `skeletonMode` is on, `graph` arrives as the SKELETON (rooms + sockets +
  // aggregated meta-edges, NO interiors); expanding a room asks the HOST to fetch that
  // room's interior (onRoomExpand) and merge it into `graph`. The browser thus never
  // receives ~13k nodes at once. `roomLoading` is the set of room target-ids whose
  // interior is currently being fetched (drives a "loading" affordance on the card).
  skeletonMode?: boolean;
  onRoomExpand?: (targetId: string) => void;
  roomLoading?: Set<string>;
  // ── Map view (§6.1 / issue 8): a genuinely DISTINCT collapsed-skeleton "territory" overview,
  // NOT the by-target Graph in disguise. When on: ALL rooms stay collapsed to finding-weighted
  // cards regardless of tier (the §1 skeleton, surfaced as its own view), intra-room detail is
  // never drawn, and structural meta-edges are dropped so only the cross-target SEMANTIC ribbons
  // + the socket bus remain — the firmware's territory at a glance.
  mapMode?: boolean;
  // In Map view, double-tapping a target card DRILLS into the scoped Graph for that binary
  // (design §6.1) instead of expanding its interior in place.
  onRoomDrill?: (targetId: string) => void;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core>();
  const ehRef = useRef<any>(null);
  const drawRef = useRef<(src: string, dst: string) => void>();
  const focusCbRef = useRef<((id: string, hop?: number) => void) | undefined>();
  const tapRef = useRef<{ id: string | null; t: number }>({ id: null, t: 0 });
  // Saved resting positions of nodes the focus model temporarily re-arranges, so clearing
  // focus restores the graph exactly (the rearrange is a live-instance, reversible nicety —
  // NOT a layout-engine change to the resting graph).
  const savedPos = useRef<Map<string, { x: number; y: number }>>(new Map());
  // true once the current cy's initial layout has settled — so the focus effect knows
  // whether to apply immediately or wait for layoutstop (positions must be final first).
  const layoutDone = useRef(false);
  // the live focus-applier, so the build effect's layoutstop can invoke the *current* one.
  const applyFocusRef = useRef<(() => void) | null>(null);
  // the room most recently expanded by an explicit user act — the build's layoutstop scopes
  // an auto-frame to it (design §3.4: auto-zoom only on an explicit navigation act).
  const justExpanded = useRef<string | null>(null);
  // set on an explicit COLLAPSE so the rebuild's layoutstop ANIMATES the re-fit (a glide back to
  // the skeleton) instead of snapping — the symmetric counterpart to justExpanded (issue 3).
  const justCollapsed = useRef<boolean>(false);
  // findings tri-state + layer/filter state are CONTROLLED when the host passes them
  // (Phase 5), else fall back to internal state so GraphView still works standalone.
  const [findingsLocal, setFindingsLocal] = useState<"all" | "unresolved" | "none">("all");
  const findings = findingsProp ?? findingsLocal;
  const setFindings = (f: "all" | "unresolved" | "none") => (onFindings ? onFindings(f) : setFindingsLocal(f));
  const [layersLocal, setLayersLocal] = useState<LayerState>(defaultLayers);
  const layers = layersProp ?? layersLocal;
  const setLayers = (l: LayerState) => (onLayers ? onLayers(l) : setLayersLocal(l));
  const [filtersLocal, setFiltersLocal] = useState<FilterState>(defaultFilters);
  const filters = filtersProp ?? filtersLocal;
  const setFilters = (f: FilterState) => (onFilters ? onFilters(f) : setFiltersLocal(f));
  // Phase-2 legacy double-tap collapse (flat-mode only — used when groupBy === "none").
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [filterOpen, setFilterOpen] = useState(false);
  const [layersOpen, setLayersOpen] = useState(false);
  const [drawMode, setDrawMode] = useState(false);
  // Phase-2 hop radius for new focuses launched from the verb menu / filter (1–3).
  const [hop, setHop] = useState(1);
  // Reversible hard-hide: nodes the user explicitly hid (right-click → Hide). Surfaced as a
  // restore chip; never a silent loss (design §4.1 — manuallyHidden + a "N hidden ↺" chip).
  const [hidden, setHidden] = useState<Set<string>>(new Set());
  // Dependency-free right-click verb menu (focus / expand-hops / hide / reveal). Cytoscape-
  // native cxttap drives it — no cytoscape-cxtmenu dependency (Phase 2 stays dep-free).
  const [menu, setMenu] = useState<{ x: number; y: number; id: string; type: string } | null>(null);

  // ── Phase 3: grouping facet + per-room expand/collapse state ──────────────────────────
  // "Group by" reorganizes the canvas into compound rooms; "none" = the flat Phase-1/2 graph
  // (the REGRESSION FALLBACK). The default is by-target. Tier detection drives whether rooms
  // open collapsed (skeleton) or expanded.
  const [groupByLocal, setGroupByLocal] = useState<GroupBy>("target");
  const groupBy = groupByProp ?? groupByLocal;
  const setGroupBy = (g: GroupBy) => (onGroupBy ? onGroupBy(g) : setGroupByLocal(g));
  // Which room ids are EXPANDED (revealing their interior). At LARGE/PATHOLOGICAL the
  // default is "no rooms expanded" (the skeleton); at SMALL/MEDIUM all rooms auto-expand.
  const [expandedRooms, setExpandedRooms] = useState<Set<string>>(new Set());
  // After a Group-by change or initial mount we (re)derive the auto-expand default once per
  // (groupBy, graph, tier) so the user's manual expand/collapse afterwards is respected.
  const autoKey = useRef<string>("");

  // keep the latest callbacks in refs so the cytoscape effect needn't re-run on them
  drawRef.current = onDrawEdge;
  focusCbRef.current = onFocus;
  // current committed focus, mirrored to a ref so the build effect's layoutstop can read it
  // without re-subscribing (it captures the ref, not a stale `focus`).
  const focusValRef = useRef<FocusSpec | null>(null);
  focusValRef.current = focus ?? null;

  // graph size tier (drives the default frame, design §1/D1). In skeletonMode the
  // payload is ALWAYS the firmware-scale skeleton → force "large" so it opens collapsed
  // to the rooms (never auto-expanding ~hundreds of interiors that aren't even loaded).
  const tier = useMemo(() => {
    if (skeletonMode) return "large" as const;
    const n = graph.nodes.length + graph.edges.length;
    if (n <= 40) return "small" as const;
    if (n <= 80) return "medium" as const;
    return "large" as const;
  }, [graph, skeletonMode]);

  // children map for the flat-mode collapse: contains (parent→child) + about (→ finding).
  const childrenOf = useMemo(() => {
    const m: Record<string, string[]> = {};
    for (const e of graph.edges) {
      if (e.type === "contains") (m[e.source] ??= []).push(e.target);
      else if (e.type === "about") (m[e.target] ??= []).push(e.source);
    }
    return m;
  }, [graph]);

  const descendants = (id: string): string[] => {
    const out: string[] = [], stack = [...(childrenOf[id] || [])];
    while (stack.length) { const c = stack.pop()!; out.push(c); for (const g of childrenOf[c] || []) stack.push(g); }
    return out;
  };

  // ── Phase 3: derive the compound model from the grouping facet ─────────────────────────
  // Returns, for the chosen grouping: a parent assignment (childId → roomId), the synthetic
  // ROOM parent nodes (with rollup metadata), the firmware grandparent (by-target), and which
  // ids are "loose" (no room — e.g. shared sockets → the network bus lane).
  const model = useMemo(() => {
    const byId = new Map(graph.nodes.map((n) => [n.id, n] as const));
    // map a finding to the node/target(s) it is `about` (for target-grouping placement: nest a
    // finding under the room of the FINEST node it concerns). `about` edges are emitted
    // src=finding → dst=node/target (engine/findings.py), so the finding is e.source. (Hypothesis
    // `about` edges go node→target — guard on the source being a finding so they don't pollute.)
    const findingAbout = new Map<string, string[]>(); // findingId → [nodeId/targetId]
    for (const e of graph.edges) {
      if (e.type === "about" && byId.get(e.source)?.type === "finding") {
        (findingAbout.get(e.source) ?? findingAbout.set(e.source, []).get(e.source)!).push(e.target);
      }
    }

    const parentOf = new Map<string, string>();   // childId → roomId
    // `skel` carries the backend skeleton's PRE-COMPUTED rollup (counts + worst severity)
    // for a room whose interior is NOT loaded — so a collapsed room card shows the right
    // `14 fn · 2⚠` chip even though the browser holds none of its interior nodes.
    const rooms: { id: string; label: string; tkey: string; gkind: "target" | "type" | "finding"; kind?: string;
                   skel?: { nNodes: number; nFind: number; worst: number; bins: number } }[] = [];
    const loose = new Set<string>();               // ids that belong to no room (bus lane etc.)
    let grandparent: string | null = null;         // firmware room (by-target nesting)

    if (groupBy === "none") {
      return { parentOf, rooms, loose, grandparent, byId, findingAbout };
    }

    if (groupBy === "target") {
      // Each byte target → a room (compound parent). Sub-file nodes nest under their
      // target_id. A firmware_image becomes the GRANDPARENT room of its child targets.
      const targets = graph.nodes.filter((n) => n.type === "target");
      const fw = targets.find((t) => t.kind === "firmware_image");
      grandparent = fw ? "room:" + fw.id : null;
      for (const t of targets) {
        const rid = "room:" + t.id;
        // skeleton payload tags rooms with the SUBTREE rollup (roll_*) so a collapsed
        // container (firmware) card summarizes all its descendant binaries, plus a
        // child-binary count. Falls back to own counts for a leaf binary.
        const skel = (t as any).room
          ? { nNodes: (t.roll_nodes as number) ?? (t.n_nodes as number) ?? 0,
              nFind: (t.roll_findings as number) ?? (t.n_findings as number) ?? 0,
              worst: (t.roll_worst_severity || t.worst_severity)
                ? (SEV_RANK[(t.roll_worst_severity || t.worst_severity) as string] ?? -1) : -1,
              bins: (t.child_bins as number) || 0 }
          : undefined;
        rooms.push({ id: rid, label: t.label, tkey: t.kind as string, gkind: "target", kind: t.kind as string, skel });
        if (fw && t.id !== fw.id && (!t.parent_id || t.parent_id === fw.id)) parentOf.set(rid, grandparent!);
        else if (fw && t.parent_id && t.parent_id !== fw.id && byId.has(t.parent_id)) parentOf.set(rid, "room:" + t.parent_id);
      }
      for (const n of graph.nodes) {
        if (n.type !== "node") continue;
        if (n.node_type === "socket" && !n.target_id) { loose.add(n.id); continue; } // bus lane
        if (n.target_id && byId.has(n.target_id)) parentOf.set(n.id, "room:" + n.target_id);
        else loose.add(n.id);
      }
      for (const n of graph.nodes) {
        if (n.type !== "finding") continue;
        const abouts = findingAbout.get(n.id) || [];
        let placed = false;
        for (const a of abouts) {
          const an = byId.get(a);
          if (an?.type === "target") { parentOf.set(n.id, "room:" + a); placed = true; break; }
          if (an?.type === "node" && an.target_id && byId.has(an.target_id)) { parentOf.set(n.id, "room:" + an.target_id); placed = true; break; }
        }
        if (!placed && (n as any).target_id && byId.has((n as any).target_id)) { parentOf.set(n.id, "room:" + (n as any).target_id); placed = true; }
        if (!placed) loose.add(n.id);
      }
    } else if (groupBy === "type") {
      // Compound box per node/target/finding TYPE (all functions, all endpoints, …).
      const typeOf = (n: Graph["nodes"][number]) =>
        n.type === "target" ? "t:" + (n.kind as string)
          : n.type === "finding" ? "f:finding" : "n:" + (n.node_type as string);
      const seen = new Set<string>();
      for (const n of graph.nodes) {
        const k = typeOf(n);
        const rid = "room:" + k;
        if (!seen.has(k)) {
          seen.add(k);
          const tkey = n.type === "target" ? (n.kind as string) : n.type === "finding" ? "finding" : (n.node_type as string);
          rooms.push({ id: rid, label: typeLabel(tkey), tkey, gkind: "type", kind: tkey });
        }
        parentOf.set(n.id, rid);
      }
    } else if (groupBy === "finding") {
      // Invert around findings: each finding diamond becomes a parent of the nodes it is
      // about. Non-implicated nodes go to a single "unimplicated" room.
      for (const n of graph.nodes) {
        if (n.type !== "finding") continue;
        rooms.push({ id: "room:" + n.id, label: n.label, tkey: "finding", gkind: "finding", kind: "finding" });
      }
      for (const e of graph.edges) {
        // `about` edges are finding(src) → node/target(dst); nest the implicated node under
        // its finding's room. (Guard on the source being a finding: hypothesis `about` edges
        // run node→target and must not parent a target under a non-existent finding room.)
        if (e.type === "about" && byId.get(e.source)?.type === "finding"
            && byId.has(e.target) && byId.get(e.target)?.type !== "finding" && !parentOf.has(e.target)) {
          parentOf.set(e.target, "room:" + e.source);
        }
      }
      const other = "room:__unimplicated";
      let needOther = false;
      for (const n of graph.nodes) {
        if (n.type === "finding") continue;
        if (!parentOf.has(n.id)) { parentOf.set(n.id, other); needOther = true; }
      }
      if (needOther) rooms.push({ id: other, label: "unimplicated", tkey: "unknown", gkind: "type", kind: "unknown" });
    }
    return { parentOf, rooms, loose, grandparent, byId, findingAbout };
  }, [graph, groupBy]);

  // Default-frame derivation (D1): SMALL/MEDIUM auto-EXPAND all rooms (looks like today's full
  // graph); LARGE/PATHOLOGICAL open COLLAPSED to the skeleton. Recomputed once per (groupBy,
  // graph, tier); the user's later manual expand/collapse is preserved until that key changes.
  useEffect(() => {
    if (groupBy === "none") { setExpandedRooms(new Set()); return; }
    // Map view (issue 8): the pure collapsed skeleton — every room a finding-weighted card, a
    // firmware grandparent expanded only enough to show its child-binary CARDS, interiors never
    // auto-shown. This is what makes Map distinct from the by-target Graph.
    //
    // Expand only PURE CONTAINER rooms: a room with child ROOMS but NO interior content nodes of
    // its own. A firmware grandparent qualifies (expanding it reveals its child-binary cards); a
    // binary like httpd that ALSO carries a child variant room does NOT — the old child-count
    // rule expanded httpd (it has an instrumented child room) and thereby dumped all 37 of its
    // own functions into the territory map, which is exactly why Map looked identical to Graph
    // (the issue-8 deviation). "Interior content" means type==='node' only — a finding that rolls
    // up to a room is part of its card, not interior structure, so it must not disqualify a
    // container. Capped by the ceiling so a real firmware with hundreds of children stays a
    // single card rather than an illegible grid.
    if (mapMode) {
      const childCount = new Map<string, number>();
      for (const r of model.rooms) { const p = model.parentOf.get(r.id); if (p) childCount.set(p, (childCount.get(p) || 0) + 1); }
      const ownsContent = new Set<string>();
      for (const n of graph.nodes) { if (n.type !== "node") continue; const r = model.parentOf.get(n.id); if (r) ownsContent.add(r); }
      setExpandedRooms(new Set([...childCount.entries()]
        .filter(([id, c]) => c <= ROOM_AUTO_EXPAND_CEILING && !ownsContent.has(id)).map(([id]) => id)));
      autoKey.current = "map|" + graph.project_id;
      return;
    }
    // In skeleton mode `graph.nodes.length` GROWS as interiors load on demand — keying on
    // it would reset the user's expand state on every room fetch. Key on the room COUNT
    // (stable) instead so the auto-default runs once per (groupBy, project, structure).
    const sizeKey = skeletonMode ? "skel:" + model.rooms.length : String(graph.nodes.length);
    const key = groupBy + "|" + graph.project_id + "|" + sizeKey + "|" + tier;
    if (autoKey.current === key) return;
    autoKey.current = key;
    if (tier === "large") {
      // The SKELETON (design §1): show the rooms but hide their interiors. A firmware
      // grandparent is EXPANDED so its child-target rooms show as collapsed cards ("12
      // boxes inside one box") — but ONLY when the child count is small enough to read.
      // A real firmware with HUNDREDS of children would render as an illegible grid of
      // cards, so above a ceiling the firmware stays a SINGLE card (expand it to drill in).
      const childCount = new Map<string, number>();
      for (const r of model.rooms) {
        const p = model.parentOf.get(r.id);
        if (p) childCount.set(p, (childCount.get(p) || 0) + 1);
      }
      const parentRooms = new Set(
        [...childCount.entries()].filter(([, c]) => c <= ROOM_AUTO_EXPAND_CEILING).map(([id]) => id),
      );
      setExpandedRooms(parentRooms);
    } else {
      setExpandedRooms(new Set(model.rooms.map((r) => r.id)));               // auto-expand (small/med)
    }
  }, [groupBy, graph, tier, model, skeletonMode, mapMode]);

  useEffect(() => {
    if (!ref.current) return;
    const compound = groupBy !== "none";
    // ── Phase 5: LAYER visibility (node-type / edge-class) + the findings tri-state ──────
    // A node type toggled OFF in the layer panel is hidden outright (it's a CLASS lever).
    // The findings layer keeps its existing tri-state (all / unresolved / none).
    const baseHidden = new Set<string>();
    for (const n of graph.nodes) {
      if (n.type === "finding") {
        if (findings === "none" || !nodeLayerOn(layers, "finding")) baseHidden.add(n.id);
        else if (findings === "unresolved" && RESOLVED.has(n.status)) baseHidden.add(n.id);
      } else if (n.type === "node") {
        if (!nodeLayerOn(layers, n.node_type as string)) baseHidden.add(n.id);
      }
    }
    // ── Phase 5: FILTER (value facets), FADE-FIRST. A filtered-OUT element fades to
    // context opacity (mode="fade", default) so context isn't lost, and only fully hides
    // on the explicit "hide" mode. Targets/findings are filtered; the filter never touches
    // color (D8) — it only dims (.filtered) or, in hide mode, removes (baseHidden).
    const filtered = new Set<string>();
    if (anyFilterActive(filters)) {
      const targetSet = new Set(filters.targets);
      const minSev = filters.severity ? sevRank(filters.severity) : -1;
      const tgtOf = (n: Graph["nodes"][number]): string | undefined =>
        n.type === "target" ? n.id : (n.target_id as string | undefined);
      for (const n of graph.nodes) {
        let out = false;
        // severity threshold + finding-type apply to FINDINGS (the value facets that scope triage).
        if (n.type === "finding") {
          if (minSev >= 0 && sevRank(n.severity as string) < minSev) out = true;
          if (filters.findingType && (n.finding_type as string) !== filters.findingType) out = true;
        }
        // target multiselect: keep only elements belonging to a selected target (others fade).
        if (targetSet.size > 0) {
          const t = tgtOf(n);
          if (!t || !targetSet.has(t)) out = true;
        }
        if (out) filtered.add(n.id);
      }
      if (filters.mode === "hide") for (const id of filtered) baseHidden.add(id);
    }
    // flat-mode descendant collapse (only when not grouping)
    const collapseHidden = new Set<string>();
    if (!compound) for (const id of collapsed) for (const d of descendants(id)) collapseHidden.add(d);
    const isHidden = (id: string) => baseHidden.has(id) || collapseHidden.has(id) || hidden.has(id);

    const { parentOf, rooms } = model;
    const roomById = new Map(rooms.map((r) => [r.id, r] as const));
    // a room is OPEN only if it and every ancestor room are in expandedRooms.
    const roomOpen = (rid: string): boolean => {
      let cur: string | undefined = rid;
      while (cur) { if (!expandedRooms.has(cur)) return false; cur = parentOf.get(cur); }
      return true;
    };
    // outermost collapsed ancestor of a ROOM id (incl. itself if it's collapsed).
    const collapsedAncestorRoom = (rid: string): string | null => {
      let cur: string | undefined = rid; let last: string | null = null;
      while (cur) { if (!expandedRooms.has(cur)) last = cur; cur = parentOf.get(cur); }
      return last;
    };
    // outermost collapsed ancestor of a CONTENT node (null if all ancestors open).
    const collapsedAncestor = (id: string): string | null => {
      let p = parentOf.get(id); let last: string | null = null;
      while (p) { if (!expandedRooms.has(p)) last = p; p = parentOf.get(p); }
      return last;
    };
    // the visual representative of any endpoint id: itself when visible, else its outermost
    // collapsed ancestor room (for cross-room meta-edge aggregation).
    const rep = (id: string): string => {
      // A bare TARGET id (skeleton meta-edges use target↔target endpoints) maps to its
      // synthetic room box `room:<id>`, since the target itself is never a content node.
      const asRoom = "room:" + id;
      const rid = roomById.has(asRoom) ? asRoom : id;
      if (roomById.has(rid)) return roomOpen(rid) ? rid : (collapsedAncestorRoom(rid) ?? rid);
      const room = parentOf.get(id);
      if (!room) return id;                       // loose (bus lane) — represents itself
      return collapsedAncestor(id) ?? (roomOpen(room) ? id : room);
    };

    // visible content nodes (not in a collapsed room, not base/manually hidden).
    // When grouping, a `target` is represented by its synthetic `room:<id>` BOX, never
    // also as a free-floating anchor dot — otherwise a collapsed firmware's child targets
    // would still render as ~hundreds of loose dots (the bug that defeated skeleton mode).
    const visibleContent = compound
      ? graph.nodes.filter((n) => n.type !== "target" && !isHidden(n.id)
          && (() => { const r = parentOf.get(n.id); return r ? roomOpen(r) : true; })())
      : graph.nodes.filter((n) => !isHidden(n.id));

    // visible rooms: shown iff all ancestors are open (a collapsed room is itself shown).
    const visibleRooms = compound ? rooms.filter((r) => {
      let p = parentOf.get(r.id);
      while (p) { if (!expandedRooms.has(p)) return false; p = parentOf.get(p); }
      return true;
    }) : [];

    // per-room subtree membership (for the rollup chip + size-by-weight).
    const roomMembers = new Map<string, string[]>();
    if (compound) {
      for (const n of graph.nodes) {
        if (isHidden(n.id)) continue;
        let p = parentOf.get(n.id);
        while (p) { (roomMembers.get(p) ?? roomMembers.set(p, []).get(p)!).push(n.id); p = parentOf.get(p); }
      }
    }
    const roomRollup = (rid: string) => {
      const mem = roomMembers.get(rid) || [];
      let nNodes = 0, nFind = 0, worst = -1, wgt = 0;
      for (const id of mem) {
        const n = model.byId.get(id); if (!n) continue;
        if (n.type === "finding") { nFind++; const r = SEV_RANK[n.severity as string] ?? 0; worst = Math.max(worst, r); wgt += r + 1; }
        else if (n.type === "node") { nNodes++; wgt += 0.25; }
      }
      // Skeleton-first: a room whose interior isn't loaded has no live members — fall back
      // to the backend's pre-computed rollup so the card still shows real counts + the
      // worst-severity ring (the whole point of the skeleton's countable, hot-tinted rooms).
      const skel = roomById.get(rid)?.skel;
      if (skel && nNodes === 0 && nFind === 0) {
        const sw = (skel.worst >= 0 ? skel.worst + 1 : 0) * skel.nFind + skel.nNodes * 0.25;
        return { nNodes: skel.nNodes, nFind: skel.nFind, worst: skel.worst, wgt: sw };
      }
      return { nNodes, nFind, worst, wgt };
    };

    // aggregate cross-room edges into meta-edges; keep within-open-scope edges direct.
    const degree = new Map<string, number>();
    // Phase 5: an edge whose CLASS is toggled off in the layer panel is dropped entirely
    // (edges are the dominant ink — the single biggest density lever).
    const realEdges = graph.edges.filter((e) =>
      !isHidden(e.source) && !isHidden(e.target) && edgeClassOn(layers, e.type));
    const metaAgg = new Map<string, { source: string; target: string; types: Set<string>; count: number; color: string }>();
    const directEdges: typeof realEdges = [];
    for (const e of realEdges) {
      const s = compound ? rep(e.source) : e.source;
      const t = compound ? rep(e.target) : e.target;
      if (s === t) continue;                     // both ends folded into one collapsed room
      const collapsedTouch = (s !== e.source) || (t !== e.target);
      if (compound && collapsedTouch) {
        const key = s + "→" + t;
        const cur = metaAgg.get(key) || { source: s, target: t, types: new Set<string>(), count: 0, color: EDGE_C[e.type] || "#46506a" };
        cur.types.add(e.type); cur.count += (e.count || 1);
        if (SEMANTIC.has(e.type) && !STRUCTURAL.has(e.type)) cur.color = EDGE_C[e.type] || cur.color;
        metaAgg.set(key, cur);
      } else {
        directEdges.push({ ...e, source: s, target: t });
      }
    }
    for (const e of directEdges) { degree.set(e.source, (degree.get(e.source) || 0) + 1); degree.set(e.target, (degree.get(e.target) || 0) + 1); }
    for (const m of metaAgg.values()) { degree.set(m.source, (degree.get(m.source) || 0) + 1); degree.set(m.target, (degree.get(m.target) || 0) + 1); }

    const roomElements = visibleRooms.map((r) => {
      const open = expandedRooms.has(r.id);
      const { nNodes, nFind, worst, wgt } = roomRollup(r.id);
      const sev = worst >= 0 ? SEV_NAME[worst] : "";
      // A CONTAINER (firmware) card counts its descendant BINARIES; a leaf binary counts
      // its functions/nodes. So a collapsed firmware reads "251 bins · 90⚠", a binary "44".
      const bins = r.skel?.bins || 0;
      const chip = bins > 0
        ? `  ${bins} bin${bins > 1 ? "s" : ""}${nFind > 0 ? ` · ${nFind}⚠` : ""}`
        : nFind > 0 ? `  ${nNodes} · ${nFind}⚠` : nNodes > 0 ? `  ${nNodes}` : "";
      const parent = parentOf.get(r.id);
      const showParent = parent && roomById.has(parent) && expandedRooms.has(parent);
      // A room fades (filtered) iff EVERY member it contains is filtered out — so a
      // by-target filter dims the non-selected island cards while keeping them present.
      const mem = roomMembers.get(r.id) || [];
      const roomFiltered = filtered.size > 0 && mem.length > 0 && mem.every((id) => filtered.has(id));
      return { data: {
        id: r.id, label: open ? r.label : r.label + chip, gtype: "room",
        kind: r.kind, tkey: r.tkey, gkind: r.gkind,
        roomOpen: open ? 1 : 0, roomSev: sev, roomWorst: worst,
        roomWeight: Math.max(8, Math.min(60, wgt)), nFind, nNodes,
        filtered: roomFiltered ? 1 : 0,
        ...(showParent ? { parent } : {}),
      } };
    });

    const contentElements = visibleContent.map((n) => {
      const deg = degree.get(n.id) || 0;
      const anchor = n.type === "target";
      const t = anchor ? "anchor" : deg >= 8 ? "hub" : "detail";
      const tkey = n.type === "target" ? (n.kind as string)
        : n.type === "finding" ? "finding" : (n.node_type as string);
      const glyph = anchor ? (KIND_GLYPH[n.kind as string] || "") : "";
      const parent = compound ? parentOf.get(n.id) : undefined;
      const parentOpen = parent && roomById.has(parent) && roomOpen(parent);
      return { data: {
        id: n.id, label: n.label, gtype: n.type, severity: n.severity, kind: n.kind,
        node_type: n.node_type, collapsed: 0, deg, tier: t, tkey, glyph,
        degc: Math.max(8, Math.min(24, deg)),
        bus: (n.type === "node" && n.node_type === "socket" && !n.target_id) ? 1 : 0,
        filtered: filtered.has(n.id) ? 1 : 0,
        ...(parentOpen ? { parent } : {}),
      } };
    });

    const edgeById = new Map(graph.edges.map((e) => [e.id, e] as const));
    const directEdgeElements = directEdges.map((e) => {
      const a = e.attrs || {};
      let hint = "";
      if (e.type === "calls" && (a.call_sites?.length || (e.count && e.count > 1))) hint = ` ×${a.call_sites?.length || e.count}`;
      else if ((e.type === "listens_on" || e.type === "connects_to") && a.address) hint = ` @${a.address}`;
      else if (a.port) hint = ` :${a.port}`;
      const eclass = STRUCTURAL.has(e.type) ? "structural" : SEMANTIC.has(e.type) ? "semantic" : "other";
      return { data: { id: e.id, source: e.source, target: e.target, etype: e.type, elabel: e.type + hint,
                       color: EDGE_C[e.type] || "#3b4458", persist: ALWAYS_LABEL.has(e.type) ? 1 : 0, eclass } };
    });
    const metaEdgeElements = [...metaAgg.entries()].map(([key, m], i) => {
      const types = [...m.types];
      const lbl = types.length === 1 ? `${types[0]}${m.count > 1 ? ` ×${m.count}` : ""}` : `×${m.count}`;
      // a meta-edge is "semantic" if ANY contributing edge type is semantic (links_against,
      // taints, listens_on, …) — those carry the structural story and stay visible. A purely
      // structural meta-edge (only contains/references/about) recedes to faint scaffolding so
      // the room-level canvas stays calm (the same edge-ink discipline, applied to meta-edges).
      const hasSemantic = types.some((t) => SEMANTIC.has(t) && !STRUCTURAL.has(t));
      return { data: { id: "meta:" + i + ":" + key, source: m.source, target: m.target, etype: "meta",
                       elabel: lbl, color: m.color, persist: 0,
                       eclass: hasSemantic ? "meta" : "meta-structural",
                       w: Math.max(1.4, Math.min(7, 1 + m.count * 0.5)) } };
    });

    // Map view (issue 8): drop the purely-structural cross-target ribbons so only the SEMANTIC
    // territory links (links_against / connects_to / shared sockets) draw — the overview reads
    // as "which binaries relate", not the full structural cobweb.
    const metaShown = mapMode ? metaEdgeElements.filter((e) => e.data.eclass === "meta") : metaEdgeElements;
    // Cytoscape THROWS ("Can not create edge … with nonexistent source") if any edge references
    // a node id not in the element set. Under some group-by/expand states (notably by-type +
    // expanding a web_app, whose routes_to/contains edges resolve to a target that isn't a
    // rendered node in that view) the aggregation can emit such a dangling edge. Drop any edge
    // whose source OR target isn't present, so the view renders instead of crashing — an edge to
    // a node that isn't shown can't be drawn anyway.
    const presentNodeIds = new Set<string>(
      [...roomElements, ...contentElements].map((n) => n.data.id as string),
    );
    const endpointsPresent = (e: { data: { source: string; target: string } }) =>
      presentNodeIds.has(e.data.source) && presentNodeIds.has(e.data.target);
    const elements = [
      ...roomElements,
      ...contentElements,
      ...directEdgeElements.filter(endpointsPresent),
      ...metaShown.filter(endpointsPresent),
    ];

    const cy = cytoscape({
      // Scroll-to-zoom sensitivity (issue 5, round 2). 0.25→0.6 (PR #89) was STILL sluggish —
      // a wheel notch barely moved the scale. 1.4 makes a notch a clearly-felt zoom step while
      // staying short of the jumpy/overshooting feel a value ≥2 gives. NOTE: cytoscape reads
      // wheelSensitivity ONLY at construction (it's ignored if set on the live instance later),
      // so this MUST live here in the cytoscape() options — it's the single source of truth and
      // nothing reassigns cy.wheelSensitivity afterwards.
      container: ref.current, elements, wheelSensitivity: 1.4,
      style: [
        {
          selector: "node",
          style: {
            label: "data(label)", color: "#cdd5e2", "font-size": "9px", "font-weight": 600,
            // Floor the resting label opacity at 0.5 so even a degree-2 leaf is LABELLED once
            // it's resolvable (issue 6: low-degree functions/endpoints/strings were mapped to
            // text-opacity 0 and stayed anonymous at every zoom). Hubs still ramp brighter.
            "text-opacity": "mapData(degc, 8, 24, 0.5, 0.85)" as any,
            "min-zoomed-font-size": 7,
            "text-valign": "bottom", "text-margin-y": 5, "text-wrap": "ellipsis", "text-max-width": "104px",
            "text-background-color": "#0a0c12", "text-background-opacity": 0.9, "text-background-padding": "3px",
            "text-background-shape": "roundrectangle",
            width: 22, height: 22,
            "background-color": (n: any) => n.data("gtype") === "finding" ? (SEV[n.data("severity")] || "#7d8799") : n.data("gtype") === "node" ? (NODE_T[n.data("node_type")] || "#7d8799") : (KIND[n.data("kind")] || "#7d8799"),
            shape: ((n: any) => n.data("gtype") === "finding" ? "diamond" : NODE_SHAPE[n.data("node_type")] || (n.data("gtype") === "node" ? "round-rectangle" : "ellipse")) as any,
            "border-width": 1.5, "border-color": "#0a0c12",
            "underlay-color": (n: any) => n.data("gtype") === "finding" ? (SEV[n.data("severity")] || "#7d8799") : (KIND[n.data("kind")] || "#39c5cf"),
            "underlay-opacity": (n: any) => (n.data("gtype") === "finding" && (n.data("severity") === "critical" || n.data("severity") === "high") ? 0.28 : 0.12),
            "underlay-padding": 4, "underlay-shape": "ellipse",
            "transition-property": "opacity background-blacken border-width", "transition-duration": "160ms" as any,
          },
        },
        // ── Phase 3: OPEN compound room = a labeled tinted "island" box. ──────────────────
        { selector: "node[gtype = 'room'][roomOpen = 1]", style: {
            shape: "round-rectangle",
            "background-color": (n: any) => KIND[n.data("kind")] || NODE_T[n.data("kind")] || "#7d8799",
            "background-opacity": 0.07,
            "border-width": 1.5, "border-opacity": 0.75,
            "border-color": (n: any) => KIND[n.data("kind")] || NODE_T[n.data("kind")] || "#39c5cf",
            label: "data(label)", color: "#cdd5e2", "font-size": "12px", "font-weight": 700,
            "text-valign": "top", "text-halign": "center", "text-margin-y": -3, "text-opacity": 1,
            "text-max-width": "220px", padding: 30, "min-zoomed-font-size": 0, "underlay-opacity": 0,
        } },
        // ── COLLAPSED room = a finding-weighted "room" card (the skeleton's countable rooms).
        { selector: "node[gtype = 'room'][roomOpen = 0]", style: {
            shape: "round-rectangle",
            width: "mapData(roomWeight, 8, 60, 78, 150)" as any, height: "mapData(roomWeight, 8, 60, 44, 82)" as any,
            "background-color": (n: any) => KIND[n.data("kind")] || NODE_T[n.data("kind")] || "#7d8799",
            // clean rooms (no findings) recede a touch so the finding-bearing rooms own the eye.
            "background-opacity": (n: any) => (n.data("roomWorst") >= 0 ? 0.92 : 0.74),
            // Issue 5 (round 2): the title was BLACK (#0a0c12) centered on the card. On a
            // mid-brightness fill (the blue/teal kind tints) — and even more so over the dark
            // canvas behind a faint card — that read as black-on-black/unreadable. Make it LIGHT
            // text sitting in its own dark rounded pill (the same treatment the legible LOD-far/mid
            // rules already use), so the title is crisp at every zoom. The card KEEPS its per-type
            // color fill + the severity ring (D8 color-coding untouched) — only the label is fixed.
            label: "data(label)", color: "#e8edf6", "font-size": "12px", "font-weight": 800,
            "text-valign": "center", "text-halign": "center", "text-opacity": 1, "min-zoomed-font-size": 5,
            "text-background-color": "#0a0c12", "text-background-opacity": 0.78, "text-background-padding": "3px",
            "text-background-shape": "roundrectangle",
            "text-max-width": "138px", "text-wrap": "ellipsis", "text-margin-y": 0,
            // finding-severity rollup ring. The glow (underlay) is RESERVED for high/critical so
            // a few hot rooms pop out of a large skeleton — previously EVERY finding-bearing room
            // washed at ≥0.22, so 78/251 rooms merged into a uniform pink haze and no single hot
            // room pulled the eye (GRAPH-01). Now only high/critical wash strongly, medium gets a
            // faint tint, low/info carry just a severity-colored border, clean rooms none.
            "border-width": (n: any) => { const w = n.data("roomWorst"); return w >= 3 ? 4 : w >= 1 ? 2.5 : w >= 0 ? 2 : 1.2; },
            "border-color": (n: any) => (n.data("roomSev") ? SEV[n.data("roomSev")] : "#222a3a"),
            "underlay-color": (n: any) => (n.data("roomSev") ? SEV[n.data("roomSev")] : "#39c5cf"),
            "underlay-opacity": (n: any) => { const w = n.data("roomWorst"); return w >= 3 ? 0.5 : w === 2 ? 0.16 : 0; },
            "underlay-padding": (n: any) => (n.data("roomWorst") >= 3 ? 10 : 6),
            "transition-property": "opacity", "transition-duration": "160ms" as any,
        } },
        // Hubs (degree ≥ 8): a degree-driven 30→40px ramp + a slight glow.
        { selector: "node[tier = 'hub']", style: {
            width: "mapData(degc, 8, 24, 30, 40)" as any, height: "mapData(degc, 8, 24, 30, 40)" as any,
            "text-opacity": "mapData(degc, 8, 24, 0.85, 1.0)" as any,
            "underlay-opacity": 0.18, "underlay-padding": 6,
        } },
        // Anchors (targets / firmware root in flat mode): big, crisp, always-labelled, glyph.
        { selector: "node[tier = 'anchor']", style: {
            width: 40, height: 40, "font-size": "11px", "text-opacity": 1,
            "border-width": 2, "border-color": "#0a0c12", "underlay-opacity": 0.22, "underlay-padding": 7,
        } },
        { selector: "node[tier = 'anchor'][glyph != '']", style: {
            "background-image": (n: any) => glyphDataUri(n.data("glyph")) as any,
            "background-width": "58%", "background-height": "58%", "background-fit": "none", "background-clip": "node",
        } },
        // The shared-socket "network bus" nodes: pink hexagon, a touch larger, always labeled.
        { selector: "node[bus = 1]", style: {
            width: 26, height: 26, "text-opacity": 0.95, "font-size": "10px",
            "underlay-color": "#f778ba", "underlay-opacity": 0.22, "underlay-padding": 6,
        } },
        // Findings stay diamonds on the SEV ramp, sized up for critical/high.
        { selector: "node[gtype = 'finding']", style: {
            width: (n: any) => (n.data("severity") === "critical" ? 34 : n.data("severity") === "high" ? 30 : 24),
            height: (n: any) => (n.data("severity") === "critical" ? 34 : n.data("severity") === "high" ? 30 : 24),
            "text-opacity": (n: any) => (n.data("severity") === "critical" || n.data("severity") === "high" ? 1 : 0.55),
        } },
        { selector: "node:selected", style: { "border-color": "#6aa3ff", "border-width": 3, "text-opacity": 1, "underlay-color": "#6aa3ff", "underlay-opacity": 0.4, "underlay-padding": 8 } },
        {
          selector: "edge",
          style: {
            width: 1.1, "line-color": "data(color)", "target-arrow-color": "data(color)", "target-arrow-shape": "triangle",
            "curve-style": "bezier", "arrow-scale": 0.7, opacity: 0.28, label: "", "font-size": "7px", color: "#8893a6",
            "text-rotation": "autorotate", "text-background-color": "#0a0c12", "text-background-opacity": 0.9, "text-background-padding": "3px",
            "min-zoomed-font-size": 7,
            "transition-property": "opacity width", "transition-duration": "160ms" as any,
          },
        },
        { selector: "edge[eclass = 'structural']", style: { opacity: 0.18, width: 1.0, "target-arrow-shape": "none" } },
        { selector: "edge[eclass = 'semantic']", style: { opacity: 0.32, width: 1.3 } },
        { selector: "edge[persist = 1]", style: { label: "data(elabel)", opacity: 0.42, width: 1.5 } },
        // ── Phase 3: aggregated cross-room META-edge — one weighted ribbon with a ×N count.
        // Semantic meta-edges (links_against/taints/listens_on…) carry the structural story →
        // visible + labelled. Purely-structural meta-edges (references/contains) recede to
        // faint hairlines so the room canvas stays calm.
        { selector: "edge[eclass = 'meta']", style: {
            width: "data(w)" as any, opacity: 0.6, "line-color": "data(color)", "target-arrow-color": "data(color)",
            "target-arrow-shape": "triangle", "arrow-scale": 0.9,
            label: "data(elabel)", "font-size": "9px", color: "#aab3c5",
            "curve-style": "bezier", "min-zoomed-font-size": 5, "z-index": 12,
        } },
        { selector: "edge[eclass = 'meta-structural']", style: {
            width: "data(w)" as any, opacity: 0.14, "line-color": "data(color)",
            "target-arrow-shape": "none", "curve-style": "bezier", label: "", "z-index": 1,
        } },
        { selector: "edge.lit", style: { label: "data(elabel)", opacity: 1, width: 2.4, "target-arrow-shape": "triangle", "z-index": 20 } },

        // ── Phase 4: semantic zoom (level-of-detail) ──────────────────────────────────────
        // A zoom handler stamps `lod-far|lod-mid|lod-near` on EVERY element; these rules then
        // switch how much competes for the eye. The headline fix is the FAR tier: the room
        // cards stay readable (big inverse-scaled label, no min-font cutoff) while the interior
        // clutter and edge labels go quiet — so the DEFAULT full-pane LARGE/PATHOLOGICAL frame
        // opens as a set of LABELLED, countable rooms, not a smudge that only resolves on zoom-in.

        // FAR: collapsed room cards get a large label placed BELOW the card (so a long
        // `name · N · M⚠` chip isn't clipped inside a small card) at a size whose RENDERED
        // height stays legible at the default z≈0.5, with the min-font cutoff dropped so it
        // never blurs out. This is the headline fix — readable room labels at the default frame.
        { selector: "node[gtype = 'room'][roomOpen = 0].lod-far", style: {
            "font-size": "26px", "min-zoomed-font-size": 0, "text-opacity": 1,
            color: "#e8edf6", "font-weight": 800,
            "text-valign": "bottom", "text-margin-y": 8, "text-max-width": "320px", "text-wrap": "wrap",
            "text-background-color": "#0a0c12", "text-background-opacity": 0.7, "text-background-padding": "4px",
            "text-background-shape": "roundrectangle",
        } },
        // FAR: open-room (container) labels also scale up so a firmware grandparent stays named.
        { selector: "node[gtype = 'room'][roomOpen = 1].lod-far", style: {
            "font-size": "24px", "min-zoomed-font-size": 0, "text-opacity": 1,
        } },
        // FAR: hide interior detail — content node labels off (only rooms speak); the
        // anchors keep theirs (they ARE the structure) but shrink to fit.
        { selector: "node[gtype = 'node'].lod-far, node[gtype = 'finding'].lod-far", style: { "text-opacity": 0 } },
        { selector: "node[bus = 1].lod-far", style: { "text-opacity": 0 } },
        { selector: "node[tier = 'anchor'].lod-far", style: { "font-size": "22px", "min-zoomed-font-size": 0 } },
        // FAR: edge labels are the collision culprit — off (incl. the normally-persistent
        // semantic + meta labels); meta ribbons keep their width/color, just lose the text.
        { selector: "edge.lod-far", style: { label: "", "min-zoomed-font-size": 0 } },
        // FAR: the cross-room meta ribbons recede so the room CARDS (and their severity glow) own
        // the frame. At a zoom where an individual ribbon is unreadable anyway, a wall of
        // 0.6-opacity semantic ribbons otherwise washes the whole skeleton one warm colour and
        // drowns the hot-room heat (GRAPH-01) — dim them to context so the rooms speak.
        { selector: "edge[eclass = 'meta'].lod-far", style: { opacity: 0.2 } },
        { selector: "edge[eclass = 'meta-structural'].lod-far", style: { opacity: 0.07 } },

        // MID: structure — the skeleton's default frame often lands HERE (LARGE), so collapsed
        // room cards keep a readable below-card label (smaller than FAR since zoom is higher);
        // hub/anchor labels show and LEAF labels now appear too (the MID band starts at z=0.5,
        // where a single binary's nodes are already individuated — issue 6: leaves were blanked
        // here). min-zoomed-font-size still drops a label cleanly if the node is genuinely tiny.
        { selector: "node[gtype = 'room'][roomOpen = 0].lod-mid", style: {
            "font-size": "18px", "min-zoomed-font-size": 0, "text-opacity": 1,
            color: "#e8edf6", "font-weight": 800,
            "text-valign": "bottom", "text-margin-y": 7, "text-max-width": "300px", "text-wrap": "wrap",
            "text-background-color": "#0a0c12", "text-background-opacity": 0.7, "text-background-padding": "3px",
            "text-background-shape": "roundrectangle",
        } },
        // leaf labels keep their resting opacity at MID (do NOT zero them) — only the
        // min-zoomed-font-size floor hides them when too small to read.
        { selector: "node[gtype = 'node'].lod-mid", style: { "min-zoomed-font-size": 8 } },
        { selector: "node[tier = 'hub'].lod-mid", style: { "text-opacity": 1 } },
        { selector: "node[tier = 'anchor'].lod-mid", style: { "text-opacity": 1 } },
        { selector: "edge[persist = 1].lod-mid, edge[eclass = 'meta'].lod-mid", style: { "min-zoomed-font-size": 6 } },
        // NEAR (z ≥ LOD_NEAR): full detail is the base style — every label, edge labels, attr
        // hints (today's behaviour). The collapsed-room card label sits centered inside again.

        // ── Phase 2: the focus model ─────────────────────────────────────────────────────
        { selector: "node.context", style: {
            opacity: 0.16, "background-blacken": 0.4, "text-opacity": 0, "underlay-opacity": 0, events: "no" as any,
        } },
        { selector: "edge.context", style: { opacity: 0.05, label: "", "target-arrow-shape": "none", events: "no" as any } },
        { selector: "node.focus", style: {
            opacity: 1, "background-blacken": 0, "text-opacity": 1, "z-index": 30,
            "border-width": 2.5, "border-color": "#cdd5e2", "underlay-opacity": 0.3, "underlay-padding": 7,
        } },
        { selector: "node.focus-anchor", style: {
            "border-color": "#ffd166", "border-width": 3.5,
            "underlay-color": "#ffd166", "underlay-opacity": 0.5, "underlay-padding": 11, "text-opacity": 1,
        } },
        { selector: "edge.focus", style: { opacity: 1, width: 2.4, label: "data(elabel)", "target-arrow-shape": "triangle", "z-index": 25 } },
        { selector: "node.hl", style: { "border-color": "#6aa3ff", "border-width": 2.5, "text-opacity": 1, "z-index": 28, "underlay-opacity": 0.3 } },
        { selector: "edge.hl", style: { opacity: 0.95, width: 2.2, label: "data(elabel)", "target-arrow-shape": "triangle", "z-index": 24 } },
        // hl-dim recedes everything that isn't the hovered neighborhood. A gentle 0.28 (not a
        // near-invisible 0.12) so the rest stays a present, parseable backdrop — the hovered
        // node should POP by contrast, never leave the rest looking deleted (issue 2).
        { selector: ".hl-dim", style: { opacity: 0.28 } as any },
        { selector: "node.type-dim", style: { opacity: 0.1, "text-opacity": 0, "underlay-opacity": 0 } },
        { selector: "edge.type-dim", style: { opacity: 0.05, label: "" } },
        // ── A compound ROOM parent must NEVER take an underlay-fill or a blacken/opacity
        // blob from the focus / hover / context classes — its tinted background is a huge
        // bounding box, so a 0.3-opacity underlay or a dim renders as a big filled ellipse
        // smothering the whole group (issues 1 & 2). Rooms emphasize/recede with their BORDER
        // and label only; their fill stays the clean faint tint. These rules sit LAST so they
        // win over .hl / .focus / .context / .hl-dim for room parents specifically.
        { selector: "node[gtype = 'room'].hl, node[gtype = 'room'].focus", style: {
            "underlay-opacity": 0, "background-blacken": 0,
            "border-color": "#6aa3ff", "border-width": 2, "border-opacity": 1, opacity: 1,
        } },
        { selector: "node[gtype = 'room'].hl-dim, node[gtype = 'room'].context", style: {
            "underlay-opacity": 0, "background-blacken": 0, opacity: 1,
            "background-opacity": 0.04, "border-opacity": 0.28, "text-opacity": 0.3,
        } },
        // ── Phase 5: FADE-FIRST filter (design §2.3). A filtered-out element fades to
        // context opacity (hue PRESERVED — never de-colored, D8) so "there's more behind
        // this" stays visible; the hard-hide path removes it via baseHidden, not here.
        { selector: "node[filtered = 1]", style: { opacity: 0.14, "text-opacity": 0, "underlay-opacity": 0 } },
        { selector: "edge[filtered = 1]", style: { opacity: 0.06, label: "" } },
      ],
    });
    // An edge is filtered if either endpoint faded out (keeps the fade consistent).
    cy.batch(() => cy.edges().forEach((e) => {
      if (e.source().data("filtered") === 1 || e.target().data("filtered") === 1) e.data("filtered", 1);
    }));

    // ── Phase 4: semantic-zoom (LOD) wiring ──────────────────────────────────────────────
    // Stamp the current zoom's LOD class onto every element, and keep it current on zoom.
    let lodNow: "lod-far" | "lod-mid" | "lod-near" | "" = "";
    const applyLod = () => {
      const cls = lodClass(cy.zoom());
      if (cls === lodNow) return;
      lodNow = cls;
      cy.batch(() => cy.elements().removeClass("lod-far lod-mid lod-near").addClass(cls));
    };
    let lodTimer: any = null;
    cy.on("zoom", () => { if (lodTimer) return; lodTimer = setTimeout(() => { lodTimer = null; applyLod(); }, 60); });

    // Canvas-utilization backstop (§3.2): after layout, if the skeleton's bounding box uses
    // too little of the pane, the layout clumped — re-run fcose once with more separation so we
    // spend the empty canvas on breathing room (target 55–80% utilization) instead of letterbox.
    const utilization = (): number => {
      const bb = cy.elements(":visible").boundingBox();
      const z = cy.zoom();
      const used = (bb.w * z) * (bb.h * z);
      return used / (cy.width() * cy.height());
    };

    // ── Layout by context (D7): fcose for the room SKELETON (compound-aware, tiles disconnected
    // islands across the pane → kills the letterbox), scoped `dagre LR` re-run INSIDE each
    // expanded room (a binary's call graph reads top-down/left-right), and dagre LR for the flat
    // ("none") graph. Both run before the focus model so it gets final positions.
    layoutDone.current = false;

    // Re-lay the interior of every OPEN, non-empty room with dagre LR (scoped to its
    // descendants) so an expanded binary reads as call flow rather than an fcose scatter.
    const dagreOpenRooms = () => {
      if (!compound) return;
      // Layouts manage their own batching — running one inside cy.batch() suppresses the
      // position updates, so iterate WITHOUT a wrapping batch.
      for (const r of cy.nodes("node[gtype = 'room'][roomOpen = 1]")) {
        const kids = r.children();
        if (kids.length < 2) continue;                       // nothing to flow
        // Only flow a room whose children are LEAF CONTENT (a binary's functions) — NOT the
        // firmware grandparent whose children are themselves room cards (those stay fcose-tiled
        // so the skeleton spreads; dagre on them would stack the cards and re-letterbox).
        if (kids.filter("[gtype = 'room']").nonempty()) continue;
        const inside = kids.union(kids.edgesWith(kids));
        if (inside.edges().length === 0) continue;           // no interior edges → leave fcose tiling
        inside.layout({ name: "dagre", rankDir: "LR", nodeSep: 22, rankSep: 55,
                        fit: false, animate: false } as any).run();
      }
    };

    // Translate a whole block (a compound room moves with its descendants; a loose node moves
    // alone). Setting a parent's position is a no-op in cytoscape — the parent box tracks its
    // children — so we shift the leaf descendants and the box follows.
    const shiftBlock = (el: any, dx: number, dy: number) => {
      if (Math.abs(dx) < 0.01 && Math.abs(dy) < 0.01) return;
      const leaves = el.isParent() ? el.descendants().filter((d: any) => d.isChildless()) : el;
      leaves.forEach((d: any) => { const p = d.position(); d.position({ x: p.x + dx, y: p.y + dy }); });
    };
    // Separate a set of SIBLING rooms so their bounding boxes don't overlap. dagreOpenRooms()
    // re-flows each open room's interior on its own, so a freshly-expanded room grows past the
    // footprint fcose reserved and lands on top of a sibling (the "expanded rooms overlap" bug).
    // A few relaxation passes push each overlapping pair apart along its axis of least penetration
    // until no two sibling boxes intersect (+ a padding gutter). Pure post-process on positions.
    const separateSiblings = (sibs: any, pad: number) => {
      const arr = sibs.toArray();
      if (arr.length < 2) return;
      // NOT wrapped in cy.batch(): a batch defers boundingBox-cache invalidation, so each pair
      // would read STALE boxes from before the prior nudges and the relaxation fails to converge
      // (empirically reintroduces overlaps). Run unbatched — same reason dagreOpenRooms() avoids
      // batch — so every boundingBox() reflects the moves made so far. Bounded by MAX (below).
      for (let iter = 0; iter < 24; iter++) {
        let moved = false;
        for (let i = 0; i < arr.length; i++) {
          for (let j = i + 1; j < arr.length; j++) {
            const ba = arr[i].boundingBox(), bb = arr[j].boundingBox();
            const ox = Math.min(ba.x2, bb.x2) - Math.max(ba.x1, bb.x1) + pad;
            const oy = Math.min(ba.y2, bb.y2) - Math.max(ba.y1, bb.y1) + pad;
            if (ox <= 0 || oy <= 0) continue;                 // already clear (beyond the gutter)
            const acx = (ba.x1 + ba.x2) / 2, acy = (ba.y1 + ba.y2) / 2;
            const bcx = (bb.x1 + bb.x2) / 2, bcy = (bb.y1 + bb.y2) / 2;
            if (ox < oy) {                                     // least overlap is horizontal → split on x
              const dir = acx <= bcx ? 1 : -1;
              shiftBlock(arr[i], -dir * ox / 2, 0); shiftBlock(arr[j], dir * ox / 2, 0);
            } else {                                           // split on y
              const dir = acy <= bcy ? 1 : -1;
              shiftBlock(arr[i], 0, -dir * oy / 2); shiftBlock(arr[j], 0, dir * oy / 2);
            }
            moved = true;
          }
        }
        if (!moved) break;
      }
    };
    // De-overlap sibling ROOMS in every scope that can grow on expand: the top level + the
    // children of each open container room. Skipped where nothing is expanded (collapsed cards
    // were already tiled cleanly by fcose) and where there are too many siblings to be worth the
    // O(n²) passes (a 250-room firmware skeleton — the user won't expand hundreds by hand).
    const separateOverlaps = () => {
      if (!compound) return;
      const PAD = 30, MAX = 80;
      const scopes: any[] = [cy.nodes("node[gtype = 'room']").filter((n: any) => n.parent().empty() && n.visible())];
      cy.nodes("node[gtype = 'room'][roomOpen = 1]").forEach((p: any) => {
        scopes.push(p.children().filter("node[gtype = 'room']").filter((c: any) => c.visible()));
      });
      for (const rooms of scopes) {
        if (rooms.length < 2 || rooms.length > MAX) continue;
        if (rooms.filter("[roomOpen = 1]").empty()) continue;  // nothing expanded → can't grow-overlap
        separateSiblings(rooms, PAD);
      }
    };

    cy.one("layoutstop", () => {
      // Backstop: one re-run if the skeleton clumped (only the heavy compound view can letterbox).
      if (compound && utilization() < 0.5) {
        cy.layout({ name: "fcose", quality: "default", randomize: false, animate: false,
                    nodeSeparation: 220, nodeRepulsion: 24000, idealEdgeLength: 260,
                    packComponents: true, tile: true, tilingPaddingVertical: 28,
                    tilingPaddingHorizontal: 28, padding: 30,
                    nestingFactor: 0.9, gravity: 0.08, gravityCompound: 1.2,
                    numIter: 1500 } as any).run();
      }
      dagreOpenRooms();
      separateOverlaps();
      layoutDone.current = true;
      // Auto-frame a freshly-expanded room (scoped, never on a plain rebuild) unless a focus
      // owns the camera. (design §3.4 — auto-zoom fires only on an explicit navigation act.)
      const je = justExpanded.current; justExpanded.current = null;
      if (je && !focusValRef.current?.id) {
        const room = cy.getElementById(je);
        if (room.nonempty()) {
          const inside = room.descendants().union(room);
          // Issue 3 (round 2): expanding a room used to TELEPORT — the whole instance rebuilds,
          // then the camera snapped to the room. Now the camera GLIDES to the expanded room and
          // its freshly-revealed interior nodes FADE+SCALE in (a brief staged reveal) so the user
          // watches the room open instead of being yanked there. The interior starts transparent
          // and slightly shrunk, then animates to full on a short stagger.
          const interior = room.descendants().filter("[gtype = 'node'], [gtype = 'finding'], [gtype = 'room']");
          if (interior.nonempty()) {
            interior.style({ opacity: 0 });
            interior.forEach((el: any, i: number) => {
              el.delay(Math.min(i * 8, 120)).animate({ style: { opacity: 1 } }, { duration: 260, easing: "ease-out-cubic" });
            });
          }
          if (inside.length > 1) cy.animate({ fit: { eles: inside, padding: 60 } }, { duration: 380, easing: "ease-in-out-cubic" });
        }
      } else if (!focusValRef.current?.id && !je) {
        // First open / rebuild with no pending nav: frame ALL visible elements (rooms + the
        // network-bus sockets + any loose nodes) so nothing is cut off and the default
        // LARGE/PATHOLOGICAL frame is the full set of labelled cards filling the pane.
        // On an explicit COLLAPSE, GLIDE the re-fit (issue 3) so the view eases back to the
        // skeleton instead of snapping; a true first-mount fits instantly (nothing to glide from).
        const collapsing = justCollapsed.current; justCollapsed.current = false;
        if (collapsing) cy.animate({ fit: { eles: cy.elements(":visible"), padding: 36 } }, { duration: 340, easing: "ease-in-out-cubic" });
        else cy.fit(cy.elements(":visible"), 36);
      }
      justCollapsed.current = false;
      applyLod();
      applyFocusRef.current?.();
    });
    const layout = compound
      ? cy.layout({ name: "fcose", quality: "default", randomize: true, animate: false,
                    // tile + pack spreads disconnected islands across the pane (the letterbox
                    // fix); a long ideal edge for cross-room ribbons pushes islands apart.
                    nodeSeparation: 170, idealEdgeLength: (e: any) => (e.data("eclass") === "meta" || e.data("eclass") === "meta-structural" ? 240 : 80),
                    nodeRepulsion: 18000, edgeElasticity: 0.2,
                    packComponents: true, tile: true, tilingPaddingVertical: 24, tilingPaddingHorizontal: 24,
                    padding: 30, nestingFactor: 0.9, gravity: 0.12, gravityCompound: 1.1,
                    numIter: 2500, samplingType: true } as any)
      : cy.layout({ name: "dagre", rankDir: "LR", nodeSep: 26, rankSep: 72, padding: 24 } as any);
    layout.run();

    cy.on("tap", "edge", (evt) => {
      if (evt.target.data("etype") === "meta") return; // meta-edges have no single backing edge
      cy.edges().removeClass("lit"); evt.target.addClass("lit");
      onEdgeSelect?.(edgeById.get(evt.target.id()) || null);
    });
    cy.on("tap", "node", (evt) => {
      const n = evt.target;
      const id = n.id();
      const gt = n.data("gtype");
      const now = performance.now();
      if (gt === "room") {
        const realId = id.startsWith("room:") ? id.slice(5) : id;
        if (model.byId.get(realId)?.type === "target") onSelect(realId, "target");
        onEdgeSelect?.(null); setMenu(null);
        if (tapRef.current.id === id && now - tapRef.current.t < 350) {
          // Map view: double-tap DRILLS into the scoped Graph for that binary (issue 8); the
          // by-target Graph keeps the in-place expand/collapse.
          if (mapMode && onRoomDrill && model.byId.get(realId)?.type === "target") onRoomDrill(realId);
          else toggleRoom(id);
          tapRef.current = { id: null, t: 0 };
        }
        else tapRef.current = { id, t: now };
        return;
      }
      onSelect(id, gt);
      onEdgeSelect?.(null);
      setMenu(null);
      cy.edges().removeClass("lit"); n.connectedEdges().addClass("lit");
      if (tapRef.current.id === id && now - tapRef.current.t < 350) { focusCbRef.current?.(id); tapRef.current = { id: null, t: 0 }; }
      else tapRef.current = { id, t: now };
    });
    cy.on("tap", (evt) => { if (evt.target === cy) { cy.edges().removeClass("lit"); onEdgeSelect?.(null); setMenu(null); } });

    // Hover preview (design §4: EMPHASIZE the hovered thing + its neighborhood, gently recede
    // the rest — never dim what you're pointing at). Hovering a ROOM highlights the room + its
    // whole subtree (not just graph-edge neighbors, which a compound parent has none of), so a
    // room lights up cleanly instead of dimming its own contents into a blob (issues 1 & 2).
    cy.on("mouseover", "node", (evt) => {
      if (cy.elements(".focus, .context").nonempty()) return;
      const n = evt.target;
      const keep = n.data("gtype") === "room"
        ? n.union(n.descendants()).union(n.descendants().connectedEdges()).union(n.connectedEdges())
        : n.closedNeighborhood().union(n.parent());   // include the parent room so its border lights
      cy.elements().addClass("hl-dim");
      keep.removeClass("hl-dim").addClass("hl");
    });
    cy.on("mouseout", "node", () => {
      if (cy.elements(".focus, .context").nonempty()) return;
      cy.elements().removeClass("hl hl-dim");
    });

    // Cytoscape's cxttap also fires the originalEvent's preventDefault for nodes — but the
    // native menu suppression can't rely on cxttap alone (it fires after the browser menu, and
    // only over hit elements). The DOM-level capture-phase listener below is the real guarantee;
    // these handlers just drive the app verb menu.
    cy.on("cxttap", "node", (evt) => {
      evt.originalEvent?.preventDefault?.();
      const n = evt.target;
      // Anchor the menu at the CURSOR, not the node's center. `evt.renderedPosition` is the
      // click point in the same rendered (cy-container) coordinate space the menu is positioned
      // in (#cy fills the position:relative .graph-wrap), so it drops the menu where the pointer
      // actually is; fall back to the node center only if the event lacks a position.
      const rp = evt.renderedPosition ?? n.renderedPosition();
      setMenu({ x: rp.x, y: rp.y, id: n.id(), type: n.data("gtype") });
    });
    cy.on("cxttap", "edge", (evt) => { evt.originalEvent?.preventDefault?.(); setMenu(null); });
    cy.on("cxttap", (evt) => { if (evt.target === cy) { evt.originalEvent?.preventDefault?.(); setMenu(null); } });
    cy.on("pan zoom drag", () => setMenu(null));
    // Round 2 (issue 2): PR #89's container-level contextmenu preventDefault leaked the browser's
    // native menu on some paths. The leaks: (a) it sat on the inner #cy div, but cytoscape stacks
    // several <canvas> layers AND edgehandles injects its own canvas — a stray stopPropagation on
    // any of them, or a right-click landing on a layer outside the listener's subtree, slips past;
    // (b) bubble-phase can be pre-empted. Fix: register on the OUTER graph-wrap in the CAPTURE
    // phase so EVERY right-click anywhere in the graph area (canvas layers, DOM overlays, node/edge
    // HTML, empty background) is intercepted on the way DOWN, before anything can swallow it — the
    // app verb menu is then the only menu that ever appears. Removed on teardown.
    const container = ref.current;
    const wrap = (container.closest(".graph-wrap") as HTMLElement | null) ?? container;
    const suppressCtx = (e: Event) => e.preventDefault();
    wrap.addEventListener("contextmenu", suppressCtx, { capture: true });

    cyRef.current = cy;
    (window as any).__cy = cy;

    const eh = (cy as any).edgehandles({
      snap: true, noEdgeEventsInDraw: true,
      canConnect: (s: any, t: any) => s.id() !== t.id() && s.data("gtype") !== "room" && t.data("gtype") !== "room",
      edgeParams: () => ({ data: { color: "#6aa3ff", etype: "draft" } }),
    });
    ehRef.current = eh;
    eh.disable();
    cy.on("ehcomplete", (_evt: any, src: any, tgt: any, addedEdge: any) => {
      try { addedEdge?.remove(); } catch { /* ignore */ }
      setDrawMode(false);
      drawRef.current?.(src.id(), tgt.id());
    });

    return () => {
      try { eh.destroy(); } catch { /* ignore */ }
      ehRef.current = null;
      savedPos.current.clear();
      wrap.removeEventListener("contextmenu", suppressCtx, { capture: true } as any);
      if ((window as any).__cy === cy) (window as any).__cy = undefined;
      cy.destroy();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graph, findings, layers, filters, collapsed, hidden, groupBy, expandedRooms, model, mapMode]);

  // In skeleton mode a room id is "room:<targetId>" — strip to ask the host to fetch
  // that target's interior (a no-op if already merged into `graph`).
  const requestRoomInterior = (rid: string) => {
    if (!skeletonMode || !onRoomExpand) return;
    if (rid.startsWith("room:")) onRoomExpand(rid.slice(5));
  };
  // expand/collapse one room (used by double-tap + the room verb menu).
  const toggleRoom = (rid: string) => setExpandedRooms((s) => {
    const x = new Set(s);
    if (x.has(rid)) { x.delete(rid); justExpanded.current = null; justCollapsed.current = true; }
    else { x.add(rid); justExpanded.current = rid; justCollapsed.current = false; requestRoomInterior(rid); }
    return x;
  });
  const collapseAll = () => { justCollapsed.current = true; justExpanded.current = null; setExpandedRooms(new Set()); };
  // Expand-all at firmware scale would re-summon the whole graph — in skeleton mode the
  // host hasn't even loaded the interiors, so expand-all only expands CONTAINER rooms
  // (the firmware grandparent) to reveal the child-binary cards, never every leaf.
  const expandAll = () => {
    if (skeletonMode) {
      const containers = new Set(model.rooms.map((r) => model.parentOf.get(r.id)).filter(Boolean) as string[]);
      setExpandedRooms(containers);
      return;
    }
    setExpandedRooms(new Set(model.rooms.map((r) => r.id)));
  };

  // Toggle edgehandles draw mode on the live instance (no graph rebuild needed).
  useEffect(() => {
    const eh = ehRef.current; if (!eh) return;
    if (drawMode) { eh.enable(); eh.enableDrawMode(); } else { eh.disableDrawMode(); eh.disable(); }
  }, [drawMode]);

  useEffect(() => {
    const cy = cyRef.current; if (!cy) return;
    cy.$(":selected").unselect();
    if (selectedId) { const el = cy.getElementById(selectedId); if (el && el.nonempty()) { el.select(); el.connectedEdges?.().addClass("lit"); } }
  }, [selectedId]);

  // ── Phase 3: auto-expand the path to a focus target inside a collapsed room ────────────
  // (addresses the Phase-2 reviewer note: focusing/searching a node inside a collapsed group
  // must expand its group so the focus actually lands.)
  useEffect(() => {
    if (!focus?.id || groupBy === "none") return;
    const need: string[] = [];
    let p = model.parentOf.get(focus.id);
    while (p) { if (!expandedRooms.has(p)) need.push(p); p = model.parentOf.get(p); }
    if (need.length) setExpandedRooms((s) => { const x = new Set(s); need.forEach((r) => x.add(r)); return x; });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focus?.id, groupBy, model]);

  // ── Phase 5: panels-drive-scope (§6.3) ────────────────────────────────────────────────
  // When the host scopes the center view to a target (a left-tree row click), expand that
  // target's room and frame it — the panels DRIVE what the center shows. A no-op when a
  // focus owns the camera (focus is the finer, explicit gesture). Scope-frames the room's
  // card when collapsed, or its interior when open. Never fires on plain selection.
  useEffect(() => {
    const cy = cyRef.current; if (!cy || !scope || focus?.id || groupBy === "none") return;
    const rid = "room:" + scope;
    // In skeleton mode, scoping to a target loads + opens its interior on demand.
    if (skeletonMode) { requestRoomInterior(rid); }
    // expand the path to the scoped room so its card/interior is visible
    const need: string[] = [];
    let p: string | undefined = model.parentOf.get(rid);
    while (p) { if (!expandedRooms.has(p)) need.push(p); p = model.parentOf.get(p); }
    if (need.length) { setExpandedRooms((s) => { const x = new Set(s); need.forEach((r) => x.add(r)); return x; }); return; }
    const room = cy.getElementById(rid);
    if (room.nonempty()) {
      const eles = room.descendants().nonempty() ? room.descendants().union(room) : room;
      cy.animate({ fit: { eles, padding: 60 } }, { duration: 320 });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scope, groupBy, model, expandedRooms]);

  // ── Phase 2: apply the committed focus to the live cy instance ────────────────────────
  useEffect(() => {
    const cy = cyRef.current; if (!cy) return;
    let cancelled = false;
    const restore = () => {
      if (savedPos.current.size) {
        cy.batch(() => savedPos.current.forEach((p, id) => { const el = cy.getElementById(id); if (!el.empty()) el.position(p); }));
        savedPos.current.clear();
      }
    };
    let ran = false;
    const apply = () => {
      if (cancelled || ran) return;
      ran = true;
      cy.elements().removeClass("focus context focus-anchor hl hl-dim");
      if (!focus?.id) { if (savedPos.current.size) { restore(); cy.animate({ fit: { eles: cy.elements(), padding: 28 } }, { duration: 300 }); } return; }
      const anchor = cy.getElementById(focus.id);
      if (anchor.empty()) return;
      const h = Math.max(1, Math.min(3, focus.hop || 1));
      const ring = new Map<string, number>([[anchor.id(), 0]]);
      let frontier = anchor as any;
      let reached = anchor as any;
      for (let i = 1; i <= h; i++) {
        const next = frontier.neighborhood().nodes().difference(reached);
        next.forEach((n: any) => { if (!ring.has(n.id())) ring.set(n.id(), i); });
        reached = reached.union(next);
        frontier = next;
      }
      const focusNodes = reached;
      const focusEles = focusNodes.union(focusNodes.edgesWith(focusNodes));
      cy.elements().not(focusEles).addClass("context");
      focusEles.addClass("focus");
      anchor.removeClass("focus").addClass("focus focus-anchor");

      // Hub focus → CONCENTRIC (D7): the anchor centered, neighbors ringed by hop distance, so
      // a high-degree hub's neighbors are placed around it on-screen instead of running off into
      // the dark. Positions are saved first so clearing focus restores the resting graph exactly
      // (the rearrange is a reversible live-instance nicety, not a resting-layout change).
      restore();
      cy.batch(() => focusNodes.forEach((n: any) => savedPos.current.set(n.id(), { ...n.position() })));
      const maxRing = Math.max(1, ...[...ring.values()]);
      focusNodes.layout({
        name: "concentric", animate: false, fit: false, padding: 40,
        // outermost ring = the anchor (level high), inner rings = farther hops, so concentric's
        // "higher level toward center" rule centers the anchor and rings neighbors by hop.
        concentric: (n: any) => maxRing + 1 - (ring.get(n.id()) ?? maxRing),
        levelWidth: () => 1,
        minNodeSpacing: 26, spacingFactor: 1.1,
        startAngle: (3 / 2) * Math.PI,
      } as any).run();
      cy.animate({ fit: { eles: focusNodes, padding: 70 } }, { duration: 340 });
    };
    applyFocusRef.current = apply;
    if (layoutDone.current) apply();
    return () => { cancelled = true; if (applyFocusRef.current === apply) applyFocusRef.current = null; };
  }, [focus?.id, focus?.hop, graph, hidden, expandedRooms]);

  // Legend isolate/preview-by-type (Phase 1).
  useEffect(() => {
    const cy = cyRef.current; if (!cy) return;
    cy.elements().removeClass("type-dim");
    if (!isolateType || focus?.id) return;
    const keepNodes = cy.nodes(`[tkey = "${isolateType}"]`);
    const keepByEdge = cy.edges(`[etype = "${isolateType}"]`);
    const keepEdges = keepByEdge.union(keepNodes.connectedEdges());
    const keep = keepNodes.union(keepEdges).union(keepByEdge.connectedNodes());
    cy.elements().not(keep).addClass("type-dim");
  }, [isolateType, graph, focus?.id]);

  const fit = () => cyRef.current?.animate({ fit: { eles: cyRef.current.elements(), padding: 28 } }, { duration: 250 });
  const zoom = (f: number) => { const cy = cyRef.current; if (cy) cy.animate({ zoom: cy.zoom() * f, center: { eles: cy.elements() } }, { duration: 150 }); };

  // Verb-menu actions (right-click).
  const menuIsRoom = menu?.type === "room";
  const menuFocus = () => { if (menu) onFocus?.(menu.id, hop); setMenu(null); };
  const menuExpand = () => { if (menu) { const h = Math.min(3, (focus?.id === menu.id ? (focus.hop || 1) : 1) + 1); onFocus?.(menu.id, h); } setMenu(null); };
  const menuHide = () => { if (menu) setHidden((s) => { const x = new Set(s); x.add(menu.id); return x; }); setMenu(null); };
  const menuReveal = () => { if (menu) { const realId = menu.id.startsWith("room:") ? menu.id.slice(5) : menu.id; onSelect(realId, menuIsRoom ? "target" : menu.type); } setMenu(null); };
  const menuToggleRoom = () => { if (menu) toggleRoom(menu.id); setMenu(null); };
  const restoreHidden = () => setHidden(new Set());

  const curHop = focus?.hop || 1;
  const compound = groupBy !== "none";

  // ── Phase 5 layer/filter helpers ──────────────────────────────────────────────────────
  const toggleNodeLayer = (key: string) =>
    setLayers({ ...layers, nodes: { ...layers.nodes, [key]: layers.nodes[key] === false } });
  const toggleEdgeLayer = (key: string) =>
    setLayers({ ...layers, edges: { ...layers.edges, [key]: layers.edges[key] === false } });
  // node-types actually present (so the panel lists only relevant toggles).
  const presentNodeTypes = useMemo(() => {
    const s = new Set<string>();
    for (const n of graph.nodes) {
      if (n.type === "finding") s.add("finding");
      else if (n.type === "node") s.add(n.node_type as string);
    }
    return s;
  }, [graph]);
  const presentEdgeClasses = useMemo(() => {
    const s = new Set<string>();
    for (const e of graph.edges) s.add((EDGE_CLASSES.find((c) => c.types.includes(e.type))?.key) || "semantic");
    return s;
  }, [graph]);
  const targetsInGraph = useMemo(
    () => graph.nodes.filter((n) => n.type === "target").map((n) => ({ id: n.id, label: n.label })),
    [graph]);
  const findingTypesInGraph = useMemo(
    () => [...new Set(graph.nodes.filter((n) => n.type === "finding")
      .map((n) => (n.finding_type as string) || "other"))], [graph]);
  const filterActive = anyFilterActive(filters);
  const layersDefault = NODE_TYPE_LAYERS.every((l) => nodeLayerOn(layers, l.key) === !NODE_LAYER_DEFAULT_OFF.has(l.key))
    && EDGE_CLASSES.every((c) => layers.edges[c.key] !== false);
  const resetLayers = () => setLayers(defaultLayers());
  const clearFilters = () => setFilters(defaultFilters());

  return (
    <div className="graph-wrap">
      <div id="cy" ref={ref} />
      <div className="graph-meta">
        {/* In skeleton mode the headline count is the ROOMS, not the (deliberately not-loaded)
            interior node count — the whole point is the browser never holds ~13k nodes. */}
        {skeletonMode
          ? <span className="badge" title="Showing the firmware skeleton — expand a room to load its interior on demand">
              skeleton · {model.rooms.length} rooms
            </span>
          : <span className="badge">{graph.nodes.length} nodes</span>}
        {!compound && collapsed.size > 0 && <span className="badge" style={{ marginLeft: 6 }}>{collapsed.size} collapsed</span>}
        {!skeletonMode && compound && expandedRooms.size === 0 && model.rooms.length > 0 && <span className="badge" style={{ marginLeft: 6 }}>skeleton · {model.rooms.length} rooms</span>}
        {skeletonMode && roomLoading && roomLoading.size > 0 && <span className="badge" style={{ marginLeft: 6 }}>loading {roomLoading.size} room{roomLoading.size > 1 ? "s" : ""}…</span>}
      </div>
      {skeletonMode && (
        <div className="graph-skeleton-hint"
             style={{ position: "absolute", left: 10, top: 10, zIndex: 5, maxWidth: 320,
                      background: "var(--surface-2)", border: "1px solid var(--border)", borderRadius: 8,
                      padding: "6px 9px", fontSize: 11, color: "var(--text-dim, #8893a6)", pointerEvents: "none" }}>
          Showing the skeleton — {model.rooms.length} rooms. Double-click (or "Expand room") a room to load its interior.
        </div>
      )}
      {hidden.size > 0 && (
        <button className="badge hide-chip" title="Restore all hidden nodes"
                onClick={restoreHidden}
                style={{ position: "absolute", left: 10, bottom: 10, cursor: "pointer", zIndex: 5, display: "inline-flex", alignItems: "center", gap: 4 }}>
          <Icon name="refresh" size={11} /> {hidden.size} hidden · restore ↺
        </button>
      )}
      {focus?.id && (
        <div className="focus-bar"
             style={{ position: "absolute", right: 10, top: 10, zIndex: 6, display: "flex", gap: 4, alignItems: "center",
                      background: "var(--surface-2)", border: "1px solid var(--border)", borderRadius: 8, padding: "3px 6px" }}>
          <span className="muted" style={{ fontSize: 11 }}>focus · {curHop} hop{curHop > 1 ? "s" : ""}</span>
          <button className="btn sm icon ghost" title="Fewer hops" disabled={curHop <= 1}
                  onClick={() => onFocus?.(focus.id, Math.max(1, curHop - 1))}><Icon name="minus" size={12} /></button>
          <button className="btn sm icon ghost" title="More hops" disabled={curHop >= 3}
                  onClick={() => onFocus?.(focus.id, Math.min(3, curHop + 1))}><Icon name="plus" size={12} /></button>
          <button className="btn sm ghost" title="Clear focus — back to the full graph" onClick={() => onClearFocus?.()}>
            <Icon name="x" size={12} /> clear
          </button>
        </div>
      )}
      {menu && (
        <div className="menu graph-cxt"
             // Clamp against the ACTUAL canvas size so a cursor-anchored menu near the right/bottom
             // edge is nudged just enough to stay on-screen (the old fixed 1100 detached it from the
             // pointer on wide canvases); otherwise it sits exactly where the click landed.
             style={{ position: "absolute",
                      left: Math.max(4, Math.min(menu.x, (cyRef.current?.width() ?? 1200) - 204)),
                      top: Math.max(4, Math.min(menu.y, (cyRef.current?.height() ?? 800) - (menuIsRoom ? 84 : 152))),
                      zIndex: 20, width: 200 }}
             onMouseLeave={() => setMenu(null)}>
          {menuIsRoom ? (
            <>
              <div className="mi" onClick={menuToggleRoom}><Icon name={expandedRooms.has(menu.id) ? "minus" : "plus"} size={13} /> {expandedRooms.has(menu.id) ? "Collapse room" : "Expand room"}</div>
              <div className="mi" onClick={menuReveal}><Icon name="fit" size={13} /> Reveal in panel</div>
            </>
          ) : (
            <>
              <div className="mi" onClick={menuFocus}><Icon name="search" size={13} /> Focus neighborhood</div>
              <div className="mi" onClick={menuExpand}><Icon name="plus" size={13} /> Expand one hop</div>
              <div className="mi" onClick={menuReveal}><Icon name="fit" size={13} /> Reveal in panel</div>
              <div className="mi danger" onClick={menuHide}><Icon name="x" size={13} /> Hide this node</div>
            </>
          )}
        </div>
      )}
      {/* ── Phase 5: FILTER CHIP RAIL (value facets, fade-first) ──────────────────────────
          A collapsible rail of composable VALUE filters (severity / target / finding-type),
          distinct from the class LAYERS. Fade-first by default (a filtered-out element fades,
          keeping context); the ⓘ toggle flips to hard-hide. Pinned top-left under the
          breadcrumb, shown only when opened or active. */}
      {(filterOpen || filterActive) && (
        <div className="filter-rail">
          <span className="rail-label"><Icon name="filter" size={11} /> filters</span>
          <select className="chip-sel" value={filters.severity ?? ""} title="Minimum finding severity"
                  onChange={(e) => setFilters({ ...filters, severity: e.target.value || null })}>
            <option value="">severity: any</option>
            <option value="low">≥ low</option><option value="medium">≥ medium</option>
            <option value="high">≥ high</option><option value="critical">critical</option>
          </select>
          {findingTypesInGraph.length > 1 && (
            <select className="chip-sel" value={filters.findingType ?? ""} title="Finding type"
                    onChange={(e) => setFilters({ ...filters, findingType: e.target.value || null })}>
              <option value="">type: any</option>
              {findingTypesInGraph.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
          )}
          {targetsInGraph.length > 1 && (
            <select className="chip-sel" value="" title="Add a target to the filter (others fade)"
                    onChange={(e) => { const v = e.target.value; if (v && !filters.targets.includes(v)) setFilters({ ...filters, targets: [...filters.targets, v] }); }}>
              <option value="">+ target…</option>
              {targetsInGraph.filter((t) => !filters.targets.includes(t.id)).map((t) => <option key={t.id} value={t.id}>{t.label}</option>)}
            </select>
          )}
          {filters.targets.map((tid) => {
            const t = targetsInGraph.find((x) => x.id === tid);
            return (
              <span className="chip active" key={tid} title="Remove target from filter"
                    onClick={() => setFilters({ ...filters, targets: filters.targets.filter((x) => x !== tid) })}>
                {t?.label || tid.slice(0, 8)} <Icon name="x" size={10} />
              </span>
            );
          })}
          <button className={"chip" + (filters.mode === "hide" ? " active" : "")}
                  title={filters.mode === "hide" ? "Hard-hide filtered elements (click → fade-first)" : "Fade filtered elements (click → hard-hide)"}
                  onClick={() => setFilters({ ...filters, mode: filters.mode === "hide" ? "fade" : "hide" })}>
            {filters.mode === "hide" ? "hide" : "fade"}
          </button>
          {filterActive && <button className="chip clear" title="Clear all filters" onClick={clearFilters}>clear ↺</button>}
        </div>
      )}
      <div className="graph-controls">
        {/* group-by — a LABELLED selector (the bare "by target" pill never said WHAT it did),
            sized to its own content so it no longer forces the icon buttons to its width. */}
        <div className="gb-group">
          <span className="gb-label">group by</span>
          <select className="sel group-by-sel" value={groupBy} title="Reorganize the canvas into compound rooms"
                  onChange={(e) => setGroupBy(e.target.value as GroupBy)}>
            <option value="target">target</option>
            <option value="type">type</option>
            <option value="finding">finding</option>
            <option value="none">none (flat)</option>
          </select>
        </div>
        {/* ALL controls sit in ONE flat row along the bottom — the action icons (layers /
            filter / skeleton / draw) then the zoom cluster. The group-by selector is the only
            thing on the row above it. */}
        <div className="button-row">
        <div className="ctrl-cluster">
        {/* ── LAYER PANEL: show/hide each node TYPE and edge CLASS independently (§2.2). */}
        <div style={{ position: "relative" }}>
          <button className={"btn icon" + (layersDefault ? "" : " primary")} title="Layers — show/hide node types & edge classes" onClick={() => { setLayersOpen((o) => !o); setFilterOpen(false); }}>
            <Icon name="hex" />
          </button>
          {layersOpen && (
            <div className="menu layer-panel" style={{ right: 0, top: "auto", bottom: 36, minWidth: 248 }} onMouseLeave={() => setLayersOpen(false)}>
              <div className="lp-head">
                <span className="muted" style={{ fontSize: 11 }}>node types</span>
                {!layersDefault && <button className="lp-reset" onClick={resetLayers} title="Reset layers to defaults">reset</button>}
              </div>
              <div className="lp-grid">
                {NODE_TYPE_LAYERS.filter((l) => presentNodeTypes.has(l.key)).map((l) => (
                  <label className="lp-row" key={l.key} title={`Toggle ${l.label} nodes`}>
                    <input type="checkbox" checked={nodeLayerOn(layers, l.key)} onChange={() => toggleNodeLayer(l.key)} />
                    <span>{l.label}</span>
                  </label>
                ))}
              </div>
              <div className="lp-head"><span className="muted" style={{ fontSize: 11 }}>edge classes</span></div>
              <div className="lp-grid">
                {EDGE_CLASSES.filter((c) => presentEdgeClasses.has(c.key)).map((c) => (
                  <label className="lp-row" key={c.key} title={`Toggle ${c.label} edges`}>
                    <input type="checkbox" checked={layers.edges[c.key] !== false} onChange={() => toggleEdgeLayer(c.key)} />
                    <span>{c.label}</span>
                  </label>
                ))}
              </div>
            </div>
          )}
        </div>
        {/* filters / extras */}
        <div style={{ position: "relative" }}>
          <button className={"btn icon" + (filterActive ? " primary" : "")} title="Filters & options" onClick={() => { setFilterOpen((o) => !o); setLayersOpen(false); }}><Icon name="filter" /></button>
          {filterOpen && (
            <div className="menu" style={{ right: 0, top: "auto", bottom: 36, minWidth: 216 }}>
              {compound && (
                <>
                  <div className="mi" onClick={expandAll}><Icon name="fit" size={13} /> Expand all rooms</div>
                  <div className="mi" onClick={collapseAll}><Icon name="minus" size={13} /> Collapse all (skeleton)</div>
                  <div style={{ height: 1, background: "var(--border)", margin: "4px 0" }} />
                </>
              )}
              <div className="sub"><label className="muted" style={{ fontSize: 11 }}>findings</label>
                <select className="sel" value={findings} onChange={(e) => setFindings(e.target.value as any)}>
                  <option value="all">all findings</option><option value="unresolved">unresolved only</option><option value="none">hide findings</option>
                </select>
              </div>
              <div className="sub"><label className="muted" style={{ fontSize: 11 }}>focus neighborhood ({hop} hop{hop > 1 ? "s" : ""})</label>
                <input type="range" min={1} max={3} value={hop} onChange={(e) => setHop(Number(e.target.value))} style={{ width: "100%" }} />
              </div>
              {!compound && <div className="mi" onClick={() => setCollapsed(new Set())}><Icon name="fit" size={13} /> expand all</div>}
              {hidden.size > 0 && <div className="mi" onClick={restoreHidden}><Icon name="refresh" size={13} /> restore {hidden.size} hidden</div>}
            </div>
          )}
        </div>
        {/* Skeleton toggle when grouped: ONE button (collapse-all ⇆ expand-all). Replaces the
            old standalone −/+ collapse/expand pair, which both duplicated the zoom −/+ visually
            (issue 4 — two identical +/- pill pairs) and the filter-menu's expand/collapse rows.
            A firmware/chip glyph reads as "the rooms", never as a zoom control. */}
        {compound && (
          expandedRooms.size > 0
            ? <button className="btn icon" title="Collapse all rooms (back to the skeleton)" onClick={collapseAll}><Icon name="chip" /></button>
            : <button className="btn icon" title="Expand all rooms"
                      onClick={() => { if (model.rooms.length && (graph.nodes.length <= 200 || window.confirm(`Expand all rooms? This reveals ~${graph.nodes.length} nodes.`))) expandAll(); }}>
                <Icon name="chip" />
              </button>
        )}
        {onDrawEdge && (
          <button className={"btn icon" + (drawMode ? " primary" : "")}
                  title={drawMode ? "Draw edge: drag from a source node to a target node (click to cancel)" : "Draw an edge: drag from one node to another"}
                  onClick={() => setDrawMode((d) => !d)}><Icon name="link" /></button>
        )}
        </div>
        {/* zoom cluster — the ONLY +/- pair on the rail now. */}
        <div className="zoom-cluster">
          <button className="btn icon" title="Zoom in" onClick={() => zoom(1.25)}><Icon name="plus" /></button>
          <button className="btn icon" title="Fit to view" onClick={fit}><Icon name="fit" /></button>
          <button className="btn icon" title="Zoom out" onClick={() => zoom(0.8)}><Icon name="minus" /></button>
        </div>
        </div>
      </div>
    </div>
  );
}
