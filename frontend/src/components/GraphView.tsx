import { useEffect, useMemo, useRef, useState } from "react";
import cytoscape from "cytoscape";
import dagre from "cytoscape-dagre";
import edgehandles from "cytoscape-edgehandles";
import fcose from "cytoscape-fcose";
import { Graph } from "../api";
import { Icon } from "./Icon";

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
};
// Per-node-type shape, so types are distinguishable independent of color (a redundant
// channel: color + shape, so types stay tellable apart when nodes shrink below
// hue-resolution and for low-contrast/colorblind viewers — color is never weakened).
// Phase-1 extension: every conceptual type is now shape-distinct.
export const NODE_SHAPE: Record<string, string> = {
  socket: "hexagon", endpoint: "tag", param: "ellipse", input: "triangle", sink: "vee",
  struct: "barrel", hypothesis: "pentagon", pattern: "diamond",
  string: "round-tag", symbol: "round-diamond",
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
const LOD_NEAR = 1.35;
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
  const [findings, setFindings] = useState<"all" | "unresolved" | "none">("all");
  const [showFns, setShowFns] = useState(true);
  // Phase-2 legacy double-tap collapse (flat-mode only — used when groupBy === "none").
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [filterOpen, setFilterOpen] = useState(false);
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
  const [groupBy, setGroupBy] = useState<GroupBy>("target");
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

  // graph size tier (drives the default frame, design §1/D1).
  const tier = useMemo(() => {
    const n = graph.nodes.length + graph.edges.length;
    if (n <= 40) return "small" as const;
    if (n <= 80) return "medium" as const;
    return "large" as const;
  }, [graph]);

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
    const rooms: { id: string; label: string; tkey: string; gkind: "target" | "type" | "finding"; kind?: string }[] = [];
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
        rooms.push({ id: rid, label: t.label, tkey: t.kind as string, gkind: "target", kind: t.kind as string });
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
    const key = groupBy + "|" + graph.project_id + "|" + graph.nodes.length + "|" + tier;
    if (autoKey.current === key) return;
    autoKey.current = key;
    if (tier === "large") {
      // The SKELETON (design §1): show the rooms but hide their interiors. A firmware
      // grandparent is EXPANDED so its ~12 child-target rooms are visible as collapsed cards
      // ("12 boxes inside one box"); every leaf room stays collapsed. So expand only rooms
      // that PARENT another room (the containers), never the leaves.
      const parentRooms = new Set(model.rooms.map((r) => model.parentOf.get(r.id)).filter(Boolean) as string[]);
      setExpandedRooms(parentRooms);
    } else {
      setExpandedRooms(new Set(model.rooms.map((r) => r.id)));               // auto-expand (small/med)
    }
  }, [groupBy, graph, tier, model]);

  useEffect(() => {
    if (!ref.current) return;
    const compound = groupBy !== "none";
    const baseHidden = new Set<string>();
    for (const n of graph.nodes) {
      if (n.type === "node" && (n.node_type === "symbol" || n.node_type === "string")) baseHidden.add(n.id);
      else if (n.type === "node" && n.node_type === "function" && !showFns) baseHidden.add(n.id);
      else if (n.type === "finding") {
        if (findings === "none") baseHidden.add(n.id);
        else if (findings === "unresolved" && RESOLVED.has(n.status)) baseHidden.add(n.id);
      }
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
      if (roomById.has(id)) return roomOpen(id) ? id : (collapsedAncestorRoom(id) ?? id);
      const room = parentOf.get(id);
      if (!room) return id;                       // loose (bus lane) — represents itself
      return collapsedAncestor(id) ?? (roomOpen(room) ? id : room);
    };

    // visible content nodes (not in a collapsed room, not base/manually hidden)
    const visibleContent = compound
      ? graph.nodes.filter((n) => !isHidden(n.id) && (() => { const r = parentOf.get(n.id); return r ? roomOpen(r) : true; })())
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
      return { nNodes, nFind, worst, wgt };
    };

    // aggregate cross-room edges into meta-edges; keep within-open-scope edges direct.
    const degree = new Map<string, number>();
    const realEdges = graph.edges.filter((e) => !isHidden(e.source) && !isHidden(e.target));
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
      const chip = nFind > 0 ? `  ${nNodes} · ${nFind}⚠` : nNodes > 0 ? `  ${nNodes}` : "";
      const parent = parentOf.get(r.id);
      const showParent = parent && roomById.has(parent) && expandedRooms.has(parent);
      return { data: {
        id: r.id, label: open ? r.label : r.label + chip, gtype: "room",
        kind: r.kind, tkey: r.tkey, gkind: r.gkind,
        roomOpen: open ? 1 : 0, roomSev: sev, roomWorst: worst,
        roomWeight: Math.max(8, Math.min(60, wgt)), nFind, nNodes,
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

    const elements = [...roomElements, ...contentElements, ...directEdgeElements, ...metaEdgeElements];

    const cy = cytoscape({
      container: ref.current, elements, wheelSensitivity: 0.25,
      style: [
        {
          selector: "node",
          style: {
            label: "data(label)", color: "#cdd5e2", "font-size": "9px", "font-weight": 600,
            "text-opacity": "mapData(degc, 8, 24, 0.0, 0.55)" as any,
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
            "background-opacity": 0.92,
            label: "data(label)", color: "#0a0c12", "font-size": "12px", "font-weight": 800,
            "text-valign": "center", "text-halign": "center", "text-opacity": 1, "min-zoomed-font-size": 5,
            "text-max-width": "138px", "text-wrap": "ellipsis", "text-margin-y": 0,
            // finding-severity rollup ring: the worst finding inside tints the border (red/orange).
            "border-width": (n: any) => (n.data("roomWorst") >= 3 ? 4 : n.data("roomWorst") >= 0 ? 2.5 : 1.5),
            "border-color": (n: any) => (n.data("roomSev") ? SEV[n.data("roomSev")] : "#0a0c12"),
            "underlay-color": (n: any) => (n.data("roomSev") ? SEV[n.data("roomSev")] : "#39c5cf"),
            "underlay-opacity": (n: any) => (n.data("roomWorst") >= 3 ? 0.45 : n.data("roomWorst") >= 0 ? 0.22 : 0),
            "underlay-padding": (n: any) => (n.data("roomWorst") >= 3 ? 9 : 6),
            "transition-property": "opacity", "transition-duration": "160ms" as any,
        } },
        // Hubs (degree ≥ 8): a degree-driven 30→40px ramp + a slight glow.
        { selector: "node[tier = 'hub']", style: {
            width: "mapData(degc, 8, 24, 30, 40)" as any, height: "mapData(degc, 8, 24, 30, 40)" as any,
            "text-opacity": "mapData(degc, 8, 24, 0.55, 0.95)" as any,
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

        // MID: structure — the skeleton's default frame often lands HERE (LARGE), so collapsed
        // room cards keep a readable below-card label (smaller than FAR since zoom is higher);
        // hub/anchor labels show, semantic + meta edge labels return, leaf labels stay suppressed.
        { selector: "node[gtype = 'room'][roomOpen = 0].lod-mid", style: {
            "font-size": "18px", "min-zoomed-font-size": 0, "text-opacity": 1,
            color: "#e8edf6", "font-weight": 800,
            "text-valign": "bottom", "text-margin-y": 7, "text-max-width": "300px", "text-wrap": "wrap",
            "text-background-color": "#0a0c12", "text-background-opacity": 0.7, "text-background-padding": "3px",
            "text-background-shape": "roundrectangle",
        } },
        { selector: "node[gtype = 'node'].lod-mid", style: { "text-opacity": 0 } },
        { selector: "node[tier = 'hub'].lod-mid", style: { "text-opacity": 0.9 } },
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
        { selector: ".hl-dim", style: { opacity: 0.12 } as any },
        { selector: "node.type-dim", style: { opacity: 0.1, "text-opacity": 0, "underlay-opacity": 0 } },
        { selector: "edge.type-dim", style: { opacity: 0.05, label: "" } },
      ],
    });

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
      layoutDone.current = true;
      // Auto-frame a freshly-expanded room (scoped, never on a plain rebuild) unless a focus
      // owns the camera. (design §3.4 — auto-zoom fires only on an explicit navigation act.)
      const je = justExpanded.current; justExpanded.current = null;
      if (je && !focusValRef.current?.id) {
        const room = cy.getElementById(je);
        if (room.nonempty()) { const inside = room.descendants().union(room); if (inside.length > 1) cy.animate({ fit: { eles: inside, padding: 60 } }, { duration: 340 }); }
      } else if (!focusValRef.current?.id && !je) {
        // First open / rebuild with no pending nav: frame ALL visible elements (rooms + the
        // network-bus sockets + any loose nodes) so nothing is cut off and the default
        // LARGE/PATHOLOGICAL frame is the full set of labelled cards filling the pane.
        cy.fit(cy.elements(":visible"), 36);
      }
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
        if (tapRef.current.id === id && now - tapRef.current.t < 350) { toggleRoom(id); tapRef.current = { id: null, t: 0 }; }
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

    cy.on("mouseover", "node", (evt) => {
      if (cy.elements(".focus, .context").nonempty()) return;
      const n = evt.target;
      cy.elements().addClass("hl-dim");
      n.closedNeighborhood().removeClass("hl-dim").addClass("hl");
    });
    cy.on("mouseout", "node", () => {
      if (cy.elements(".focus, .context").nonempty()) return;
      cy.elements().removeClass("hl hl-dim");
    });

    cy.on("cxttap", "node", (evt) => {
      evt.originalEvent?.preventDefault?.();
      const n = evt.target;
      const rp = n.renderedPosition();
      setMenu({ x: rp.x, y: rp.y, id: n.id(), type: n.data("gtype") });
    });
    cy.on("cxttap", (evt) => { if (evt.target === cy) setMenu(null); });
    cy.on("pan zoom drag", () => setMenu(null));

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
      if ((window as any).__cy === cy) (window as any).__cy = undefined;
      cy.destroy();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graph, findings, showFns, collapsed, hidden, groupBy, expandedRooms, model]);

  // expand/collapse one room (used by double-tap + the room verb menu).
  const toggleRoom = (rid: string) => setExpandedRooms((s) => {
    const x = new Set(s);
    if (x.has(rid)) { x.delete(rid); justExpanded.current = null; }
    else { x.add(rid); justExpanded.current = rid; }
    return x;
  });
  const collapseAll = () => setExpandedRooms(new Set());
  const expandAll = () => setExpandedRooms(new Set(model.rooms.map((r) => r.id)));

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

  return (
    <div className="graph-wrap">
      <div id="cy" ref={ref} />
      <div className="graph-meta">
        <span className="badge">{graph.nodes.length} nodes</span>
        {!compound && collapsed.size > 0 && <span className="badge" style={{ marginLeft: 6 }}>{collapsed.size} collapsed</span>}
        {compound && expandedRooms.size === 0 && model.rooms.length > 0 && <span className="badge" style={{ marginLeft: 6 }}>skeleton · {model.rooms.length} rooms</span>}
      </div>
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
             style={{ position: "absolute", left: Math.max(4, Math.min(menu.x, 1100)), top: Math.max(4, menu.y), zIndex: 20, minWidth: 178 }}
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
      <div className="graph-controls">
        <div style={{ position: "relative" }}>
          <button className="btn icon" title="Filter & grouping" onClick={() => setFilterOpen((o) => !o)}><Icon name="filter" /></button>
          {filterOpen && (
            <div className="menu" style={{ right: 0, top: "auto", bottom: 36, minWidth: 216 }}>
              <div className="sub"><label className="muted" style={{ fontSize: 11 }}>group by (compound rooms)</label>
                <select className="sel" value={groupBy} onChange={(e) => setGroupBy(e.target.value as GroupBy)}>
                  <option value="target">target (default)</option>
                  <option value="type">node type</option>
                  <option value="finding">finding</option>
                  <option value="none">none (flat)</option>
                </select>
              </div>
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
              <div className="mi" onClick={() => setShowFns((v) => !v)}><Icon name={showFns ? "check" : "x"} size={13} /> functions</div>
              {!compound && <div className="mi" onClick={() => setCollapsed(new Set())}><Icon name="fit" size={13} /> expand all</div>}
              {hidden.size > 0 && <div className="mi" onClick={restoreHidden}><Icon name="refresh" size={13} /> restore {hidden.size} hidden</div>}
            </div>
          )}
        </div>
        {/* Quick collapse/expand-all when grouped (one-click skeleton ⇆ full). */}
        {compound && (
          <>
            <button className="btn icon" title="Collapse all rooms (back to the skeleton)" onClick={collapseAll}><Icon name="minus" /></button>
            <button className="btn icon" title="Expand all rooms"
                    onClick={() => { if (model.rooms.length && (graph.nodes.length <= 200 || window.confirm(`Expand all rooms? This reveals ~${graph.nodes.length} nodes.`))) expandAll(); }}>
              <Icon name="plus" />
            </button>
          </>
        )}
        {onDrawEdge && (
          <button className={"btn icon" + (drawMode ? " primary" : "")}
                  title={drawMode ? "Draw edge: drag from a source node to a target node (click to cancel)" : "Draw an edge: drag from one node to another"}
                  onClick={() => setDrawMode((d) => !d)}><Icon name="link" /></button>
        )}
        <button className="btn icon" title="Fit" onClick={fit}><Icon name="fit" /></button>
        <button className="btn icon" title="Zoom in" onClick={() => zoom(1.25)}><Icon name="plus" /></button>
        <button className="btn icon" title="Zoom out" onClick={() => zoom(0.8)}><Icon name="minus" /></button>
      </div>
    </div>
  );
}
