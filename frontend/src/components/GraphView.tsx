import { useEffect, useMemo, useRef, useState } from "react";
import cytoscape from "cytoscape";
import dagre from "cytoscape-dagre";
import edgehandles from "cytoscape-edgehandles";
import { Graph } from "../api";
import { Icon } from "./Icon";

cytoscape.use(dagre);
cytoscape.use(edgehandles);

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

// A committed focus: the anchor node + the hop radius of neighborhood it pulls into focus.
export interface FocusSpec { id: string; hop: number }

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
  // true once the current cy's initial dagre layout has settled — so the focus effect knows
  // whether to apply immediately or wait for layoutstop (positions must be final first).
  const layoutDone = useRef(false);
  // the live focus-applier, so the build effect's layoutstop can invoke the *current* one.
  const applyFocusRef = useRef<(() => void) | null>(null);
  const [findings, setFindings] = useState<"all" | "unresolved" | "none">("all");
  const [showFns, setShowFns] = useState(true);
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

  // keep the latest callbacks in refs so the cytoscape effect needn't re-run on them
  drawRef.current = onDrawEdge;
  focusCbRef.current = onFocus;
  // the current committed focus, mirrored into a ref so the build effect's one-shot
  // layoutstop handler can read it without re-subscribing.
  const focusValRef = useRef<FocusSpec | null>(null);
  focusValRef.current = focus ?? null;

  // children map for collapse: contains (parent→child) + about (node/target → its finding)
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

  useEffect(() => {
    if (!ref.current) return;
    const baseHidden = new Set<string>();
    for (const n of graph.nodes) {
      if (n.type === "node" && (n.node_type === "symbol" || n.node_type === "string")) baseHidden.add(n.id);
      else if (n.type === "node" && n.node_type === "function" && !showFns) baseHidden.add(n.id);
      else if (n.type === "finding") {
        if (findings === "none") baseHidden.add(n.id);
        else if (findings === "unresolved" && RESOLVED.has(n.status)) baseHidden.add(n.id);
      }
    }
    const collapseHidden = new Set<string>();
    for (const id of collapsed) for (const d of descendants(id)) collapseHidden.add(d);
    const isHidden = (id: string) => baseHidden.has(id) || collapseHidden.has(id) || hidden.has(id);

    const shown = graph.nodes.filter((n) => !isHidden(n.id));
    const vEdges = graph.edges.filter((e) => !isHidden(e.source) && !isHidden(e.target));
    const collapsedCount = (id: string) => descendants(id).filter((d) => !baseHidden.has(d)).length;

    // Importance signal → node size (§4.5): give the eye an entry point. Degree over the
    // VISIBLE edges, with targets/findings promoted to anchor tiers so hubs and the
    // firmware root read bigger and leaf nodes smaller (a bounded ramp, never every node 26px).
    const degree = new Map<string, number>();
    for (const e of vEdges) {
      degree.set(e.source, (degree.get(e.source) || 0) + 1);
      degree.set(e.target, (degree.get(e.target) || 0) + 1);
    }
    const elements = [
      ...shown.map((n) => {
        const isCollapsed = collapsed.has(n.id);
        const n2 = collapsedCount(n.id);
        const label = isCollapsed && n2 ? `${n.label}  ▸${n2}` : n.label;
        const deg = degree.get(n.id) || 0;
        // tier: anchor (target/project root) · hub (high degree) · detail (the rest).
        // The diamond findings get their own severity-driven bump in the stylesheet.
        const anchor = n.type === "target";
        const tier = anchor ? "anchor" : deg >= 8 ? "hub" : "detail";
        // legend isolate-by-type key (kind for targets, node_type for nodes, "finding").
        const tkey = n.type === "target" ? (n.kind as string)
          : n.type === "finding" ? "finding" : (n.node_type as string);
        const glyph = anchor ? (KIND_GLYPH[n.kind as string] || "") : "";
        return { data: {
          id: n.id, label, gtype: n.type, severity: n.severity, kind: n.kind,
          node_type: n.node_type, collapsed: isCollapsed ? 1 : 0,
          deg, tier, tkey, glyph,
          // capped degree for the mapData size ramp on hubs (8→24 → 30→40px).
          degc: Math.max(8, Math.min(24, deg)),
        } };
      }),
      ...vEdges.map((e) => {
        const a = e.attrs || {};
        let hint = "";
        if (e.type === "calls" && (a.call_sites?.length || (e.count && e.count > 1))) hint = ` ×${a.call_sites?.length || e.count}`;
        else if ((e.type === "listens_on" || e.type === "connects_to") && a.address) hint = ` @${a.address}`;
        else if (a.port) hint = ` :${a.port}`;
        const eclass = STRUCTURAL.has(e.type) ? "structural" : SEMANTIC.has(e.type) ? "semantic" : "other";
        return { data: { id: e.id, source: e.source, target: e.target, etype: e.type, elabel: e.type + hint,
                         color: EDGE_C[e.type] || "#3b4458", persist: ALWAYS_LABEL.has(e.type) ? 1 : 0,
                         eclass } };
      }),
    ];

    const cy = cytoscape({
      container: ref.current, elements, wheelSensitivity: 0.25,
      // Labels never render sub-legibly: they fade/vanish cleanly rather than colliding.
      style: [
        {
          selector: "node",
          style: {
            // Label discipline (§3.3/§5): node labels fade in with zoom (`mapData(zoom)`)
            // so they don't collide into soup when zoomed out on a big graph, and grow
            // crisp on approach. `min-zoomed-font-size` makes a label disappear cleanly
            // rather than render as illegible mush. Anchors/hubs/selection override below.
            label: "data(label)", color: "#cdd5e2", "font-size": "9px", "font-weight": 600,
            "text-opacity": "mapData(degc, 8, 24, 0.0, 0.55)" as any,
            "min-zoomed-font-size": 7,
            "text-valign": "bottom", "text-margin-y": 5, "text-wrap": "ellipsis", "text-max-width": "104px",
            "text-background-color": "#0a0c12", "text-background-opacity": 0.9, "text-background-padding": "3px",
            "text-background-shape": "roundrectangle",
            // Importance-driven sizing (§4.5): detail = 22px, hubs ramp 30→40 by degree.
            // Anchors/findings get explicit sizes in their own selectors below.
            width: 22, height: 22,
            "background-color": (n: any) => n.data("gtype") === "finding" ? (SEV[n.data("severity")] || "#7d8799") : n.data("gtype") === "node" ? (NODE_T[n.data("node_type")] || "#7d8799") : (KIND[n.data("kind")] || "#7d8799"),
            shape: ((n: any) => n.data("gtype") === "finding" ? "diamond" : NODE_SHAPE[n.data("node_type")] || (n.data("gtype") === "node" ? "round-rectangle" : "ellipse")) as any,
            "border-width": (n: any) => n.data("collapsed") ? 3 : 1.5, "border-color": (n: any) => n.data("collapsed") ? "#e3b341" : "#0a0c12",
            "underlay-color": (n: any) => n.data("gtype") === "finding" ? (SEV[n.data("severity")] || "#7d8799") : (KIND[n.data("kind")] || "#39c5cf"),
            "underlay-opacity": (n: any) => (n.data("gtype") === "finding" && (n.data("severity") === "critical" || n.data("severity") === "high") ? 0.28 : 0.12),
            "underlay-padding": 4, "underlay-shape": "ellipse",
            // Smooth the focus/context mute transitions (live class toggles, no relayout).
            "transition-property": "opacity background-blacken border-width", "transition-duration": "160ms" as any,
          },
        },
        // Hubs (degree ≥ 8): a degree-driven 30→40px ramp + a slight glow, and their
        // labels read a bit earlier (they're the structure-bearing nodes).
        { selector: "node[tier = 'hub']", style: {
            width: "mapData(degc, 8, 24, 30, 40)" as any, height: "mapData(degc, 8, 24, 30, 40)" as any,
            "text-opacity": "mapData(degc, 8, 24, 0.55, 0.95)" as any,
            "underlay-opacity": 0.18, "underlay-padding": 6,
        } },
        // Anchors (targets / firmware root): the entry point — big, crisp, always-labelled,
        // with a monochrome type glyph as a third (color-independent) channel.
        { selector: "node[tier = 'anchor']", style: {
            width: 40, height: 40, "font-size": "11px", "text-opacity": 1,
            "border-width": 2, "border-color": "#0a0c12",
            "underlay-opacity": 0.22, "underlay-padding": 7,
        } },
        // The anchor glyph (a centered monochrome mark on top of the node fill).
        { selector: "node[tier = 'anchor'][glyph != '']", style: {
            "background-image": (n: any) => glyphDataUri(n.data("glyph")) as any,
            "background-width": "58%", "background-height": "58%",
            "background-fit": "none", "background-clip": "node",
        } },
        // Findings stay diamonds on the SEV ramp, sized up for critical/high so the eye is
        // pulled to the hot ones first (the missing entry point).
        { selector: "node[gtype = 'finding']", style: {
            width: (n: any) => (n.data("severity") === "critical" ? 34 : n.data("severity") === "high" ? 30 : 24),
            height: (n: any) => (n.data("severity") === "critical" ? 34 : n.data("severity") === "high" ? 30 : 24),
            "text-opacity": (n: any) => (n.data("severity") === "critical" || n.data("severity") === "high" ? 1 : 0.55),
        } },
        { selector: "node:selected", style: { "border-color": "#6aa3ff", "border-width": 3, "text-opacity": 1, "underlay-color": "#6aa3ff", "underlay-opacity": 0.4, "underlay-padding": 8 } },
        {
          selector: "edge",
          style: {
            // Edge-ink recede (§3.1/§5): the resting graph is CALM. Base width + opacity
            // are lower than before so edges stop dominating as a cobweb; structural and
            // semantic classes tune from here (below).
            width: 1.1, "line-color": "data(color)", "target-arrow-color": "data(color)", "target-arrow-shape": "triangle",
            "curve-style": "bezier", "arrow-scale": 0.7, opacity: 0.28, label: "", "font-size": "7px", color: "#8893a6",
            "text-rotation": "autorotate", "text-background-color": "#0a0c12", "text-background-opacity": 0.9, "text-background-padding": "3px",
            "min-zoomed-font-size": 7,
            "transition-property": "opacity width", "transition-duration": "160ms" as any,
          },
        },
        // Structural scaffolding (contains/references/located_in/built_from/…): the gray
        // cobweb — recede hardest and DROP the arrowhead at rest so the colored semantic
        // edges separate out. This is the biggest LARGE win.
        { selector: "edge[eclass = 'structural']", style: { opacity: 0.18, width: 1.0, "target-arrow-shape": "none" } },
        // Semantic / security edges (calls/taints/routes_to/listens_on/…): a touch stronger.
        { selector: "edge[eclass = 'semantic']", style: { opacity: 0.32, width: 1.3 } },
        // Semantic edges whose type/attrs are the point — labelled at rest (above the zoom
        // floor), brighter still. Their labels also obey min-zoomed-font-size.
        { selector: "edge[persist = 1]", style: { label: "data(elabel)", opacity: 0.42, width: 1.5 } },
        { selector: "edge.lit", style: { label: "data(elabel)", opacity: 1, width: 2.4, "target-arrow-shape": "triangle", "z-index": 20 } },

        // ── Phase 2: the focus model (the core fix for the drowned highlight) ───────────
        // A committed focus (.focus) is the SUBJECT: full saturation, crisp label, bright
        // edges with labels — color does maximal work here. Everything outside the focus
        // neighborhood becomes .context: muted to ~16% opacity + desaturated
        // (background-blacken) + labels dropped — BUT hue preserved at low alpha (mute, not
        // de-color, per D8). `events:no` so the faded backdrop doesn't steal taps.
        { selector: "node.context", style: {
            opacity: 0.16, "background-blacken": 0.4, "text-opacity": 0, "underlay-opacity": 0,
            events: "no" as any,
        } },
        { selector: "edge.context", style: { opacity: 0.05, label: "", "target-arrow-shape": "none", events: "no" as any } },
        { selector: "node.focus", style: {
            opacity: 1, "background-blacken": 0, "text-opacity": 1, "z-index": 30,
            "border-width": 2.5, "border-color": "#cdd5e2",
            "underlay-opacity": 0.3, "underlay-padding": 7,
        } },
        // The focus ANCHOR (the node you focused) reads strongest of all — amber ring.
        { selector: "node.focus-anchor", style: {
            "border-color": "#ffd166", "border-width": 3.5,
            "underlay-color": "#ffd166", "underlay-opacity": 0.5, "underlay-padding": 11, "text-opacity": 1,
        } },
        { selector: "edge.focus", style: {
            opacity: 1, width: 2.4, label: "data(elabel)", "target-arrow-shape": "triangle", "z-index": 25,
        } },
        // Hover preview (transient, no commit): lift the hovered node + its 1-hop ring out
        // of the resting graph WITHOUT muting everything (distinct from .focus, §4.1).
        { selector: "node.hl", style: { "border-color": "#6aa3ff", "border-width": 2.5, "text-opacity": 1, "z-index": 28, "underlay-opacity": 0.3 } },
        { selector: "edge.hl", style: { opacity: 0.95, width: 2.2, label: "data(elabel)", "target-arrow-shape": "triangle", "z-index": 24 } },
        { selector: ".hl-dim", style: { opacity: 0.12 } as any },

        // Legend isolate-by-type (lightweight Phase-1 preview): hovering/clicking a legend
        // chip dims everything that ISN'T that type, hue preserved at low alpha.
        { selector: "node.type-dim", style: { opacity: 0.1, "text-opacity": 0, "underlay-opacity": 0 } },
        { selector: "edge.type-dim", style: { opacity: 0.05, label: "" } },
      ],
      // NB: dagre is synchronous — if the layout runs from the constructor it fires
      // `layoutstop` before we can subscribe. So we run it explicitly below, AFTER wiring the
      // layoutstop handler, so the focus model reliably gets the final-positions signal.
    });
    // The focus model needs FINAL node positions before its concentric re-arrange + scoped
    // frame. Run the layout explicitly, mark done on settle, and invoke whatever focus is
    // committed at that point (a URL-restored focus applies here).
    layoutDone.current = false;
    cy.one("layoutstop", () => { layoutDone.current = true; applyFocusRef.current?.(); });
    cy.layout({ name: "dagre", rankDir: "LR", nodeSep: 26, rankSep: 72, padding: 24 } as any).run();
    const edgeById = new Map(graph.edges.map((e) => [e.id, e] as const));
    cy.on("tap", "edge", (evt) => {
      cy.edges().removeClass("lit"); evt.target.addClass("lit");
      onEdgeSelect?.(edgeById.get(evt.target.id()) || null);
    });
    cy.on("tap", "node", (evt) => {
      const id = evt.target.id();
      onSelect(id, evt.target.data("gtype"));
      onEdgeSelect?.(null);
      setMenu(null);
      cy.edges().removeClass("lit"); evt.target.connectedEdges().addClass("lit");
      const now = performance.now();
      if (tapRef.current.id === id && now - tapRef.current.t < 350) {
        // double-tap → FOCUS this node's neighborhood (the high-value Phase-2 gesture).
        // Collapse/expand moved to the right-click verb menu.
        focusCbRef.current?.(id);
        tapRef.current = { id: null, t: 0 };
      } else tapRef.current = { id, t: now };
    });
    cy.on("tap", (evt) => { if (evt.target === cy) { cy.edges().removeClass("lit"); onEdgeSelect?.(null); setMenu(null); } });

    // Hover preview (transient, design §4.1): lift the hovered node + its direct edges,
    // gently dim the rest — never commits focus, never reframes. Suspended while a focus is
    // committed (the committed .context mute already governs the canvas).
    cy.on("mouseover", "node", (evt) => {
      if (cy.elements(".focus, .context").nonempty()) return; // committed focus owns the canvas
      const n = evt.target;
      cy.elements().addClass("hl-dim");
      n.closedNeighborhood().removeClass("hl-dim").addClass("hl");
    });
    cy.on("mouseout", "node", () => {
      if (cy.elements(".focus, .context").nonempty()) return;
      cy.elements().removeClass("hl hl-dim");
    });

    // Right-click verb menu (dependency-free): focus / expand a hop / hide / reveal.
    cy.on("cxttap", "node", (evt) => {
      evt.originalEvent?.preventDefault?.();
      const n = evt.target;
      const rp = n.renderedPosition();
      setMenu({ x: rp.x, y: rp.y, id: n.id(), type: n.data("gtype") });
    });
    cy.on("cxttap", (evt) => { if (evt.target === cy) setMenu(null); });
    cy.on("pan zoom drag", () => setMenu(null));

    cyRef.current = cy;
    (window as any).__cy = cy; // exposed for headless A/B capture + debugging (harmless)

    // Draw-to-connect: edgehandles draws a temporary edge src→dst; we cancel its
    // creation and instead open the Add-edge modal prefilled with the endpoints.
    // It is left disabled (drawMode toggles it) so normal tap/select/pan is unaffected.
    const eh = (cy as any).edgehandles({
      snap: true,
      noEdgeEventsInDraw: true,
      canConnect: (s: any, t: any) => s.id() !== t.id(),
      edgeParams: () => ({ data: { color: "#6aa3ff", etype: "draft" } }),
    });
    ehRef.current = eh;
    eh.disable();
    cy.on("ehcomplete", (_evt: any, src: any, tgt: any, addedEdge: any) => {
      try { addedEdge?.remove(); } catch { /* ignore */ }
      setDrawMode(false); // single-shot: drop back to normal select/pan after one edge
      drawRef.current?.(src.id(), tgt.id());
    });

    return () => {
      try { eh.destroy(); } catch { /* ignore */ }
      ehRef.current = null;
      savedPos.current.clear(); // positions belong to THIS cy; the next build gets fresh ones
      if ((window as any).__cy === cy) (window as any).__cy = undefined;
      cy.destroy();
    };
  }, [graph, findings, showFns, collapsed, hidden]);

  // Toggle edgehandles draw mode on the live instance (no graph rebuild needed).
  useEffect(() => {
    const eh = ehRef.current; if (!eh) return;
    if (drawMode) { eh.enable(); eh.enableDrawMode(); } else { eh.disableDrawMode(); eh.disable(); }
  }, [drawMode]);

  useEffect(() => {
    const cy = cyRef.current; if (!cy) return;
    cy.$(":selected").unselect();
    if (selectedId) { const el = cy.getElementById(selectedId); if (el) { el.select(); el.connectedEdges?.().addClass("lit"); } }
  }, [selectedId]);

  // ── Phase 2: apply the committed focus to the live cy instance ────────────────────────
  // A focus = the anchor node + its N-hop neighborhood gets `.focus`; everything else gets
  // `.context` (muted, hue-preserved). Then a SCOPED auto-frame fits to the focus set —
  // never a full-graph fit, never on hover (design D5). Re-runs when the focus or hop
  // changes, and after a rebuild (graph dep) so a URL-restored focus survives reload.
  useEffect(() => {
    const cy = cyRef.current; if (!cy) return;
    let cancelled = false;
    const restore = () => {
      // put every re-arranged node back where the resting layout left it
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
      if (anchor.empty()) return; // focus target not in the visible graph — nothing to do
      const h = Math.max(1, Math.min(3, focus.hop || 1));
      // grow the neighborhood hop-by-hop over the visible graph; track each node's hop ring.
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

      // Live concentric re-arrange of JUST the focus set around the anchor, so the scoped
      // auto-frame lands on a genuinely readable local diagram instead of fitting a
      // hub's neighbours scattered across a flat dagre layout (the resting graph is
      // untouched; positions are saved + restored on clear — design §3.1 hub focus, applied
      // live within Phase-2's "isolate + auto-frame" without a layout-engine swap).
      restore();
      const center = { ...anchor.position() };
      const byRing = new Map<number, string[]>();
      ring.forEach((r, id) => { if (r > 0) (byRing.get(r) || byRing.set(r, []).get(r)!).push(id); });
      cy.batch(() => {
        focusNodes.forEach((n: any) => savedPos.current.set(n.id(), { ...n.position() }));
        anchor.position(center);
        byRing.forEach((ids, r) => {
          const radius = 150 * r;
          ids.forEach((id, idx) => {
            const ang = (2 * Math.PI * idx) / ids.length + r * 0.4;
            cy.getElementById(id).position({ x: center.x + radius * Math.cos(ang), y: center.y + radius * Math.sin(ang) });
          });
        });
      });
      cy.animate({ fit: { eles: focusNodes, padding: 70 } }, { duration: 340 });
    };
    // Positions must be FINAL before the concentric re-arrange + scoped frame, else dagre's
    // late completion overwrites them. If the layout has already settled, apply now; otherwise
    // the build effect's layoutstop handler invokes us via this ref (it ran first, so it sees
    // the committed focus and defers full-graph framing to us).
    applyFocusRef.current = apply;
    if (layoutDone.current) apply();
    return () => { cancelled = true; if (applyFocusRef.current === apply) applyFocusRef.current = null; };
  }, [focus?.id, focus?.hop, graph, hidden]);

  // Legend isolate/preview-by-type: dim everything that is not the chosen node-type OR
  // edge-type. A node-type keeps its nodes + their incident edges; an edge-type keeps those
  // edges + their endpoints. Hue is preserved (mute, not de-color). Live on the cy instance.
  // Suppressed while a focus is committed (focus owns the canvas).
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

  // Verb-menu actions (right-click). All reversible / non-destructive.
  const menuFocus = () => { if (menu) onFocus?.(menu.id, hop); setMenu(null); };
  const menuExpand = () => { if (menu) { const h = Math.min(3, (focus?.id === menu.id ? (focus.hop || 1) : 1) + 1); onFocus?.(menu.id, h); } setMenu(null); };
  const menuHide = () => { if (menu) setHidden((s) => { const x = new Set(s); x.add(menu.id); return x; }); setMenu(null); };
  const menuReveal = () => { if (menu) onSelect(menu.id, menu.type); setMenu(null); };
  const restoreHidden = () => setHidden(new Set());

  const curHop = focus?.hop || 1;

  return (
    <div className="graph-wrap">
      <div id="cy" ref={ref} />
      <div className="graph-meta">
        <span className="badge">{graph.nodes.length} nodes</span>
        {collapsed.size > 0 && <span className="badge" style={{ marginLeft: 6 }}>{collapsed.size} collapsed</span>}
      </div>
      {/* Reversible hide chip (design §4.1): hidden nodes are never a silent loss. */}
      {hidden.size > 0 && (
        <button className="badge hide-chip" title="Restore all hidden nodes"
                onClick={restoreHidden}
                style={{ position: "absolute", left: 10, bottom: 10, cursor: "pointer", zIndex: 5, display: "inline-flex", alignItems: "center", gap: 4 }}>
          <Icon name="refresh" size={11} /> {hidden.size} hidden · restore ↺
        </button>
      )}
      {/* Focus bar: present only while a focus is committed; grows the neighborhood 1→3 hops
          live (re-framing each step) and offers "Clear focus" back to the resting view. */}
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
      {/* Right-click verb menu (dependency-free). */}
      {menu && (
        <div className="menu graph-cxt"
             style={{ position: "absolute", left: Math.max(4, Math.min(menu.x, 1100)), top: Math.max(4, menu.y), zIndex: 20, minWidth: 172 }}
             onMouseLeave={() => setMenu(null)}>
          <div className="mi" onClick={menuFocus}><Icon name="search" size={13} /> Focus neighborhood</div>
          <div className="mi" onClick={menuExpand}><Icon name="plus" size={13} /> Expand one hop</div>
          <div className="mi" onClick={menuReveal}><Icon name="fit" size={13} /> Reveal in panel</div>
          <div className="mi danger" onClick={menuHide}><Icon name="x" size={13} /> Hide this node</div>
        </div>
      )}
      <div className="graph-controls">
        <div style={{ position: "relative" }}>
          <button className="btn icon" title="Filter" onClick={() => setFilterOpen((o) => !o)}><Icon name="filter" /></button>
          {filterOpen && (
            <div className="menu" style={{ right: 0, top: "auto", bottom: 36, minWidth: 200 }}>
              <div className="sub"><label className="muted" style={{ fontSize: 11 }}>findings</label>
                <select className="sel" value={findings} onChange={(e) => setFindings(e.target.value as any)}>
                  <option value="all">all findings</option><option value="unresolved">unresolved only</option><option value="none">hide findings</option>
                </select>
              </div>
              <div className="sub"><label className="muted" style={{ fontSize: 11 }}>focus neighborhood ({hop} hop{hop > 1 ? "s" : ""})</label>
                <input type="range" min={1} max={3} value={hop} onChange={(e) => setHop(Number(e.target.value))} style={{ width: "100%" }} />
              </div>
              <div className="mi" onClick={() => setShowFns((v) => !v)}><Icon name={showFns ? "check" : "x"} size={13} /> functions</div>
              <div className="mi" onClick={() => setCollapsed(new Set())}><Icon name="fit" size={13} /> expand all</div>
              {hidden.size > 0 && <div className="mi" onClick={restoreHidden}><Icon name="refresh" size={13} /> restore {hidden.size} hidden</div>}
            </div>
          )}
        </div>
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
