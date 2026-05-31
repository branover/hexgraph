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
export const KIND: Record<string, string> = { firmware_image: "#a371f7", executable: "#6aa3ff", shared_library: "#39c5cf", web_app: "#2dd4bf", unknown: "#7d8799" };
// Sub-file/conceptual node colors — each visually distinct (no two near-identical hues).
export const NODE_T: Record<string, string> = {
  function: "#7ee787", symbol: "#d2a8ff", string: "#79c0ff", struct: "#ffa657",
  hypothesis: "#e3b341", pattern: "#bc8cff",
  input: "#58a6ff", sink: "#db6d28", socket: "#f778ba", endpoint: "#2dd4bf", param: "#a5d6ff",
};
// Per-node-type shape, so types are distinguishable independent of color.
export const NODE_SHAPE: Record<string, string> = {
  socket: "hexagon", endpoint: "tag", param: "ellipse", input: "triangle", sink: "vee",
};
export const EDGE_C: Record<string, string> = {
  contains: "#46506a", calls: "#6aa3ff", about: "#3b4458", related_to: "#f0883e",
  instance_of_pattern: "#f0883e", links_against: "#39c5cf", similar_to: "#8b5cf6",
  taints: "#ff7b72", bypasses: "#ff5d6c", listens_on: "#f778ba", connects_to: "#f0a0d0",
  routes_to: "#2dd4bf", references: "#46506a", derived_from: "#8b5cf6",
};
// Semantic edges whose type/attrs are the point — always labelled, not just on hover.
const ALWAYS_LABEL = new Set(["taints", "bypasses", "listens_on", "connects_to", "routes_to"]);
const RESOLVED = new Set(["confirmed", "dismissed", "reported"]);

export default function GraphView({ graph, onSelect, onEdgeSelect, onDrawEdge, selectedId }: { graph: Graph; onSelect: (id: string, type: string) => void; onEdgeSelect?: (edge: Graph["edges"][number] | null) => void; onDrawEdge?: (srcId: string, dstId: string) => void; selectedId?: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core>();
  const ehRef = useRef<any>(null);
  const drawRef = useRef<(src: string, dst: string) => void>();
  const tapRef = useRef<{ id: string | null; t: number }>({ id: null, t: 0 });
  const [findings, setFindings] = useState<"all" | "unresolved" | "none">("all");
  const [showFns, setShowFns] = useState(true);
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [filterOpen, setFilterOpen] = useState(false);
  const [drawMode, setDrawMode] = useState(false);

  // keep the latest callback in a ref so the cytoscape effect needn't re-run on it
  drawRef.current = onDrawEdge;

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
    const nodeById = new Map(graph.nodes.map((n) => [n.id, n] as const));
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
    const isHidden = (id: string) => baseHidden.has(id) || collapseHidden.has(id);

    const shown = graph.nodes.filter((n) => !isHidden(n.id));
    const vEdges = graph.edges.filter((e) => !isHidden(e.source) && !isHidden(e.target));
    const collapsedCount = (id: string) => descendants(id).filter((d) => !baseHidden.has(d)).length;

    const elements = [
      ...shown.map((n) => {
        const isCollapsed = collapsed.has(n.id);
        const n2 = collapsedCount(n.id);
        const label = isCollapsed && n2 ? `${n.label}  ▸${n2}` : n.label;
        return { data: { id: n.id, label, gtype: n.type, severity: n.severity, kind: n.kind, node_type: n.node_type, collapsed: isCollapsed ? 1 : 0 } };
      }),
      ...vEdges.map((e) => {
        const a = e.attrs || {};
        let hint = "";
        if (e.type === "calls" && (a.call_sites?.length || (e.count && e.count > 1))) hint = ` ×${a.call_sites?.length || e.count}`;
        else if ((e.type === "listens_on" || e.type === "connects_to") && a.address) hint = ` @${a.address}`;
        else if (a.port) hint = ` :${a.port}`;
        return { data: { id: e.id, source: e.source, target: e.target, etype: e.type, elabel: e.type + hint,
                         color: EDGE_C[e.type] || "#3b4458", persist: ALWAYS_LABEL.has(e.type) ? 1 : 0 } };
      }),
    ];

    const cy = cytoscape({
      container: ref.current, elements, wheelSensitivity: 0.25,
      style: [
        {
          selector: "node",
          style: {
            label: "data(label)", color: "#cdd5e2", "font-size": "9px", "font-weight": 600,
            "text-valign": "bottom", "text-margin-y": 5, "text-wrap": "ellipsis", "text-max-width": "104px",
            width: 26, height: 26,
            "background-color": (n: any) => n.data("gtype") === "finding" ? (SEV[n.data("severity")] || "#7d8799") : n.data("gtype") === "node" ? (NODE_T[n.data("node_type")] || "#7d8799") : (KIND[n.data("kind")] || "#7d8799"),
            shape: ((n: any) => n.data("gtype") === "finding" ? "diamond" : NODE_SHAPE[n.data("node_type")] || (n.data("gtype") === "node" ? "round-rectangle" : "ellipse")) as any,
            "border-width": (n: any) => n.data("collapsed") ? 3 : 2, "border-color": (n: any) => n.data("collapsed") ? "#e3b341" : "#0a0c12",
            "underlay-color": (n: any) => n.data("gtype") === "finding" ? (SEV[n.data("severity")] || "#7d8799") : (KIND[n.data("kind")] || "#39c5cf"),
            "underlay-opacity": (n: any) => (n.data("gtype") === "finding" && (n.data("severity") === "critical" || n.data("severity") === "high") ? 0.28 : 0.12),
            "underlay-padding": 5, "underlay-shape": "ellipse",
          },
        },
        { selector: "node:selected", style: { "border-color": "#6aa3ff", "border-width": 3, "underlay-color": "#6aa3ff", "underlay-opacity": 0.4, "underlay-padding": 8 } },
        {
          selector: "edge",
          style: {
            width: 1.6, "line-color": "data(color)", "target-arrow-color": "data(color)", "target-arrow-shape": "triangle",
            "curve-style": "bezier", "arrow-scale": 0.75, opacity: 0.55, label: "", "font-size": "7px", color: "#8893a6",
            "text-rotation": "autorotate", "text-background-color": "#0a0c12", "text-background-opacity": 0.8, "text-background-padding": "2px",
          },
        },
        // Semantic edges (taints/bypasses/listens_on/connects_to/routes_to) carry the
        // graph's meaning — label them at rest, a touch brighter than structural edges.
        { selector: "edge[persist = 1]", style: { label: "data(elabel)", opacity: 0.8 } },
        { selector: "edge.lit", style: { label: "data(elabel)", opacity: 1, width: 2.2 } },
      ],
      layout: { name: "dagre", rankDir: "LR", nodeSep: 26, rankSep: 72, padding: 24 } as any,
    });
    const edgeById = new Map(graph.edges.map((e) => [e.id, e] as const));
    cy.on("tap", "edge", (evt) => {
      cy.edges().removeClass("lit"); evt.target.addClass("lit");
      onEdgeSelect?.(edgeById.get(evt.target.id()) || null);
    });
    cy.on("tap", "node", (evt) => {
      const id = evt.target.id();
      onSelect(id, evt.target.data("gtype"));
      onEdgeSelect?.(null);
      cy.edges().removeClass("lit"); evt.target.connectedEdges().addClass("lit");
      const now = performance.now();
      if (tapRef.current.id === id && now - tapRef.current.t < 350) {
        // double-tap → collapse/expand this node's subtree (if it has children)
        if ((childrenOf[id] || []).length) setCollapsed((prev) => { const s = new Set(prev); s.has(id) ? s.delete(id) : s.add(id); return s; });
        tapRef.current = { id: null, t: 0 };
      } else tapRef.current = { id, t: now };
    });
    cy.on("tap", (evt) => { if (evt.target === cy) { cy.edges().removeClass("lit"); onEdgeSelect?.(null); } });
    cyRef.current = cy;

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

    return () => { try { eh.destroy(); } catch { /* ignore */ } ehRef.current = null; cy.destroy(); };
  }, [graph, findings, showFns, collapsed]);

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

  const fit = () => cyRef.current?.animate({ fit: { eles: cyRef.current.elements(), padding: 28 } }, { duration: 250 });
  const zoom = (f: number) => { const cy = cyRef.current; if (cy) cy.animate({ zoom: cy.zoom() * f, center: { eles: cy.elements() } }, { duration: 150 }); };

  return (
    <div className="graph-wrap">
      <div id="cy" ref={ref} />
      <div className="graph-meta">
        <span className="badge">{graph.nodes.length} nodes</span>
        {collapsed.size > 0 && <span className="badge" style={{ marginLeft: 6 }}>{collapsed.size} collapsed</span>}
      </div>
      <div className="graph-controls">
        <div style={{ position: "relative" }}>
          <button className="btn icon" title="Filter" onClick={() => setFilterOpen((o) => !o)}><Icon name="filter" /></button>
          {filterOpen && (
            <div className="menu" style={{ right: 0, top: "auto", bottom: 36, minWidth: 180 }}>
              <div className="sub"><label className="muted" style={{ fontSize: 11 }}>findings</label>
                <select className="sel" value={findings} onChange={(e) => setFindings(e.target.value as any)}>
                  <option value="all">all findings</option><option value="unresolved">unresolved only</option><option value="none">hide findings</option>
                </select>
              </div>
              <div className="mi" onClick={() => setShowFns((v) => !v)}><Icon name={showFns ? "check" : "x"} size={13} /> functions</div>
              <div className="mi" onClick={() => setCollapsed(new Set())}><Icon name="fit" size={13} /> expand all</div>
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
