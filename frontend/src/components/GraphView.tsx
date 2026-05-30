import { useEffect, useRef } from "react";
import cytoscape from "cytoscape";
import dagre from "cytoscape-dagre";
import { Graph } from "../api";
import { Icon } from "./Icon";

cytoscape.use(dagre);

const SEV: Record<string, string> = { info: "#7d8799", low: "#3fb950", medium: "#e3b341", high: "#f0883e", critical: "#ff5d6c" };
const KIND: Record<string, string> = { firmware_image: "#a371f7", executable: "#6aa3ff", shared_library: "#39c5cf", unknown: "#7d8799" };
const NODE_T: Record<string, string> = { function: "#7ee787", symbol: "#d2a8ff", string: "#79c0ff", struct: "#ffa657" };
const EDGE_C: Record<string, string> = {
  contains: "#46506a", calls: "#6aa3ff", about: "#3b4458", related_to: "#f0883e",
  instance_of_pattern: "#f0883e", links_against: "#39c5cf", similar_to: "#8b5cf6",
};
function edgeColor(t: string) { return EDGE_C[t] || "#3b4458"; }

export default function GraphView({ graph, onSelect, selectedId }: { graph: Graph; onSelect: (id: string, type: string) => void; selectedId?: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core>();

  useEffect(() => {
    if (!ref.current) return;
    // Progressive disclosure: hide bulk symbol/string nodes; show targets, functions, findings.
    const hidden = new Set(
      graph.nodes.filter((n) => n.type === "node" && (n.node_type === "symbol" || n.node_type === "string")).map((n) => n.id)
    );
    const shown = graph.nodes.filter((n) => !hidden.has(n.id));
    const vEdges = graph.edges.filter((e) => !hidden.has(e.source) && !hidden.has(e.target));
    const elements = [
      ...shown.map((n) => ({ data: { id: n.id, label: n.label, gtype: n.type, severity: n.severity, kind: n.kind, node_type: n.node_type } })),
      ...vEdges.map((e) => ({ data: { id: e.id, source: e.source, target: e.target, etype: e.type, color: edgeColor(e.type) } })),
    ];
    const cy = cytoscape({
      container: ref.current,
      elements,
      wheelSensitivity: 0.25,
      style: [
        {
          selector: "node",
          style: {
            label: "data(label)", color: "#cdd5e2", "font-size": "9px", "font-weight": 600,
            "text-valign": "bottom", "text-margin-y": 5, "text-wrap": "ellipsis", "text-max-width": "104px",
            width: 26, height: 26,
            "background-color": (n: any) =>
              n.data("gtype") === "finding" ? (SEV[n.data("severity")] || "#7d8799")
              : n.data("gtype") === "node" ? (NODE_T[n.data("node_type")] || "#7d8799")
              : (KIND[n.data("kind")] || "#7d8799"),
            shape: (n: any) =>
              n.data("gtype") === "finding" ? "diamond"
              : n.data("gtype") === "node" ? "round-rectangle" : "ellipse",
            "border-width": 2, "border-color": "#0a0c12",
            // soft halo: severity for findings, kind for targets
            "underlay-color": (n: any) =>
              n.data("gtype") === "finding" ? (SEV[n.data("severity")] || "#7d8799") : (KIND[n.data("kind")] || "#39c5cf"),
            "underlay-opacity": (n: any) => (n.data("gtype") === "finding" && (n.data("severity") === "critical" || n.data("severity") === "high") ? 0.28 : 0.12),
            "underlay-padding": 5, "underlay-shape": "ellipse",
          },
        },
        { selector: "node:selected", style: { "border-color": "#6aa3ff", "border-width": 3, "underlay-color": "#6aa3ff", "underlay-opacity": 0.4, "underlay-padding": 8 } },
        {
          selector: "edge",
          style: {
            width: 1.6, "line-color": "data(color)", "target-arrow-color": "data(color)",
            "target-arrow-shape": "triangle", "curve-style": "bezier", "arrow-scale": 0.75, opacity: 0.55,
            label: "", "font-size": "7px", color: "#8893a6", "text-rotation": "autorotate",
            "text-background-color": "#0a0c12", "text-background-opacity": 0.8, "text-background-padding": "2px",
          },
        },
        { selector: "edge.lit", style: { label: "data(etype)", opacity: 1, width: 2.2 } },
      ],
      layout: { name: "dagre", rankDir: "LR", nodeSep: 26, rankSep: 72, padding: 24 } as any,
    });
    const litEdges = (node: any) => { cy.edges().removeClass("lit"); node.connectedEdges().addClass("lit"); };
    cy.on("tap", "node", (evt) => { onSelect(evt.target.id(), evt.target.data("gtype")); litEdges(evt.target); });
    cy.on("tap", (evt) => { if (evt.target === cy) cy.edges().removeClass("lit"); });
    cyRef.current = cy;
    return () => cy.destroy();
  }, [graph]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.$(":selected").unselect();
    if (selectedId) {
      const el = cy.getElementById(selectedId);
      if (el) { el.select(); el.connectedEdges?.().addClass("lit"); }
    }
  }, [selectedId]);

  const fit = () => cyRef.current?.animate({ fit: { eles: cyRef.current.elements(), padding: 28 } }, { duration: 250 });
  const zoom = (f: number) => { const cy = cyRef.current; if (cy) cy.animate({ zoom: cy.zoom() * f, center: { eles: cy.elements() } }, { duration: 150 }); };
  const relayout = () => cyRef.current?.layout({ name: "dagre", rankDir: "LR", nodeSep: 26, rankSep: 72, padding: 24 } as any).run();

  const count = graph.nodes.filter((n) => !(n.type === "node" && (n.node_type === "symbol" || n.node_type === "string"))).length;

  return (
    <div className="graph-wrap">
      <div id="cy" ref={ref} />
      <div className="graph-meta"><span className="badge">{count} nodes</span></div>
      <div className="graph-controls">
        <button className="btn icon" title="Fit" onClick={fit}><Icon name="fit" /></button>
        <button className="btn icon" title="Zoom in" onClick={() => zoom(1.25)}><Icon name="plus" /></button>
        <button className="btn icon" title="Zoom out" onClick={() => zoom(0.8)}><Icon name="minus" /></button>
        <button className="btn icon" title="Re-layout" onClick={relayout}><Icon name="refresh" /></button>
      </div>
    </div>
  );
}
