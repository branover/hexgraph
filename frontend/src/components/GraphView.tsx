import { useEffect, useRef } from "react";
import cytoscape from "cytoscape";
import dagre from "cytoscape-dagre";
import { Graph } from "../api";

cytoscape.use(dagre);

const SEV: Record<string, string> = { info: "#6e7681", low: "#3fb950", medium: "#d29922", high: "#fb8b46", critical: "#f85149" };
const KIND: Record<string, string> = { firmware_image: "#a371f7", executable: "#5aa2ff", shared_library: "#39c5cf", unknown: "#818b9c" };
const NODE_T: Record<string, string> = { function: "#7ee787", symbol: "#d2a8ff", string: "#79c0ff", struct: "#ffa657" };

export default function GraphView({ graph, onSelect, selectedId }: { graph: Graph; onSelect: (id: string, type: string) => void; selectedId?: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core>();

  useEffect(() => {
    if (!ref.current) return;
    // Progressive disclosure: hide bulk symbol/string nodes (they clutter the graph);
    // show targets, functions/structs, and findings + the edges between them.
    const hidden = new Set(
      graph.nodes.filter((n) => n.type === "node" && (n.node_type === "symbol" || n.node_type === "string")).map((n) => n.id)
    );
    const shown = graph.nodes.filter((n) => !hidden.has(n.id));
    const vEdges = graph.edges.filter((e) => !hidden.has(e.source) && !hidden.has(e.target));
    const elements = [
      ...shown.map((n) => ({ data: { id: n.id, label: n.label, gtype: n.type, severity: n.severity, kind: n.kind, node_type: n.node_type } })),
      ...vEdges.map((e) => ({ data: { id: e.id, source: e.source, target: e.target, etype: e.type } })),
    ];
    const cy = cytoscape({
      container: ref.current,
      elements,
      wheelSensitivity: 0.2,
      style: [
        {
          selector: "node",
          style: {
            label: "data(label)", color: "#c9d1d9", "font-size": "8px",
            "text-valign": "bottom", "text-margin-y": 3, "text-wrap": "ellipsis", "text-max-width": "90px",
            width: 20, height: 20,
            "background-color": (n: any) =>
              n.data("gtype") === "finding" ? (SEV[n.data("severity")] || "#6e7681")
              : n.data("gtype") === "node" ? (NODE_T[n.data("node_type")] || "#818b9c")
              : (KIND[n.data("kind")] || "#818b9c"),
            shape: (n: any) =>
              n.data("gtype") === "finding" ? "diamond"
              : n.data("gtype") === "node" ? "round-rectangle" : "ellipse",
            "border-width": 2, "border-color": "#0b0e14",
          },
        },
        { selector: "node:selected", style: { "border-color": "#5aa2ff", "border-width": 3 } },
        {
          selector: "edge",
          style: {
            width: 1.3, "line-color": "#39414f", "target-arrow-color": "#39414f",
            "target-arrow-shape": "triangle", "curve-style": "bezier", "arrow-scale": 0.7,
            label: "data(etype)", "font-size": "6px", color: "#5a6473", "text-rotation": "autorotate",
          },
        },
      ],
      layout: { name: "dagre", rankDir: "LR", nodeSep: 18, rankSep: 60, padding: 18 } as any,
    });
    cy.on("tap", "node", (evt) => onSelect(evt.target.id(), evt.target.data("gtype")));
    cyRef.current = cy;
    return () => cy.destroy();
  }, [graph]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.$(":selected").unselect();
    if (selectedId) cy.getElementById(selectedId).select();
  }, [selectedId]);

  return <div id="cy" ref={ref} />;
}
