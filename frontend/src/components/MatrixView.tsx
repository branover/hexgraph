// Phase 5 — the Matrix complementary view (design-graph-presentation §6.1 / §6 "Matrix").
//
// The node-link view can't cleanly show a dense N×N relationship (cross-binary
// links_against / references / similar_to / connects_to). A matrix shows it with zero
// edge crossings at any tier: rows × cols are the binaries, each cell the count of edges
// of the chosen class from row→col. Cell click → reveal that pair in the graph. Pure React
// over the already-fetched `graph`; reuses the type vocab (color untouched, D8).

import { useMemo, useState } from "react";
import { Graph } from "../api";
import { KIND } from "./GraphView";

// Cross-target edge classes worth a matrix (small-N, dense). `calls`/`taints` etc. live
// inside a binary; these are the BETWEEN-binary relationships the graph hairballs on.
const REL_TYPES: { key: string; label: string; types: string[] }[] = [
  { key: "links_against", label: "links against", types: ["links_against"] },
  { key: "references", label: "references", types: ["references"] },
  { key: "similar_to", label: "similar to", types: ["similar_to"] },
  { key: "connects_to", label: "connects to", types: ["connects_to"] },
];

export default function MatrixView({
  graph, onReveal,
}: {
  graph: Graph;
  onReveal: (id: string, type: string) => void;
}) {
  const [rel, setRel] = useState<string>("links_against");

  const { targets, byId, targetOf } = useMemo(() => {
    const targets = graph.nodes.filter((n) => n.type === "target");
    const byId = new Map(graph.nodes.map((n) => [n.id, n] as const));
    const targetOf = (id: string): string | undefined => {
      const n = byId.get(id);
      return n?.type === "target" ? n.id : (n?.target_id as string | undefined);
    };
    return { targets, byId, targetOf };
  }, [graph]);

  // available relationship classes (only those actually present, so the selector is honest).
  const present = useMemo(() => {
    const has = new Set(graph.edges.map((e) => e.type));
    return REL_TYPES.filter((r) => r.types.some((t) => has.has(t)));
  }, [graph]);
  const activeRel = present.find((r) => r.key === rel) || present[0];

  // cell[i][j] = count of edges of the active class whose endpoints resolve to targets i→j.
  const { cells, max } = useMemo(() => {
    const idx = new Map(targets.map((t, i) => [t.id, i] as const));
    const cells: number[][] = targets.map(() => targets.map(() => 0));
    let max = 0;
    if (activeRel) {
      const want = new Set(activeRel.types);
      for (const e of graph.edges) {
        if (!want.has(e.type)) continue;
        const s = targetOf(e.source), d = targetOf(e.target);
        if (s == null || d == null) continue;
        const si = idx.get(s), di = idx.get(d);
        if (si == null || di == null || si === di) continue;
        cells[si][di] += (e.count || 1);
        if (cells[si][di] > max) max = cells[si][di];
      }
    }
    return { cells, max };
  }, [targets, graph, activeRel, targetOf]);

  if (targets.length < 2) {
    return <div className="matrix-view"><div className="muted" style={{ padding: 24 }}>The Matrix view needs at least two targets to show cross-target relationships.</div></div>;
  }

  const tint = (kind?: string) => KIND[kind || ""] || "#7d8799";
  const cellColor = (v: number) => v === 0 ? "transparent" : `rgba(106,163,255,${0.18 + 0.62 * (v / Math.max(1, max))})`;

  return (
    <div className="matrix-view">
      <div className="tv-bar">
        <span className="rail-label">relationship</span>
        <select className="chip-sel" value={activeRel?.key || ""} onChange={(e) => setRel(e.target.value)}>
          {present.map((r) => <option key={r.key} value={r.key}>{r.label}</option>)}
        </select>
        <span className="muted" style={{ fontSize: 11 }}>{targets.length} × {targets.length} targets · cell = count (row → col)</span>
      </div>
      <div className="mx-scroll">
        <table className="mx-table">
          <thead>
            <tr>
              <th className="mx-corner" />
              {targets.map((t) => (
                <th key={t.id} className="mx-colh" title={t.label}>
                  <span className="mx-coltxt" style={{ color: tint(t.kind as string) }}>{t.label}</span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {targets.map((row, i) => (
              <tr key={row.id}>
                <th className="mx-rowh" title={row.label} onClick={() => onReveal(row.id, "target")}>
                  <span className="sw-dot" style={{ background: tint(row.kind as string) }} /> {row.label}
                </th>
                {targets.map((col, j) => {
                  const v = cells[i][j];
                  return (
                    <td key={col.id} className={"mx-cell" + (i === j ? " diag" : "") + (v > 0 ? " hot" : "")}
                        style={{ background: i === j ? "var(--surface-2)" : cellColor(v) }}
                        title={v > 0 ? `${row.label} → ${col.label}: ${v} ${activeRel?.label}` : ""}
                        onClick={() => v > 0 && onReveal(col.id, "target")}>
                      {v > 0 ? v : ""}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
