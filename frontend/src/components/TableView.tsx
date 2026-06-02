// Phase 5 — the Table complementary view (design-graph-presentation §6.1).
//
// A node-link diagram is the WRONG representation for "many of the same type"; a sortable,
// filterable table scales infinitely and makes a PATHOLOGICAL target fully usable as a list
// (answer "the 3 highest-degree functions in httpd" in two clicks). Two tabs: Nodes (type
// swatch · name · type · target · degree · #findings) and Edges (type · source · target ·
// origin · confidence). Reuses the shared color/type vocab (D8 — color untouched). Pure
// React over the already-fetched `graph` (no new backend); row click → reveal in the graph.

import { useMemo, useState } from "react";
import { Graph } from "../api";
import { Icon } from "./Icon";
import {
  LayerState, FilterState, nodeLayerOn, edgeClassOn, sevRank, anyFilterActive, nodeColor,
} from "./graphLayers";

type SortDir = "asc" | "desc";

export default function TableView({
  graph, layers, filters, onReveal, scope,
}: {
  graph: Graph;
  layers: LayerState;
  filters: FilterState;
  onReveal: (id: string, type: string) => void;
  scope?: string | null;
}) {
  const [tab, setTab] = useState<"nodes" | "edges">("nodes");
  const [sortKey, setSortKey] = useState<string>("degree");
  const [dir, setDir] = useState<SortDir>("desc");
  const [q, setQ] = useState("");

  // degree + finding-count per node (over the SAME layer/filter facets the graph honors, so
  // the Table is a faithful list of what the graph shows — never a divergent universe).
  const { rows, labelOf, targetOf } = useMemo(() => {
    const byId = new Map(graph.nodes.map((n) => [n.id, n] as const));
    const labelOf = (id: string) => byId.get(id)?.label || id.slice(0, 8);
    const targetIds = new Set(graph.nodes.filter((n) => n.type === "target").map((n) => n.id));
    const targetOf = (id: string): string | undefined => {
      const n = byId.get(id);
      return n?.type === "target" ? n.id : (n?.target_id as string | undefined);
    };
    // honor layers (node-type/edge-class) + filters (severity/target/finding-type) exactly.
    const minSev = filters.severity ? sevRank(filters.severity) : -1;
    const tgtSet = new Set(filters.targets);
    const passesNode = (n: Graph["nodes"][number]): boolean => {
      if (n.type === "finding") { if (!nodeLayerOn(layers, "finding")) return false; }
      else if (n.type === "node" && !nodeLayerOn(layers, n.node_type as string)) return false;
      if (scope) { const t = targetOf(n.id); if (t !== scope && n.id !== scope) return false; }
      if (anyFilterActive(filters)) {
        if (n.type === "finding") {
          if (minSev >= 0 && sevRank(n.severity as string) < minSev) return false;
          if (filters.findingType && (n.finding_type as string) !== filters.findingType) return false;
        }
        if (tgtSet.size > 0) { const t = targetOf(n.id); if (!t || !tgtSet.has(t)) return false; }
      }
      return true;
    };
    const deg = new Map<string, number>();
    const find = new Map<string, number>();
    for (const e of graph.edges) {
      if (!edgeClassOn(layers, e.type)) continue;
      deg.set(e.source, (deg.get(e.source) || 0) + 1);
      deg.set(e.target, (deg.get(e.target) || 0) + 1);
      if (e.type === "about") {
        const f = byId.get(e.source);
        if (f?.type === "finding") find.set(e.target, (find.get(e.target) || 0) + 1);
      }
    }
    const rows = graph.nodes.filter(passesNode).map((n) => {
      const t = n.type === "target" ? "target" : n.type;
      const typeKey = n.type === "target" ? (n.kind as string) : n.type === "finding" ? "finding" : (n.node_type as string);
      const tid = targetOf(n.id);
      return {
        id: n.id, gtype: t, name: n.label, typeKey,
        color: nodeColor(n.type, n.kind as string, n.node_type as string),
        severity: (n.severity as string) || "",
        target: tid && targetIds.has(tid) ? labelOf(tid) : (n.type === "target" ? "—" : ""),
        degree: deg.get(n.id) || 0,
        findings: find.get(n.id) || 0,
      };
    });
    return { rows, labelOf, targetOf };
  }, [graph, layers, filters, scope]);

  const edgeRows = useMemo(() => {
    const minSev = filters.severity ? sevRank(filters.severity) : -1;
    void minSev;
    return graph.edges
      .filter((e) => edgeClassOn(layers, e.type))
      .filter((e) => !scope || targetOf(e.source) === scope || targetOf(e.target) === scope)
      .map((e) => ({
        id: e.id, type: e.type, source: labelOf(e.source), target: labelOf(e.target),
        origin: e.origin || "", confidence: typeof e.confidence === "number" ? e.confidence : null,
        count: e.count || 1,
      }));
  }, [graph, layers, filters, scope, labelOf, targetOf]);

  const filteredNodeRows = useMemo(() => {
    const term = q.trim().toLowerCase();
    const r = term ? rows.filter((x) => x.name.toLowerCase().includes(term) || x.typeKey.includes(term)) : rows;
    const k = sortKey as keyof typeof r[number];
    const sorted = [...r].sort((a, b) => {
      const av = a[k] as any, bv = b[k] as any;
      const cmp = typeof av === "number" && typeof bv === "number" ? av - bv : String(av).localeCompare(String(bv));
      return dir === "asc" ? cmp : -cmp;
    });
    return sorted;
  }, [rows, q, sortKey, dir]);

  const filteredEdgeRows = useMemo(() => {
    const term = q.trim().toLowerCase();
    const r = term ? edgeRows.filter((x) => x.type.includes(term) || x.source.toLowerCase().includes(term) || x.target.toLowerCase().includes(term)) : edgeRows;
    const k = sortKey as keyof typeof r[number];
    const sorted = [...r].sort((a, b) => {
      const av = (a as any)[k] ?? "", bv = (b as any)[k] ?? "";
      const cmp = typeof av === "number" && typeof bv === "number" ? av - bv : String(av).localeCompare(String(bv));
      return dir === "asc" ? cmp : -cmp;
    });
    return sorted;
  }, [edgeRows, q, sortKey, dir]);

  const sortBy = (key: string) => {
    if (sortKey === key) setDir((d) => (d === "asc" ? "desc" : "asc"));
    else { setSortKey(key); setDir(key === "degree" || key === "findings" || key === "count" || key === "confidence" ? "desc" : "asc"); }
  };
  const Th = ({ k, children, w }: { k: string; children: React.ReactNode; w?: number }) => (
    <th onClick={() => sortBy(k)} style={{ cursor: "pointer", width: w }}>
      {children}{sortKey === k && <span className="sort-caret">{dir === "asc" ? " ▲" : " ▼"}</span>}
    </th>
  );

  return (
    <div className="table-view">
      <div className="tv-bar">
        <div className="seg tgroup" style={{ gap: 2, border: "1px solid var(--border)", borderRadius: 7, padding: 2 }}>
          <button className={"btn sm" + (tab === "nodes" ? " primary" : " ghost")} onClick={() => { setTab("nodes"); setSortKey("degree"); setDir("desc"); }}>
            Nodes · {filteredNodeRows.length}
          </button>
          <button className={"btn sm" + (tab === "edges" ? " primary" : " ghost")} onClick={() => { setTab("edges"); setSortKey("type"); setDir("asc"); }}>
            Edges · {filteredEdgeRows.length}
          </button>
        </div>
        <div className="input" style={{ flex: 1, minWidth: 160 }}>
          <Icon name="search" size={13} />
          <input placeholder={tab === "nodes" ? "Filter by name / type…" : "Filter by type / endpoint…"} value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        {scope && <span className="badge">scoped</span>}
      </div>
      <div className="tv-scroll">
        {tab === "nodes" ? (
          <table className="dtable">
            <thead><tr>
              <Th k="name">name</Th>
              <Th k="typeKey" w={120}>type</Th>
              <Th k="target" w={150}>target</Th>
              <Th k="degree" w={70}>degree</Th>
              <Th k="findings" w={80}>findings</Th>
            </tr></thead>
            <tbody>
              {filteredNodeRows.map((r) => (
                <tr key={r.id} onClick={() => onReveal(r.id, r.gtype === "target" ? "target" : r.gtype === "finding" ? "finding" : "node")}>
                  <td><span className="sw-dot" style={{ background: r.color }} /> {r.name}</td>
                  <td className="muted">{r.gtype === "finding" ? <span className={"chip sev-" + r.severity}>{r.severity || "finding"}</span> : r.typeKey}</td>
                  <td className="muted">{r.target}</td>
                  <td className="num">{r.degree}</td>
                  <td className="num">{r.findings || ""}</td>
                </tr>
              ))}
              {filteredNodeRows.length === 0 && <tr><td colSpan={5} className="muted" style={{ padding: 16 }}>No matching nodes.</td></tr>}
            </tbody>
          </table>
        ) : (
          <table className="dtable">
            <thead><tr>
              <Th k="type" w={150}>type</Th>
              <Th k="source">source</Th>
              <Th k="target">target</Th>
              <Th k="origin" w={90}>origin</Th>
              <Th k="confidence" w={90}>conf</Th>
              <Th k="count" w={60}>×</Th>
            </tr></thead>
            <tbody>
              {filteredEdgeRows.map((r) => (
                <tr key={r.id}>
                  <td>{r.type}</td>
                  <td className="muted">{r.source}</td>
                  <td className="muted">{r.target}</td>
                  <td className="muted">{r.origin}</td>
                  <td className="num">{r.confidence != null ? r.confidence : ""}</td>
                  <td className="num">{r.count > 1 ? r.count : ""}</td>
                </tr>
              ))}
              {filteredEdgeRows.length === 0 && <tr><td colSpan={6} className="muted" style={{ padding: 16 }}>No matching edges.</td></tr>}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
