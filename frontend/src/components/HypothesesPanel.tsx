import { useEffect, useMemo, useRef, useState } from "react";
import { api, HypothesisRow, HYPOTHESIS_WORK_STATES } from "../api";
import { Icon } from "./Icon";

// Evidence-status → colour (matches the singular HypothesisPanel detail view).
const STATUS_CLR: Record<string, string> = {
  open: "var(--muted)", supported: "#7ee787", refuted: "#ff5d6c",
  contested: "#e3b341", confirmed: "#39c5cf", rejected: "#ff5d6c",
};
// Work-state → a calm glyph + label, so the worklist axis reads at a glance.
const WS_ICON: Record<string, string> = { investigating: "search", parked: "minus", done: "check" };
const WS_ORDER = ["investigating", "parked", "done"];
// The evidence verdicts a close can record (the orthogonal status axis).
const VERDICTS = ["", "confirmed", "supported", "refuted", "rejected"];

// The plural Hypotheses worklist — a right-pane tab mirroring FindingsPanel: sort + filter by
// work-state and evidence status, evidence counts, check-off (work_state→done + verdict), and a
// per-row pin-to-graph toggle. Clicking a row selects the hypothesis; the singular
// HypothesisPanel renders the full evidence detail in the split below.
// (design-working-memory.md §4.4)
export default function HypothesesPanel({
  projectId, reloadKey, selectedId, onSelect, onChanged,
}: {
  projectId: string; reloadKey?: number; selectedId?: string;
  onSelect: (h: HypothesisRow) => void; onChanged?: () => void;
}) {
  const [rows, setRows] = useState<HypothesisRow[]>([]);
  const [q, setQ] = useState("");
  const [ws, setWs] = useState("all");
  const [st, setSt] = useState("all");
  const [sort, setSort] = useState<"recency" | "work" | "evidence">("recency");
  const [busy, setBusy] = useState<string | null>(null);
  const selRef = useRef<HTMLDivElement>(null);

  const load = () => api.hypotheses(projectId).then((r) => setRows(r.hypotheses)).catch(() => setRows([]));
  useEffect(() => { load(); /* eslint-disable-next-line */ }, [projectId, reloadKey]);
  useEffect(() => { selRef.current?.scrollIntoView({ block: "nearest", behavior: "smooth" }); }, [selectedId]);

  const refresh = async () => { await load(); onChanged?.(); };
  const close = async (h: HypothesisRow, verdict: string) => {
    setBusy(h.id);
    try { await api.setHypothesisWorkState(h.id, "done", verdict || undefined); await refresh(); }
    finally { setBusy(null); }
  };
  const reopen = async (h: HypothesisRow) => {
    setBusy(h.id);
    try { await api.setHypothesisWorkState(h.id, "investigating"); await refresh(); }
    finally { setBusy(null); }
  };
  const togglePin = async (h: HypothesisRow) => {
    setBusy(h.id);
    try { await api.pinHypothesis(h.id, !h.pinned_to_graph); await refresh(); }
    finally { setBusy(null); }
  };

  const filtered = useMemo(() => {
    let hs = rows.slice();
    if (ws !== "all") hs = hs.filter((h) => h.work_state === ws);
    if (st !== "all") hs = hs.filter((h) => h.status === st);
    if (q) hs = hs.filter((h) => (h.statement + (h.rationale || "")).toLowerCase().includes(q.toLowerCase()));
    if (sort === "work") hs.sort((a, b) => WS_ORDER.indexOf(a.work_state) - WS_ORDER.indexOf(b.work_state));
    else if (sort === "evidence") hs.sort((a, b) => (b.supports_count + b.refutes_count) - (a.supports_count + a.refutes_count));
    else hs.sort((a, b) => (b.created_at || "").localeCompare(a.created_at || ""));
    return hs;
  }, [rows, ws, st, q, sort]);

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    rows.forEach((h) => (c[h.work_state] = (c[h.work_state] || 0) + 1));
    return c;
  }, [rows]);

  const Row = (h: HypothesisRow) => {
    const done = h.work_state === "done";
    return (
      <div key={h.id} ref={h.id === selectedId ? selRef : undefined}
           className={"hyp-row fade-in" + (h.id === selectedId ? " sel" : "") + (done ? " done" : "")}
           onClick={() => onSelect(h)}>
        <button className={"hyp-check" + (done ? " on" : "")} title={done ? "Reopen (investigating)" : "Check off as done"}
                disabled={busy === h.id}
                onClick={(e) => { e.stopPropagation(); done ? reopen(h) : close(h, ""); }}>
          <Icon name="check" size={12} />
        </button>
        <div className="hyp-body">
          <div className="hyp-stmt">{h.statement}</div>
          <div className="hyp-meta">
            <span className="tag" style={{ color: STATUS_CLR[h.status], fontWeight: 600 }}>{h.status}</span>
            <span className="tag ws"><Icon name={WS_ICON[h.work_state] || "search"} size={10} /> {h.work_state}</span>
            {(h.supports_count > 0 || h.refutes_count > 0) && (
              <span className="hyp-ev" title="supporting · refuting evidence">
                <Icon name="check" size={10} />{h.supports_count}
                <Icon name="x" size={10} />{h.refutes_count}
              </span>
            )}
          </div>
        </div>
        <button className={"btn sm icon ghost hyp-pin" + (h.pinned_to_graph ? " on" : "")}
                title={h.pinned_to_graph ? "Pinned to graph — click to unpin" : "Pin to graph canvas"}
                disabled={busy === h.id}
                onClick={(e) => { e.stopPropagation(); togglePin(h); }}>
          <Icon name="hex" size={12} />
        </button>
      </div>
    );
  };

  return (
    <>
      <div className="fbar">
        <div className="input" style={{ flex: 1 }}>
          <Icon name="search" size={13} />
          <input placeholder="filter hypotheses…" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <select className="sel" value={ws} onChange={(e) => setWs(e.target.value)} title="filter by work-state">
          <option value="all">work</option>
          {HYPOTHESIS_WORK_STATES.map((s) => <option key={s} value={s}>{s}{counts[s] ? ` (${counts[s]})` : ""}</option>)}
        </select>
        <select className="sel" value={st} onChange={(e) => setSt(e.target.value)} title="filter by evidence status">
          {["all", "open", "supported", "refuted", "contested", "confirmed", "rejected"].map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <select className="sel" value={sort} onChange={(e) => setSort(e.target.value as any)} title="sort">
          <option value="recency">recent</option>
          <option value="work">work-state</option>
          <option value="evidence">evidence</option>
        </select>
      </div>
      <div className="scroll">
        {filtered.length === 0 && (
          <div className="empty">
            {rows.length === 0
              ? "No hypotheses yet. Record an open question from a finding, or with graph_create_hypothesis."
              : "No hypotheses match."}
          </div>
        )}
        {filtered.map(Row)}
      </div>
    </>
  );
}
