import { useEffect, useState } from "react";
import { api, Hypothesis } from "../api";
import { Icon } from "./Icon";

// Status → severity-ish color so the verdict reads at a glance.
const STATUS_CLR: Record<string, string> = {
  open: "var(--muted)", supported: "#7ee787", refuted: "#ff5d6c",
  contested: "#e3b341", confirmed: "#39c5cf", rejected: "#ff5d6c",
};
const WS_ICON: Record<string, string> = { investigating: "search", parked: "minus", done: "check" };

// Hypothesis detail: statement, the two orthogonal axes (evidence-derived status + the
// investigating/parked/done WORK-STATE), the pin-to-graph toggle, and the supporting/refuting
// findings. Shown by NodeInspector for hypothesis nodes (design-working-memory.md §4.4).
export default function HypothesisPanel({ hypothesisId, onViewFinding, onChanged }: {
  hypothesisId: string; onViewFinding?: (fid: string) => void; onChanged?: () => void;
}) {
  const [h, setH] = useState<Hypothesis | null>(null);
  useEffect(() => { api.hypothesis(hypothesisId).then(setH).catch(() => setH(null)); }, [hypothesisId]);
  if (!h) return null;

  const setStatus = async (status: string) => { const r = await api.setHypothesisStatus(h.id, status); setH(r); onChanged?.(); };
  const setWork = async (work_state: string) => { const r = await api.setHypothesisWorkState(h.id, work_state); setH(r); onChanged?.(); };
  const togglePin = async () => { const r = await api.pinHypothesis(h.id, !h.pinned_to_graph); setH(r); onChanged?.(); };
  const EvList = ({ items, kind }: { items: Hypothesis["supports"]; kind: "supports" | "refutes" }) => (
    <>
      <div className="sec">{kind === "supports" ? "Supporting" : "Refuting"} evidence · {items.length}</div>
      {items.length === 0 ? <div className="muted" style={{ fontSize: 11 }}>none yet</div> : (
        <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
          {items.map((e) => (
            <div key={e.finding_id} className="res" onClick={() => onViewFinding?.(e.finding_id)} style={{ cursor: "pointer" }}>
              <Icon name={kind === "supports" ? "check" : "x"} size={11} />
              <span className={"chip sev-" + e.severity}>{e.severity}</span> {e.title}
              {e.origin !== "human" && <span className="muted" style={{ fontSize: 10 }}> · {e.origin}</span>}
            </div>
          ))}
        </div>
      )}
    </>
  );

  return (
    <div style={{ marginTop: 4 }}>
      <div className="chips">
        <span className="tag" style={{ color: STATUS_CLR[h.status], fontWeight: 700 }}>{h.status}</span>
        <span className="muted" style={{ fontSize: 10.5, alignSelf: "center" }}>
          {h.status_origin === "human" ? "pinned by analyst" : "derived from evidence"}
        </span>
        <span className="tag" title="work-state — am I on this?">
          <Icon name={WS_ICON[h.work_state] || "search"} size={10} /> {h.work_state}
        </span>
        <button className={"btn sm icon ghost" + (h.pinned_to_graph ? " primary" : "")} onClick={togglePin}
                title={h.pinned_to_graph ? "Pinned to the graph canvas — click to unpin" : "Pin to the graph canvas"}>
          <Icon name="hex" size={12} />
        </button>
      </div>
      {h.rationale && <p style={{ color: "var(--fg-dim)" }}>{h.rationale}</p>}
      <div className="actions">
        <button className="btn sm" onClick={() => setStatus("confirmed")}><Icon name="check" size={12} /> Confirm</button>
        <button className="btn sm danger" onClick={() => setStatus("rejected")}><Icon name="x" size={12} /> Reject</button>
        <button className="btn sm ghost" onClick={() => setStatus("open")}><Icon name="refresh" size={12} /> Reopen</button>
      </div>
      {/* Work-state axis (orthogonal to the verdict): am I actively on this, set aside, or done? */}
      <div className="actions">
        {h.work_state !== "done"
          ? <button className="btn sm" onClick={() => setWork("done")}><Icon name="check" size={12} /> Mark done</button>
          : <button className="btn sm ghost" onClick={() => setWork("investigating")}><Icon name="refresh" size={12} /> Resume</button>}
        {h.work_state !== "parked"
          ? <button className="btn sm ghost" onClick={() => setWork("parked")}><Icon name="minus" size={12} /> Park</button>
          : <button className="btn sm ghost" onClick={() => setWork("investigating")}><Icon name="search" size={12} /> Investigating</button>}
      </div>
      <EvList items={h.supports} kind="supports" />
      <EvList items={h.refutes} kind="refutes" />
    </div>
  );
}
