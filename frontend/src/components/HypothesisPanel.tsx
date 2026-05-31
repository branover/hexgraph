import { useEffect, useState } from "react";
import { api, Hypothesis } from "../api";
import { Icon } from "./Icon";

// Status → severity-ish color so the verdict reads at a glance.
const STATUS_CLR: Record<string, string> = {
  open: "var(--muted)", supported: "#7ee787", refuted: "#ff5d6c",
  contested: "#e3b341", confirmed: "#39c5cf", rejected: "#ff5d6c",
};

// Hypothesis lifecycle: statement, evidence-derived status (sticky human verdict),
// and the supporting/refuting findings. Shown by NodeInspector for hypothesis nodes.
export default function HypothesisPanel({ hypothesisId, onViewFinding, onChanged }: {
  hypothesisId: string; onViewFinding?: (fid: string) => void; onChanged?: () => void;
}) {
  const [h, setH] = useState<Hypothesis | null>(null);
  useEffect(() => { api.hypothesis(hypothesisId).then(setH).catch(() => setH(null)); }, [hypothesisId]);
  if (!h) return null;

  const setStatus = async (status: string) => { const r = await api.setHypothesisStatus(h.id, status); setH(r); onChanged?.(); };
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
      </div>
      {h.rationale && <p style={{ color: "var(--fg-dim)" }}>{h.rationale}</p>}
      <div className="actions">
        <button className="btn sm" onClick={() => setStatus("confirmed")}><Icon name="check" size={12} /> Confirm</button>
        <button className="btn sm danger" onClick={() => setStatus("rejected")}><Icon name="x" size={12} /> Reject</button>
        <button className="btn sm ghost" onClick={() => setStatus("open")}><Icon name="refresh" size={12} /> Reopen</button>
      </div>
      <EvList items={h.supports} kind="supports" />
      <EvList items={h.refutes} kind="refutes" />
    </div>
  );
}
