import { useEffect, useState } from "react";
import { AnalysisRunRow, RunDiff, TargetNode, api } from "../api";
import { Icon } from "./Icon";

// Compare two analysis runs over the same target (e.g. the same task re-run under
// a different model/scenario) → which findings were added, dropped, or changed
// severity. This is what makes per-task model selection legible.
export default function RunCompareModal({ targets, onClose }: {
  targets: TargetNode[]; onClose: () => void;
}) {
  const [targetId, setTargetId] = useState(targets[0]?.id || "");
  const [runs, setRuns] = useState<AnalysisRunRow[]>([]);
  const [a, setA] = useState("");
  const [b, setB] = useState("");
  const [diff, setDiff] = useState<RunDiff | null>(null);
  const [note, setNote] = useState("");

  useEffect(() => {
    setRuns([]); setA(""); setB(""); setDiff(null); setNote("");
    if (!targetId) return;
    api.targetRuns(targetId).then((rs) => {
      setRuns(rs);
      if (rs.length >= 2) { setB(rs[0].id); setA(rs[1].id); }  // newest vs previous
      else setNote("This target has fewer than two recorded runs to compare.");
    }).catch(() => setNote("Failed to load runs."));
  }, [targetId]);

  useEffect(() => {
    if (a && b && a !== b) api.runsDiff(a, b).then(setDiff).catch(() => setDiff(null));
    else setDiff(null);
  }, [a, b]);

  const label = (r: AnalysisRunRow) =>
    `${r.task_type} · ${r.model || r.backend} · ${r.finding_count} findings · ${new Date(r.created_at).toLocaleString()}`;
  const RunSelect = ({ v, set, title }: { v: string; set: (s: string) => void; title: string }) => (
    <div className="field" style={{ flex: 1 }}><label>{title}</label>
      <select value={v} onChange={(e) => set(e.target.value)}>
        <option value="">select run…</option>
        {runs.map((r) => <option key={r.id} value={r.id}>{label(r)}</option>)}
      </select>
    </div>
  );
  const Row = ({ items, kind }: { items: any[]; kind: "added" | "dropped" | "changed" }) => (
    <>
      <div className="sec">{kind === "added" ? "Added (only in B)" : kind === "dropped" ? "Dropped (only in A)" : "Severity changed"} · {items.length}</div>
      {items.length === 0 ? <div className="muted" style={{ fontSize: 11 }}>none</div> : (
        <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
          {items.map((it, i) => (
            <div key={i} className="res">
              <Icon name={kind === "added" ? "plus" : kind === "dropped" ? "minus" : "refresh"} size={11} />
              {kind === "changed"
                ? <><span>{it.title}</span> <span className="muted">{it.from} → <b>{it.to}</b></span></>
                : <><span className={"chip sev-" + it.severity}>{it.severity}</span> {it.title}</>}
            </div>
          ))}
        </div>
      )}
    </>
  );

  return (
    <div className="modal-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="modal fade-in" style={{ width: 640, maxHeight: "86vh", display: "flex", flexDirection: "column" }}>
        <h3 style={{ marginBottom: 10 }}>
          <Icon name="refresh" size={16} /> Compare runs
          <span style={{ flex: 1 }} />
          <button className="btn sm ghost icon" onClick={onClose}><Icon name="x" size={13} /></button>
        </h3>
        <div className="field"><label>target</label>
          <select value={targetId} onChange={(e) => setTargetId(e.target.value)}>
            {targets.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
          </select>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <RunSelect v={a} set={setA} title="run A (baseline)" />
          <RunSelect v={b} set={setB} title="run B (compare)" />
        </div>
        <div style={{ overflow: "auto", marginTop: 6 }}>
          {note && <div className="muted" style={{ fontSize: 12 }}>{note}</div>}
          {a && b && a === b && <div className="muted" style={{ fontSize: 12 }}>Pick two different runs.</div>}
          {diff && (<><Row items={diff.added} kind="added" /><Row items={diff.dropped} kind="dropped" /><Row items={diff.changed} kind="changed" /></>)}
        </div>
      </div>
    </div>
  );
}
