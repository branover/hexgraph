import { useEffect, useState } from "react";
import { api } from "../api";

const ST: Record<string, string> = {
  succeeded: "var(--low)", needs_triage: "var(--medium)", running: "var(--accent)",
  queued: "var(--muted)", failed: "var(--critical)",
};

export function TasksPanel({ tasks, selectedId, onSelect }: { tasks: any[]; selectedId?: string; onSelect: (id: string) => void }) {
  return (
    <div className="scroll">
      {tasks.length === 0 && <div className="empty">No tasks yet.</div>}
      {tasks.map((t) => (
        <div key={t.id} className={"finding" + (t.id === selectedId ? " sel" : "")} onClick={() => onSelect(t.id)}>
          <span className="ttl">{t.type}</span>
          <span style={{ float: "right", color: ST[t.status] || "var(--muted)", fontSize: 12 }}>{t.status}</span>
          <div className="mt">
            {t.finding_count} findings · {t.backend || "—"}{t.model ? " · " + t.model : ""}
            {t.cost_estimate ? ` · $${t.cost_estimate.toFixed(4)}` : " · $0"}
          </div>
        </div>
      ))}
    </div>
  );
}

export function TaskDetail({ taskId, onViewFinding, onRerun }: { taskId: string; onViewFinding: (id: string) => void; onRerun: (newId: string) => void }) {
  const [d, setD] = useState<any>(null);
  useEffect(() => { setD(null); api.taskDetail(taskId).then(setD).catch(() => {}); }, [taskId]);
  if (!d) return <div className="empty">Loading task…</div>;
  const t = d.task;
  return (
    <div className="insp scroll">
      <h3>{t.type} <span className="muted" style={{ fontSize: 12 }}>{t.status}</span></h3>
      <div className="actions">
        <button className="btn sm primary" onClick={async () => onRerun((await api.rerun(taskId)).task_id)}>Re-run</button>
      </div>
      <div className="kv">backend: <code>{t.backend || "—"}</code>{t.model ? <> · model: <code>{t.model}</code></> : null} · cost: ${(t.cost_estimate || 0).toFixed(4)}</div>
      {t.context_bundle_id && <div className="kv">context bundle: <code>{t.context_bundle_id.slice(0, 8)}</code></div>}
      {Object.keys(t.params || {}).length > 0 && <div className="kv">params: <code>{JSON.stringify(t.params)}</code></div>}
      <div className="kv">trace: {d.trace_files.join(", ") || "—"}</div>
      <div className="kv" style={{ marginTop: 10 }}>Findings produced ({d.findings.length})</div>
      {d.findings.map((f: any) => (
        <div key={f.id} className="finding" onClick={() => onViewFinding(f.id)}>
          <span className={"chip sev-" + f.severity}>{f.severity}</span>
          <span className="ttl">{f.title}</span>
        </div>
      ))}
    </div>
  );
}
