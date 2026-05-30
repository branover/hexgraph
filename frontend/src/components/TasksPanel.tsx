import { useEffect, useState } from "react";
import { api } from "../api";
import { Icon } from "./Icon";

const ST: Record<string, string> = {
  succeeded: "var(--low)", needs_triage: "var(--medium)", running: "var(--accent)",
  queued: "var(--muted)", failed: "var(--critical)",
};

export function TasksPanel({ tasks, selectedId, onSelect }: { tasks: any[]; selectedId?: string; onSelect: (id: string) => void }) {
  return (
    <div className="scroll">
      {tasks.length === 0 && <div className="empty">No tasks yet.</div>}
      {tasks.map((t) => (
        <div key={t.id} className={"finding fade-in" + (t.id === selectedId ? " sel" : "")} onClick={() => onSelect(t.id)}
             style={{ ["--sev" as any]: ST[t.status] || "var(--muted)" }}>
          <div className="rail" />
          <div className="body">
            <div className="row1">
              <Icon name="task" size={13} />
              <span className="ttl">{t.type.replace(/_/g, " ")}</span>
              <span className="grow" />
              <span style={{ color: ST[t.status] || "var(--muted)", fontSize: 11.5, fontWeight: 600 }}>{t.status}</span>
            </div>
            <div className="mt">
              {t.finding_count} findings · {t.backend || "—"}{t.model ? " · " + t.model : ""} · ${(t.cost_estimate || 0).toFixed(4)}
            </div>
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
    <div className="insp scroll fade-in">
      <div className="head"><Icon name="task" size={17} /><h3>{t.type.replace(/_/g, " ")}</h3></div>
      <div className="chips">
        <span className="tag" style={{ color: ST[t.status] }}>{t.status}</span>
        <span className="tag">{t.backend || "—"}</span>
        {t.model && <span className="tag">{t.model}</span>}
        <span className="tag">${(t.cost_estimate || 0).toFixed(4)}</span>
      </div>
      <div className="actions">
        <button className="btn sm primary" onClick={async () => onRerun((await api.rerun(taskId)).task_id)}><Icon name="refresh" size={12} /> Re-run</button>
      </div>
      <div className="sec">Provenance</div>
      <div className="kvs">
        {t.context_bundle_id && <><span className="k">bundle</span><code>{t.context_bundle_id.slice(0, 12)}</code></>}
        {Object.keys(t.params || {}).length > 0 && <><span className="k">params</span><code>{JSON.stringify(t.params)}</code></>}
        <span className="k">trace</span><span>{d.trace_files.join(", ") || "—"}</span>
      </div>
      <div className="sec">Findings produced ({d.findings.length})</div>
      {d.findings.map((f: any) => (
        <div key={f.id} className="finding" onClick={() => onViewFinding(f.id)} style={{ ["--sev" as any]: "var(--info)" }}>
          <div className="rail" />
          <div className="body"><div className="row1"><span className={"chip sev-" + f.severity}>{f.severity}</span><span className="ttl">{f.title}</span></div></div>
        </div>
      ))}
    </div>
  );
}
