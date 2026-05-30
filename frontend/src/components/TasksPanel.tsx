import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api";
import { Icon } from "./Icon";

const ST: Record<string, string> = {
  succeeded: "var(--low)", needs_triage: "var(--medium)", running: "var(--accent)",
  queued: "var(--muted)", failed: "var(--critical)",
};
const fmt = (iso?: string) => { if (!iso) return ""; return new Date(iso).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }); };

export function TasksPanel({ tasks, selectedId, onSelect, onClear }: {
  tasks: any[]; selectedId?: string; onSelect: (id: string) => void; onClear?: () => void;
}) {
  const [sort, setSort] = useState("recent");
  const [typeF, setTypeF] = useState("all");
  const selRef = useRef<HTMLDivElement>(null);
  useEffect(() => { selRef.current?.scrollIntoView({ block: "nearest", behavior: "smooth" }); }, [selectedId, tasks.length]);

  const types = useMemo(() => ["all", ...Array.from(new Set(tasks.map((t) => t.type)))], [tasks]);
  const view = useMemo(() => {
    const v = typeF === "all" ? tasks.slice() : tasks.filter((t) => t.type === typeF);
    const by: Record<string, (a: any, b: any) => number> = {
      recent: (a, b) => (b.created_at || "").localeCompare(a.created_at || ""),
      oldest: (a, b) => (a.created_at || "").localeCompare(b.created_at || ""),
      type: (a, b) => a.type.localeCompare(b.type),
      cost: (a, b) => (b.cost_estimate || 0) - (a.cost_estimate || 0),
      findings: (a, b) => (b.finding_count || 0) - (a.finding_count || 0),
    };
    return v.sort(by[sort] || by.recent);
  }, [tasks, typeF, sort]);

  return (
    <>
      <div className="fbar">
        <select className="sel" value={sort} onChange={(e) => setSort(e.target.value)} title="sort">
          {[["recent", "newest"], ["oldest", "oldest"], ["type", "by type"], ["cost", "by cost"], ["findings", "by findings"]].map(([v, l]) => <option key={v} value={v}>{l}</option>)}
        </select>
        <select className="sel" value={typeF} onChange={(e) => setTypeF(e.target.value)} title="filter by type">
          {types.map((t) => <option key={t} value={t}>{t === "all" ? "all types" : t}</option>)}
        </select>
        <span className="grow" />
        {onClear && <button className="btn sm danger" onClick={onClear} title="Remove finding-less tasks"><Icon name="x" size={12} /> Clear</button>}
      </div>
      <div className="scroll">
        {view.length === 0 && <div className="empty">No tasks.</div>}
        {view.map((t) => (
          <div key={t.id} ref={t.id === selectedId ? selRef : undefined}
               className={"finding fade-in" + (t.id === selectedId ? " sel" : "")} onClick={() => onSelect(t.id)}
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
                <span>{fmt(t.created_at)}</span><span>· {t.finding_count} findings</span>
                <span>· {t.backend || "—"}{t.model ? " · " + t.model : ""}</span><span>· ${(t.cost_estimate || 0).toFixed(4)}</span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </>
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
