import { useEffect, useState } from "react";
import { api, Finding } from "../api";
import { Icon } from "./Icon";

// Detail + triage + follow-on launch + provenance for a selected finding.
export default function Inspector({ finding, onChanged, onLaunch, onViewTask, onHighlight }: {
  finding: Finding | null; onChanged: () => void; onLaunch: (taskId: string) => void;
  onViewTask?: (taskId: string) => void; onHighlight?: (ids: string[]) => void;
}) {
  const [sugg, setSugg] = useState<any[]>([]);
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    setSugg([]); setCopied(false);
    if (finding) api.suggestions(finding.id).then(setSugg).catch(() => setSugg([]));
  }, [finding?.id]);

  if (!finding) return <div className="empty">Select a finding in the list or a node in the graph.</div>;
  const ev = finding.evidence || {};

  const setStatus = async (s: string) => { await api.setStatus(finding.id, s); onChanged(); };
  const spawn = async (i: number) => { const { task_id } = await api.spawnFollowup(finding.id, i); onLaunch(task_id); };
  const launchSuggested = async (s: any) => {
    const { task_id } = await api.launch({ target_id: finding.target_id, type: s.task_type, params: s.params || {} });
    onLaunch(task_id);
  };
  const copy = () => { navigator.clipboard?.writeText(ev.decompiled_snippet || ""); setCopied(true); setTimeout(() => setCopied(false), 1200); };

  return (
    <div className="insp scroll fade-in">
      <div className="head">
        <Icon name="bug" size={18} />
        <h3>{finding.title}</h3>
      </div>
      <div className="chips">
        <span className={"chip sev-" + finding.severity}><span className="d" />{finding.severity}</span>
        <span className="tag">{finding.category}</span>
        <span className="tag">{finding.confidence} confidence</span>
        <span className="tag">{finding.status}</span>
        {finding.origin && finding.origin !== "agent" && <span className="tag">{finding.origin}</span>}
      </div>
      <div className="actions">
        <button className="btn sm" onClick={() => setStatus("confirmed")}><Icon name="check" size={12} /> Accept</button>
        <button className="btn sm danger" onClick={() => setStatus("dismissed")}><Icon name="x" size={12} /> Dismiss</button>
        {onViewTask && <button className="btn sm ghost" onClick={() => onViewTask(finding.task_id)}><Icon name="task" size={12} /> Task</button>}
        {onHighlight && (
          <button className="btn sm ghost" onClick={async () => {
            const comps = await api.components(finding.id);
            onHighlight(comps.map((c: any) => c.id).filter(Boolean));
          }}><Icon name="target" size={12} /> Components</button>
        )}
      </div>

      <p>{finding.summary}</p>

      {(ev.function || ev.sink || ev.address || ev.file) && (
        <>
          <div className="sec">Evidence</div>
          <div className="kvs">
            {ev.function && <><span className="k">function</span><code>{ev.function}</code></>}
            {ev.sink && <><span className="k">sink</span><code>{ev.sink}</code></>}
            {ev.address && <><span className="k">address</span><code>{ev.address}</code></>}
            {ev.file && <><span className="k">file</span><code>{ev.file}</code></>}
            {ev.extra?.mitigations && <><span className="k">mitigations</span><code>{JSON.stringify(ev.extra.mitigations)}</code></>}
          </div>
        </>
      )}

      {ev.decompiled_snippet && (
        <>
          <div className="sec">Decompiled</div>
          <div className="codewrap">
            <button className="btn sm icon copy" title="Copy" onClick={copy}><Icon name={copied ? "check" : "copy"} size={12} /></button>
            <pre>{ev.decompiled_snippet}</pre>
          </div>
        </>
      )}

      <div className="sec">Reasoning</div>
      <p style={{ color: "var(--fg-dim)" }}>{finding.reasoning}</p>

      {finding.human_notes && (<><div className="sec">Analyst notes</div><p>{finding.human_notes}</p></>)}

      {finding.suggested_followups?.length ? (
        <>
          <div className="sec">Follow-ups</div>
          <div className="actions">
            {finding.suggested_followups.map((s, i) => (
              <button className="btn sm" key={i} onClick={() => spawn(i)}><Icon name="run" size={11} /> {s.label}</button>
            ))}
          </div>
        </>
      ) : null}

      {sugg.length > 0 && (
        <>
          <div className="sec">Suggested next steps</div>
          <div className="actions">
            {sugg.map((s, i) => (
              <button className="btn sm" key={i} onClick={() => launchSuggested(s)}><Icon name="spark" size={11} /> {s.label}</button>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
