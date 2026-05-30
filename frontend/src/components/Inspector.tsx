import { useEffect, useState } from "react";
import { api, Finding } from "../api";

// Detail + triage + follow-on launch for a selected finding (provenance to its
// task/components comes with P5). `onLaunch` polls + refreshes the workspace.
export default function Inspector({ finding, onChanged, onLaunch }: {
  finding: Finding | null; onChanged: () => void; onLaunch: (taskId: string) => void;
}) {
  const [sugg, setSugg] = useState<any[]>([]);
  useEffect(() => {
    setSugg([]);
    if (finding) api.suggestions(finding.id).then(setSugg).catch(() => setSugg([]));
  }, [finding?.id]);

  if (!finding) return <div className="empty">Select a finding or node.</div>;
  const ev = finding.evidence || {};

  const setStatus = async (s: string) => { await api.setStatus(finding.id, s); onChanged(); };
  const spawn = async (i: number) => { const { task_id } = await api.spawnFollowup(finding.id, i); onLaunch(task_id); };
  const launchSuggested = async (s: any) => {
    const { task_id } = await api.launch({ target_id: finding.target_id, type: s.task_type, params: s.params || {} });
    onLaunch(task_id);
  };

  return (
    <div className="insp scroll">
      <span className={"chip sev-" + finding.severity}>{finding.severity}</span>
      <h3 style={{ display: "inline", marginLeft: 6 }}>{finding.title}</h3>
      <div className="actions" style={{ marginTop: 10 }}>
        <span className="muted">status: <b>{finding.status}</b></span>
        <button className="btn sm" onClick={() => setStatus("confirmed")}>Accept</button>
        <button className="btn sm" onClick={() => setStatus("dismissed")}>Dismiss</button>
      </div>
      <p>{finding.summary}</p>
      <div className="kv">Reasoning</div>
      <p>{finding.reasoning}</p>
      {ev.function && <div className="kv">function: <code>{ev.function}</code></div>}
      {ev.sink && <div className="kv">sink: <code>{ev.sink}</code></div>}
      {ev.decompiled_snippet && <pre>{ev.decompiled_snippet}</pre>}
      {ev.extra?.mitigations && <div className="kv">mitigations: <code>{JSON.stringify(ev.extra.mitigations)}</code></div>}

      {finding.suggested_followups?.length ? (
        <>
          <div className="kv">Follow-ups</div>
          <div className="actions">
            {finding.suggested_followups.map((s, i) => (
              <button className="btn sm" key={i} onClick={() => spawn(i)}>{s.label}</button>
            ))}
          </div>
        </>
      ) : null}

      {sugg.length > 0 && (
        <>
          <div className="kv">Suggested next steps</div>
          <div className="actions">
            {sugg.map((s, i) => (
              <button className="btn sm" key={i} onClick={() => launchSuggested(s)}>✦ {s.label}</button>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
