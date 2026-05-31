import { useEffect, useState } from "react";
import { api, Finding } from "../api";
import { Icon } from "./Icon";
import Annotations from "./Annotations";

const LIFECYCLE = ["new", "triaging", "confirmed", "reported"];
function Lifecycle({ status }: { status: string }) {
  const dismissed = status === "dismissed";
  const idx = LIFECYCLE.indexOf(status);
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 4, margin: "8px 0", flexWrap: "wrap" }}>
      {LIFECYCLE.map((s, i) => (
        <span key={s} style={{
          fontSize: 10.5, padding: "2px 8px", borderRadius: 999,
          background: !dismissed && i <= idx ? "var(--accent-grad)" : "var(--surface-3)",
          color: !dismissed && i <= idx ? "#0a0c12" : "var(--muted)", fontWeight: 700,
        }}>{s}</span>
      ))}
      {dismissed && <span className="chip sev-info">dismissed</span>}
    </div>
  );
}

// Detail + triage + follow-on launch + provenance for a selected finding.
export default function Inspector({ finding, projectId, hypotheses = [], onChanged, onLaunch, onOpenLaunch, onViewTask, onHighlight, fuzzingEnabled }: {
  finding: Finding | null; projectId?: string; hypotheses?: { id: string; statement: string }[];
  onChanged: () => void; onLaunch: (taskId: string) => void;
  onOpenLaunch?: (type: string, opts?: { objective?: string; params?: any }) => void;
  onViewTask?: (taskId: string) => void; onHighlight?: (ids: string[]) => void; fuzzingEnabled?: boolean;
}) {
  const [sugg, setSugg] = useState<any[]>([]);
  const [copied, setCopied] = useState(false);
  const [hypId, setHypId] = useState("");
  useEffect(() => {
    setSugg([]); setCopied(false); setHypId("");
    if (finding) api.suggestions(finding.id).then(setSugg).catch(() => setSugg([]));
  }, [finding?.id]);

  if (!finding) return <div className="empty">Select a finding in the list or a node in the graph.</div>;
  const ev = finding.evidence || {};

  const setStatus = async (s: string) => { await api.setStatus(finding.id, s); onChanged(); };
  // Follow-ups open the deliberate LaunchModal (prefilled) rather than firing
  // blind; fall back to direct spawn only if no modal handler is wired.
  const spawn = async (i: number, fu: any) => {
    if (onOpenLaunch) onOpenLaunch(fu.task_type, { objective: fu.label, params: fu.params || {} });
    else { const { task_id } = await api.spawnFollowup(finding.id, i); onLaunch(task_id); }
  };
  const launchSuggested = async (s: any) => {
    if (onOpenLaunch) onOpenLaunch(s.task_type, { objective: s.label, params: s.params || {} });
    else { const { task_id } = await api.launch({ target_id: finding.target_id, type: s.task_type, params: s.params || {} }); onLaunch(task_id); }
  };
  const copy = () => { navigator.clipboard?.writeText(ev.decompiled_snippet || ""); setCopied(true); setTimeout(() => setCopied(false), 1200); };
  const newHypothesis = async () => {
    if (!projectId) return;
    const statement = window.prompt("New hypothesis (this finding becomes supporting evidence):", finding.title);
    if (!statement?.trim()) return;
    const h = await api.createHypothesis(projectId, { statement: statement.trim(), target_id: finding.target_id });
    await api.linkEvidence(h.id, finding.id, "supports");
    onChanged();
  };
  const linkHyp = async (relation: string) => { if (hypId) { await api.linkEvidence(hypId, finding.id, relation); setHypId(""); onChanged(); } };

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
      <Lifecycle status={finding.status} />
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
        {finding.task_type === "harness_generation" && fuzzingEnabled && onOpenLaunch && (
          <button className="btn sm primary" title="Fuzz using this harness"
                  onClick={() => onOpenLaunch("fuzzing")}><Icon name="run" size={12} /> Fuzz this harness</button>
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
              <button className="btn sm" key={i} onClick={() => spawn(i, s)}><Icon name="run" size={11} /> {s.label}</button>
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

      <div className="sec">Hypotheses</div>
      <div className="actions" style={{ flexWrap: "wrap" }}>
        <button className="btn sm" onClick={newHypothesis}><Icon name="plus" size={11} /> New from finding</button>
        {hypotheses.length > 0 && (
          <>
            <select className="sel" value={hypId} onChange={(e) => setHypId(e.target.value)}>
              <option value="">link to existing…</option>
              {hypotheses.map((h) => <option key={h.id} value={h.id}>{h.statement.slice(0, 60)}</option>)}
            </select>
            <button className="btn sm" disabled={!hypId} onClick={() => linkHyp("supports")}><Icon name="check" size={11} /> supports</button>
            <button className="btn sm danger" disabled={!hypId} onClick={() => linkHyp("refutes")}><Icon name="x" size={11} /> refutes</button>
          </>
        )}
      </div>

      {projectId && <Annotations projectId={projectId} nodeKind="finding" nodeId={finding.id} onChanged={onChanged} />}
    </div>
  );
}
