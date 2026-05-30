import { useEffect, useState } from "react";
import { api, TargetNode } from "../api";
import { Icon } from "./Icon";

const MODELS = ["(project default)", "claude-opus-4-8", "claude-sonnet-4-6", "claude-haiku-4-5-20251001"];
const SCENARIOS = ["(default)", "critical_overflow", "no_findings", "malformed_then_valid", "error_rate_limit", "error_timeout"];
const EFFORT = ["low", "medium", "high"];

// Deliberate task launch: objective/prompt, model, effort, budget, mock scenario,
// and a live pre-flight preview of the exact context bundle that will be sent.
export default function LaunchModal({ target, taskType, isMock, onClose, onLaunched }: {
  target: TargetNode; taskType: string; isMock: boolean; onClose: () => void; onLaunched: (taskId: string) => void;
}) {
  const [objective, setObjective] = useState("");
  const [model, setModel] = useState("(project default)");
  const [scenario, setScenario] = useState("(default)");
  const [effort, setEffort] = useState("medium");
  const [budget, setBudget] = useState("10.00");
  const [fn, setFn] = useState("");
  const [preview, setPreview] = useState<any>(null);
  const [busy, setBusy] = useState(false);

  const body = () => {
    const params: any = { effort, budget_usd: parseFloat(budget) || 0 };
    if (fn.trim()) params.function = fn.trim();
    if (isMock && scenario !== "(default)") params.mock_scenario = scenario;
    return {
      target_id: target.id, type: taskType, objective: objective.trim() || undefined,
      model: model === "(project default)" ? undefined : model, params,
    };
  };

  useEffect(() => {
    let live = true;
    api.previewTask(body()).then((p) => live && setPreview(p)).catch(() => {});
    return () => { live = false; };
  }, [objective, fn, scenario, model, effort]); // eslint-disable-line

  const launch = async () => {
    setBusy(true);
    try { const { task_id } = await api.launch(body()); onLaunched(task_id); onClose(); }
    finally { setBusy(false); }
  };

  return (
    <div className="modal-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="modal fade-in" style={{ width: 760, display: "grid", gridTemplateColumns: "1fr 1fr", gap: 18 }}>
        <div>
          <h3><Icon name="run" size={16} /> Launch {taskType.replace(/_/g, " ")}</h3>
          <div className="muted" style={{ fontSize: 12, marginTop: -8, marginBottom: 12 }}>on {target.name}</div>
          <div className="field"><label>objective / prompt</label>
            <textarea value={objective} onChange={(e) => setObjective(e.target.value)} rows={3}
              style={{ width: "100%", resize: "vertical", background: "var(--bg)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: 7, padding: 8, font: "inherit" }}
              placeholder="What should the agent focus on? (optional — folded into the context)" />
          </div>
          <div className="field"><label>focus function (optional)</label>
            <input value={fn} onChange={(e) => setFn(e.target.value)} placeholder="e.g. cgi_handler" />
          </div>
          <div className="field"><label>model</label>
            <select value={model} onChange={(e) => setModel(e.target.value)}>{MODELS.map((m) => <option key={m}>{m}</option>)}</select>
          </div>
          <div style={{ display: "flex", gap: 10 }}>
            <div className="field" style={{ flex: 1 }}><label>effort</label>
              <select value={effort} onChange={(e) => setEffort(e.target.value)}>{EFFORT.map((e2) => <option key={e2}>{e2}</option>)}</select>
            </div>
            <div className="field" style={{ flex: 1 }}><label>budget cap ($)</label>
              <input value={budget} onChange={(e) => setBudget(e.target.value)} />
            </div>
          </div>
          {isMock && (
            <div className="field"><label>mock scenario</label>
              <select value={scenario} onChange={(e) => setScenario(e.target.value)}>{SCENARIOS.map((s) => <option key={s}>{s}</option>)}</select>
            </div>
          )}
        </div>
        <div>
          <div className="sec" style={{ marginTop: 4 }}>Context preview {preview && <span className="muted">· ~{preview.token_estimate} tok</span>}</div>
          <pre style={{ maxHeight: 300, fontSize: 11 }}>{preview ? preview.prompt : "assembling…"}</pre>
          {preview && (
            <div className="muted" style={{ fontSize: 11, marginTop: 6 }}>
              {preview.items.length} items · {isMock ? "$0 (mock)" : `est ≤ $${budget} cap`}
              {preview.dropped?.length ? ` · ${preview.dropped.length} dropped to fit budget` : ""}
            </div>
          )}
          <div className="muted" style={{ fontSize: 11, marginTop: 6 }}>Decompilation is added at run time.</div>
          <div className="foot">
            <button className="btn ghost" onClick={onClose}>Cancel</button>
            <button className="btn primary" onClick={launch} disabled={busy}>
              <Icon name="run" size={12} /> {busy ? "launching…" : "Launch agent"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
