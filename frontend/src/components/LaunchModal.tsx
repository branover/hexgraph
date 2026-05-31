import { useEffect, useState } from "react";
import { api, TargetNode } from "../api";
import { Icon } from "./Icon";

const MODELS = ["(project default)", "claude-opus-4-8", "claude-sonnet-4-6", "claude-haiku-4-5-20251001"];
const SCENARIOS = ["(default)", "critical_overflow", "agentic_overflow", "no_findings", "malformed_then_valid", "error_rate_limit", "error_timeout"];
const EFFORT = ["low", "medium", "high"];

// Deliberate task launch: objective/prompt, model, effort, budget, mock scenario,
// and a live pre-flight preview of the exact context bundle that will be sent.
// Reused for finding follow-ups (prefilled objective/params + parent_finding_id).
export default function LaunchModal({ target, taskType, isMock, initialObjective, initialParams,
  parentFindingId, anchorKind, anchorId, onClose, onLaunched }: {
  target: TargetNode; taskType: string; isMock: boolean;
  initialObjective?: string; initialParams?: Record<string, any>; parentFindingId?: string;
  anchorKind?: string; anchorId?: string;
  onClose: () => void; onLaunched: (taskId: string) => void;
}) {
  const [objective, setObjective] = useState(initialObjective || "");
  const [model, setModel] = useState("(project default)");
  const [scenario, setScenario] = useState((initialParams?.mock_scenario as string) || "(default)");
  const [effort, setEffort] = useState((initialParams?.effort as string) || "medium");
  const [budget, setBudget] = useState("10.00");
  const [fn, setFn] = useState((initialParams?.function as string) || "");
  const isFuzz = taskType === "fuzzing";
  const [fuzzTime, setFuzzTime] = useState(String(initialParams?.max_total_time ?? 60));
  const [triage, setTriage] = useState(Boolean(initialParams?.triage));
  const [preview, setPreview] = useState<any>(null);
  const [busy, setBusy] = useState(false);

  const body = () => {
    const params: any = { ...(initialParams || {}), effort, budget_usd: parseFloat(budget) || 0 };
    if (fn.trim()) params.function = fn.trim(); else delete params.function;
    if (isMock && scenario !== "(default)") params.mock_scenario = scenario; else delete params.mock_scenario;
    if (isFuzz) { params.max_total_time = parseInt(fuzzTime) || 60; params.triage = triage; }
    return {
      target_id: target.id, type: taskType, objective: objective.trim() || undefined,
      model: model === "(project default)" ? undefined : model, params,
      parent_finding_id: parentFindingId, anchor_kind: anchorKind, anchor_id: anchorId,
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
      <div className="modal launch fade-in">
        <h3>
          <Icon name="run" size={16} /> Launch {taskType.replace(/_/g, " ")}
          <span className="muted" style={{ fontWeight: 400, fontSize: 12 }}>· on {target.name}</span>
          {parentFindingId && <span className="tag" style={{ marginLeft: 6 }}>follow-up</span>}
          <span style={{ flex: 1 }} />
          <button className="btn sm ghost icon" onClick={onClose}><Icon name="x" size={13} /></button>
        </h3>

        <div className="launch-grid">
          <div className="launch-form">
            <div className="field"><label>objective / prompt</label>
              <textarea value={objective} onChange={(e) => setObjective(e.target.value)} rows={4}
                placeholder="What should the agent focus on? (optional — folded into the context)" />
            </div>
            <div className="field"><label>focus function (optional)</label>
              <input value={fn} onChange={(e) => setFn(e.target.value)} placeholder="e.g. cgi_handler" />
            </div>
            <div className="field"><label>model</label>
              <select value={model} onChange={(e) => setModel(e.target.value)}>{MODELS.map((m) => <option key={m}>{m}</option>)}</select>
            </div>
            <div className="grid2">
              <div className="field"><label>effort</label>
                <select value={effort} onChange={(e) => setEffort(e.target.value)}>{EFFORT.map((e2) => <option key={e2}>{e2}</option>)}</select>
              </div>
              <div className="field"><label>budget cap ($)</label>
                <input value={budget} onChange={(e) => setBudget(e.target.value)} />
              </div>
            </div>
            {isMock && (
              <div className="field"><label>mock scenario</label>
                <select value={scenario} onChange={(e) => setScenario(e.target.value)}>{SCENARIOS.map((s) => <option key={s}>{s}</option>)}</select>
              </div>
            )}
            {isFuzz && (
              <>
                <div className="field"><label>fuzz time (s)</label>
                  <input value={fuzzTime} onChange={(e) => setFuzzTime(e.target.value)} />
                </div>
                <label className="switch" style={{ fontSize: 12, display: "flex", gap: 8, alignItems: "center", marginTop: 4 }}>
                  <input type="checkbox" checked={triage} onChange={(e) => setTriage(e.target.checked)} />
                  <span>LLM-triage crashes (real backend only)</span>
                </label>
                <div className="muted" style={{ fontSize: 11, marginTop: 6 }}>
                  Uses the latest harness for this target. Crashes become findings automatically.
                </div>
              </>
            )}
          </div>

          <div className="launch-preview">
            <div className="sec">Context preview {preview && <span className="muted">· ~{preview.token_estimate} tok · {preview.items.length} items</span>}</div>
            <pre>{preview ? preview.prompt : "assembling…"}</pre>
            <div className="muted" style={{ fontSize: 11, marginTop: 6 }}>
              {isMock ? "$0 (mock)" : `est ≤ $${budget} cap`}
              {preview?.dropped?.length ? ` · ${preview.dropped.length} item(s) dropped to fit budget` : ""}
              {" · decompilation is added at run time."}
            </div>
          </div>
        </div>

        <div className="foot">
          <button className="btn ghost" onClick={onClose}>Cancel</button>
          <button className="btn primary" onClick={launch} disabled={busy}>
            <Icon name="run" size={12} /> {busy ? "launching…" : "Launch agent"}
          </button>
        </div>
      </div>
    </div>
  );
}
