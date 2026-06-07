import { useEffect, useState } from "react";
import { api, Finding } from "../api";
import { Icon } from "./Icon";
import Annotations from "./Annotations";
import Provenance from "./Provenance";
import Mitigations from "./Mitigations";

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

// "input_reachable" → "input reachable"; keep enum-ish tokens human-readable.
const human = (s: any) => String(s ?? "").replace(/_/g, " ");

// The assurance triple as a one-line "standard · method · precondition", with the
// lab-confirmed (code_present/dynamic) vs reachable (input_reachable) distinction made
// legible — this is the crux the assurance work exists to keep honest.
function AssuranceLine({ a }: { a: any }) {
  if (!a) return null;
  const isReachable = a.standard === "input_reachable";
  const isDynamic = a.method === "dynamic";
  const lab = a.standard === "code_present" && isDynamic; // lab-confirmed in isolation
  const color = isReachable && isDynamic ? "#2ea043" : lab ? "#d29922" : "var(--muted)";
  const note = isReachable
    ? "reachable through the live deployed input boundary"
    : lab ? "lab-confirmed in isolation — production input path not established"
    : "static / suspected";
  return (
    <>
      <span className="k">assurance</span>
      <span style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 6 }}>
        <code style={{ color, borderColor: color }}>
          {human(a.standard)} · {human(a.method)} · {human(a.precondition)}
          {a.precondition_inferred ? " (inferred)" : ""}
        </code>
        <span className="muted" style={{ fontSize: 10.5 }}>{note}</span>
      </span>
    </>
  );
}

// Render a PoC spec's steps in plain language (web steps / a tcp send / a binary run),
// so the analyst reads what the PoC DOES without parsing the raw JSON (still available
// in the collapsible below).
function PocSteps({ poc }: { poc: any }) {
  if (!poc) return null;
  const lines: string[] = [];
  const oracle = poc.oracle;
  const steps = poc.steps || (poc.request ? [poc.request] : []);
  if (steps.length) {
    steps.forEach((s: any, i: number) => {
      const method = (s.method || "GET").toUpperCase();
      const path = s.path || "/";
      const bits = [`${i + 1}. ${method} ${path}`];
      if (s.params && Object.keys(s.params).length) bits.push(`params ${JSON.stringify(s.params)}`);
      if (s.body) bits.push(`body ${typeof s.body === "string" ? s.body : JSON.stringify(s.body)}`);
      if (s.json) bits.push(`json ${JSON.stringify(s.json)}`);
      if (s.headers && Object.keys(s.headers).length) bits.push(`headers ${Object.keys(s.headers).join(", ")}`);
      lines.push(bits.join("  ·  "));
    });
  } else if (poc.transport === "tcp" || poc.tcp || poc.port) {
    const tcp = (poc.tcp && typeof poc.tcp === "object") ? poc.tcp : poc;
    lines.push(`Send to TCP port ${tcp.port || poc.port}: ${JSON.stringify(tcp.payload ?? poc.payload ?? "")}`);
  } else {
    if (poc.env && Object.keys(poc.env).length) lines.push(`env: ${Object.entries(poc.env).map(([k, v]) => `${k}=${v}`).join(" ")}`);
    lines.push(`run target ${(poc.argv || []).join(" ")}`.trim());
    if (poc.stdin) lines.push(`stdin: ${poc.stdin}`);
  }
  return (
    <div className="kvs" style={{ marginTop: 4 }}>
      <span className="k">steps</span>
      <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
        {lines.map((l, i) => <code key={i} style={{ whiteSpace: "pre-wrap", fontSize: 11 }}>{l}</code>)}
        {oracle && <span className="muted" style={{ fontSize: 10.5 }}>
          oracle: {oracle.type || "output_contains"}{oracle.value !== undefined ? ` = ${JSON.stringify(oracle.value)}` : ""}
        </span>}
      </div>
    </div>
  );
}

// Detail + triage + follow-on launch + provenance for a selected finding.
export default function Inspector({ finding, projectId, hypotheses = [], onChanged, onDeleted, onLaunch, onOpenLaunch, onViewTask, onHighlight, fuzzingEnabled, onOpenSource }: {
  finding: Finding | null; projectId?: string; hypotheses?: { id: string; statement: string }[];
  onChanged: () => void; onDeleted?: () => void; onLaunch: (taskId: string) => void;
  onOpenLaunch?: (type: string, opts?: { objective?: string; params?: any }) => void;
  onViewTask?: (taskId: string) => void; onHighlight?: (ids: string[]) => void; fuzzingEnabled?: boolean;
  onOpenSource?: (ref: { tree_id?: string; rel?: string; line?: number }) => void;
}) {
  const [sugg, setSugg] = useState<any[]>([]);
  const [copied, setCopied] = useState(false);
  const [hypId, setHypId] = useState("");
  const [editing, setEditing] = useState(false);
  const [form, setForm] = useState<Partial<Finding>>({});
  const [savingEdit, setSavingEdit] = useState(false);
  const [editErr, setEditErr] = useState<string>();
  const [verifying, setVerifying] = useState(false);
  const [verifyMsg, setVerifyMsg] = useState<string>();
  const [pocOpen, setPocOpen] = useState(false);
  const [reproCopied, setReproCopied] = useState(false);
  const [solvedCopied, setSolvedCopied] = useState(false);
  const [minimalCopied, setMinimalCopied] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  useEffect(() => {
    setSugg([]); setCopied(false); setHypId("");
    setEditing(false); setEditErr(undefined); setVerifyMsg(undefined); setPocOpen(false); setReproCopied(false); setSolvedCopied(false);
    setConfirmDelete(false); setDeleting(false);
    if (finding) api.suggestions(finding.id).then(setSugg).catch(() => setSugg([]));
  }, [finding?.id]);

  if (!finding) return <div className="empty">Select a finding in the list or a node in the graph.</div>;
  const ev = finding.evidence || {};
  const poc = ev.extra?.poc;
  const verification = ev.extra?.verification;
  const sourceRef = ev.extra?.source_ref;  // {tree_id, rel, line} — the jump-to-source link (Phase 1)
  // Canonical assurance is evidence.extra.assurance; a PoC also nests it under verification.
  const assurance = ev.extra?.assurance || verification?.assurance;
  const reproCommand = ev.extra?.repro_command;
  const reproStr = Array.isArray(reproCommand) ? reproCommand.join(" ") : reproCommand;
  // Symbolic-execution (angr) solver evidence: the solved input that drives the
  // path to the sink, plus how it was found. evidence.reproducer carries the bytes;
  // evidence.extra.solver carries the model + path + provenance.
  const solver = ev.extra?.solver;
  const solvedInput = ev.reproducer || solver?.concrete_input_hex;
  // The minimal reproducer: angr's full reproducer includes unconstrained filler bytes, so the
  // constrained-byte prefix (minimal_input_hex) is the part that actually matters — what a human
  // should copy. Only show it when it's genuinely shorter than the full buffer.
  const minimalInput: string | undefined = solver?.minimal_input_hex;
  const constrainedLen: number | undefined = solver?.constrained_len;
  const showMinimal = !!minimalInput && minimalInput !== solvedInput;

  const setStatus = async (s: string) => { await api.setStatus(finding.id, s); onChanged(); };

  // HARD delete — irreversible, behind an inline confirm. Distinct from Dismiss
  // (which keeps the row, reversibly). On success the finding is gone from the
  // graph/list, so we ask the parent to clear the selection.
  const doDelete = async () => {
    setDeleting(true);
    try {
      await api.deleteFinding(finding.id);
      setConfirmDelete(false);
      (onDeleted || onChanged)();
    } finally { setDeleting(false); }
  };

  const startEdit = () => {
    setForm({
      title: finding.title, severity: finding.severity, confidence: finding.confidence,
      category: finding.category, summary: finding.summary, reasoning: finding.reasoning, status: finding.status,
    });
    setEditErr(undefined); setEditing(true);
  };
  const discardEdit = () => { setEditing(false); setEditErr(undefined); };
  const saveEdit = async () => {
    setSavingEdit(true); setEditErr(undefined);
    try {
      await api.patchFinding(finding.id, {
        title: form.title, severity: form.severity, confidence: form.confidence,
        category: form.category, summary: form.summary, reasoning: form.reasoning, status: form.status,
      });
      setEditing(false); onChanged();
    } catch (e: any) { setEditErr(String(e.message || e)); }
    finally { setSavingEdit(false); }
  };

  const verify = async () => {
    setVerifying(true); setVerifyMsg(undefined);
    try {
      const r = await api.verifyFinding(finding.id);
      setVerifyMsg(r.detail || (r.verified ? "verified" : "not verified"));
      onChanged();
    } catch (e: any) { setVerifyMsg(String(e.message || e)); }
    finally { setVerifying(false); }
  };
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
  const copyRepro = () => { navigator.clipboard?.writeText(reproStr || ""); setReproCopied(true); setTimeout(() => setReproCopied(false), 1200); };
  const copySolved = () => { navigator.clipboard?.writeText(solvedInput || ""); setSolvedCopied(true); setTimeout(() => setSolvedCopied(false), 1200); };
  const copyMinimal = () => { navigator.clipboard?.writeText(minimalInput || ""); setMinimalCopied(true); setTimeout(() => setMinimalCopied(false), 1200); };
  const newHypothesis = async () => {
    if (!projectId) return;
    const statement = window.prompt("New hypothesis (this finding becomes supporting evidence):", finding.title);
    if (!statement?.trim()) return;
    const h = await api.createHypothesis(projectId, { statement: statement.trim(), target_id: finding.target_id });
    await api.linkEvidence(h.id, finding.id, "supports");
    onChanged();
  };
  const linkHyp = async (relation: string) => { if (hypId) { await api.linkEvidence(hypId, finding.id, relation); setHypId(""); onChanged(); } };

  // One "Next steps" list: the finding's own follow-ups first, then rule-based
  // suggestions that aren't already covered (deduped by task_type+label) — so the
  // two sources don't show near-identical buttons twice.
  const fuKey = (s: any) => `${s.task_type}|${(s.label || "").toLowerCase()}`;
  const fuKeys = new Set((finding.suggested_followups || []).map(fuKey));
  const nextSteps = [
    ...(finding.suggested_followups || []).map((s: any, i: number) => ({ label: s.label, from: "finding" as const, run: () => spawn(i, s) })),
    ...sugg.filter((s) => !fuKeys.has(fuKey(s))).map((s: any) => ({ label: s.label, from: "suggester" as const, run: () => launchSuggested(s) })),
  ];

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
        {finding.finding_type && finding.finding_type !== "vulnerability" && (
          <span className="tag" style={{ textTransform: "none" }}>{finding.finding_type.replace(/_/g, " ")}</span>
        )}
        {finding.verified && <span className="tag" style={{ color: "#2ea043", borderColor: "#2ea043" }}>✓ verified PoC</span>}
        {finding.origin && finding.origin !== "agent" && <span className="tag">{finding.origin}</span>}
      </div>
      <Lifecycle status={finding.status} />
      <div className="actions">
        {!editing && <button className="btn sm ghost" onClick={startEdit}><Icon name="sliders" size={12} /> Edit</button>}
        <button className="btn sm" onClick={() => setStatus("confirmed")}><Icon name="check" size={12} /> Confirm</button>
        <button className="btn sm danger" title="Set aside reversibly — keeps the finding, greyed; you can restore it"
                onClick={() => setStatus("dismissed")}><Icon name="x" size={12} /> Dismiss</button>
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
        {/* HARD delete, deliberately set apart from the benign Dismiss above: pushed to
            the right, opens a two-step inline confirm before anything is destroyed. */}
        <span style={{ flex: 1 }} />
        {!confirmDelete ? (
          <button className="btn sm danger" style={{ borderStyle: "dashed" }}
                  title="Permanently delete this finding — IRREVERSIBLE (use Dismiss to set it aside reversibly)"
                  onClick={() => setConfirmDelete(true)}><Icon name="trash" size={12} /> Delete</button>
        ) : (
          <span style={{ display: "inline-flex", alignItems: "center", gap: 6, padding: "2px 8px",
                         border: "1px solid var(--danger, #f85149)", borderRadius: 8 }}>
            <span className="muted" style={{ fontSize: 11, color: "var(--danger, #f85149)" }}>Delete permanently?</span>
            <button className="btn sm danger" disabled={deleting} onClick={doDelete}>
              <Icon name="trash" size={12} /> {deleting ? "Deleting…" : "Yes, delete"}</button>
            <button className="btn sm ghost" disabled={deleting} onClick={() => setConfirmDelete(false)}>Cancel</button>
          </span>
        )}
      </div>

      {editing ? (
        <div className="edit-finding" style={{ display: "flex", flexDirection: "column", gap: 8, margin: "8px 0" }}>
          <label className="fld"><span className="k">title</span>
            <input className="sel" value={form.title ?? ""} onChange={(e) => setForm((f) => ({ ...f, title: e.target.value }))} /></label>
          <div style={{ display: "flex", gap: 8 }}>
            <label className="fld" style={{ flex: 1 }}><span className="k">severity</span>
              <select className="sel" value={form.severity ?? "info"} onChange={(e) => setForm((f) => ({ ...f, severity: e.target.value }))}>
                {["critical", "high", "medium", "low", "info"].map((s) => <option key={s} value={s}>{s}</option>)}
              </select></label>
            <label className="fld" style={{ flex: 1 }}><span className="k">confidence</span>
              <select className="sel" value={form.confidence ?? "medium"} onChange={(e) => setForm((f) => ({ ...f, confidence: e.target.value }))}>
                {["high", "medium", "low"].map((s) => <option key={s} value={s}>{s}</option>)}
              </select></label>
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <label className="fld" style={{ flex: 1 }}><span className="k">category</span>
              <input className="sel" value={form.category ?? ""} onChange={(e) => setForm((f) => ({ ...f, category: e.target.value }))} /></label>
            <label className="fld" style={{ flex: 1 }}><span className="k">status</span>
              <select className="sel" value={form.status ?? "new"} onChange={(e) => setForm((f) => ({ ...f, status: e.target.value }))}>
                {["new", "triaging", "confirmed", "reported", "dismissed"].map((s) => <option key={s} value={s}>{s}</option>)}
              </select></label>
          </div>
          <label className="fld"><span className="k">summary</span>
            <textarea className="sel" rows={3} value={form.summary ?? ""} onChange={(e) => setForm((f) => ({ ...f, summary: e.target.value }))} /></label>
          <label className="fld"><span className="k">reasoning</span>
            <textarea className="sel" rows={4} value={form.reasoning ?? ""} onChange={(e) => setForm((f) => ({ ...f, reasoning: e.target.value }))} /></label>
          {editErr && <div className="err">{editErr}</div>}
          <div className="actions">
            <button className="btn sm primary" onClick={saveEdit} disabled={savingEdit}><Icon name="check" size={12} /> {savingEdit ? "saving…" : "Save"}</button>
            <button className="btn sm ghost" onClick={discardEdit} disabled={savingEdit}><Icon name="x" size={12} /> Discard</button>
          </div>
        </div>
      ) : (
        <p>{finding.summary}</p>
      )}

      {(poc || verification) && (
        <>
          <div className="sec">Proof of Concept</div>
          {(verification || assurance) && (
            <div className="kvs">
              {verification && <>
                <span className="k">status</span>
                <span>
                  {verification.verified
                    ? <span className="tag" style={{ color: "#2ea043", borderColor: "#2ea043" }}>✓ verified</span>
                    : <span className="tag" style={{ color: "#ff5d6c", borderColor: "#ff5d6c" }}>✗ not verified</span>}
                </span>
              </>}
              <AssuranceLine a={assurance} />
              {verification?.detail && <><span className="k">detail</span><span>{verification.detail}</span></>}
              {verification && verification.exit_code !== undefined && verification.exit_code !== null && <><span className="k">exit code</span><code>{String(verification.exit_code)}</code></>}
              {verification?.nonce && <><span className="k">nonce</span><code>{verification.nonce}</code></>}
            </div>
          )}
          {assurance?.detail && <p className="muted" style={{ fontSize: 11, margin: "2px 0 0" }}>{assurance.detail}</p>}

          {/* Plain-language steps so the analyst reads what the PoC does (raw JSON below). */}
          <PocSteps poc={poc} />

          {/* Copy-paste reproduction command derived from the spec (display only). */}
          {reproStr && (
            <>
              <div className="kvs" style={{ marginTop: 6 }}><span className="k">reproduce</span><span /></div>
              <div className="codewrap">
                <button className="btn sm icon copy" title="Copy reproduction command" onClick={copyRepro}>
                  <Icon name={reproCopied ? "check" : "copy"} size={12} />
                </button>
                <pre style={{ whiteSpace: "pre-wrap", fontSize: 11 }}>{reproStr}</pre>
              </div>
            </>
          )}

          {verification?.output && (
            <pre className="codewrap" style={{ whiteSpace: "pre-wrap", maxHeight: 240, overflow: "auto", fontSize: 11 }}>{String(verification.output).slice(0, 1000)}</pre>
          )}
          {poc && (
            <details open={pocOpen} onToggle={(e) => setPocOpen((e.target as HTMLDetailsElement).open)} style={{ marginTop: 6 }}>
              <summary style={{ cursor: "pointer", fontSize: 12 }} className="muted">PoC spec (JSON)</summary>
              <pre className="codewrap" style={{ whiteSpace: "pre-wrap", maxHeight: 280, overflow: "auto", fontSize: 11 }}>{JSON.stringify(poc, null, 2)}</pre>
            </details>
          )}
          {poc && (
            <div className="actions" style={{ marginTop: 8 }}>
              <button className="btn sm primary" onClick={verify} disabled={verifying}>
                <Icon name={verifying ? "refresh" : "run"} size={12} className={verifying ? "spin" : ""} />
                {verifying ? " verifying…" : verification ? " Re-verify" : " Verify PoC"}
              </button>
              {verifyMsg && <span className="muted" style={{ fontSize: 11 }}>{verifyMsg}</span>}
            </div>
          )}
        </>
      )}

      {/* Symbolic-execution (angr) solver evidence — the flagship "solved input that
          reaches the sink" result. The reproducer bytes are the headline (copyable);
          the solver block explains the input model, the path, and how it was found. */}
      {(solvedInput || solver) && (
        <>
          <div className="sec">Solved input <span className="muted" style={{ fontWeight: 400 }}>· {solver?.backend || "angr"} symbolic execution</span></div>
          {solver?.sink_func && (
            <p className="muted" style={{ fontSize: 11, margin: "0 0 6px" }}>
              Constraint-solved an input that drives execution to <code>{solver.sink_func}</code>
              {solver.input_model ? <> via the <code>{human(solver.input_model)}</code> input boundary</> : null}.
            </p>
          )}
          {/* The constrained prefix is the part that actually matters — angr's full reproducer
              pads with unconstrained filler bytes. Surface it FIRST (and most prominently) so a
              human copies the real serial, with the full buffer shown below for completeness. */}
          {showMinimal && (
            <>
              <div className="kvs">
                <span className="k">constrained serial</span>
                <span className="muted" style={{ fontSize: 10.5 }}>
                  first {constrainedLen} {constrainedLen === 1 ? "byte" : "bytes"} that matter
                </span>
              </div>
              <div className="codewrap">
                <button className="btn sm icon copy" title="Copy the constrained bytes (the part that matters)" onClick={copyMinimal}>
                  <Icon name={minimalCopied ? "check" : "copy"} size={12} />
                </button>
                <pre style={{ whiteSpace: "pre-wrap", wordBreak: "break-all", fontSize: 11 }}>{minimalInput}</pre>
              </div>
            </>
          )}
          {solvedInput && (
            <>
              <div className="kvs">
                <span className="k">{showMinimal ? "full reproducer" : "reproducer"}</span>
                {showMinimal
                  ? <span className="muted" style={{ fontSize: 10.5 }}>incl. unconstrained filler</span>
                  : <span />}
              </div>
              <div className="codewrap">
                <button className="btn sm icon copy" title="Copy the solved input bytes" onClick={copySolved}>
                  <Icon name={solvedCopied ? "check" : "copy"} size={12} />
                </button>
                <pre style={{ whiteSpace: "pre-wrap", wordBreak: "break-all", fontSize: 11 }}>{solvedInput}</pre>
              </div>
              {solver?.concrete_input_repr && (
                <p className="muted" style={{ fontSize: 10.5, margin: "2px 0 0" }}>
                  as bytes: <code>{solver.concrete_input_repr}</code>
                </p>
              )}
            </>
          )}
          {solver && (
            <div className="kvs" style={{ marginTop: 6 }}>
              {solver.input_model && <><span className="k">input model</span><code>{human(solver.input_model)}</code></>}
              {solver.reached_addr && <><span className="k">reached</span><code>{solver.reached_addr}</code></>}
              {(solver.sink_addr || solver.sink_func) && <><span className="k">sink</span><code>{solver.sink_addr || solver.sink_func}</code></>}
              {Array.isArray(solver.path_addrs) && solver.path_addrs.length > 0 && (
                <><span className="k">path</span><span className="muted" style={{ fontSize: 11 }}>{solver.path_addrs.length} basic blocks to the sink</span></>
              )}
              {solver.provenance?.angr_version && <><span className="k">angr</span><code>{solver.provenance.angr_version}</code></>}
              {typeof solver.provenance?.steps === "number" && <><span className="k">steps</span><code>{solver.provenance.steps}</code></>}
              {typeof solver.provenance?.elapsed === "number" && <><span className="k">elapsed</span><code>{solver.provenance.elapsed}s</code></>}
            </div>
          )}
          {Array.isArray(solver?.path_addrs) && solver.path_addrs.length > 0 && (
            <details style={{ marginTop: 6 }}>
              <summary style={{ cursor: "pointer", fontSize: 12 }} className="muted">Path to sink ({solver.path_addrs.length} blocks)</summary>
              <pre className="codewrap" style={{ whiteSpace: "pre-wrap", maxHeight: 200, overflow: "auto", fontSize: 11 }}>{solver.path_addrs.join(" → ")}</pre>
            </details>
          )}
          {solver?.observation_id && (
            <p className="muted" style={{ fontSize: 10.5, margin: "4px 0 0" }}>
              observation <code>{String(solver.observation_id).slice(0, 8)}…</code>
            </p>
          )}
        </>
      )}

      {(ev.function || ev.sink || ev.address || ev.file) && (
        <>
          <div className="sec">Evidence</div>
          <div className="kvs">
            {ev.function && <><span className="k">function</span><code>{ev.function}</code></>}
            {ev.sink && <><span className="k">sink</span><code>{ev.sink}</code></>}
            {ev.address && <><span className="k">address</span><code>{ev.address}</code></>}
            {ev.file && <><span className="k">file</span><code>{ev.file}</code></>}
            {ev.extra?.mitigations && <><span className="k">mitigations</span><Mitigations mitigations={ev.extra.mitigations} /></>}
          </div>
        </>
      )}

      {sourceRef?.tree_id && sourceRef?.rel && onOpenSource && (
        <div className="actions" style={{ marginTop: 8 }}>
          <button className="btn sm" title="Open this finding's source location in the Source tab"
                  onClick={() => onOpenSource(sourceRef)}>
            <Icon name="doc" size={12} /> Open in source{sourceRef.line ? ` (line ${sourceRef.line})` : ""}
          </button>
        </div>
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

      {!editing && (
        <>
          <div className="sec">Reasoning</div>
          <p style={{ color: "var(--fg-dim)" }}>{finding.reasoning}</p>
        </>
      )}

      {finding.human_notes && (<><div className="sec">Analyst notes</div><p>{finding.human_notes}</p></>)}

      {/* Provenance: the tool results this finding was derived from (read-only).
          Stored on evidence.extra.provenance — renders nothing when absent. */}
      <Provenance ids={ev.extra?.provenance} />

      {nextSteps.length > 0 && (
        <>
          <div className="sec">Next steps</div>
          <div className="actions">
            {nextSteps.map((s, i) => (
              <button className="btn sm" key={i} title={s.from === "finding" ? "Suggested by this finding" : "Rule-based suggestion"}
                      onClick={() => s.run()}>
                <Icon name={s.from === "finding" ? "run" : "spark"} size={11} /> {s.label}
              </button>
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
