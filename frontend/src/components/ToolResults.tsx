import { useEffect, useMemo, useState } from "react";
import { createPortal } from "react-dom";
import { Observation, api } from "../api";
import { Icon } from "./Icon";

// "function_list" → "function list"; keep result-kind tokens human-readable.
const human = (s: string) => String(s || "").replace(/_/g, " ");

function relTime(iso: string | null): string {
  if (!iso) return "";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return "";
  const secs = Math.max(0, (Date.now() - t) / 1000);
  if (secs < 60) return "just now";
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return `${Math.floor(secs / 86400)}d ago`;
}

// The raw CAS payload of one tool result, pretty-printed in a modal overlay. Fetched
// lazily by id (list/search responses carry metadata only, not the full payload).
export function RawResultModal({ obsId, onClose }: { obsId: string; onClose: () => void }) {
  const [obs, setObs] = useState<Observation | null>(null);
  const [err, setErr] = useState<string>();
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    setObs(null); setErr(undefined);
    api.observation(obsId).then(setObs).catch((e) => setErr(String(e.message || e)));
  }, [obsId]);
  const text = useMemo(() => {
    if (!obs) return "";
    const p = obs.payload;
    return typeof p === "string" ? p : JSON.stringify(p ?? null, null, 2);
  }, [obs]);
  const copy = () => { navigator.clipboard?.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1200); };
  // Portal to body so the fixed-position backdrop escapes the detail pane's transformed
  // / overflow-clipped ancestors and overlays the whole viewport.
  return createPortal((
    <div className="modal-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="modal" style={{ maxWidth: 760, width: "92%" }} onClick={(e) => e.stopPropagation()}>
        <h3>
          <Icon name="task" size={16} />
          {obs ? human(obs.result_kind) : "Tool result"}
          <span style={{ flex: 1 }} />
          <button className="btn sm ghost icon" onClick={onClose}><Icon name="x" size={13} /></button>
        </h3>
        <div className="modal-b scroll" style={{ maxHeight: "70vh", overflow: "auto" }}>
          {err && <div className="err">{err}</div>}
          {!obs && !err && <div className="muted" style={{ fontSize: 12 }}>loading…</div>}
          {obs && (
            <>
              <div className="kvs" style={{ marginBottom: 10 }}>
                <span className="k">tool</span><code>{obs.tool}</code>
                <span className="k">kind</span><span>{human(obs.result_kind)}</span>
                {Object.keys(obs.args || {}).length > 0 && (<><span className="k">args</span><code>{JSON.stringify(obs.args)}</code></>)}
                {obs.summary && (<><span className="k">summary</span><span>{obs.summary}</span></>)}
                <span className="k">status</span>
                <span><span className={"tag"} style={obs.status === "ok" ? { color: "#2ea043", borderColor: "#2ea043" } : { color: "#ff5d6c", borderColor: "#ff5d6c" }}>{obs.status}</span></span>
                {obs.content_hash && (<><span className="k">bytes</span><code>{obs.content_hash.slice(0, 16)}…</code></>)}
                <span className="k">recorded</span><span>{relTime(obs.created_at)}{obs.source ? ` · ${obs.source}` : ""}</span>
                {obs.size > 0 && (<><span className="k">size</span><span>{obs.size} B</span></>)}
              </div>
              <div className="sec" style={{ display: "flex", alignItems: "center" }}>
                <span>Raw payload</span><span style={{ flex: 1 }} />
                <button className="btn sm icon ghost" title="Copy" onClick={copy}><Icon name={copied ? "check" : "copy"} size={12} /></button>
              </div>
              <pre className="codewrap" style={{ whiteSpace: "pre-wrap", fontSize: 11, maxHeight: "48vh", overflow: "auto" }}>{text}</pre>
            </>
          )}
        </div>
      </div>
    </div>
  ), document.body);
}

// The "Tool Results" panel (Phase O, design §5.6): the durable record of deterministic
// tool calls — decompiles, listings, xrefs, taint, strings. Scoped to a TARGET (every call
// on that binary) or, with `nodeId`, to a NODE (its full result-set — every result that
// references it via node_refs: decompile/disasm/xrefs/recover_constant/…). Filter by
// tool/kind; click a row to read the raw CAS payload. Read-only: results persist here and
// do NOT auto-populate the graph; promote what matters.
export default function ToolResults({ projectId, targetId, nodeId }: { projectId: string; targetId?: string; nodeId?: string }) {
  const [rows, setRows] = useState<Observation[] | null>(null);
  const [err, setErr] = useState<string>();
  const [tool, setTool] = useState("all");
  const [kind, setKind] = useState("all");
  const [open, setOpen] = useState<string | null>(null);

  useEffect(() => {
    setRows(null); setErr(undefined);
    const req = nodeId
      ? api.nodeObservations(projectId, nodeId)
      : api.observations(projectId, targetId!, { limit: 200 });
    req.then((r) => setRows(r.observations)).catch((e) => setErr(String(e.message || e)));
  }, [projectId, targetId, nodeId]);

  const tools = useMemo(() => Array.from(new Set((rows || []).map((o) => o.tool))).sort(), [rows]);
  const kinds = useMemo(() => Array.from(new Set((rows || []).map((o) => o.result_kind))).sort(), [rows]);
  const filtered = useMemo(() => (rows || []).filter((o) =>
    (tool === "all" || o.tool === tool) && (kind === "all" || o.result_kind === kind)), [rows, tool, kind]);

  return (
    <>
      <div className="sec" style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <span>Tool Results{rows ? ` · ${rows.length}` : ""}</span>
      </div>
      {err && <div className="err">{err}</div>}
      {rows && rows.length === 0 && !err && (
        <div className="muted" style={{ fontSize: 11.5 }}>
          {nodeId
            ? "No tool results reference this node yet. Decompiling it, or running xrefs / recover-constant against it, records them here."
            : "No tool results yet. Running a task or an agent's analysis tools on this target records them here."}
        </div>
      )}
      {rows && rows.length > 0 && (
        <>
          {(tools.length > 1 || kinds.length > 1) && (
            <div style={{ display: "flex", gap: 6, margin: "2px 0 8px" }}>
              {tools.length > 1 && (
                <select className="sel" value={tool} onChange={(e) => setTool(e.target.value)} title="filter by tool">
                  <option value="all">all tools</option>
                  {tools.map((t) => <option key={t} value={t}>{t}</option>)}
                </select>
              )}
              {kinds.length > 1 && (
                <select className="sel" value={kind} onChange={(e) => setKind(e.target.value)} title="filter by kind">
                  <option value="all">all kinds</option>
                  {kinds.map((k) => <option key={k} value={k}>{human(k)}</option>)}
                </select>
              )}
            </div>
          )}
          <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
            {filtered.map((o) => (
              <button key={o.id} className="toolresult" onClick={() => setOpen(o.id)} title="View the raw tool result">
                <div className="tr-row1">
                  <span className="tag" style={{ textTransform: "none" }}>{human(o.result_kind)}</span>
                  <code className="tr-tool">{o.tool}</code>
                  {o.status !== "ok" && <span className="tag" style={{ color: "#ff5d6c", borderColor: "#ff5d6c" }}>error</span>}
                  <span style={{ flex: 1 }} />
                  <span className="muted tr-time">{relTime(o.created_at)}</span>
                </div>
                {o.summary && <div className="tr-summary muted">{o.summary}</div>}
              </button>
            ))}
            {filtered.length === 0 && <div className="muted" style={{ fontSize: 11.5 }}>No tool results match the filter.</div>}
          </div>
        </>
      )}
      {open && <RawResultModal obsId={open} onClose={() => setOpen(null)} />}
    </>
  );
}
