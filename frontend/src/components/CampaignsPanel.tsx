import { useEffect, useRef, useState } from "react";
import { Campaign, api } from "../api";
import { Icon } from "./Icon";

const STATUS_COLOR: Record<string, string> = {
  running: "#58a6ff", building: "#d29922", queued: "#8b949e",
  completed: "#2ea043", failed: "#ff5d6c", stopped: "#8b949e", paused: "#d29922",
  // A campaign that did 0 work / ran a degraded engine — a distinct WARNING terminal
  // state, visually unlike a clean "completed" (the battle-test no-op confusion).
  degraded: "#d29922",
};

function StatusPill({ status }: { status: string }) {
  const c = STATUS_COLOR[status] || "var(--muted)";
  const live = status === "running" || status === "building";
  return (
    <span className="tag" style={{ color: c, borderColor: c, display: "inline-flex", alignItems: "center", gap: 4 }}>
      {live && <span className="dot ok" style={{ background: c }} />}{status}
    </span>
  );
}

const fmtNum = (n?: number) => (n == null ? "—" : n >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : n >= 1e3 ? `${(n / 1e3).toFixed(1)}k` : String(n));

// Live campaign status via SSE with a polling fallback. We subscribe to
// /api/campaigns/{id}/events; if the EventSource errors (no SSE / proxy buffering) we
// fall back to interval polling GET /api/campaigns/{id} — live status either way.
function useLiveCampaign(id: string | undefined, onUpdate: (c: Campaign) => void) {
  const cb = useRef(onUpdate); cb.current = onUpdate;
  useEffect(() => {
    if (!id) return;
    let es: EventSource | null = null;
    let poll: any = null;
    let closed = false;
    const startPolling = () => {
      if (poll || closed) return;
      poll = setInterval(async () => {
        try {
          const c = await api.campaign(id);
          cb.current(c);
          if (["completed", "failed", "stopped", "degraded"].includes(c.status)) { clearInterval(poll); poll = null; }
        } catch { /* keep trying */ }
      }, 1500);
    };
    try {
      es = new EventSource(api.campaignEventsUrl(id));
      es.onmessage = (ev) => { try { cb.current(JSON.parse(ev.data)); } catch { /* ignore */ } };
      es.addEventListener("done", () => { es?.close(); });
      es.onerror = () => { es?.close(); es = null; startPolling(); };
    } catch { startPolling(); }
    return () => { closed = true; es?.close(); if (poll) clearInterval(poll); };
  }, [id]);
}

// The Campaigns tab: a live row per campaign (status, exec/s, edges, crashes, coverage)
// + Stop/Resume controls. Selecting a campaign opens its Artifacts triage view.
export function CampaignsPanel({ projectId, selectedId, onSelect, onStartCampaign }: {
  projectId: string; selectedId?: string; onSelect: (id: string) => void; onStartCampaign?: () => void;
}) {
  const [rows, setRows] = useState<Campaign[]>([]);
  const load = () => api.campaigns(projectId).then((r) => setRows(r.campaigns)).catch(() => setRows([]));
  useEffect(() => { load(); /* eslint-disable-next-line */ }, [projectId]);
  // Refresh the whole list periodically so newly-started campaigns appear.
  useEffect(() => { const t = setInterval(load, 4000); return () => clearInterval(t); /* eslint-disable-next-line */ }, [projectId]);

  const patch = (c: Campaign) => setRows((rs) => rs.map((r) => (r.id === c.id ? c : r)));
  const hasLive = rows.some((r) => r.status === "running" || r.status === "building");

  return (
    <div className="list scroll fade-in" style={{ display: "flex", flexDirection: "column", gap: 6, padding: 8 }}>
      {onStartCampaign && rows.length > 0 && (
        <div style={{ display: "flex", justifyContent: "flex-end" }}>
          <button className="btn sm" onClick={onStartCampaign} title="Start a new fuzz campaign">
            <Icon name="bug" size={11} /> New campaign
          </button>
        </div>
      )}
      {rows.length === 0 && (
        <div className="empty" style={{ padding: 16, fontSize: 12 }}>
          No fuzz campaigns yet. Start one from a target's Run menu or the <b>Fuzz</b> button
          {onStartCampaign && <> — <button className="btn sm" onClick={onStartCampaign}><Icon name="bug" size={11} /> Fuzz a target</button></>}.
        </div>
      )}
      {hasLive && <LiveBinder ids={rows.filter((r) => r.status === "running" || r.status === "building").map((r) => r.id)} onUpdate={patch} />}
      {rows.map((c) => (
        <CampaignRow key={c.id} c={c} selected={c.id === selectedId} onSelect={() => onSelect(c.id)}
                     onChanged={(nc) => { patch(nc); }} />
      ))}
    </div>
  );
}

// Mount a hidden live subscriber per running campaign id (hooks must be top-level, so
// one child component per id keeps the SSE/poll lifecycle clean).
function LiveBinder({ ids, onUpdate }: { ids: string[]; onUpdate: (c: Campaign) => void }) {
  return <>{ids.map((id) => <LiveOne key={id} id={id} onUpdate={onUpdate} />)}</>;
}
function LiveOne({ id, onUpdate }: { id: string; onUpdate: (c: Campaign) => void }) {
  useLiveCampaign(id, onUpdate);
  return null;
}

function CampaignRow({ c, selected, onSelect, onChanged }: {
  c: Campaign; selected: boolean; onSelect: () => void; onChanged: (c: Campaign) => void;
}) {
  const [busy, setBusy] = useState(false);
  const st = c.stats || {};
  const stop = async (e: React.MouseEvent) => { e.stopPropagation(); setBusy(true); try { onChanged(await api.stopCampaign(c.id)); } finally { setBusy(false); } };
  const resume = async (e: React.MouseEvent) => { e.stopPropagation(); setBusy(true); try { onChanged(await api.resumeCampaign(c.id)); } catch (x: any) { alert(String(x.message || x)); } finally { setBusy(false); } };
  const cov = st.coverage_percent;
  return (
    <div className={"card" + (selected ? " sel" : "")} onClick={onSelect}
         style={{ cursor: "pointer", border: "1px solid var(--border)", borderRadius: 6, padding: "8px 10px",
                  background: selected ? "var(--surface-2)" : "var(--surface)" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <Icon name="bug" size={14} />
        <span style={{ fontWeight: 600, fontSize: 12.5, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{c.name}</span>
        <span style={{ flex: 1 }} />
        <StatusPill status={c.status} />
      </div>
      <div style={{ display: "flex", gap: 12, fontSize: 11, marginTop: 6, color: "var(--muted)", flexWrap: "wrap" }}>
        <span title="engine · surface">{c.engine} · {c.surface}</span>
        <span title="executions">{fmtNum(st.execs)} execs</span>
        <span title="edges covered">{fmtNum(st.edges_covered)} edges</span>
        <span title="unique crashes" style={{ color: (st.crash_count || 0) > 0 ? "#ff5d6c" : undefined }}>
          <Icon name="bug" size={10} /> {st.crash_count || 0} crashes
        </span>
        {cov != null && <span title="coverage">{cov.toFixed(0)}% cov</span>}
        {c.coverage_instrumented === false && <span title="coverage-blind run" style={{ color: "#d29922" }}>black-box</span>}
      </div>
      {c.error && <div className="muted" style={{ fontSize: 10.5, marginTop: 4, color: "#ff5d6c" }}>{c.error}</div>}
      {/* A degraded campaign's WHY (0 execs / unreachable / engine instability) — never
          let a no-op pass as a clean success. engine_note shows even when not terminal. */}
      {c.warning && (
        <div style={{ fontSize: 10.5, marginTop: 5, padding: "4px 7px", borderRadius: 4,
                      background: "rgba(210,153,34,0.12)", border: "1px solid #d29922", color: "#d29922",
                      display: "flex", gap: 5, alignItems: "flex-start" }}>
          <Icon name="alert" size={11} /> <span>{c.warning}</span>
        </div>
      )}
      {!c.warning && c.engine_note && (
        <div className="muted" style={{ fontSize: 10.5, marginTop: 4, color: "#d29922" }}>⚠ {c.engine_note}</div>
      )}
      <div className="actions" style={{ marginTop: 6 }}>
        {(c.status === "running" || c.status === "building") && (
          <button className="btn sm ghost danger" onClick={stop} disabled={busy}><Icon name="x" size={11} /> Stop</button>
        )}
        {(c.status === "stopped" || c.status === "completed" || c.status === "failed" || c.status === "degraded") && (
          <button className="btn sm ghost" onClick={resume} disabled={busy}><Icon name="run" size={11} /> Resume</button>
        )}
      </div>
    </div>
  );
}
