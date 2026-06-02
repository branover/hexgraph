import { useEffect, useState } from "react";
import { FuzzEngines, FuzzEnvironment, SettingsView, TargetNode, api } from "../api";
import { Icon } from "./Icon";

// The surface-aware Fuzz modal (design §6.3). The engine list is SERVER-ADVERTISED
// (GET /api/fuzz/engines?target_id=…) — the UI never hardcodes engines, mirroring how
// the Build modal previews the recipe and the LLM-backend registry is server-driven.
// The user sets the per-campaign ResourceSpec (mem/cpus/pids/timeout + unconstrained),
// defaulting from Settings. Launching a campaign is non-blocking (status `running`); the
// Campaigns tab streams live status.
export default function FuzzModal({ projectId, target, settings, onClose, onStarted }: {
  projectId: string; target: TargetNode; settings: SettingsView | null;
  onClose: () => void; onStarted: (campaignId: string) => void;
}) {
  const [eng, setEng] = useState<FuzzEngines | null>(null);
  const [engine, setEngine] = useState<string>("");
  const [maxTime, setMaxTime] = useState(String(settings?.settings.features.fuzzing?.max_total_time ?? 60));
  const [maxLen, setMaxLen] = useState(String(settings?.settings.features.fuzzing?.max_len ?? 4096));
  const [maxCrashes, setMaxCrashes] = useState(String(settings?.settings.features.fuzzing?.max_crashes ?? 10));
  const [instances, setInstances] = useState("1");
  const [fn, setFn] = useState("");
  // ResourceSpec defaults from Settings (the global default a campaign inherits).
  const rdef = settings?.settings.features.fuzzing?.resources;
  const [mem, setMem] = useState(rdef?.mem ?? "2g");
  const [cpus, setCpus] = useState(String(rdef?.cpus ?? 2));
  const [pids, setPids] = useState(String(rdef?.pids ?? 256));
  const [unconstrained, setUnconstrained] = useState(Boolean(rdef?.unconstrained));
  // Remote fuzz environments (Phase 6) — WHERE the campaign runs. Shown only when
  // features.fuzz_remote is on (the gate); defaults to `local`.
  const fuzzRemoteOn = Boolean(settings?.settings.features.fuzz_remote?.enabled);
  const [envs, setEnvs] = useState<FuzzEnvironment[]>([]);
  const [environment, setEnvironment] = useState("local");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string>();

  useEffect(() => {
    api.fuzzEngines(undefined, target.id).then((e) => {
      setEng(e);
      if (e.default) setEngine(e.default);
    }).catch((x) => setErr(String(x.message || x)));
  }, [target.id]);

  useEffect(() => {
    if (fuzzRemoteOn) api.fuzzEnvironments().then((r) => setEnvs(r.environments)).catch(() => {});
  }, [fuzzRemoteOn]);

  const start = async () => {
    setBusy(true); setErr(undefined);
    try {
      const resources = unconstrained
        ? { unconstrained: true }
        : { mem, cpus: parseFloat(cpus) || 2, pids: parseInt(pids) || 256, unconstrained: false };
      const c = await api.startCampaign(projectId, {
        target_id: target.id,
        surface: eng?.surface || undefined,
        engine: engine || undefined,
        function: fn.trim() || undefined,
        max_total_time: parseInt(maxTime) || 60,
        max_len: parseInt(maxLen) || 4096,
        max_crashes: parseInt(maxCrashes) || 10,
        instances: parseInt(instances) || 1,
        resources,
        environment: fuzzRemoteOn && environment !== "local" ? environment : undefined,
      });
      onStarted(c.id);
      onClose();
    } catch (e: any) { setErr(String(e.message || e)); setBusy(false); }
  };

  return (
    <div className="modal-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="modal" style={{ maxWidth: 560 }} onClick={(e) => e.stopPropagation()}>
        <h3>
          <Icon name="bug" size={16} /> Fuzz campaign
          <span className="muted" style={{ fontWeight: 400, fontSize: 12 }}> · on {target.name}</span>
          <span style={{ flex: 1 }} />
          <button className="btn sm ghost icon" onClick={onClose}><Icon name="x" size={13} /></button>
        </h3>
        <div className="modal-b" style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <div className="muted" style={{ fontSize: 11.5 }}>
            HexGraph spawns a <b>detached, hardened sandbox container</b> and reaps crashes as they
            appear — you never run a fuzzer by hand. Engines are <b>what the server advertises</b> for
            this target's attack surface. Live status streams in the <b>Campaigns</b> tab.
          </div>

          <div className="row" style={{ display: "flex", gap: 16, alignItems: "center" }}>
            <label style={{ fontSize: 12 }}>surface</label>
            <span className="tag">{eng?.surface || "…"}{eng?.inferred ? " (inferred)" : ""}</span>
            <label style={{ fontSize: 12, marginLeft: 12 }}>engine</label>
            <select value={engine} onChange={(e) => setEngine(e.target.value)}
                    style={{ background: "var(--bg)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: 4, fontSize: 12, padding: "2px 6px" }}>
              {(eng?.engines || []).map((x) => <option key={x} value={x}>{x}{x === eng?.default ? " (default)" : ""}</option>)}
            </select>
          </div>

          {fuzzRemoteOn && (
            <div className="row" style={{ display: "flex", gap: 12, alignItems: "center" }}>
              <label style={{ fontSize: 12 }}>environment</label>
              <select value={environment} onChange={(e) => setEnvironment(e.target.value)}
                      style={{ background: "var(--bg)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: 4, fontSize: 12, padding: "2px 6px" }}>
                {envs.map((e) => (
                  <option key={e.id} value={e.id} disabled={!e.is_local && !e.connection_present}>
                    {e.name}{e.is_local ? " (local)" : e.connection_present ? "" : " — no connection"}
                  </option>
                ))}
              </select>
              <span className="muted" style={{ fontSize: 10.5 }}>
                where the container runs — remote = a user-owned Docker host, SAME sandbox boundary.
              </span>
            </div>
          )}

          <div className="field"><label>focus function (optional)</label>
            <input value={fn} onChange={(e) => setFn(e.target.value)} placeholder="e.g. cgi_handler (uses the latest harness for this target)"
                   style={{ width: "100%", background: "var(--bg)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: 4, padding: "4px 6px", fontSize: 12 }} />
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 10 }}>
            <label style={{ fontSize: 11.5 }}>max time (s)
              <input value={maxTime} onChange={(e) => setMaxTime(e.target.value)} className="num-input"
                     style={{ width: "100%", marginTop: 2, background: "var(--bg)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: 4, padding: "3px 4px", fontSize: 12 }} /></label>
            <label style={{ fontSize: 11.5 }}>max len
              <input value={maxLen} onChange={(e) => setMaxLen(e.target.value)}
                     style={{ width: "100%", marginTop: 2, background: "var(--bg)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: 4, padding: "3px 4px", fontSize: 12 }} /></label>
            <label style={{ fontSize: 11.5 }}>max crashes
              <input value={maxCrashes} onChange={(e) => setMaxCrashes(e.target.value)}
                     style={{ width: "100%", marginTop: 2, background: "var(--bg)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: 4, padding: "3px 4px", fontSize: 12 }} /></label>
            <label style={{ fontSize: 11.5 }}>instances
              <input value={instances} onChange={(e) => setInstances(e.target.value)}
                     style={{ width: "100%", marginTop: 2, background: "var(--bg)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: 4, padding: "3px 4px", fontSize: 12 }} /></label>
          </div>

          <div>
            <div className="sec-label">Resources (this campaign) <span className="muted" style={{ fontWeight: 400 }}>· defaults from Settings</span></div>
            <label className="switch" style={{ fontSize: 12, display: "flex", gap: 8, alignItems: "center", margin: "4px 0 8px" }}>
              <input type="checkbox" checked={unconstrained} onChange={(e) => setUnconstrained(e.target.checked)} />
              <span>Unconstrained (use the whole machine — lifts mem/cpu/pids only)</span>
            </label>
            {!unconstrained && (
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10 }}>
                <label style={{ fontSize: 11.5 }}>memory
                  <input value={mem} onChange={(e) => setMem(e.target.value)}
                         style={{ width: "100%", marginTop: 2, background: "var(--bg)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: 4, padding: "3px 4px", fontSize: 12 }} /></label>
                <label style={{ fontSize: 11.5 }}>cpus
                  <input value={cpus} onChange={(e) => setCpus(e.target.value)}
                         style={{ width: "100%", marginTop: 2, background: "var(--bg)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: 4, padding: "3px 4px", fontSize: 12 }} /></label>
                <label style={{ fontSize: 11.5 }}>pids
                  <input value={pids} onChange={(e) => setPids(e.target.value)}
                         style={{ width: "100%", marginTop: 2, background: "var(--bg)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: 4, padding: "3px 4px", fontSize: 12 }} /></label>
              </div>
            )}
            <div className="muted" style={{ fontSize: 10.5, marginTop: 6 }}>
              Resource ceilings are NOT a security relaxation — the sandbox stays <code>--network none</code>,
              cap-dropped, no-new-privileges, read-only, non-root regardless.
            </div>
          </div>

          {err && <div className="err" style={{ fontSize: 11.5 }}>{err}</div>}
        </div>
        <div className="modal-f" style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
          <button className="btn sm ghost" onClick={onClose} disabled={busy}>Cancel</button>
          <button className="btn sm primary" onClick={start} disabled={busy || !(eng?.engines || []).length}>
            {busy ? <><Icon name="refresh" size={12} className="spin" /> starting…</> : <><Icon name="run" size={12} /> Start campaign</>}
          </button>
        </div>
      </div>
    </div>
  );
}
