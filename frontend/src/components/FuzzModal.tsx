import { useEffect, useState } from "react";
import { FuzzEngines, FuzzEnvironment, SettingsView, TargetNode, api } from "../api";
import { Icon } from "./Icon";

// The surface-aware Fuzz modal (design §6.3). The engine list is SERVER-ADVERTISED
// (GET /api/fuzz/engines?target_id=…) — the UI never hardcodes engines, mirroring how
// the Build modal previews the recipe and the LLM-backend registry is server-driven.
// The user sets the per-campaign ResourceSpec (mem/cpus/pids/timeout + unconstrained),
// defaulting from Settings. Launching a campaign is non-blocking (status `running`); the
// Campaigns tab streams live status.
export default function FuzzModal({ projectId, target: initialTarget, targets, settings, onClose, onStarted }: {
  projectId: string; target: TargetNode; targets?: TargetNode[]; settings: SettingsView | null;
  onClose: () => void; onStarted: (campaignId: string) => void;
}) {
  // The target under fuzz — defaulted by the caller (the best candidate), switchable here
  // when a target list is supplied (so a launch from the Campaigns tab isn't pinned to the
  // wrong root). Re-infers the surface/engine on change.
  const [target, setTarget] = useState<TargetNode>(initialTarget);
  const pickable = (targets || []).filter((t) => t.kind !== "firmware_image");
  const [eng, setEng] = useState<FuzzEngines | null>(null);
  const [engine, setEngine] = useState<string>("");
  const [maxTime, setMaxTime] = useState(String(settings?.settings.features.fuzzing?.max_total_time ?? 60));
  const [maxLen, setMaxLen] = useState(String(settings?.settings.features.fuzzing?.max_len ?? 4096));
  const [maxCrashes, setMaxCrashes] = useState(String(settings?.settings.features.fuzzing?.max_crashes ?? 10));
  const [instances, setInstances] = useState("1");
  const [fn, setFn] = useState("");
  // Optional seeds (host corpus file paths) + dictionary tokens — applicable to every
  // surface (auto-derived when omitted). Newline/comma separated.
  const [seeds, setSeeds] = useState("");
  const [dictionary, setDictionary] = useState("");
  // Network-surface inputs (host/port/protocol/proto_spec) — shown only when the selected
  // surface is `network` (a live service / rehosted device). Usually inferred from the
  // target; this lets the user point boofuzz at a specific host:port or supply a binary
  // protocol spec (the same fields REST CampaignCreate.net accepts).
  const [host, setHost] = useState("");
  const [port, setPort] = useState("");
  const [protocol, setProtocol] = useState("tcp");
  const [protoSpec, setProtoSpec] = useState("");
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

  const isNetwork = eng?.surface === "network";
  const splitList = (s: string) => s.split(/[\n,]/).map((x) => x.trim()).filter(Boolean);

  const start = async () => {
    setBusy(true); setErr(undefined);
    try {
      const resources = unconstrained
        ? { unconstrained: true }
        : { mem, cpus: parseFloat(cpus) || 2, pids: parseInt(pids) || 256, unconstrained: false };
      // Network-surface overrides (boofuzz host/port/protocol + an optional binary-protocol
      // proto_spec). proto_spec is JSON; surface a clear error rather than sending garbage.
      let net: { host?: string; port?: number; protocol?: string; proto_spec?: any } | undefined;
      if (isNetwork) {
        let parsedSpec: any;
        if (protoSpec.trim()) {
          try { parsedSpec = JSON.parse(protoSpec); }
          catch { setErr("proto_spec must be valid JSON"); setBusy(false); return; }
        }
        net = {
          host: host.trim() || undefined,
          port: port.trim() ? parseInt(port) : undefined,
          protocol,
          proto_spec: parsedSpec,
        };
      }
      const seedList = splitList(seeds);
      const dictList = splitList(dictionary);
      const c = await api.startCampaign(projectId, {
        target_id: target.id,
        surface: eng?.surface || undefined,
        engine: engine || undefined,
        function: fn.trim() || undefined,
        max_total_time: parseInt(maxTime) || 60,
        max_len: parseInt(maxLen) || 4096,
        max_crashes: parseInt(maxCrashes) || 10,
        instances: parseInt(instances) || 1,
        seeds: seedList.length ? seedList : undefined,
        dictionary: dictList.length ? dictList : undefined,
        net,
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

          {pickable.length > 1 && (
            <div className="row" style={{ display: "flex", gap: 12, alignItems: "center" }}>
              <label style={{ fontSize: 12 }}>target</label>
              <select value={target.id} onChange={(e) => { const t = pickable.find((x) => x.id === e.target.value); if (t) setTarget(t); }}
                      style={{ flex: 1, background: "var(--bg)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: 4, fontSize: 12, padding: "2px 6px" }}>
                {pickable.map((t) => (
                  <option key={t.id} value={t.id}>{t.name} · {t.kind}{(t.metadata?.instrumented) ? " (instrumented)" : ""}</option>
                ))}
              </select>
              <span className="muted" style={{ fontSize: 10.5 }}>which surface to fuzz</span>
            </div>
          )}

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

          {isNetwork && (
            <div>
              <div className="sec-label">Network target <span className="muted" style={{ fontWeight: 400 }}>· loopback/private only · every send audited</span></div>
              <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr 1fr", gap: 10 }}>
                <label style={{ fontSize: 11.5 }}>host
                  <input value={host} onChange={(e) => setHost(e.target.value)} placeholder="inferred from target (e.g. 127.0.0.1)"
                         style={{ width: "100%", marginTop: 2, background: "var(--bg)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: 4, padding: "3px 4px", fontSize: 12 }} /></label>
                <label style={{ fontSize: 11.5 }}>port
                  <input value={port} onChange={(e) => setPort(e.target.value)} placeholder="e.g. 8080"
                         style={{ width: "100%", marginTop: 2, background: "var(--bg)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: 4, padding: "3px 4px", fontSize: 12 }} /></label>
                <label style={{ fontSize: 11.5 }}>protocol
                  <select value={protocol} onChange={(e) => setProtocol(e.target.value)}
                          style={{ width: "100%", marginTop: 2, background: "var(--bg)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: 4, padding: "3px 4px", fontSize: 12 }}>
                    <option value="tcp">tcp</option><option value="udp">udp</option>
                  </select></label>
              </div>
              <label style={{ fontSize: 11.5, display: "block", marginTop: 8 }}>proto_spec (optional, JSON — a boofuzz generational request/state spec for a binary protocol)
                <textarea value={protoSpec} onChange={(e) => setProtoSpec(e.target.value)} rows={3} spellCheck={false}
                          placeholder='e.g. {"requests": [...]} — omit for the default text/CRLF spec'
                          style={{ width: "100%", marginTop: 2, background: "var(--bg)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: 4, padding: "4px 6px", fontSize: 11.5, fontFamily: "var(--mono, monospace)" }} /></label>
            </div>
          )}

          {!isNetwork && (
            <div className="field"><label>focus function (optional)</label>
              <input value={fn} onChange={(e) => setFn(e.target.value)} placeholder="e.g. cgi_handler (uses the latest harness for this target)"
                     style={{ width: "100%", background: "var(--bg)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: 4, padding: "4px 6px", fontSize: 12 }} />
            </div>
          )}

          <div className="field"><label>seeds <span className="muted" style={{ fontWeight: 400 }}>· optional · host corpus file paths, comma/newline separated</span></label>
            <textarea value={seeds} onChange={(e) => setSeeds(e.target.value)} rows={2} spellCheck={false}
                      placeholder="e.g. /path/to/seed1.bin, /path/to/seed2.bin — omit to start from an empty/auto corpus"
                      style={{ width: "100%", background: "var(--bg)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: 4, padding: "4px 6px", fontSize: 11.5, fontFamily: "var(--mono, monospace)" }} />
          </div>

          <div className="field"><label>dictionary <span className="muted" style={{ fontWeight: 400 }}>· optional · tokens, comma/newline separated (auto-derived from the target's strings when omitted)</span></label>
            <textarea value={dictionary} onChange={(e) => setDictionary(e.target.value)} rows={2} spellCheck={false}
                      placeholder='e.g. GET, POST, Content-Length, \xff\xd8 — guides the mutator'
                      style={{ width: "100%", background: "var(--bg)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: 4, padding: "4px 6px", fontSize: 11.5, fontFamily: "var(--mono, monospace)" }} />
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
