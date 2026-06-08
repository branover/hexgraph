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
  // AFL source-fuzz instrumentation knobs (source_lib/file_format) — default from Settings,
  // overridable per campaign. bug_oracles = AFL++ 5.x bug detectors; pathCov 0..3 = Ball-Larus
  // path sensitivity; cmplog = the CmpLog `-c` binary (magic-byte/memcmp gating).
  const fz = settings?.settings.features.fuzzing;
  const [bugOracles, setBugOracles] = useState(Boolean(fz?.bug_oracles));
  const [pathCov, setPathCov] = useState(String(fz?.path_coverage ?? 0));
  const [cmplog, setCmplog] = useState(Boolean(fz?.cmplog));
  // Network-surface inputs (host/port/protocol/proto_spec) — shown only when the selected
  // surface is `network` (a live service / rehosted device). Usually inferred from the
  // target; this lets the user point boofuzz at a specific host:port or supply a binary
  // protocol spec (the same fields REST CampaignCreate.net accepts).
  const [host, setHost] = useState("");
  const [port, setPort] = useState("");
  const [protocol, setProtocol] = useState("tcp");
  const [protoSpec, setProtoSpec] = useState("");
  // ResourceSpec defaults from Settings: the shared container default overlaid with the
  // fuzzing-type override (resources.default ← resources.fuzzing) — the same merge the
  // server applies as a campaign's inherited baseline.
  const rsCfg = settings?.settings.resources;
  const rdef = { ...(rsCfg?.default ?? {}), ...(rsCfg?.fuzzing ?? {}) };
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
  // The instrumentation knobs apply to AFL source fuzzing (the target's own sources are
  // recompiled); not to binary-only (qemu) or live-network campaigns.
  const isSource = eng?.surface === "source_lib" || eng?.surface === "file_format";
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
        bug_oracles: isSource ? bugOracles : undefined,
        path_coverage: isSource ? (parseInt(pathCov) || 0) : undefined,
        cmplog: isSource ? cmplog : undefined,
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
      <div className="modal fuzz" onClick={(e) => e.stopPropagation()}>
        <h3>
          <Icon name="bug" size={16} /> Fuzz campaign
          <span className="muted" style={{ fontWeight: 400, fontSize: 12 }}> · on {target.name}</span>
          <span style={{ flex: 1 }} />
          <button className="btn sm ghost icon" onClick={onClose}><Icon name="x" size={13} /></button>
        </h3>
        <div className="modal-b" style={{ display: "flex", flexDirection: "column", gap: 0 }}>
          <p className="lede">
            HexGraph spawns a <b>detached, hardened sandbox container</b> and reaps crashes as they
            appear — you never run a fuzzer by hand. Engines are <b>what the server advertises</b> for
            this target's attack surface. Live status streams in the <b>Campaigns</b> tab.
          </p>

          {/* ── Target & engine ───────────────────────────────────────── */}
          <div className="grp" style={{ marginTop: 12 }}>
            <div className="grp-h"><Icon name="target" size={12} /> Target &amp; engine</div>
            <div className="inline">
              {pickable.length > 1 && (
                <div className="fld" style={{ flex: 2 }}>
                  <label>surface <span className="sub">· which target to fuzz</span></label>
                  <select value={target.id} onChange={(e) => { const t = pickable.find((x) => x.id === e.target.value); if (t) setTarget(t); }}>
                    {pickable.map((t) => (
                      <option key={t.id} value={t.id}>{t.name} · {t.kind}{(t.metadata?.instrumented) ? " (instrumented)" : ""}</option>
                    ))}
                  </select>
                </div>
              )}
              <div className="fld" style={{ flex: "none" }}>
                <label>attack surface</label>
                <span className="tag" style={{ alignSelf: "flex-start", padding: "5px 9px" }}>{eng?.surface || "…"}{eng?.inferred ? " · inferred" : ""}</span>
              </div>
              <div className="fld">
                <label>engine</label>
                <select value={engine} onChange={(e) => setEngine(e.target.value)}>
                  {(eng?.engines || []).map((x) => <option key={x} value={x}>{x}{x === eng?.default ? " (default)" : ""}</option>)}
                </select>
              </div>
              {fuzzRemoteOn && (
                <div className="fld">
                  <label>environment</label>
                  <select value={environment} onChange={(e) => setEnvironment(e.target.value)}>
                    {envs.map((e) => (
                      <option key={e.id} value={e.id} disabled={!e.is_local && !e.connection_present}>
                        {e.name}{e.is_local ? " (local)" : e.connection_present ? "" : " — no connection"}
                      </option>
                    ))}
                  </select>
                </div>
              )}
            </div>
            {fuzzRemoteOn && (
              <div className="muted" style={{ fontSize: 10.5, marginTop: 7 }}>
                Environment = WHERE the container runs — remote is a user-owned Docker host, SAME sandbox boundary.
              </div>
            )}
          </div>

          {/* ── Network target (network surface only) ──────────────────── */}
          {isNetwork && (
            <div className="grp">
              <div className="grp-h"><Icon name="globe" size={12} /> Network target
                <span className="note">· loopback / private only · every send audited</span></div>
              <div className="grid" style={{ gridTemplateColumns: "2fr 1fr 1fr" }}>
                <div><label>host</label>
                  <input value={host} onChange={(e) => setHost(e.target.value)} placeholder="inferred (e.g. 127.0.0.1)" /></div>
                <div><label>port</label>
                  <input value={port} onChange={(e) => setPort(e.target.value)} placeholder="e.g. 8080" /></div>
                <div><label>protocol</label>
                  <select value={protocol} onChange={(e) => setProtocol(e.target.value)}>
                    <option value="tcp">tcp</option><option value="udp">udp</option>
                  </select></div>
              </div>
              <div className="fld" style={{ marginTop: 10 }}>
                <label>proto_spec <span className="sub">· optional JSON · a boofuzz request/state spec for a binary protocol</span></label>
                <textarea value={protoSpec} onChange={(e) => setProtoSpec(e.target.value)} rows={3} spellCheck={false}
                          placeholder='e.g. {"requests": [...]} — omit for the default text/CRLF spec' />
              </div>
            </div>
          )}

          {/* ── Inputs (focus fn / seeds / dictionary) ─────────────────── */}
          <div className="grp">
            <div className="grp-h"><Icon name="arrowin" size={12} /> Inputs</div>
            {!isNetwork && (
              <div className="fld" style={{ marginBottom: 10 }}>
                <label>focus function <span className="sub">· optional</span></label>
                <input value={fn} onChange={(e) => setFn(e.target.value)} placeholder="e.g. cgi_handler (uses the latest harness for this target)" />
              </div>
            )}
            <div className="fld" style={{ marginBottom: 10 }}>
              <label>seeds <span className="sub">· optional · host corpus file paths, comma/newline separated</span></label>
              <textarea value={seeds} onChange={(e) => setSeeds(e.target.value)} rows={2} spellCheck={false}
                        placeholder="e.g. /path/to/seed1.bin, /path/to/seed2.bin — omit to start from an empty/auto corpus" />
            </div>
            <div className="fld">
              <label>dictionary <span className="sub">· optional · tokens, comma/newline separated (auto-derived from strings when omitted)</span></label>
              <textarea value={dictionary} onChange={(e) => setDictionary(e.target.value)} rows={2} spellCheck={false}
                        placeholder='e.g. GET, POST, Content-Length, \xff\xd8 — guides the mutator' />
            </div>
          </div>

          {/* ── Stop conditions ────────────────────────────────────────── */}
          <div className="grp">
            <div className="grp-h"><Icon name="sliders" size={12} /> Stop conditions</div>
            <div className="grid" style={{ gridTemplateColumns: "1fr 1fr 1fr 1fr" }}>
              <div><label>max time (s)</label><input value={maxTime} onChange={(e) => setMaxTime(e.target.value)} /></div>
              <div><label>max len</label><input value={maxLen} onChange={(e) => setMaxLen(e.target.value)} /></div>
              <div><label>max crashes</label><input value={maxCrashes} onChange={(e) => setMaxCrashes(e.target.value)} /></div>
              <div><label>instances</label><input value={instances} onChange={(e) => setInstances(e.target.value)} /></div>
            </div>
          </div>

          {/* ── Instrumentation (AFL source-fuzz surfaces only) ────────── */}
          {isSource && (
            <div className="grp">
              <div className="grp-h"><Icon name="bug" size={12} /> Instrumentation
                <span className="note">· AFL++ source-fuzz · defaults from Settings</span></div>
              <label className="switch" style={{ fontSize: 12, display: "flex", gap: 9, alignItems: "center", marginBottom: 10 }}>
                <input type="checkbox" checked={bugOracles} onChange={(e) => setBugOracles(e.target.checked)} />
                <span>Bug-detection oracles <span className="muted" style={{ fontWeight: 400 }}>— AFL++ 5.x SCALAR / BUDGET / SIZEFILL / ALLOCSIZE / SLACK (arithmetic &amp; OOB bugs ASan misses)</span></span>
              </label>
              <label className="switch" style={{ fontSize: 12, display: "flex", gap: 9, alignItems: "center", marginBottom: 11 }}>
                <input type="checkbox" checked={cmplog} onChange={(e) => setCmplog(e.target.checked)} />
                <span>CmpLog <span className="muted" style={{ fontWeight: 400 }}>— defeat magic-byte / <code>memcmp</code> gates (the <code>-c</code> binary)</span></span>
              </label>
              <div className="fld">
                <label>path coverage <span className="sub">· Ball-Larus per-function path sensitivity — more signal, more overhead</span></label>
                <select value={pathCov} onChange={(e) => setPathCov(e.target.value)}>
                  <option value="0">off</option>
                  <option value="1">1 · relaxed</option>
                  <option value="2">2 · restricted</option>
                  <option value="3">3 · strict</option>
                </select>
              </div>
            </div>
          )}

          {/* ── Resources ──────────────────────────────────────────────── */}
          <div className="grp">
            <div className="grp-h"><Icon name="chip" size={12} /> Resources
              <span className="note">· this campaign · defaults from Settings</span></div>
            <label className="switch" style={{ fontSize: 12, display: "flex", gap: 9, alignItems: "center", marginBottom: unconstrained ? 0 : 11 }}>
              <input type="checkbox" checked={unconstrained} onChange={(e) => setUnconstrained(e.target.checked)} />
              <span>Unconstrained <span className="muted" style={{ fontWeight: 400 }}>— use the whole machine (lifts mem/cpu/pids only)</span></span>
            </label>
            {!unconstrained && (
              <div className="grid" style={{ gridTemplateColumns: "1fr 1fr 1fr" }}>
                <div><label>memory</label><input value={mem} onChange={(e) => setMem(e.target.value)} /></div>
                <div><label>cpus</label><input value={cpus} onChange={(e) => setCpus(e.target.value)} /></div>
                <div><label>pids</label><input value={pids} onChange={(e) => setPids(e.target.value)} /></div>
              </div>
            )}
            <div className="resnote">
              Resource ceilings are NOT a security relaxation — the sandbox stays <code>--network none</code>,
              cap-dropped, no-new-privileges, read-only, non-root regardless.
            </div>
          </div>

          {err && <div className="err" style={{ fontSize: 11.5, marginTop: 10 }}>{err}</div>}
        </div>
        <div className="modal-f" style={{ display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 14, borderTop: "1px solid var(--border)", paddingTop: 14 }}>
          <button className="btn sm ghost" onClick={onClose} disabled={busy}>Cancel</button>
          <button className="btn primary" onClick={start} disabled={busy || !(eng?.engines || []).length}>
            {busy ? <><Icon name="refresh" size={12} className="spin" /> starting…</> : <><Icon name="run" size={12} /> Start campaign</>}
          </button>
        </div>
      </div>
    </div>
  );
}
