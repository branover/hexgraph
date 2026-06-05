import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { FuzzEnvironment, GhidraStatus, SettingsView, api } from "../api";
import Header from "../components/Header";
import { Icon } from "../components/Icon";

// Human labels for the policy gates that require a restart to *enable* (matches
// policy.POLICY_GATES). rehost/remote have no toggle on this page, but can still
// show up in the top "restart required" banner if configured on elsewhere.
const GATE_LABELS: Record<string, string> = {
  fuzzing: "Fuzzing",
  poc: "PoC verification",
  build: "Source & build",
  build_fetch: "Bounded dependency fetch",
  network: "Network egress",
  rehost: "Firmware rehosting",
  remote: "Remote live devices",
  fuzz_remote: "Remote fuzz environments",
};

// Self-service configuration: optional features + non-secret prefs. API keys are
// status-only here (env/config.toml BYOK) — the server never writes secrets.
export default function Settings() {
  const nav = useNavigate();
  const [v, setV] = useState<SettingsView | null>(null);
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState("");
  const [ghidra, setGhidra] = useState<GhidraStatus | null>(null);
  const [testing, setTesting] = useState(false);
  // Remote fuzz environments (Phase 6) — NON-SECRET metadata + presence-only connection.
  const [envs, setEnvs] = useState<FuzzEnvironment[]>([]);
  const [newEnvName, setNewEnvName] = useState("");
  const [newEnvTransport, setNewEnvTransport] = useState("ssh");
  const [newEnvDesc, setNewEnvDesc] = useState("");
  const [envBusy, setEnvBusy] = useState("");
  const loadEnvs = () => api.fuzzEnvironments().then((r) => setEnvs(r.environments)).catch(() => {});

  const close = () => { if (window.history.length > 1) nav(-1); else nav("/"); };
  useEffect(() => {
    api.getSettings().then(setV).catch((e) => setErr(String(e.message || e)));
    loadEnvs();
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") close(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const patch = async (p: Record<string, any>) => {
    setSaving(true); setErr("");
    try { setV(await api.patchSettings(p)); }
    catch (e: any) { setErr(String(e.message || e)); }
    finally { setSaving(false); }
  };
  const testConn = async () => { setTesting(true); try { setGhidra(await api.testGhidra()); } finally { setTesting(false); } };

  if (!v) return <><Header /><div className="settings"><div className="empty">{err || "Loading settings…"}</div></div></>;
  const g = v.settings.features.ghidra;
  // Docker container ceilings: the shared default + the effective fuzz-campaign override
  // (resources.default ← resources.fuzzing) the Fuzzing card edits.
  const rd = v.settings.resources.default;
  const rf = { ...rd, ...(v.settings.resources.fuzzing ?? {}) };
  // A "restart to apply" chip next to a policy gate whose toggle is saved-on but the
  // running server started with it off (the frozen startup ceiling clamps it off until
  // the next restart). Disabling is always live, so it never shows for an off toggle.
  const pending = (gate: string) =>
    v.policy?.features?.[gate]?.pending_restart ? (
      <span className="badge warn" style={{ marginLeft: 8 }}
            title="Saved in settings, but this running server started with it OFF. Restart `hexgraph serve` to activate.">
        <Icon name="refresh" size={11} /> restart to apply
      </span>
    ) : null;
  const pendingNames = (v.policy?.pending ?? []).map((k) => GATE_LABELS[k] ?? k);

  return (
    <>
      <Header />
      <div className="settings">
        <div className="settings-inner">
          <h2>
            <Icon name="gear" size={20} /> Settings
            <span style={{ flex: 1 }} />
            <button className="btn sm ghost" onClick={close} title="Close (Esc)"><Icon name="x" size={13} /> Close</button>
          </h2>
          {err && <div className="banner err">{err}</div>}
          {saving && <div className="muted" style={{ fontSize: 12 }}>saving…</div>}
          {v.policy?.restart_required && (
            <div className="banner warn">
              <b>Restart required to activate.</b>{" "}
              {pendingNames.join(", ")} {pendingNames.length > 1 ? "are" : "is"} enabled in settings, but this
              running server started with {pendingNames.length > 1 ? "them" : "it"} off. A long-lived server
              freezes which capabilities it may use at startup, so a capability turned on now is <b>saved</b> but
              stays <b>inactive</b> until you restart <code>hexgraph serve</code>. This is deliberate: it stops a
              capability (execution, network egress, …) from being silently granted to an already-running server
              or agent session. Turning a capability <i>off</i> always takes effect immediately.
            </div>
          )}

          {/* Model access */}
          <section className="card2">
            <h3>Model access</h3>
            <div className="row">
              <label>Default backend</label>
              <select className="sel" value={v.settings.llm.backend} onChange={(e) => patch({ "llm.backend": e.target.value })}>
                {["mock", "anthropic", "claude_code"].map((b) => <option key={b}>{b}</option>)}
              </select>
            </div>
            <div className="row">
              <label>Model preference</label>
              <input className="inp" defaultValue={v.settings.llm.model || ""} placeholder="(backend default)"
                     onBlur={(e) => patch({ "llm.model": e.target.value.trim() || null })} />
            </div>
            <div className="keys">
              {Object.entries(v.secrets).map(([name, s]) => (
                <div key={name} className="keyrow">
                  <span className={"dot " + (s.present ? "ok" : "off")} />
                  <code>{name === "anthropic_api_key" ? "ANTHROPIC_API_KEY" : "HEXGRAPH_API_KEY"}</code>
                  <span className="muted">{s.present ? `detected (${s.source})` : "not set"}</span>
                </div>
              ))}
            </div>
            <p className="hint">
              API keys are <b>never stored or transmitted by HexGraph</b>. Set <code>ANTHROPIC_API_KEY</code> in your
              environment or under <code>[anthropic]</code> in <code>{v.paths.config_toml}</code>. BYOK only.
            </p>
          </section>

          {/* Container resources */}
          <section className="card2">
            <div className="h3row">
              <h3><Icon name="chip" size={15} /> Container resources <span className="muted">· docker ceilings</span></h3>
            </div>
            <p className="hint">
              The per-container CPU / memory / pids / scratch ceilings every sandboxed container runs under. This is the
              <b> shared default</b> — the analysis sandbox, the build image and fuzz campaigns all inherit it. Raising
              <b> memory</b> also raises the memory-derived limits (the unconstrained scratch size, libFuzzer's RSS bound).
              Tuning these is <b>not</b> a security relaxation: containers stay <code>--network none</code>, cap-dropped,
              no-new-privileges, read-only and non-root regardless.
            </p>
            <label className="switch" style={{ display: "flex", gap: 8, marginTop: 4 }}>
              <input type="checkbox" checked={Boolean(rd.unconstrained)}
                     onChange={(e) => patch({ "resources.default.unconstrained": e.target.checked })} />
              <span>unconstrained (use the whole machine — lifts mem/cpu/pids only)</span>
            </label>
            {!rd.unconstrained && (
              <div className="grid2" style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12, marginTop: 8 }}>
                <div className="row"><label>memory</label>
                  <input className="inp" defaultValue={rd.mem ?? "2g"}
                         onBlur={(e) => patch({ "resources.default.mem": e.target.value.trim() || "2g" })} /></div>
                <div className="row"><label>cpus</label>
                  <input className="inp num-input" type="number" step="0.5" defaultValue={rd.cpus ?? 2}
                         onBlur={(e) => patch({ "resources.default.cpus": parseFloat(e.target.value) || 2 })} /></div>
                <div className="row"><label>pids</label>
                  <input className="inp num-input" type="number" defaultValue={rd.pids ?? 256}
                         onBlur={(e) => patch({ "resources.default.pids": parseInt(e.target.value) || 256 })} /></div>
                <div className="row"><label>scratch tmpfs</label>
                  <input className="inp" defaultValue={rd.tmpfs ?? "512m"}
                         onBlur={(e) => patch({ "resources.default.tmpfs": e.target.value.trim() || "512m" })} /></div>
                <div className="row"><label>timeout (s)</label>
                  <input className="inp num-input" type="number" defaultValue={rd.timeout ?? 300}
                         onBlur={(e) => patch({ "resources.default.timeout": parseInt(e.target.value) || 300 })} /></div>
              </div>
            )}
            <p className="hint" style={{ marginTop: 8 }}>
              Need different ceilings per container type? Fuzz campaigns have their own override in the Fuzzing card below;
              the analysis sandbox and build image can diverge via <code>resources.sandbox.*</code> / <code>resources.build.*</code>
              (Settings API or <code>hexgraph config set</code>) — each inherits this default for anything it doesn't set.
            </p>
          </section>

          {/* Ghidra */}
          <section className="card2">
            <div className="h3row">
              <h3><Icon name="bulb" size={15} /> Ghidra integration <span className="muted">· optional</span></h3>
              <label className="switch">
                <input type="checkbox" checked={g.enabled} onChange={(e) => patch({ "features.ghidra.enabled": e.target.checked })} />
                <span>{g.enabled ? "enabled" : "disabled"}</span>
              </label>
            </div>
            {g.enabled && (
              <>
                <div className="row">
                  <label>Mode</label>
                  <select className="sel" value={g.mode} onChange={(e) => patch({ "features.ghidra.mode": e.target.value })}>
                    <option value="headless">headless (in sandbox)</option>
                    <option value="bridge">connect to running Ghidra (bridge)</option>
                  </select>
                </div>
                {g.mode === "headless" && (
                  <>
                    <div className="row">
                      <label>Analyze timeout (s)</label>
                      <input className="inp" type="number" defaultValue={g.timeout}
                             onBlur={(e) => patch({ "features.ghidra.timeout": parseInt(e.target.value) || 600 })} />
                    </div>
                    <p className="hint">Headless Ghidra runs inside the <code>--network none</code> sandbox image.
                      Build it with <code>just sandbox-build with_ghidra=1</code>. Falls back to radare2 if unavailable.</p>
                  </>
                )}
                {g.mode === "bridge" && (
                  <>
                    <div className="row">
                      <label>Bridge host</label>
                      <input className="inp" defaultValue={g.bridge.host}
                             onBlur={(e) => patch({ "features.ghidra.bridge.host": e.target.value.trim() })} />
                    </div>
                    <div className="row">
                      <label>Bridge port</label>
                      <input className="inp" type="number" defaultValue={g.bridge.port}
                             onBlur={(e) => patch({ "features.ghidra.bridge.port": parseInt(e.target.value) || 4768 })} />
                    </div>
                    <p className="hint">In Ghidra, run <code>ghidra_bridge_server.py</code> (loopback). Client:
                      <code> pip install ghidra_bridge</code>. Programs you have open can be imported as targets.</p>
                  </>
                )}
                <label className="switch" style={{ marginTop: 8 }}>
                  <input type="checkbox" checked={g.enrich_recon} onChange={(e) => patch({ "features.ghidra.enrich_recon": e.target.checked })} />
                  <span>Enrich recon with Ghidra (function inventory · call graph · structs)</span>
                </label>
                <div className="actions" style={{ marginTop: 12 }}>
                  <button className="btn sm" onClick={testConn} disabled={testing}>
                    <Icon name="refresh" size={12} className={testing ? "spin" : ""} /> Test connection
                  </button>
                  {ghidra && (
                    <span className={"badge " + (ghidra.ok ? "" : "warn")}>
                      <span className={"dot " + (ghidra.ok ? "ok" : "off")} /> {ghidra.detail}
                    </span>
                  )}
                </div>
              </>
            )}
          </section>

          {/* Fuzzing */}
          <section className="card2">
            <div className="h3row">
              <h3><Icon name="bug" size={15} /> Fuzzing <span className="muted">· optional · executes code</span>{pending("fuzzing")}</h3>
              <label className="switch">
                <input type="checkbox" checked={v.settings.features.fuzzing.enabled}
                       onChange={(e) => patch({ "features.fuzzing.enabled": e.target.checked })} />
                <span>{v.settings.features.fuzzing.enabled ? "enabled" : "disabled"}</span>
              </label>
            </div>
            <p className="hint">
              ⚠ Enabling this relaxes the static-only policy: fuzz tasks <b>execute</b> the compiled
              harness (libFuzzer + ASan) inside the sandbox (still <code>--network none</code>, capped,
              timed, disposable). The target is never run as-is. Default stop parameters:
            </p>
            {v.settings.features.fuzzing.enabled && (
              <div className="grid2" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                <div className="row"><label>max fuzz time (s)</label>
                  <input className="inp num-input" type="number" defaultValue={v.settings.features.fuzzing.max_total_time}
                         onBlur={(e) => patch({ "features.fuzzing.max_total_time": parseInt(e.target.value) || 60 })} /></div>
                <div className="row"><label>max input (bytes)</label>
                  <input className="inp num-input" type="number" defaultValue={v.settings.features.fuzzing.max_len}
                         onBlur={(e) => patch({ "features.fuzzing.max_len": parseInt(e.target.value) || 4096 })} /></div>
                <div className="row"><label>max crashes</label>
                  <input className="inp num-input" type="number" defaultValue={v.settings.features.fuzzing.max_crashes}
                         onBlur={(e) => patch({ "features.fuzzing.max_crashes": parseInt(e.target.value) || 10 })} /></div>
                <div className="row"><label>sandbox timeout (s)</label>
                  <input className="inp num-input" type="number" defaultValue={v.settings.features.fuzzing.timeout}
                         onBlur={(e) => patch({ "features.fuzzing.timeout": parseInt(e.target.value) || 300 })} /></div>
              </div>
            )}
            {v.settings.features.fuzzing.enabled && (
              <>
                <div className="sec-label" style={{ marginTop: 12 }}>Default campaign resources (overrides the shared default)</div>
                <p className="hint" style={{ marginTop: 2 }}>
                  Campaign ceilings layered over the shared <b>Container resources</b> above — set a value here to
                  diverge fuzzing from it, or leave it and campaigns inherit the default. A campaign's Fuzz modal can
                  override these again per run. <b>Unconstrained</b> lets a campaign use the whole machine — it lifts
                  <code>mem/cpu/pids</code> ONLY and is <b>not</b> a security relaxation (the sandbox stays
                  <code>--network none</code>, cap-dropped, non-root, read-only regardless).
                </p>
                <label className="switch" style={{ display: "flex", gap: 8, marginTop: 6 }}>
                  <input type="checkbox" checked={Boolean(rf.unconstrained)}
                         onChange={(e) => patch({ "resources.fuzzing.unconstrained": e.target.checked })} />
                  <span>unconstrained (use the whole machine)</span>
                </label>
                {!rf.unconstrained && (
                  <div className="grid2" style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12, marginTop: 8 }}>
                    <div className="row"><label>memory</label>
                      <input className="inp" defaultValue={rf.mem ?? "2g"}
                             onBlur={(e) => patch({ "resources.fuzzing.mem": e.target.value.trim() || "2g" })} /></div>
                    <div className="row"><label>cpus</label>
                      <input className="inp num-input" type="number" step="0.5" defaultValue={rf.cpus ?? 2}
                             onBlur={(e) => patch({ "resources.fuzzing.cpus": parseFloat(e.target.value) || 2 })} /></div>
                    <div className="row"><label>pids</label>
                      <input className="inp num-input" type="number" defaultValue={rf.pids ?? 256}
                             onBlur={(e) => patch({ "resources.fuzzing.pids": parseInt(e.target.value) || 256 })} /></div>
                  </div>
                )}
              </>
            )}
          </section>

          {/* Source & Build */}
          <section className="card2">
            <div className="h3row">
              <h3><Icon name="chip" size={15} /> Source &amp; Build <span className="muted">· optional · compiles source</span>{pending("build")}</h3>
              <label className="switch">
                <input type="checkbox" checked={v.settings.features.build.enabled}
                       onChange={(e) => patch({ "features.build.enabled": e.target.checked })} />
                <span>{v.settings.features.build.enabled ? "enabled" : "disabled"}</span>
              </label>
            </div>
            <p className="hint">
              ⚠ Enabling this turns on the <b>build gate</b>: HexGraph may compile a managed source tree into
              an <b>instrumented artifact</b> (the Builder seam) via a recorded, reproducible recipe inside the
              sandbox. Building runs untrusted third-party code (<code>configure</code>/<code>make</code>), so it
              has its OWN gate — separate from executing the target. <b>Vendored / offline only</b> this phase
              (<code>--network none</code> during compile). With it on, a <b>Build (instrumented)</b> button
              appears in the Source tab; its instrumented derived target becomes coverage-guided-fuzzable.
            </p>
            {v.settings.features.build.enabled && (
              <>
                <div className="grid2" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                  <div className="row"><label>build image</label>
                    <input className="inp" defaultValue={v.settings.features.build.image ?? "hexgraph-build:latest"}
                           onBlur={(e) => patch({ "features.build.image": e.target.value.trim() || "hexgraph-build:latest" })} /></div>
                  <div className="row"><label>build timeout (s)</label>
                    <input className="inp num-input" type="number" defaultValue={v.settings.features.build.timeout ?? 1800}
                           onBlur={(e) => patch({ "features.build.timeout": parseInt(e.target.value) || 1800 })} /></div>
                </div>
                <div style={{ display: "flex", gap: 18, flexWrap: "wrap", marginTop: 8 }}>
                  <label style={{ fontSize: 12.5 }}>
                    <input type="checkbox" checked={(v.settings.features.build as any).ccache ?? true}
                           onChange={(e) => patch({ "features.build.ccache": e.target.checked })} /> ccache (incremental rebuild reuse)
                  </label>
                  <label style={{ fontSize: 12.5 }}>
                    <input type="checkbox" checked={(v.settings.features.build as any).cache_reuse ?? true}
                           onChange={(e) => patch({ "features.build.cache_reuse": e.target.checked })} /> reuse cached artifact (skip identical rebuild)
                  </label>
                </div>
                {/* The bounded dependency-fetch tier (design §3.5 — the highest residual
                    supply-chain risk, its own fail-closed gate). */}
                <div style={{ marginTop: 10, borderTop: "1px solid var(--border)", paddingTop: 8 }}>
                  <label className="switch">
                    <input type="checkbox" checked={(v.settings.features as any).build_fetch?.enabled ?? false}
                           onChange={(e) => patch({ "features.build_fetch.enabled": e.target.checked })} />
                    <span>Bounded dependency fetch {(v.settings.features as any).build_fetch?.enabled ? "enabled" : "disabled"}</span>
                    {pending("build_fetch")}
                  </label>
                  <p className="hint" style={{ marginTop: 4 }}>
                    ⚠ The <b>highest residual supply-chain risk</b>. A SEPARATE, audited, <b>allowlisted</b> fetch
                    phase resolves declared deps over the network (package registries only), produces a
                    <b> hash-pinned lockfile</b> + SBOM-lite, then <b>drops network</b> and compiles
                    <code> --network none</code>. Fetch-then-offline — a malicious dep can be downloaded
                    (recorded) but can never run during compile or exfiltrate. NEVER folded into
                    <code> features.network</code>.
                  </p>
                </div>
                {/* The editable IDE (design §6.2 D-edit). */}
                <div style={{ marginTop: 6 }}>
                  <label className="switch">
                    <input type="checkbox" checked={(v.settings.features as any).source?.edit ?? false}
                           onChange={(e) => patch({ "features.source.edit": e.target.checked })} />
                    <span>Editable IDE {(v.settings.features as any).source?.edit ? "enabled" : "disabled"}</span>
                  </label>
                  <p className="hint" style={{ marginTop: 4 }}>
                    <b>Scratch</b> trees (your promoted harnesses/PoCs) are <b>already editable by default</b> —
                    no flag needed. This flag additionally makes <b>other</b> authored files editable
                    (harness/PoC/script in an imported-but-editable tree). A save creates a <b>new revision</b>
                    (never an in-place mutation); a build can be launched <b>rebuild-from-revision</b>.
                    Imported / extracted / vendor source stays <b>read-only</b> (editing it would break the
                    build content-hash contract).
                  </p>
                </div>
              </>
            )}
          </section>

          {/* PoC verification */}
          <section className="card2">
            <div className="h3row">
              <h3><Icon name="check" size={15} /> PoC verification <span className="muted">· optional · executes the target</span>{pending("poc")}</h3>
              <label className="switch">
                <input type="checkbox" checked={v.settings.features.poc.enabled}
                       onChange={(e) => patch({ "features.poc.enabled": e.target.checked })} />
                <span>{v.settings.features.poc.enabled ? "enabled" : "disabled"}</span>
              </label>
            </div>
            <p className="hint">
              ⚠ Like fuzzing, this relaxes the static-only policy: a <b>poc</b> task / the <code>verify_poc</code>
              tool <b>executes the target</b> with an attacker-style input inside the sandbox
              (<code>--network none</code>, capped, timed, disposable) and confirms it via an unforgeable
              nonce oracle. A verified PoC is marked <b>✓ verified</b> on the finding.
            </p>
          </section>

          {/* Network egress — bounded local-network tier */}
          <section className="card2">
            <div className="h3row">
              <h3><Icon name="globe" size={15} /> Network egress <span className="muted">· optional · contacts a live target</span>{pending("network")}</h3>
              <label className="switch">
                <input type="checkbox" checked={v.settings.features.network.enabled}
                       onChange={(e) => patch({ "features.network.enabled": e.target.checked })} />
                <span>{v.settings.features.network.enabled ? "enabled" : "disabled"}</span>
              </label>
            </div>
            <p className="hint">
              ⚠ Enabling this relaxes <code>--network none</code> for the bounded <b>local-network</b> tier:
              a sandboxed probe (e.g. <code>web_recon</code> against a <code>web_app</code> surface) may reach
              a target, but <b>only a loopback/private destination</b> on a per-target deny-all-but-this
              allowlist — external/public hosts are refused. Every outbound action is audited
              (<code>EgressEvent</code>). The target is never executed locally.
            </p>
            {v.settings.features.network.enabled && (
              <div className="row"><label>probe timeout (s)</label>
                <input className="inp num-input" type="number" defaultValue={v.settings.features.network.timeout}
                       onBlur={(e) => patch({ "features.network.timeout": parseInt(e.target.value) || 30 })} /></div>
            )}
          </section>

          {/* Remote fuzz environments — run a campaign on a user-owned remote Docker host */}
          <section className="card2">
            <div className="h3row">
              <h3><Icon name="chip" size={15} /> Remote fuzz environments <span className="muted">· optional · beefier compute</span>{pending("fuzz_remote")}</h3>
              <label className="switch">
                <input type="checkbox" checked={Boolean(v.settings.features.fuzz_remote?.enabled)}
                       onChange={(e) => patch({ "features.fuzz_remote.enabled": e.target.checked })} />
                <span>{v.settings.features.fuzz_remote?.enabled ? "enabled" : "disabled"}</span>
              </label>
            </div>
            <p className="hint">
              Run a whole fuzz <b>campaign</b> on a user-owned <b>remote Docker host</b> (beefier/unconstrained
              compute) — building + fuzzing run there with no analysis change. The control plane stays
              bound to <code>127.0.0.1</code>; the remote is purely compute and the <b>same sandbox boundary</b>
              applies there (<code>--network none</code>, cap-drop, no-new-privileges, read-only, non-root).
              The connection is a <b>secret</b> set in env (<code>HEXGRAPH_FUZZ_REMOTE_&lt;ID&gt;_DOCKER_HOST</code>)
              or <code>config.toml [fuzz_remote.&lt;id&gt;]</code> — <b>never stored here</b>, shown presence-only.
              This toggle is the only gate (<code>features.fuzz_remote</code>).
            </p>
            {v.settings.features.fuzz_remote?.enabled && (
              <div style={{ display: "flex", flexDirection: "column", gap: 8, marginTop: 8 }}>
                {envs.filter((e) => !e.is_local).length === 0 && (
                  <div className="muted" style={{ fontSize: 12 }}>No remote environments registered yet.</div>
                )}
                {envs.filter((e) => !e.is_local).map((e) => (
                  <div key={e.id} className="row" style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
                    <b>{e.name}</b>
                    <span className="tag">{e.transport}</span>
                    <span className="muted" style={{ fontSize: 11.5 }}>{e.host_descriptor || "—"}</span>
                    <span className="tag" style={{ background: e.connection_present ? "var(--ok-bg, #143)" : "var(--warn-bg, #431)" }}>
                      {e.connection_present ? "connection configured" : "no connection"}
                    </span>
                    {e.health?.checked_at && (
                      <span className="tag" title={e.health.detail}>
                        {e.health.ok ? "healthy" : "unhealthy"}{e.health.docker_version ? ` · docker ${e.health.docker_version}` : ""}
                      </span>
                    )}
                    <button className="btn sm ghost" disabled={envBusy === e.id}
                            onClick={async () => { setEnvBusy(e.id); try { await api.fuzzEnvironmentHealth(e.id); await loadEnvs(); } finally { setEnvBusy(""); } }}>
                      {envBusy === e.id ? "checking…" : "Health-check"}
                    </button>
                    <button className="btn sm ghost" onClick={async () => { await api.deleteFuzzEnvironment(e.id); loadEnvs(); }}>Remove</button>
                    <code style={{ fontSize: 10.5 }}>id: {e.id}</code>
                  </div>
                ))}
                <div className="row" style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap", marginTop: 6 }}>
                  <input className="inp" placeholder="name (e.g. fuzzbox)" value={newEnvName}
                         onChange={(e) => setNewEnvName(e.target.value)} style={{ width: 160 }} />
                  <select className="sel" value={newEnvTransport} onChange={(e) => setNewEnvTransport(e.target.value)}>
                    <option value="ssh">ssh</option><option value="tcp">tcp</option>
                  </select>
                  <input className="inp" placeholder="descriptor (non-secret, e.g. ssh://beefybox)" value={newEnvDesc}
                         onChange={(e) => setNewEnvDesc(e.target.value)} style={{ width: 240 }} />
                  <button className="btn sm primary" disabled={!newEnvName.trim() || envBusy === "new"}
                          onClick={async () => {
                            setEnvBusy("new");
                            try {
                              const r = await api.registerFuzzEnvironment({ name: newEnvName.trim(), transport: newEnvTransport, host_descriptor: newEnvDesc.trim() || undefined });
                              setNewEnvName(""); setNewEnvDesc("");
                              await loadEnvs();
                              setErr(`Registered '${r.name}' (id: ${r.id}). Set its secret connection in env: HEXGRAPH_FUZZ_REMOTE_${r.id.toUpperCase().replace(/-/g, "_")}_DOCKER_HOST`);
                            } catch (x: any) { setErr(String(x.message || x)); }
                            finally { setEnvBusy(""); }
                          }}>Register</button>
                </div>
              </div>
            )}
          </section>

          {/* MCP — coding-agent integration */}
          <section className="card2">
            <h3><Icon name="link" size={15} /> Coding-agent tools (MCP) <span className="muted">· optional</span></h3>
            <p className="hint">
              Run <code>hexgraph mcp install</code> to connect Claude Code / Codex / gemini-cli. These toggles
              decide which tool groups the agent sees — trim them so its context isn't filled with tools you
              won't use. <b>read</b>: inspect the graph/target · <b>write</b>: populate findings/nodes/edges ·
              <b> run</b>: execute sandboxed tasks.
            </p>
            {(["read", "write", "run"] as const).map((g) => (
              <label key={g} className="switch" style={{ display: "flex", gap: 8, marginTop: 6 }}>
                <input type="checkbox" checked={v.settings.features.mcp[g]}
                       onChange={(e) => patch({ [`features.mcp.${g}`]: e.target.checked })} />
                <span><code>{g}</code> tools</span>
              </label>
            ))}
          </section>

          {/* Delegate to a coding agent */}
          <section className="card2">
            <div className="h3row">
              <h3><Icon name="run" size={15} /> Delegate to a coding agent <span className="muted">· optional</span></h3>
              <label className="switch">
                <input type="checkbox" checked={v.settings.features.agent.enabled}
                       onChange={(e) => patch({ "features.agent.enabled": e.target.checked })} />
                <span>{v.settings.features.agent.enabled ? "enabled" : "disabled"}</span>
              </label>
            </div>
            <p className="hint">
              When enabled, an <b>agent_delegate</b> task appears in the Run menu: HexGraph launches your
              coding agent headless, wired to the HexGraph MCP server + VR skill and <b>restricted to
              HexGraph's sandboxed tools</b> (no shell on the target). Register the server first:
              <code> hexgraph mcp install</code>.
            </p>
            {v.settings.features.agent.enabled && (
              <>
                <div className="row"><label>Agent CLI</label>
                  <select className="sel" value={v.settings.features.agent.cli}
                          onChange={(e) => patch({ "features.agent.cli": e.target.value })}>
                    {["claude", "codex", "gemini"].map((c) => <option key={c}>{c}</option>)}
                  </select>
                </div>
                <div className="row"><label>Binary (optional)</label>
                  <input className="inp" defaultValue={v.settings.features.agent.binary} placeholder="(cli name on PATH)"
                         onBlur={(e) => patch({ "features.agent.binary": e.target.value.trim() })} />
                </div>
                <div className="row"><label>Timeout (s)</label>
                  <input className="inp" type="number" defaultValue={v.settings.features.agent.timeout}
                         onBlur={(e) => patch({ "features.agent.timeout": parseInt(e.target.value) || 900 })} />
                </div>
              </>
            )}
          </section>

          {/* Server */}
          <section className="card2">
            <h3>Server</h3>
            <div className="row">
              <label>Bind host</label>
              <input className="inp" defaultValue={v.settings.server.host}
                     onBlur={(e) => patch({ "server.host": e.target.value.trim() })} />
            </div>
            <div className="row">
              <label>Port</label>
              <input className="inp" type="number" defaultValue={v.settings.server.port}
                     onBlur={(e) => patch({ "server.port": parseInt(e.target.value) || 8765 })} />
            </div>
            <p className="hint">Loopback only by default (127.0.0.1). Changes apply on next <code>hexgraph serve</code>.
              A non-loopback bind is refused unless <code>HEXGRAPH_I_KNOW_WHAT_IM_DOING=1</code>.</p>
          </section>

          <div className="paths muted">
            <div>config.toml · <code>{v.paths.config_toml}</code></div>
            <div>settings.json · <code>{v.paths.settings_json}</code></div>
            <div>docker {v.availability.docker ? "✓ available" : "✗ not running"}</div>
          </div>
        </div>
      </div>
    </>
  );
}
