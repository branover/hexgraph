import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { GhidraStatus, SettingsView, api } from "../api";
import Header from "../components/Header";
import { Icon } from "../components/Icon";

// Self-service configuration: optional features + non-secret prefs. API keys are
// status-only here (env/config.toml BYOK) — the server never writes secrets.
export default function Settings() {
  const nav = useNavigate();
  const [v, setV] = useState<SettingsView | null>(null);
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState("");
  const [ghidra, setGhidra] = useState<GhidraStatus | null>(null);
  const [testing, setTesting] = useState(false);

  const close = () => { if (window.history.length > 1) nav(-1); else nav("/"); };
  useEffect(() => {
    api.getSettings().then(setV).catch((e) => setErr(String(e.message || e)));
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
                      Build it with <code>make sandbox-build WITH_GHIDRA=1</code>. Falls back to radare2 if unavailable.</p>
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
              <h3><Icon name="bug" size={15} /> Fuzzing <span className="muted">· optional · executes code</span></h3>
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
          </section>

          {/* PoC verification */}
          <section className="card2">
            <div className="h3row">
              <h3><Icon name="check" size={15} /> PoC verification <span className="muted">· optional · executes the target</span></h3>
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
              <h3><Icon name="globe" size={15} /> Network egress <span className="muted">· optional · contacts a live target</span></h3>
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
