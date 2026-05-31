import { useEffect, useState } from "react";
import { GhidraStatus, SettingsView, api } from "../api";
import Header from "../components/Header";
import { Icon } from "../components/Icon";

// Self-service configuration: optional features + non-secret prefs. API keys are
// status-only here (env/config.toml BYOK) — the server never writes secrets.
export default function Settings() {
  const [v, setV] = useState<SettingsView | null>(null);
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState("");
  const [ghidra, setGhidra] = useState<GhidraStatus | null>(null);
  const [testing, setTesting] = useState(false);

  useEffect(() => { api.getSettings().then(setV).catch((e) => setErr(String(e.message || e))); }, []);

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
          <h2><Icon name="chip" size={20} /> Settings</h2>
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
