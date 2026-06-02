import { useEffect, useState } from "react";
import { BuildPreview, BuildRow, SourceTreeRow, api } from "../api";
import { Icon } from "./Icon";

const SANITIZERS = ["address", "undefined", "memory"];
const ENGINES = ["libfuzzer", "afl", "none"];

// The Build modal (build-as-API in the UI, design §6.3). It shows the RECORDED
// recipe preview (read-only — NO free-text command box: the user toggles the
// instrumentation profile and the preview regenerates server-side via
// /build/preview), the injected toolchain env (the base-image contract), and the
// reproducibility recipe_sha. Building runs the recorded recipe in the sandbox,
// vendored/offline only (--network none). A build of a source tree linked to a
// target registers an instrumented derived target.
export default function BuildModal({ projectId, tree, onClose, onBuilt }: {
  projectId: string; tree: SourceTreeRow;
  onClose: () => void; onBuilt: (b: BuildRow) => void;
}) {
  const [sanitizers, setSanitizers] = useState<string[]>(["address"]);
  const [coverage, setCoverage] = useState(true); // SanCov
  const [engine, setEngine] = useState("libfuzzer");
  const [artifacts, setArtifacts] = useState("");
  const [preview, setPreview] = useState<BuildPreview | null>(null);
  const [err, setErr] = useState<string>();
  const [busy, setBusy] = useState(false);

  const spec = () => ({
    source_tree_id: tree.id,
    instrumentation: { sanitizers, coverage: coverage ? ["sancov"] : [], engine },
    artifacts: artifacts.split(/[\n,]/).map((s) => s.trim()).filter(Boolean),
  });

  // Regenerate the recorded-recipe preview whenever the instrumentation profile changes.
  useEffect(() => {
    let live = true;
    api.buildPreview(projectId, spec()).then((p) => { if (live) { setPreview(p); setErr(undefined); } })
      .catch((e) => { if (live) setErr(String(e.message || e)); });
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sanitizers.join(","), coverage, engine, artifacts]);

  const toggleSan = (s: string) =>
    setSanitizers((cur) => cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s]);

  const launch = async () => {
    setBusy(true); setErr(undefined);
    try {
      const b = await api.createBuild(projectId, { spec: spec() });
      onBuilt(b);
      onClose();
    } catch (e: any) { setErr(String(e.message || e)); setBusy(false); }
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" style={{ maxWidth: 640 }} onClick={(e) => e.stopPropagation()}>
        <div className="modal-h">
          <Icon name="chip" size={15} /> Build from source — {tree.name}
          <button className="btn sm ghost" style={{ marginLeft: "auto" }} onClick={onClose}>✕</button>
        </div>
        <div className="modal-b" style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <div className="muted" style={{ fontSize: 11.5 }}>
            HexGraph runs a <b>recorded, reproducible recipe</b> in the sandbox — you never run a
            compiler. The recipe is fixed (no free-text command); you choose the instrumentation,
            and the toolchain env is injected. <b>Vendored / offline only</b> — the build runs
            <code> --network none</code>.
          </div>

          <div>
            <div className="sec-label">Instrumentation (baked into the target's own objects)</div>
            <div style={{ display: "flex", gap: 14, flexWrap: "wrap", alignItems: "center" }}>
              {SANITIZERS.map((s) => (
                <label key={s} style={{ fontSize: 12, cursor: "pointer" }}>
                  <input type="checkbox" checked={sanitizers.includes(s)} onChange={() => toggleSan(s)} /> {s}
                </label>
              ))}
              <label style={{ fontSize: 12, cursor: "pointer" }}>
                <input type="checkbox" checked={coverage} onChange={(e) => setCoverage(e.target.checked)} /> SanCov (coverage)
              </label>
              <label style={{ fontSize: 12 }}>
                engine{" "}
                <select value={engine} onChange={(e) => setEngine(e.target.value)}
                        style={{ background: "var(--bg)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: 4, fontSize: 12 }}>
                  {ENGINES.map((x) => <option key={x} value={x}>{x}</option>)}
                </select>
              </label>
            </div>
          </div>

          <label style={{ fontSize: 12 }}>
            Artifacts to capture (rel paths, comma/newline separated — the fuzz target/.so/binary)
            <input value={artifacts} onChange={(e) => setArtifacts(e.target.value)}
                   placeholder="e.g. fuzz.o, fuzz_target"
                   style={{ width: "100%", marginTop: 4, background: "var(--bg)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: 4, padding: "4px 6px", fontSize: 12 }} />
          </label>

          <div>
            <div className="sec-label">Recorded recipe preview (read-only)</div>
            {err && <div className="err" style={{ fontSize: 11.5 }}>{err}</div>}
            {!preview && !err && <div className="muted" style={{ fontSize: 11 }}>computing recipe…</div>}
            {preview && (
              <div style={{ fontFamily: "var(--mono, monospace)", fontSize: 11, background: "var(--bg)", border: "1px solid var(--border)", borderRadius: 4, padding: 8, maxHeight: 220, overflow: "auto" }}>
                <div className="muted">system: {preview.system} · arch: {preview.arch} · network: {preview.network}</div>
                <div style={{ margin: "4px 0" }}>
                  {preview.phases.length === 0
                    ? <span className="muted">no default phases for this system (custom — author phases via the API)</span>
                    : preview.phases.map((p, i) => <div key={i}>$ {p.argv.join(" ")}</div>)}
                </div>
                <div className="muted" style={{ marginTop: 4 }}>injected (base-image contract):</div>
                {Object.entries(preview.injected_env).map(([k, v]) => <div key={k}>{k}={v}</div>)}
                <div className="muted" style={{ marginTop: 4 }}>recipe_sha: {preview.recipe_sha.slice(0, 16)}…</div>
              </div>
            )}
          </div>
        </div>
        <div className="modal-f" style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
          <button className="btn sm ghost" onClick={onClose} disabled={busy}>Cancel</button>
          <button className="btn sm primary" onClick={launch} disabled={busy || !preview}>
            {busy ? <><Icon name="refresh" size={12} className="spin" /> building…</> : <>Build (sandboxed)</>}
          </button>
        </div>
      </div>
    </div>
  );
}
