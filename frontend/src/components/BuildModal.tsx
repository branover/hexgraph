import { useEffect, useState } from "react";
import { BuildPreview, BuildRow, SourceTreeRow, api } from "../api";
import { Icon } from "./Icon";

const SANITIZERS = ["address", "undefined", "memory"];
const ENGINES = ["libfuzzer", "afl", "none"];
// Cross-compile arches (design §3.4): native + the common firmware arches. A non-native
// arch injects clang --target + the parent firmware's rootfs as --sysroot.
const ARCHES = ["x86_64", "mips", "mipsel", "arm", "armhf", "aarch64"];

// The Build modal (build-as-API in the UI, design §6.3). It shows the RECORDED
// recipe preview (read-only — NO free-text command box: the user toggles the
// instrumentation profile and the preview regenerates server-side via
// /build/preview), the injected toolchain env (the base-image contract), and the
// reproducibility recipe_sha. Building runs the recorded recipe in the sandbox,
// vendored/offline only (--network none). A build of a source tree linked to a
// target registers an instrumented derived target.
export default function BuildModal({ projectId, tree, fetchEnabled, onClose, onBuilt }: {
  projectId: string; tree: SourceTreeRow; fetchEnabled?: boolean;
  onClose: () => void; onBuilt: (b: BuildRow) => void;
}) {
  const [sanitizers, setSanitizers] = useState<string[]>(["address"]);
  const [coverage, setCoverage] = useState(true); // SanCov
  const [engine, setEngine] = useState("libfuzzer");
  const [artifacts, setArtifacts] = useState("");
  const [arch, setArch] = useState("x86_64");
  const [network, setNetwork] = useState<"none" | "fetch">("none");
  // Custom build phases (one shell command per line) for a source tree with no default
  // recipe — previously you could only "author phases via the API". When non-empty these
  // become the recorded compile phases (each a `shell` step); empty = the server default.
  const [customPhases, setCustomPhases] = useState("");
  const [preview, setPreview] = useState<BuildPreview | null>(null);
  const [err, setErr] = useState<string>();
  const [busy, setBusy] = useState(false);

  const phaseLines = () => customPhases.split(/\n/).map((s) => s.trim()).filter(Boolean);
  const spec = () => ({
    source_tree_id: tree.id,
    instrumentation: { sanitizers, coverage: coverage ? ["sancov"] : [], engine },
    artifacts: artifacts.split(/[\n,]/).map((s) => s.trim()).filter(Boolean),
    // Each non-empty line is one recorded step: `sh -c "<line>"` (the probe runs the argv
    // directly; shell:true is reserved for a recorded script PATH, not an inline command).
    ...(phaseLines().length ? { phases: phaseLines().map((cmd) => ({ argv: ["sh", "-c", cmd], shell: false })) } : {}),
    arch, network,
  });

  // Regenerate the recorded-recipe preview whenever the instrumentation profile changes.
  useEffect(() => {
    let live = true;
    api.buildPreview(projectId, spec()).then((p) => { if (live) { setPreview(p); setErr(undefined); } })
      .catch((e) => { if (live) setErr(String(e.message || e)); });
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sanitizers.join(","), coverage, engine, artifacts, arch, network, customPhases]);

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
            arch, and dependency posture, and the toolchain env is injected. The <b>compile phase
            always runs <code>--network none</code></b>; the only network is the opt-in, audited,
            allowlisted <i>fetch</i> phase, which drops network before compile.
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

          <div style={{ display: "flex", gap: 18, flexWrap: "wrap", alignItems: "center" }}>
            <label style={{ fontSize: 12 }}>
              arch{" "}
              <select value={arch} onChange={(e) => setArch(e.target.value)}
                      title="A non-native arch cross-compiles for a firmware's CPU (clang --target + the firmware rootfs as --sysroot; degrades to qemu-mode fuzzing on failure)"
                      style={{ background: "var(--bg)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: 4, fontSize: 12 }}>
                {ARCHES.map((a) => <option key={a} value={a}>{a}{a !== "x86_64" ? " (cross)" : ""}</option>)}
              </select>
            </label>
            <label style={{ fontSize: 12 }} title={fetchEnabled ? "vendored = offline-reproducible (--network none); fetch = a SEPARATE, audited, allowlisted deps phase that hash-pins a lockfile, then DROPS NETWORK before compile" : "the bounded fetch tier requires features.build_fetch"}>
              dependencies{" "}
              <select value={network} disabled={!fetchEnabled} onChange={(e) => setNetwork(e.target.value as any)}
                      style={{ background: "var(--bg)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: 4, fontSize: 12 }}>
                <option value="none">vendored — no network</option>
                <option value="fetch">fetch — audited, allowlisted</option>
              </select>
            </label>
          </div>

          <label style={{ fontSize: 12 }}>
            Artifacts to capture (rel paths, comma/newline separated — the fuzz target/.so/binary)
            <input value={artifacts} onChange={(e) => setArtifacts(e.target.value)}
                   placeholder="e.g. fuzz.o, fuzz_target"
                   style={{ width: "100%", marginTop: 4, background: "var(--bg)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: 4, padding: "4px 6px", fontSize: 12 }} />
          </label>

          <label style={{ fontSize: 12 }}>
            Custom build phases (one shell command per line — optional; overrides the default recipe)
            <textarea value={customPhases} onChange={(e) => setCustomPhases(e.target.value)} rows={3} spellCheck={false}
                      placeholder={"e.g.\n./autogen.sh\n./configure --disable-shared\nmake -j$(nproc) fuzz_target"}
                      title="For a source tree with no default recipe (a plain build.sh / autotools / custom). Each line is recorded verbatim as a shell step and runs --network none in the sandbox."
                      style={{ width: "100%", marginTop: 4, background: "var(--bg)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: 4, padding: "4px 6px", fontSize: 11.5, fontFamily: "var(--mono, monospace)" }} />
          </label>

          <div>
            <div className="sec-label">Recorded recipe preview (read-only)</div>
            {err && <div className="err" style={{ fontSize: 11.5 }}>{err}</div>}
            {!preview && !err && <div className="muted" style={{ fontSize: 11 }}>computing recipe…</div>}
            {preview && (
              <div style={{ fontFamily: "var(--mono, monospace)", fontSize: 11, background: "var(--bg)", border: "1px solid var(--border)", borderRadius: 4, padding: 8, maxHeight: 220, overflow: "auto" }}>
                <div className="muted">system: {preview.system} · arch: {preview.arch}{preview.cross ? " (cross, sysroot ✓)" : ""} · deps: {preview.network === "fetch" ? "fetch (audited/allowlisted → offline compile)" : "vendored/offline"}</div>
                {preview.network === "fetch" && preview.fetch_phases && preview.fetch_phases.length > 0 && (
                  <div style={{ margin: "2px 0" }}><span className="muted">fetch phase (network on, allowlisted):</span>{preview.fetch_phases.map((p, i) => <div key={i}>+ {p.argv.join(" ")}</div>)}</div>
                )}
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
