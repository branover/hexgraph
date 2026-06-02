import { useEffect, useState } from "react";
import { BuildPreview, BuildRow, SourceTreeRow, api } from "../api";
import { Icon } from "./Icon";

const SANITIZERS = ["address", "undefined", "memory"];
const SAN_LABEL: Record<string, string> = { address: "ASan", undefined: "UBSan", memory: "MSan" };
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
//
// Shares the Fuzz modal's design language (.modal.fuzz card/lede/footer system in
// theme.css) — grouped cards, a boxed lede, aligned field grids, a scrollable body
// and a pinned footer — so the two launch dialogs read as siblings.
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
    <div className="modal-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="modal fuzz build" onClick={(e) => e.stopPropagation()}>
        <h3>
          <Icon name="chip" size={16} /> Build from source
          <span className="muted" style={{ fontWeight: 400, fontSize: 12 }}> · {tree.name}</span>
          <span style={{ flex: 1 }} />
          <button className="btn sm ghost icon" onClick={onClose}><Icon name="x" size={13} /></button>
        </h3>
        <div className="modal-b" style={{ display: "flex", flexDirection: "column", gap: 0 }}>
          <p className="lede">
            HexGraph runs a <b>recorded, reproducible recipe</b> in the sandbox — you never run a
            compiler by hand. The recipe is fixed (no free-text command): you pick the instrumentation,
            arch, and dependency posture, and the toolchain env is injected. The <b>compile phase always
            runs <code>--network none</code></b>; the only network is the opt-in, audited, allowlisted
            <i> fetch</i> phase, which drops network before compile.
          </p>

          {/* ── Instrumentation ───────────────────────────────────────── */}
          <div className="grp" style={{ marginTop: 12 }}>
            <div className="grp-h"><Icon name="shield" size={12} /> Instrumentation
              <span className="note">· baked into the target's own objects</span></div>
            <div className="toggles">
              {SANITIZERS.map((s) => (
                <label key={s} className={"tgl" + (sanitizers.includes(s) ? " on" : "")}>
                  <input type="checkbox" checked={sanitizers.includes(s)} onChange={() => toggleSan(s)} />
                  <span>{SAN_LABEL[s]} <span className="sub">{s}</span></span>
                </label>
              ))}
              <label className={"tgl" + (coverage ? " on" : "")}>
                <input type="checkbox" checked={coverage} onChange={(e) => setCoverage(e.target.checked)} />
                <span>SanCov <span className="sub">coverage</span></span>
              </label>
            </div>
          </div>

          {/* ── Engine & arch ─────────────────────────────────────────── */}
          <div className="grp">
            <div className="grp-h"><Icon name="target" size={12} /> Engine &amp; arch</div>
            <div className="grid" style={{ gridTemplateColumns: "1fr 1fr" }}>
              <div><label>fuzzing engine</label>
                <select value={engine} onChange={(e) => setEngine(e.target.value)}>
                  {ENGINES.map((x) => <option key={x} value={x}>{x}</option>)}
                </select>
              </div>
              <div><label>arch <span className="sub">· cross-compiles for a firmware CPU</span></label>
                <select value={arch} onChange={(e) => setArch(e.target.value)}
                        title="A non-native arch cross-compiles for a firmware's CPU (clang --target + the firmware rootfs as --sysroot; degrades to qemu-mode fuzzing on failure)">
                  {ARCHES.map((a) => <option key={a} value={a}>{a}{a !== "x86_64" ? " (cross)" : ""}</option>)}
                </select>
              </div>
            </div>
          </div>

          {/* ── Dependencies ──────────────────────────────────────────── */}
          <div className="grp">
            <div className="grp-h"><Icon name="lib" size={12} /> Dependencies
              <span className="note">· {fetchEnabled ? "compile is always offline" : "fetch tier needs features.build_fetch"}</span></div>
            <div className="fld">
              <label>posture</label>
              <select value={network} disabled={!fetchEnabled} onChange={(e) => setNetwork(e.target.value as any)}
                      title={fetchEnabled ? "vendored = offline-reproducible (--network none); fetch = a SEPARATE, audited, allowlisted deps phase that hash-pins a lockfile, then DROPS NETWORK before compile" : "the bounded fetch tier requires features.build_fetch"}>
                <option value="none">vendored — no network</option>
                <option value="fetch">fetch — audited, allowlisted</option>
              </select>
            </div>
          </div>

          {/* ── Artifacts ─────────────────────────────────────────────── */}
          <div className="grp">
            <div className="grp-h"><Icon name="doc" size={12} /> Artifacts to capture</div>
            <div className="fld">
              <label>output paths <span className="sub">· rel, comma/newline separated · the fuzz target / .so / binary</span></label>
              <input value={artifacts} onChange={(e) => setArtifacts(e.target.value)}
                     placeholder="e.g. fuzz.o, fuzz_target" />
            </div>
            <div className="fld" style={{ marginTop: 10 }}>
              <label>custom build phases <span className="sub">· optional · one shell command per line · overrides the default recipe</span></label>
              <textarea value={customPhases} onChange={(e) => setCustomPhases(e.target.value)} rows={3} spellCheck={false}
                        placeholder={"e.g.\n./autogen.sh\n./configure --disable-shared\nmake -j$(nproc) fuzz_target"}
                        title="For a source tree with no default recipe (a plain build.sh / autotools / custom). Each line is recorded verbatim as a shell step and runs --network none in the sandbox." />
            </div>
          </div>

          {/* ── Recorded recipe preview ───────────────────────────────── */}
          <div className="grp">
            <div className="grp-h"><Icon name="copy" size={12} /> Recorded recipe preview
              <span className="note">· read-only · regenerated server-side</span></div>
            {err && <div className="err" style={{ fontSize: 11.5 }}>{err}</div>}
            {!preview && !err && <div className="muted" style={{ fontSize: 11 }}>computing recipe…</div>}
            {preview && (
              <div className="recipe codeview">
                <div className="rc-meta">system: {preview.system} · arch: {preview.arch}{preview.cross ? " (cross, sysroot ✓)" : ""} · deps: {preview.network === "fetch" ? "fetch (audited/allowlisted → offline compile)" : "vendored/offline"}</div>
                {preview.network === "fetch" && preview.fetch_phases && preview.fetch_phases.length > 0 && (
                  <div className="rc-block"><div className="rc-meta">fetch phase (network on, allowlisted):</div>{preview.fetch_phases.map((p, i) => <div key={i} className="rc-cmd net">+ {p.argv.join(" ")}</div>)}</div>
                )}
                <div className="rc-block">
                  {preview.phases.length === 0
                    ? <div className="rc-meta">no default phases for this system (custom — supply build phases above)</div>
                    : preview.phases.map((p, i) => <div key={i} className="rc-cmd">$ {p.argv.join(" ")}</div>)}
                </div>
                <div className="rc-block">
                  <div className="rc-meta">injected (base-image contract):</div>
                  {Object.entries(preview.injected_env).map(([k, v]) => <div key={k} className="rc-env"><span className="rc-k">{k}</span>={v}</div>)}
                </div>
                <div className="rc-sha">recipe_sha {preview.recipe_sha.slice(0, 16)}…</div>
              </div>
            )}
          </div>
        </div>
        <div className="modal-f" style={{ display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 14, borderTop: "1px solid var(--border)", paddingTop: 14 }}>
          <button className="btn sm ghost" onClick={onClose} disabled={busy}>Cancel</button>
          <button className="btn primary" onClick={launch} disabled={busy || !preview}>
            {busy ? <><Icon name="refresh" size={12} className="spin" /> building…</> : <><Icon name="chip" size={12} /> Build (sandboxed)</>}
          </button>
        </div>
      </div>
    </div>
  );
}
