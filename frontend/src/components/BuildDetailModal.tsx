import { useEffect, useState } from "react";
import { BuildRow, api } from "../api";
import { Icon } from "./Icon";

// The Build detail modal — the missing "why did it fail / what did it produce" view.
// A build row in the Builds list opens this. For a FAILED build it leads with the
// recorded error and the full build log (fetched from /api/builds/{id}/log, CAS-backed)
// so a failure is never a dead end; for a SUCCEEDED build it shows the captured
// artifacts, the reproducibility triple, and the supply-chain posture. Shares the
// Build/Fuzz modal design language (.modal.fuzz card system in theme.css).
export default function BuildDetailModal({ build, onClose }: { build: BuildRow; onClose: () => void }) {
  const [log, setLog] = useState<string | null>(null);
  const [logErr, setLogErr] = useState<string | null>(null);
  const [loadingLog, setLoadingLog] = useState(true);

  useEffect(() => {
    let live = true;
    setLoadingLog(true);
    api.buildLog(build.id)
      .then((r) => { if (live) { setLog(r.log || ""); setLogErr(null); } })
      .catch((e) => { if (live) setLogErr(String(e.message || e)); })
      .finally(() => { if (live) setLoadingLog(false); });
    return () => { live = false; };
  }, [build.id]);

  const failed = build.status === "failed";
  const artifacts = Object.entries(build.artifacts || {});
  const instr = build.instrumentation || {};
  const sans: string[] = instr.sanitizers || [];

  return (
    <div className="modal-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="modal fuzz build" onClick={(e) => e.stopPropagation()}>
        <h3>
          <Icon name={failed ? "alert" : "chip"} size={16} />
          {failed ? "Build failed" : "Build result"}
          <span className="muted" style={{ fontWeight: 400, fontSize: 12 }}>
            {" · "}{build.created_at ? new Date(build.created_at).toLocaleString() : build.id.slice(0, 8)}
          </span>
          <span style={{ flex: 1 }} />
          <button className="btn sm ghost icon" onClick={onClose}><Icon name="x" size={13} /></button>
        </h3>
        <div className="modal-b" style={{ display: "flex", flexDirection: "column", gap: 0 }}>
          {failed ? (
            <p className="lede" style={{ borderColor: "var(--accent)" }}>
              This build did not produce its instrumented artifact. The recorded error and the
              full build log are below — the usual causes are a compile/link error, a missing
              artifact path, or a recipe that needs network deps (the compile phase always runs
              <code> --network none</code>).
            </p>
          ) : (
            <p className="lede">
              The recorded recipe ran in the sandbox and produced the artifacts below. The
              reproducibility triple (recipe_sha · source content · toolchain) makes it replayable.
            </p>
          )}

          {/* ── Error (failed builds) ─────────────────────────────────── */}
          {failed && build.error && (
            <div className="grp" style={{ marginTop: 12 }}>
              <div className="grp-h"><Icon name="alert" size={12} /> Error
                {build.returncode != null && <span className="note">· exit {build.returncode}</span>}</div>
              <div className="err" style={{ fontSize: 11.5, whiteSpace: "pre-wrap" }}>{build.error}</div>
            </div>
          )}

          {/* ── Captured artifacts (succeeded builds) ─────────────────── */}
          {!failed && (
            <div className="grp" style={{ marginTop: 12 }}>
              <div className="grp-h"><Icon name="doc" size={12} /> Captured artifacts</div>
              {artifacts.length === 0
                ? <div className="muted" style={{ fontSize: 11 }}>no artifacts recorded</div>
                : <div className="recipe codeview"><div className="rc-block">
                    {artifacts.map(([rel, sha]) => (
                      <div key={rel} className="rc-env"><span className="rc-k">{rel}</span>
                        <span className="muted"> · cas {String(sha).slice(0, 12)}…</span></div>
                    ))}
                  </div></div>}
              {build.derived_target_id && (
                <div style={{ marginTop: 6 }}>
                  <span className="tag" style={{ color: "var(--accent)" }}>instrumented target registered</span>
                  {sans.length > 0 && <span className="muted" style={{ fontSize: 10.5 }}> · {sans.join(", ")}{instr.engine ? ` · ${instr.engine}` : ""}</span>}
                </div>
              )}
            </div>
          )}

          {/* ── Reproducibility / provenance ──────────────────────────── */}
          <div className="grp">
            <div className="grp-h"><Icon name="copy" size={12} /> Provenance
              {build.reproducible && <span className="note" style={{ color: "var(--ok, #6c6)" }}>· reproducible</span>}
              {build.cache_hit && <span className="note">· cache hit</span>}</div>
            <div className="recipe codeview"><div className="rc-block">
              {build.recipe_sha && <div className="rc-env"><span className="rc-k">recipe_sha</span>={build.recipe_sha}</div>}
              {build.source_content_hash && <div className="rc-env"><span className="rc-k">source</span>={build.source_content_hash}</div>}
              {build.toolchain_digest && <div className="rc-env"><span className="rc-k">toolchain</span>={build.toolchain_digest}</div>}
              {build.duration != null && <div className="rc-meta">built in {build.duration.toFixed(1)}s</div>}
              {build.lockfile && Object.keys(build.lockfile).length > 0 &&
                <div className="rc-meta">{Object.keys(build.lockfile).length} hash-pinned deps</div>}
            </div></div>
          </div>

          {/* ── Full build log ─────────────────────────────────────────── */}
          <div className="grp">
            <div className="grp-h"><Icon name="doc" size={12} /> Build log
              <span className="note">· captured in the content-addressed store</span></div>
            {loadingLog && <div className="muted" style={{ fontSize: 11 }}>loading log…</div>}
            {logErr && <div className="err" style={{ fontSize: 11.5 }}>{logErr}</div>}
            {!loadingLog && !logErr && (
              log
                ? <pre className="recipe codeview" style={{ maxHeight: 320, overflow: "auto", whiteSpace: "pre-wrap", fontSize: 11, margin: 0, padding: 10 }}>{log}</pre>
                : <div className="muted" style={{ fontSize: 11 }}>no log recorded for this build</div>
            )}
          </div>
        </div>
        <div className="modal-f" style={{ display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 14, borderTop: "1px solid var(--border)", paddingTop: 14 }}>
          <button className="btn sm ghost" onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}
