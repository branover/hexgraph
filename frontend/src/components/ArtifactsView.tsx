import { useEffect, useState } from "react";
import { Campaign, FuzzArtifact, StackFrame, api } from "../api";
import { Icon } from "./Icon";
import AssuranceChip from "./AssuranceChip";

const SEV_FOR_KIND: Record<string, string> = {
  "heap-buffer-overflow": "high", "stack-buffer-overflow": "high",
  "global-buffer-overflow": "high", "heap-use-after-free": "critical",
  "double-free": "high", "use-after-free": "critical", "SEGV": "high",
  "stack-overflow": "medium", "memory-leak": "low", "oom": "low", "timeout": "info",
};

// The Artifacts / triage view (design §6.3): a campaign's crash inbox, grouped by dedup
// bucket (one representative + dupe count). Per-group Reproduce / Minimize / Promote,
// source-mapped stacks (frame → IDE jump), assurance chips (the two-standards ladder),
// and one-click re-verify (LLM-free, via verify_artifact).
export default function ArtifactsView({ campaign, onViewFinding, onOpenSource }: {
  campaign: Campaign;
  onViewFinding?: (fid: string) => void;
  onOpenSource?: (ref: { tree_id?: string; rel?: string; line?: number }) => void;
}) {
  const [arts, setArts] = useState<FuzzArtifact[] | null>(null);
  const load = () => api.campaignArtifacts(campaign.id).then((r) => setArts(r.artifacts)).catch(() => setArts([]));
  useEffect(() => { load(); /* eslint-disable-next-line */ }, [campaign.id]);
  // Stream in new artifacts while the campaign is live.
  useEffect(() => {
    if (campaign.status !== "running" && campaign.status !== "building") return;
    const t = setInterval(load, 3000); return () => clearInterval(t); /* eslint-disable-next-line */
  }, [campaign.id, campaign.status]);

  if (!arts) return <div className="muted" style={{ padding: 12, fontSize: 12 }}>loading artifacts…</div>;

  const crashes = arts.filter((a) => a.kind === "crash");
  return (
    <div className="insp scroll fade-in" style={{ padding: 12 }}>
      <div className="head"><Icon name="bug" size={16} /><h3 style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{campaign.name}</h3></div>
      <div className="chips">
        <span className="tag">{campaign.engine} · {campaign.surface}</span>
        <span className="tag" style={campaign.status === "degraded" ? { color: "#d29922", borderColor: "#d29922" } : undefined}>{campaign.status}</span>
        <span className="tag">{(campaign.stats?.crash_count ?? crashes.length)} crashes</span>
        {campaign.stats?.coverage_percent != null && <span className="tag">{campaign.stats.coverage_percent.toFixed(0)}% cov</span>}
      </div>
      {/* A degraded campaign's WHY, so a no-op / unreachable / unstable run isn't read as a
          clean zero-crash success (the battle-test confusion). */}
      {(campaign.warning || campaign.engine_note) && (
        <div style={{ fontSize: 11, marginTop: 8, padding: "6px 9px", borderRadius: 5,
                      background: "rgba(210,153,34,0.12)", border: "1px solid #d29922", color: "#d29922",
                      display: "flex", gap: 6, alignItems: "flex-start" }}>
          <Icon name="alert" size={13} /> <span>{campaign.warning || campaign.engine_note}</span>
        </div>
      )}

      {crashes.length === 0 && (
        <div className="empty" style={{ padding: 16, fontSize: 12 }}>
          No crash artifacts yet.{campaign.status === "running" ? " Crashes stream here as the campaign finds them." : ""}
        </div>
      )}

      <div style={{ display: "flex", flexDirection: "column", gap: 10, marginTop: 8 }}>
        {crashes.map((a) => (
          <CrashGroup key={a.id} a={a} onChanged={load} onViewFinding={onViewFinding} onOpenSource={onOpenSource} />
        ))}
      </div>
    </div>
  );
}

function CrashGroup({ a, onChanged, onViewFinding, onOpenSource }: {
  a: FuzzArtifact; onChanged: () => void;
  onViewFinding?: (fid: string) => void;
  onOpenSource?: (ref: { tree_id?: string; rel?: string; line?: number }) => void;
}) {
  const [busy, setBusy] = useState<string>();
  const [msg, setMsg] = useState<string>();
  const [msgKind, setMsgKind] = useState<"ok" | "verified" | "error">("ok");
  const sev = SEV_FOR_KIND[a.sanitizer || ""] || "medium";
  const expl = a.exploitability || {};
  const status = a.finding?.status;
  const note = (text: string, kind: "ok" | "verified" | "error" = "ok") => { setMsg(text); setMsgKind(kind); };

  const verify = async () => {
    setBusy("verify"); setMsg(undefined);
    try { const r = await api.verifyArtifact(a.id); note(r.verified ? "✓ reproduced" : "✗ not reproduced", r.verified ? "verified" : "ok"); onChanged(); }
    catch (e: any) { note(String(e.message || e), "error"); }
    finally { setBusy(undefined); }
  };
  const minimize = async () => {
    setBusy("min"); setMsg(undefined);
    try { const r = await api.minimizeArtifact(a.id); note(r.verified ? "✓ minimized reproducer re-verified" : "✗ not reproduced", r.verified ? "verified" : "ok"); onChanged(); }
    catch (e: any) { note(String(e.message || e), "error"); }
    finally { setBusy(undefined); }
  };
  const promote = async (toPoc: boolean) => {
    setBusy(toPoc ? "poc" : "promote"); setMsg(undefined);
    try {
      const r = await api.promoteArtifact(a.id, toPoc);
      if (!toPoc) { note(`promoted (${r.status})`, "ok"); }
      else if (r.verified) {
        const lvl = r.assurance ? ` — ${r.assurance.standard} / ${r.assurance.method}` : "";
        note(`✓ Verified PoC: the reproducer re-crashed the harness${lvl}`, "verified");
      } else {
        note(`✗ Promoted, but could not re-confirm the crash — ${r.verify_detail || "the reproducer did not re-crash"}`, "ok");
      }
      onChanged();
    }
    catch (e: any) { note(String(e.message || e), "error"); }
    finally { setBusy(undefined); }
  };

  return (
    <div style={{ border: "1px solid var(--border)", borderRadius: 6, padding: "8px 10px", background: "var(--surface)" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
        <span className={"chip sev-" + sev}><span className="d" />{sev}</span>
        <code style={{ fontSize: 11 }}>{a.sanitizer || a.kind}</code>
        <span className="muted" style={{ fontSize: 11.5 }}>in {a.faulting_function || "?"}</span>
        {a.dupe_count > 0 && (
          <span className="tag" title="other crashing inputs bucketed to the same root cause (normalized stack hash)">
            +{a.dupe_count} dupes
          </span>
        )}
        {status && <span className="tag" style={{ color: status === "confirmed" ? "#2ea043" : undefined }}>{status}</span>}
        {a.finding?.verified && <span className="tag" style={{ color: "#2ea043", borderColor: "#2ea043" }}>✓ verified</span>}
      </div>

      <div style={{ display: "flex", gap: 10, marginTop: 6, alignItems: "center", flexWrap: "wrap" }}>
        {a.assurance && <AssuranceChip a={a.assurance} showNote />}
        {expl.rating && <span className="tag" title={(expl.signals || []).join(" · ")} style={{ textTransform: "none" }}>
          {expl.access ? `${expl.access} · ` : ""}{String(expl.rating).replace(/_/g, " ")}
        </span>}
      </div>

      {/* Source-mapped stack: click a symbolized frame → jump to source (reuses the
          Phase-1 finding→source jump). Unsymbolized (module+offset) frames are omitted. */}
      {a.frames && a.frames.length > 0 && (
        <div style={{ marginTop: 6 }}>
          <div className="sec-label" style={{ fontSize: 10.5 }}>Stack</div>
          <div style={{ fontFamily: "var(--mono, monospace)", fontSize: 10.5, display: "flex", flexDirection: "column", gap: 1 }}>
            {a.frames.slice(0, 6).map((f: StackFrame, i: number) => {
              const jumpable = i === 0 && a.source_ref?.tree_id; // the top frame is auto-linked
              return (
                <div key={i} className={jumpable ? "framelink" : undefined}
                     onClick={jumpable && onOpenSource ? () => onOpenSource(a.source_ref!) : undefined}
                     title={jumpable ? "Open this frame in the Source tab" : `${f.file}:${f.line}`}
                     style={{ cursor: jumpable && onOpenSource ? "pointer" : "default",
                              color: jumpable ? "var(--accent)" : "var(--muted)", display: "flex", gap: 6 }}>
                  <span style={{ width: 22, textAlign: "right", flex: "none" }}>#{f.idx}</span>
                  <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {f.func} <span style={{ opacity: 0.7 }}>{f.file.split("/").pop()}:{f.line}</span>
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      <div className="actions" style={{ marginTop: 8, flexWrap: "wrap" }}>
        <button className="btn sm" onClick={verify} disabled={!!busy || !a.content_cas} title="Replay the stored reproducer against the instrumented harness binary (LLM-free)">
          <Icon name={busy === "verify" ? "refresh" : "run"} size={11} className={busy === "verify" ? "spin" : ""} /> Reproduce
        </button>
        <button className="btn sm ghost" onClick={minimize} disabled={!!busy || !a.content_cas} title="Re-verify the minimized reproducer">
          <Icon name={busy === "min" ? "refresh" : "fit"} size={11} className={busy === "min" ? "spin" : ""} /> Minimize
        </button>
        <button className="btn sm ghost" onClick={() => promote(false)} disabled={!!busy || !a.finding_id} title="Confirm this crash as a tracked finding">
          <Icon name="check" size={11} /> Promote
        </button>
        <button className="btn sm primary" onClick={() => promote(true)} disabled={!!busy || !a.finding_id} title="Promote to a PoC and re-run the reproducer now to verify it (executes the target — requires PoC verification enabled)">
          <Icon name="target" size={11} /> Promote → PoC
        </button>
        {a.finding_id && onViewFinding && (
          <button className="btn sm ghost" onClick={() => onViewFinding(a.finding_id!)} title="Open the finding"><Icon name="bug" size={11} /> Finding</button>
        )}
      </div>
      {msg && (
        msgKind === "verified"
          ? <div style={{ fontSize: 11.5, marginTop: 6, padding: "4px 8px", borderRadius: 4,
                          fontWeight: 600, color: "#2ea043",
                          border: "1px solid #2ea043", background: "rgba(46,160,67,0.10)" }}>{msg}</div>
          : <div className={msgKind === "error" ? undefined : "muted"}
                 style={{ fontSize: 11, marginTop: 4, color: msgKind === "error" ? "#f85149" : undefined }}>{msg}</div>
      )}
    </div>
  );
}
