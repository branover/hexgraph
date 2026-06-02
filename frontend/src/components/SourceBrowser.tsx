import { useEffect, useRef, useState } from "react";
import { BuildRow, SourceFileEntry, SourceTreeRow, api } from "../api";
import { Icon } from "./Icon";
import BuildModal from "./BuildModal";
import { highlightLines, langForFile } from "../highlight";

// The read-only Source/IDE mode (Phase 1). A multi-tree file explorer (a dropdown
// switcher over a shared <FileTree>, mirroring FilesystemBrowser) + a code viewer.
// Editing is a later phase — this is browse + finding→source jump only.

type TreeNode = { name: string; path: string; dir: boolean; entry?: SourceFileEntry; children: Record<string, TreeNode> };

function buildTree(files: SourceFileEntry[]): TreeNode {
  const root: TreeNode = { name: "", path: "", dir: true, children: {} };
  for (const f of files) {
    const parts = f.rel.split("/");
    let cur = root;
    parts.forEach((part, i) => {
      const isLeaf = i === parts.length - 1;
      cur.children[part] ??= { name: part, path: parts.slice(0, i + 1).join("/"), dir: !isLeaf, children: {} };
      if (isLeaf) cur.children[part].entry = f;
      cur = cur.children[part];
    });
  }
  return root;
}

const fmtSize = (n?: number) => (n == null ? "" : n < 1024 ? `${n} B` : n < 1e6 ? `${(n / 1024).toFixed(0)} KB` : `${(n / 1e6).toFixed(1)} MB`);

export default function SourceBrowser({ projectId, open, onPickedTarget, buildEnabled, buildFetchEnabled, fuzzEnabled, sourceEditEnabled, onChanged }: {
  projectId: string;
  open?: { treeId?: string; rel?: string; line?: number } | null;
  onPickedTarget?: (targetIds: string[]) => void;
  buildEnabled?: boolean;
  buildFetchEnabled?: boolean;
  fuzzEnabled?: boolean;
  sourceEditEnabled?: boolean;
  onChanged?: () => void;
}) {
  const [trees, setTrees] = useState<SourceTreeRow[] | null>(null);
  const [treeId, setTreeId] = useState<string>();
  const [files, setFiles] = useState<SourceFileEntry[] | null>(null);
  const [view, setView] = useState<{ rel: string; loading: boolean; role?: string; origin?: string; encoding?: "text" | "binary"; content?: string; truncated?: boolean; err?: string } | null>(null);
  const [line, setLine] = useState<number | undefined>();
  // Coverage shading: pick a campaign whose coverage map shades the open file (design §6.3).
  const [campaigns, setCampaigns] = useState<{ id: string; name: string; status: string }[]>([]);
  const [covCampaign, setCovCampaign] = useState<string>("");
  const [coverage, setCoverage] = useState<import("../api").Coverage | null>(null);
  const [showBuild, setShowBuild] = useState(false);
  const [builds, setBuilds] = useState<BuildRow[]>([]);
  // Editable IDE (Phase 7): per-file edit mode + revision history.
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");
  const [saveErr, setSaveErr] = useState<string | null>(null);
  const [revs, setRevs] = useState<import("../api").SourceRevision[]>([]);
  const lineRef = useRef<HTMLDivElement>(null);

  const loadTrees = () => api.sourceTrees(projectId).then((r) => setTrees(r.source_trees)).catch(() => setTrees([]));
  useEffect(() => { loadTrees(); }, [projectId]);

  const loadBuilds = () => {
    if (!treeId) { setBuilds([]); return; }
    api.builds(projectId, treeId).then((r) => setBuilds(r.builds)).catch(() => setBuilds([]));
  };
  useEffect(() => { loadBuilds(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [treeId, projectId]);

  // Load campaigns that expose coverage (for the shading picker).
  useEffect(() => {
    if (!fuzzEnabled) return;
    api.campaigns(projectId).then((r) => {
      const cs = r.campaigns.map((c) => ({ id: c.id, name: c.name, status: c.status }));
      setCampaigns(cs);
      setCovCampaign((cur) => cur || (cs[0]?.id ?? ""));
    }).catch(() => setCampaigns([]));
  }, [projectId, fuzzEnabled]);

  // Fetch the selected campaign's coverage map.
  useEffect(() => {
    if (!covCampaign) { setCoverage(null); return; }
    api.campaignCoverage(covCampaign).then(setCoverage).catch(() => setCoverage(null));
  }, [covCampaign]);

  // pick a tree (deep-link, else the first)
  useEffect(() => {
    if (!trees) return;
    const want = open?.treeId && trees.some((t) => t.id === open.treeId) ? open.treeId : trees[0]?.id;
    setTreeId((cur) => cur && trees.some((t) => t.id === cur) ? cur : want);
  }, [trees, open?.treeId]);

  useEffect(() => {
    if (!treeId) { setFiles(null); return; }
    api.sourceFiles(treeId).then((r) => setFiles(r.files)).catch(() => setFiles([]));
  }, [treeId]);

  const openFile = async (rel: string, gotoLine?: number) => {
    if (!treeId) return;
    setView({ rel, loading: true });
    setLine(gotoLine);
    setEditing(false); setSaveErr(null);
    try {
      const r = await api.sourceFile(treeId, rel);
      setView({ rel, loading: false, role: r.role, origin: r.origin, encoding: r.encoding, content: r.content, truncated: r.truncated });
    } catch (e: any) { setView({ rel, loading: false, err: String(e.message || e) }); }
  };

  const tree0 = treeId ? trees?.find((t) => t.id === treeId) : undefined;
  // An editable file: features.source.edit on + an editable tree + a HexGraph-authored
  // role (extracted/vendor/imported trees stay read-only — the backend enforces this).
  const canEdit = !!(sourceEditEnabled && tree0?.editable && view?.encoding === "text"
                     && view.role && ["harness", "poc", "script", "build_recipe", "code"].includes(view.role));

  const loadRevs = () => {
    if (!treeId || !view?.rel) { setRevs([]); return; }
    api.sourceRevisions(treeId, view.rel).then((r) => setRevs(r.revisions)).catch(() => setRevs([]));
  };
  useEffect(() => { loadRevs(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [treeId, view?.rel]);

  const saveEdit = async () => {
    if (!treeId || !view?.rel) return;
    setSaveErr(null);
    try {
      await api.saveSourceRevision(treeId, { rel: view.rel, content: draft, role: view.role });
      setEditing(false);
      await openFile(view.rel);
      loadRevs(); loadBuilds(); onChanged?.();
    } catch (e: any) { setSaveErr(String(e.message || e)); }
  };

  const revert = async (rid: string) => {
    if (!treeId || !view?.rel) return;
    try { await api.revertSourceRevision(treeId, rid); await openFile(view.rel); loadRevs(); }
    catch (e: any) { setSaveErr(String(e.message || e)); }
  };

  // finding→source jump: when `open` carries a rel, switch tree + open the file at the line
  useEffect(() => {
    if (open?.treeId && open.rel && open.treeId === treeId) openFile(open.rel, open.line);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open?.treeId, open?.rel, open?.line, treeId]);

  // scroll the gutter to the target line once content renders
  useEffect(() => { if (line && lineRef.current) lineRef.current.scrollIntoView({ block: "center" }); }, [line, view?.content]);

  if (!trees) return <div className="muted" style={{ padding: 16, fontSize: 12 }}>loading source…</div>;
  if (trees.length === 0) {
    return (
      <div className="empty" style={{ padding: 24 }}>
        No source trees yet. Import a library's source or generate a harness — harnesses,
        PoCs, and build scripts are managed source files. (Read-only browse for now.)
      </div>
    );
  }

  const tree = treeId ? trees.find((t) => t.id === treeId) : undefined;
  const fileTree = files ? buildTree(files) : null;

  // Coverage line sets for the open file (match by exact rel or basename suffix, since a
  // campaign's coverage map may be rooted differently than the tree).
  const covFiles = coverage?.available ? coverage.files : null;
  const fileCov = (() => {
    if (!covFiles || !view?.rel) return null;
    if (covFiles[view.rel]) return covFiles[view.rel];
    const base = view.rel.split("/").pop();
    const key = Object.keys(covFiles).find((k) => k === base || k.endsWith("/" + base) || (base && base.endsWith("/" + k)));
    return key ? covFiles[key] : null;
  })();
  const covered = new Set(fileCov?.covered || []);
  const uncovered = new Set(fileCov?.uncovered || []);

  const Row = ({ node, depth }: { node: TreeNode; depth: number }) => {
    const kids = Object.values(node.children).sort((a, b) => Number(b.dir) - Number(a.dir) || a.name.localeCompare(b.name));
    if (node.dir && node.name) {
      return (
        <details open={depth < 2}>
          <summary style={{ paddingLeft: depth * 12, cursor: "pointer", fontSize: 12.5 }}>
            <Icon name="chip" size={12} /> {node.name}
          </summary>
          {kids.map((k) => <Row key={k.path} node={k} depth={depth + 1} />)}
        </details>
      );
    }
    if (node.dir) return <>{kids.map((k) => <Row key={k.path} node={k} depth={depth} />)}</>;
    const e = node.entry!;
    const sel = view?.rel === e.rel;
    return (
      <div className={"fsfile" + (sel ? " sel" : "")} style={{ paddingLeft: depth * 12 + 16, cursor: "pointer" }}
           onClick={() => openFile(e.rel)} title={e.rel}>
        <Icon name={e.is_harness ? "bug" : "doc"} size={12} />
        <span className="fname">{node.name}</span>
        {e.role && e.role !== "code" && <span className="tag" style={{ color: "var(--accent)" }}>{e.role}</span>}
        <span className="muted sz">{fmtSize(e.size)}</span>
      </div>
    );
  };

  return (
    <div className="srcide" style={{ display: "flex", height: "100%", minHeight: 0 }}>
      <div className="srctree" style={{ width: 260, borderRight: "1px solid var(--border)", overflow: "auto", flex: "none", display: "flex", flexDirection: "column" }}>
        <div className="pane-h sub" style={{ gap: 6 }}>
          <Icon name="doc" size={13} />
          <select value={treeId} onChange={(e) => { setTreeId(e.target.value); setView(null); }}
                  style={{ flex: 1, background: "var(--bg)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: 4, fontSize: 12, padding: "2px 4px" }}>
            {trees.map((t) => <option key={t.id} value={t.id}>{t.name} · {t.origin} ({t.file_count})</option>)}
          </select>
        </div>
        {tree && (
          <div className="muted" style={{ fontSize: 10.5, padding: "2px 8px 6px" }}>
            {tree.editable ? "editable" : "read-only"}
            {tree.origin === "extracted" && " · extracted (untrusted)"}
            {tree.target_ids.length > 0 && " · linked to a target"}
          </div>
        )}
        {fuzzEnabled && campaigns.length > 0 && (
          <div style={{ padding: "0 8px 6px" }}>
            <div className="sec-label" style={{ fontSize: 10 }}>Coverage shading</div>
            <select value={covCampaign} onChange={(e) => setCovCampaign(e.target.value)}
                    style={{ width: "100%", background: "var(--bg)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: 4, fontSize: 11, padding: "2px 4px" }}>
              <option value="">(off)</option>
              {campaigns.map((c) => <option key={c.id} value={c.id}>{c.name} · {c.status}</option>)}
            </select>
            {covCampaign && coverage && !coverage.available && (
              <div className="muted" style={{ fontSize: 10, marginTop: 3 }}>no per-line coverage map from this campaign</div>
            )}
            {fileCov && (
              <div className="cov-legend" style={{ fontSize: 10, marginTop: 5 }}>
                <span className="it"><span className="sw" style={{ background: "#2ea043" }} /> covered</span>
                <span className="it"><span className="sw" style={{ background: "#d29922" }} /> uncovered</span>
              </div>
            )}
          </div>
        )}
        {buildEnabled && tree && (
          <div style={{ padding: "0 8px 6px" }}>
            <button className="btn sm" style={{ width: "100%" }} title="Build this source tree into an instrumented artifact via a recorded recipe (sandboxed, vendored/offline)"
                    onClick={() => setShowBuild(true)}>
              <Icon name="chip" size={12} /> Build (instrumented)
            </button>
          </div>
        )}
        <div className="fsbrowser" style={{ flex: 1, overflow: "auto" }}>
          {fileTree && Object.values(fileTree.children).sort((a, b) => Number(b.dir) - Number(a.dir) || a.name.localeCompare(b.name))
            .map((k) => <Row key={k.path} node={k} depth={0} />)}
        </div>
        {builds.length > 0 && (
          <div style={{ borderTop: "1px solid var(--border)", padding: "6px 8px", maxHeight: 140, overflow: "auto" }}>
            <div className="sec-label" style={{ fontSize: 10.5 }}>Builds</div>
            {builds.map((b) => (
              <div key={b.id} style={{ fontSize: 10.5, display: "flex", gap: 6, alignItems: "center", padding: "2px 0" }}
                   title={b.error || (b.recipe_sha ? `recipe ${b.recipe_sha.slice(0, 12)}` : "")}>
                <span className={"tag"} style={{ color: b.status === "succeeded" ? "var(--ok, #6c6)" : b.status === "failed" ? "var(--accent)" : "var(--fg)" }}>{b.status}</span>
                <span className="muted" style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>
                  {Object.keys(b.artifacts || {}).join(", ") || (b.error ? "(failed)" : "—")}
                </span>
                {/* Reproducibility badge + supply-chain posture (Phase 7) */}
                {b.reproducible && <span className="tag" title="recipe_sha + source_content_hash + toolchain_digest (+ lockfile) all recorded ⇒ replayable" style={{ color: "var(--ok, #6c6)" }}>reproducible</span>}
                {b.cache_hit && <span className="tag" title="reused a prior identical build's artifact (cache hit) — no rebuild" style={{ color: "var(--fg)" }}>cached</span>}
                {b.lockfile && Object.keys(b.lockfile).length > 0 && <span className="tag" title={`${Object.keys(b.lockfile).length} hash-pinned deps (fetch tier)`} style={{ color: "var(--accent)" }}>locked</span>}
                {b.derived_target_id && <span className="tag" style={{ color: "var(--accent)" }}>instrumented</span>}
              </div>
            ))}
          </div>
        )}
      </div>
      {showBuild && tree && (
        <BuildModal projectId={projectId} tree={tree} fetchEnabled={buildFetchEnabled}
                    onClose={() => setShowBuild(false)}
                    onBuilt={() => { loadBuilds(); loadTrees(); onChanged?.(); }} />
      )}

      <div className="srcview" style={{ flex: 1, overflow: "auto", minWidth: 0 }}>
        {!view && <div className="muted" style={{ padding: 16, fontSize: 12 }}>Select a file to view its source (read-only).</div>}
        {view?.loading && <div className="muted" style={{ padding: 16, fontSize: 11 }}>loading…</div>}
        {view?.err && <div className="err" style={{ padding: 16 }}>{view.err}</div>}
        {view && !view.loading && !view.err && (
          <>
            <div className="filehdr">
              <Icon name="doc" size={13} />
              <span className="path">{view.rel}</span>
              {view.role && view.role !== "code" && <span className="tag" style={{ color: "var(--accent)" }}>{view.role}</span>}
              <span className="muted" style={{ fontSize: 10.5 }}>{fmtSize(view.encoding === "text" ? new Blob([view.content || ""]).size : undefined)}{view.encoding === "binary" && "binary (hex)"}{view.truncated && " · truncated"}</span>
              <span style={{ flex: 1 }} />
              {/* Editable IDE: read-only vs editable affordance (design §6.2 D-edit) */}
              {!canEdit && view.encoding === "text" && <span className="muted" style={{ fontSize: 10 }}>read-only</span>}
              {canEdit && !editing && (
                <button className="btn sm" title="Edit this HexGraph-authored file (a save creates a new revision)"
                        onClick={() => { setDraft(view.content || ""); setEditing(true); }}>Edit</button>
              )}
              {canEdit && editing && (
                <>
                  <button className="btn sm" onClick={saveEdit} title="Save as a new revision (never an in-place mutation)">Save revision</button>
                  <button className="btn sm" onClick={() => { setEditing(false); setSaveErr(null); }}>Cancel</button>
                </>
              )}
            </div>
            {saveErr && <div className="err" style={{ padding: "4px 12px", fontSize: 11 }}>{saveErr}</div>}
            {editing ? (
              <textarea value={draft} onChange={(e) => setDraft(e.target.value)} spellCheck={false}
                        style={{ width: "100%", minHeight: "60vh", boxSizing: "border-box", fontFamily: "var(--mono, monospace)", fontSize: 11.5, lineHeight: "1.55em", background: "var(--bg)", color: "var(--fg)", border: "none", padding: 12, resize: "vertical" }} />
            ) : view.encoding === "text" ? (
              // Syntax-highlighted, continuous code block with a dimmed gutter. The
              // highlighter (highlight.js, line-split) only colors the text; coverage
              // shading + the jump highlight ride as per-row classes UNDER it, so the
              // two decorations coexist (don't let the highlighter clobber them).
              <div className="scrollx">
                <div className="codeview">
                  {(() => {
                    const raw = view.content || "";
                    const hl = highlightLines(raw, langForFile(view.rel));
                    return hl.map((html, i) => {
                      const n = i + 1;
                      const hot = line === n;
                      const cls = "cl" + (hot ? " hot" : covered.has(n) ? " cov-y" : uncovered.has(n) ? " cov-n" : "");
                      return (
                        <div key={i} className={cls} ref={hot ? lineRef : undefined}>
                          <span className="ln">{n}</span>
                          <code className="src hljs" dangerouslySetInnerHTML={{ __html: html || " " }} />
                        </div>
                      );
                    });
                  })()}
                </div>
              </div>
            ) : (
              <pre className="codewrap" style={{ whiteSpace: "pre-wrap", padding: 12, fontFamily: "var(--mono, monospace)", fontSize: 11 }}>{view.content}</pre>
            )}
            {revs.length > 0 && (
              <div style={{ borderTop: "1px solid var(--border)", padding: "6px 12px" }}>
                <div className="sec-label" style={{ fontSize: 10.5 }}>Revisions ({revs.length})</div>
                {revs.map((r) => (
                  <div key={r.id} style={{ fontSize: 10.5, display: "flex", gap: 8, alignItems: "center", padding: "2px 0" }}>
                    <span className="tag" style={{ color: "var(--accent)" }}>r{r.seq}</span>
                    <span className="muted">{r.origin}</span>
                    {r.note && <span className="muted" style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>{r.note}</span>}
                    {!r.note && <span style={{ flex: 1 }} />}
                    {canEdit && r.seq !== revs[0].seq && (
                      <button className="btn sm" title="Revert the working file to this revision (append-only)" onClick={() => revert(r.id)}>revert</button>
                    )}
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
