import { useEffect, useRef, useState } from "react";
import { BuildRow, SourceFileEntry, SourceTreeRow, api } from "../api";
import { Icon } from "./Icon";
import BuildModal from "./BuildModal";

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

export default function SourceBrowser({ projectId, open, onPickedTarget, buildEnabled, onChanged }: {
  projectId: string;
  open?: { treeId?: string; rel?: string; line?: number } | null;
  onPickedTarget?: (targetIds: string[]) => void;
  buildEnabled?: boolean;
  onChanged?: () => void;
}) {
  const [trees, setTrees] = useState<SourceTreeRow[] | null>(null);
  const [treeId, setTreeId] = useState<string>();
  const [files, setFiles] = useState<SourceFileEntry[] | null>(null);
  const [view, setView] = useState<{ rel: string; loading: boolean; role?: string; origin?: string; encoding?: "text" | "binary"; content?: string; truncated?: boolean; err?: string } | null>(null);
  const [line, setLine] = useState<number | undefined>();
  const [showBuild, setShowBuild] = useState(false);
  const [builds, setBuilds] = useState<BuildRow[]>([]);
  const lineRef = useRef<HTMLDivElement>(null);

  const loadTrees = () => api.sourceTrees(projectId).then((r) => setTrees(r.source_trees)).catch(() => setTrees([]));
  useEffect(() => { loadTrees(); }, [projectId]);

  const loadBuilds = () => {
    if (!treeId) { setBuilds([]); return; }
    api.builds(projectId, treeId).then((r) => setBuilds(r.builds)).catch(() => setBuilds([]));
  };
  useEffect(() => { loadBuilds(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [treeId, projectId]);

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
    try {
      const r = await api.sourceFile(treeId, rel);
      setView({ rel, loading: false, role: r.role, origin: r.origin, encoding: r.encoding, content: r.content, truncated: r.truncated });
    } catch (e: any) { setView({ rel, loading: false, err: String(e.message || e) }); }
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
                {b.derived_target_id && <span className="tag" style={{ color: "var(--accent)" }}>instrumented</span>}
              </div>
            ))}
          </div>
        )}
      </div>
      {showBuild && tree && (
        <BuildModal projectId={projectId} tree={tree} onClose={() => setShowBuild(false)}
                    onBuilt={() => { loadBuilds(); loadTrees(); onChanged?.(); }} />
      )}

      <div className="srcview" style={{ flex: 1, overflow: "auto", minWidth: 0 }}>
        {!view && <div className="muted" style={{ padding: 16, fontSize: 12 }}>Select a file to view its source (read-only).</div>}
        {view?.loading && <div className="muted" style={{ padding: 16, fontSize: 11 }}>loading…</div>}
        {view?.err && <div className="err" style={{ padding: 16 }}>{view.err}</div>}
        {view && !view.loading && !view.err && (
          <>
            <div className="sec" style={{ display: "flex", alignItems: "center", gap: 8, position: "sticky", top: 0, background: "var(--panel, var(--bg))", zIndex: 1 }}>
              <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{view.rel}</span>
              {view.role && view.role !== "code" && <span className="tag" style={{ color: "var(--accent)" }}>{view.role}</span>}
              <span className="muted" style={{ fontSize: 10.5 }}>{fmtSize(view.encoding === "text" ? new Blob([view.content || ""]).size : undefined)}{view.encoding === "binary" && "binary (hex)"}{view.truncated && " · truncated"}</span>
            </div>
            {view.encoding === "text" ? (
              <div className="codelines" style={{ fontFamily: "var(--mono, monospace)", fontSize: 11.5, lineHeight: "1.55em" }}>
                {(view.content || "").split("\n").map((l, i) => {
                  const n = i + 1;
                  const hot = line === n;
                  return (
                    <div key={i} ref={hot ? lineRef : undefined}
                         style={{ display: "flex", background: hot ? "var(--hl, rgba(255,93,108,0.18))" : undefined }}>
                      <span className="muted" style={{ width: 44, textAlign: "right", paddingRight: 10, userSelect: "none", flex: "none" }}>{n}</span>
                      <pre style={{ margin: 0, whiteSpace: "pre-wrap", flex: 1 }}>{l || " "}</pre>
                    </div>
                  );
                })}
              </div>
            ) : (
              <pre className="codewrap" style={{ whiteSpace: "pre-wrap", padding: 12, fontFamily: "var(--mono, monospace)", fontSize: 11 }}>{view.content}</pre>
            )}
          </>
        )}
      </div>
    </div>
  );
}
