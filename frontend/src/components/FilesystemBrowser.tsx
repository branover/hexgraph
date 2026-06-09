import { useEffect, useState } from "react";
import { FsEntry, api } from "../api";
import { Icon } from "./Icon";

type TreeNode = { name: string; path: string; dir: boolean; entry?: FsEntry; children: Record<string, TreeNode> };

function buildTree(files: FsEntry[]): TreeNode {
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
const looksAddable = (e?: FsEntry) => !!e && (e.is_elf || /\.so(\.\d+)*$/.test(e.rel) || /\.(ko|bin)$/.test(e.rel));
// A child target exists but is hidden (the default for unpacked ELFs) → it can be REVEALED.
const isHidden = (e?: FsEntry) => !!e && !!e.added && e.revealed === false;
// All the leaf entries under a directory path (used for the per-dir "Reveal all" count).
const leavesUnder = (files: FsEntry[], prefix: string) =>
  // `""` = the whole tree (rootfs paths have no leading slash, so a "" + "/" prefix
  // would match nothing and the firmware-wide "reveal all" button would never show).
  files.filter((f) => prefix === "" || f.rel === prefix || f.rel.startsWith(prefix + "/"));

// Traversable unpacked firmware filesystem. Folders collapse; binaries/libraries can be
// added as child targets, and unpack-registered (hidden) children revealed into the graph —
// per file or, for a whole directory, in one click.
export default function FilesystemBrowser({ projectId, targetId, onChanged }: {
  projectId: string; targetId: string; onChanged?: () => void;
}) {
  const [fs, setFs] = useState<{ unpacked: boolean; method?: string; files: FsEntry[] } | null>(null);
  const [busy, setBusy] = useState("");
  const [view, setView] = useState<{ rel: string; loading: boolean; size?: number; encoding?: "text" | "binary"; content?: string; truncated?: boolean; err?: string } | null>(null);

  const load = () => api.filesystem(targetId).then(setFs).catch(() => setFs(null));
  useEffect(() => { load(); }, [targetId]);

  const add = async (rel: string) => {
    setBusy(rel);
    try { await api.promoteFile(projectId, targetId, rel); await load(); onChanged?.(); }
    catch (e: any) { alert(String(e.message || e)); }
    finally { setBusy(""); }
  };

  // Reveal a single hidden child (the ELF unpack already registered) into the graph.
  const reveal = async (e: FsEntry) => {
    if (!e.child_target_id) return;
    setBusy(e.rel);
    try { await api.setTargetVisible(projectId, e.child_target_id, true); await load(); onChanged?.(); }
    catch (err: any) { alert(String(err.message || err)); }
    finally { setBusy(""); }
  };

  // Reveal every hidden child under a directory prefix in one call.
  const revealDir = async (prefix: string) => {
    setBusy("dir:" + prefix);
    try {
      const r = await api.revealDir(projectId, targetId, prefix);
      if (r.revealed === 0) alert("No hidden binaries to reveal under " + (prefix || "/"));
      await load(); onChanged?.();
    } catch (e: any) { alert(String(e.message || e)); }
    finally { setBusy(""); }
  };

  const open = async (rel: string) => {
    setView({ rel, loading: true });
    try {
      const r = await api.readFile(targetId, rel);
      setView({ rel, loading: false, size: r.size, encoding: r.encoding, content: r.content, truncated: r.truncated });
    } catch (e: any) { setView({ rel, loading: false, err: String(e.message || e) }); }
  };

  if (!fs) return null;
  if (!fs.unpacked) {
    return <><div className="sec">Filesystem</div><div className="muted" style={{ fontSize: 11 }}>Not unpacked yet — run recon/unpack on this firmware.</div></>;
  }
  const tree = buildTree(fs.files);
  // Does this directory hold any hidden ELF child worth a "Reveal all"? (`""` = whole tree.)
  const dirHasHidden = (path: string) => leavesUnder(fs.files, path).some(isHidden);

  const Row = ({ node, depth }: { node: TreeNode; depth: number }) => {
    const kids = Object.values(node.children).sort((a, b) => Number(b.dir) - Number(a.dir) || a.name.localeCompare(b.name));
    if (node.dir && node.name) {
      const showRevealAll = dirHasHidden(node.path);
      return (
        <details open={depth < 1}>
          <summary style={{ paddingLeft: depth * 12, cursor: "pointer", fontSize: 12.5, display: "flex", alignItems: "center", gap: 6 }}>
            <Icon name="chip" size={12} /> <span>{node.name}</span>
            {showRevealAll && (
              <button className="btn sm ghost" style={{ marginLeft: "auto" }} title={`Reveal all binaries under ${node.path}/`}
                      disabled={busy === "dir:" + node.path}
                      onClick={(e) => { e.preventDefault(); e.stopPropagation(); revealDir(node.path); }}>
                {busy === "dir:" + node.path ? "…" : <><Icon name="eye" size={10} /> reveal all</>}
              </button>
            )}
          </summary>
          {kids.map((k) => <Row key={k.path} node={k} depth={depth + 1} />)}
        </details>
      );
    }
    if (node.dir) return <>{kids.map((k) => <Row key={k.path} node={k} depth={depth} />)}</>;
    const e = node.entry!;
    return (
      <div className="fsfile" style={{ paddingLeft: depth * 12 + 16 }}>
        <Icon name={e.is_elf ? "binary" : "doc"} size={12} />
        <span className="fname" style={{ cursor: "pointer" }} title="View file contents" onClick={() => open(e.rel)}>{node.name}</span>
        <span className="muted sz">{fmtSize(e.size)}</span>
        <button className="btn sm icon ghost" title="View file contents" onClick={() => open(e.rel)}>
          <Icon name="search" size={11} />
        </button>
        {isHidden(e) ? (
          // unpack registered this ELF but kept it hidden — reveal it into the graph.
          <button className="btn sm" disabled={busy === e.rel} title="Reveal this binary in the graph + Targets pane" onClick={() => reveal(e)}>
            {busy === e.rel ? "…" : <><Icon name="eye" size={10} /> reveal</>}
          </button>
        ) : e.added ? <span className="tag" style={{ color: "var(--accent)" }}>added</span>
          : looksAddable(e) ? (
            <button className="btn sm" disabled={busy === e.rel} onClick={() => add(e.rel)}>
              {busy === e.rel ? "…" : <><Icon name="plus" size={10} /> add</>}
            </button>
          ) : null}
      </div>
    );
  };

  if (view) {
    return (
      <>
        <div className="sec" style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <button className="btn sm ghost" onClick={() => setView(null)}><Icon name="x" size={11} /> Back</button>
          <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{view.rel}</span>
        </div>
        {view.loading && <div className="muted" style={{ fontSize: 11 }}>loading…</div>}
        {view.err && <div className="err">{view.err}</div>}
        {!view.loading && !view.err && (
          <>
            <div className="muted" style={{ fontSize: 11, marginBottom: 6 }}>
              {fmtSize(view.size)}
              {view.encoding === "binary" && " · binary file (hex)"}
              {view.truncated && " · truncated"}
            </div>
            <pre className="codewrap" style={{ whiteSpace: "pre-wrap", maxHeight: 360, overflow: "auto", fontFamily: "var(--mono, monospace)", fontSize: 11 }}>{view.content}</pre>
          </>
        )}
      </>
    );
  }

  return (
    <>
      <div className="sec" style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <span>Filesystem <span className="muted">· {fs.method} · {fs.files.length} files</span></span>
        {dirHasHidden("") && (
          <button className="btn sm ghost" style={{ marginLeft: "auto" }} title="Reveal every hidden binary in this firmware"
                  disabled={busy === "dir:"} onClick={() => revealDir("")}>
            {busy === "dir:" ? "…" : <><Icon name="eye" size={10} /> reveal all</>}
          </button>
        )}
      </div>
      <div className="fsbrowser">
        {Object.values(tree.children).sort((a, b) => Number(b.dir) - Number(a.dir) || a.name.localeCompare(b.name))
          .map((k) => <Row key={k.path} node={k} depth={0} />)}
      </div>
    </>
  );
}
