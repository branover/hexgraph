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

// Traversable unpacked firmware filesystem. Folders collapse; binaries/libraries
// can be added as child targets on the spot.
export default function FilesystemBrowser({ projectId, targetId, onChanged }: {
  projectId: string; targetId: string; onChanged?: () => void;
}) {
  const [fs, setFs] = useState<{ unpacked: boolean; method?: string; files: FsEntry[] } | null>(null);
  const [busy, setBusy] = useState("");

  const load = () => api.filesystem(targetId).then(setFs).catch(() => setFs(null));
  useEffect(() => { load(); }, [targetId]);

  const add = async (rel: string) => {
    setBusy(rel);
    try { await api.addFromFs(projectId, targetId, rel); await load(); onChanged?.(); }
    catch (e: any) { alert(String(e.message || e)); }
    finally { setBusy(""); }
  };

  if (!fs) return null;
  if (!fs.unpacked) {
    return <><div className="sec">Filesystem</div><div className="muted" style={{ fontSize: 11 }}>Not unpacked yet — run recon/unpack on this firmware.</div></>;
  }
  const tree = buildTree(fs.files);

  const Row = ({ node, depth }: { node: TreeNode; depth: number }) => {
    const kids = Object.values(node.children).sort((a, b) => Number(b.dir) - Number(a.dir) || a.name.localeCompare(b.name));
    if (node.dir && node.name) {
      return (
        <details open={depth < 1}>
          <summary style={{ paddingLeft: depth * 12, cursor: "pointer", fontSize: 12.5 }}>
            <Icon name="chip" size={12} /> {node.name}
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
        <span className="fname">{node.name}</span>
        <span className="muted sz">{fmtSize(e.size)}</span>
        {e.added ? <span className="tag" style={{ color: "var(--accent)" }}>added</span>
          : looksAddable(e) ? (
            <button className="btn sm" disabled={busy === e.rel} onClick={() => add(e.rel)}>
              {busy === e.rel ? "…" : <><Icon name="plus" size={10} /> add</>}
            </button>
          ) : null}
      </div>
    );
  };

  return (
    <>
      <div className="sec">Filesystem <span className="muted">· {fs.method} · {fs.files.length} files</span></div>
      <div className="fsbrowser">
        {Object.values(tree.children).sort((a, b) => Number(b.dir) - Number(a.dir) || a.name.localeCompare(b.name))
          .map((k) => <Row key={k.path} node={k} depth={0} />)}
      </div>
    </>
  );
}
