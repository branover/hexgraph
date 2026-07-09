import { useState } from "react";
import { api } from "../api";
import { Icon } from "./Icon";

// Import an already-extracted/mounted filesystem DIRECTORY as a target — the secondary
// path alongside the file-upload "Add" button, for when there's no packed firmware blob
// to unpack, just a rootfs already on disk. A typed host path, not a file/folder picker:
// the server is loopback-only/self-hosted and reads directly off its own filesystem
// (same trust model as `hexgraph ingest <path>` / the target_ingest_dir MCP tool) — a
// browser file input can't hand back an absolute host path or upload an entire tree.
export default function ImportDirModal({ projectId, onClose, onDone }: {
  projectId: string; onClose: () => void; onDone: () => void;
}) {
  const [path, setPath] = useState("");
  const [name, setName] = useState("");
  const [recon, setRecon] = useState(true);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const doImport = async () => {
    if (!path.trim()) return;
    setBusy(true); setErr("");
    try {
      await api.addTargetDir(projectId, path.trim(), name.trim() || undefined, recon);
      onDone(); onClose();
    } catch (e: any) { setErr(String(e.message || e)); }
    finally { setBusy(false); }
  };

  return (
    <div className="modal-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="modal fade-in" style={{ width: 460 }}>
        <h3>
          <Icon name="chip" size={16} /> Import a directory
          <span style={{ flex: 1 }} />
          <button className="btn sm ghost icon" onClick={onClose}><Icon name="x" size={13} /></button>
        </h3>
        <p className="muted" style={{ fontSize: 11.5, marginTop: -4, marginBottom: 12 }}>
          Import an already-extracted or mounted filesystem (a rootfs) as a target, instead of
          uploading a packed firmware image. The path is read from the HexGraph server's own
          disk, so it must be reachable from wherever <code>hexgraph serve</code> is running.
        </p>
        {err && <div className="banner err" style={{ marginBottom: 10 }}>{err}</div>}
        <div className="field">
          <label>directory path</label>
          <input value={path} onChange={(e) => setPath(e.target.value)}
            placeholder="/path/to/mounted/rootfs" autoFocus
            onKeyDown={(e) => { if (e.key === "Enter" && path.trim() && !busy) doImport(); }} />
        </div>
        <div className="field">
          <label>name (optional)</label>
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="defaults from the path" />
        </div>
        <label className="switch" style={{ gap: 8, alignItems: "center", marginTop: 4 }}>
          <input type="checkbox" checked={recon} onChange={(e) => setRecon(e.target.checked)} />
          <span>Run recon on each ELF binary found (needs Docker). Leave this off to register
            the files only, without recon.</span>
        </label>
        <div className="foot">
          <button className="btn ghost" onClick={onClose}>Cancel</button>
          <button className="btn primary" onClick={doImport} disabled={busy || !path.trim()}>
            <Icon name="plus" size={12} /> {busy ? "importing…" : "Import"}
          </button>
        </div>
      </div>
    </div>
  );
}
