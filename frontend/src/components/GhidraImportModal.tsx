import { useEffect, useState } from "react";
import { api } from "../api";
import { Icon } from "./Icon";

// List programs open in a connected Ghidra (bridge) and import one as a target
// (its real on-disk bytes → recon). Shows clear guidance if the bridge is down.
export default function GhidraImportModal({ projectId, onClose, onDone }: {
  projectId: string; onClose: () => void; onDone: () => void;
}) {
  const [programs, setPrograms] = useState<any[] | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState("");

  const refresh = () => {
    setErr(""); setPrograms(null);
    api.ghidraPrograms().then(setPrograms).catch((e) => setErr(String(e.message || e)));
  };
  useEffect(refresh, []);

  const importOne = async (p: any) => {
    setBusy(p.path); setErr("");
    try { await api.ghidraImport(projectId, p.path, p.name); onDone(); onClose(); }
    catch (e: any) { setErr(String(e.message || e)); }
    finally { setBusy(""); }
  };

  return (
    <div className="modal-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="modal fade-in" style={{ width: 560, maxHeight: "82vh", display: "flex", flexDirection: "column" }}>
        <h3>
          <Icon name="bulb" size={16} /> Import from Ghidra
          <span style={{ flex: 1 }} />
          <button className="btn sm ghost" onClick={refresh}><Icon name="refresh" size={12} /> Refresh</button>
          <button className="btn sm ghost icon" onClick={onClose} style={{ marginLeft: 6 }}><Icon name="x" size={13} /></button>
        </h3>
        {err && <div className="banner err" style={{ marginBottom: 10 }}>{err}</div>}
        <div style={{ overflow: "auto" }}>
          {programs === null && !err && <div className="empty">Connecting to Ghidra Bridge…</div>}
          {programs && programs.length === 0 && <div className="empty">No programs are open in Ghidra.</div>}
          {programs?.map((p) => (
            <div key={p.path} className="res" style={{ justifyContent: "space-between" }}>
              <span>
                <Icon name="binary" size={13} /> <b>{p.name}</b>
                <span className="muted" style={{ fontSize: 11 }}> · {p.language} · {p.functions} fns</span>
                <div className="muted" style={{ fontSize: 10.5 }}>{p.path}</div>
              </span>
              <button className="btn sm primary" disabled={!!busy} onClick={() => importOne(p)}>
                {busy === p.path ? "importing…" : "Import"}
              </button>
            </div>
          ))}
        </div>
        <p className="muted" style={{ fontSize: 11, marginTop: 10 }}>
          Requires bridge mode (Settings → Ghidra) and <code>ghidra_bridge_server.py</code> running in Ghidra.
        </p>
      </div>
    </div>
  );
}
