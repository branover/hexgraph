import { ReactNode, useState } from "react";
import { api, Graph, TargetNode } from "../api";
import { Icon } from "./Icon";

const MANUAL_NODE_TYPES = ["function", "symbol", "string", "struct", "hypothesis", "pattern"];
const TARGET_BOUND = new Set(["function", "symbol", "string", "struct"]);
const EDGE_TYPES = ["calls", "references", "reads", "writes", "links_against", "similar_to",
  "duplicate_of", "related_to", "instance_of_pattern", "contains"];

function Modal({ title, icon, onClose, children }: { title: string; icon: string; onClose: () => void; children: ReactNode }) {
  return (
    <div className="modal-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="modal fade-in">
        <h3><Icon name={icon} size={17} /> {title}</h3>
        {children}
      </div>
    </div>
  );
}

export function AddNodeModal({ projectId, targets, onClose, onDone }: {
  projectId: string; targets: TargetNode[]; onClose: () => void; onDone: () => void;
}) {
  const [nodeType, setNodeType] = useState("function");
  const [name, setName] = useState("");
  const [targetId, setTargetId] = useState(targets[0]?.id ?? "");
  const [err, setErr] = useState<string>();
  const needsTarget = TARGET_BOUND.has(nodeType);

  const submit = async () => {
    setErr(undefined);
    try {
      await api.createNode(projectId, { node_type: nodeType, name, target_id: needsTarget ? targetId : undefined });
      onDone(); onClose();
    } catch (e: any) { setErr(String(e.message || e)); }
  };

  return (
    <Modal title="Add node" icon="fn" onClose={onClose}>
      <div className="field">
        <label>type</label>
        <select value={nodeType} onChange={(e) => setNodeType(e.target.value)}>
          {MANUAL_NODE_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
      </div>
      <div className="field">
        <label>{nodeType === "hypothesis" ? "statement" : "name"}</label>
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder={nodeType === "hypothesis" ? "e.g. auth can be bypassed via token reuse" : "e.g. parse_request"} />
      </div>
      {needsTarget && (
        <div className="field">
          <label>binary (required)</label>
          <select value={targetId} onChange={(e) => setTargetId(e.target.value)}>
            {targets.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
          </select>
        </div>
      )}
      {err && <div className="err">{err}</div>}
      <div className="foot">
        <button className="btn ghost" onClick={onClose}>Cancel</button>
        <button className="btn primary" onClick={submit} disabled={!name.trim() || (needsTarget && !targetId)}>Create</button>
      </div>
    </Modal>
  );
}

export function AddEdgeModal({ projectId, graph, onClose, onDone }: {
  projectId: string; graph: Graph; onClose: () => void; onDone: () => void;
}) {
  const opts = graph.nodes.map((n) => ({ kind: n.type, id: n.id, label: `${n.label} · ${n.type}` }));
  const [src, setSrc] = useState(opts[0]?.id ?? "");
  const [dst, setDst] = useState(opts[1]?.id ?? "");
  const [type, setType] = useState("references");
  const [err, setErr] = useState<string>();
  const find = (id: string) => opts.find((o) => o.id === id);

  const submit = async () => {
    setErr(undefined);
    const s = find(src), d = find(dst);
    if (!s || !d) { setErr("pick both endpoints"); return; }
    try {
      await api.createEdge(projectId, { src_kind: s.kind, src_id: s.id, dst_kind: d.kind, dst_id: d.id, type });
      onDone(); onClose();
    } catch (e: any) { setErr(String(e.message || e)); }
  };

  return (
    <Modal title="Add edge" icon="link" onClose={onClose}>
      <div className="field"><label>from</label>
        <select value={src} onChange={(e) => setSrc(e.target.value)}>{opts.map((o) => <option key={o.id} value={o.id}>{o.label}</option>)}</select>
      </div>
      <div className="field"><label>type</label>
        <select value={type} onChange={(e) => setType(e.target.value)}>{EDGE_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}</select>
      </div>
      <div className="field"><label>to</label>
        <select value={dst} onChange={(e) => setDst(e.target.value)}>{opts.map((o) => <option key={o.id} value={o.id}>{o.label}</option>)}</select>
      </div>
      {err && <div className="err">{err}</div>}
      <div className="foot">
        <button className="btn ghost" onClick={onClose}>Cancel</button>
        <button className="btn primary" onClick={submit}>Create</button>
      </div>
    </Modal>
  );
}
