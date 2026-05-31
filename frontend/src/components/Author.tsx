import { ReactNode, useEffect, useMemo, useState } from "react";
import { api, Graph, TargetNode } from "../api";
import { Icon } from "./Icon";

const MANUAL_NODE_TYPES = ["function", "symbol", "string", "struct", "hypothesis", "pattern", "input", "sink", "socket", "endpoint", "param"];
const TARGET_BOUND = new Set(["function", "symbol", "string", "struct", "endpoint", "param"]);
const SOCKET_KINDS = ["tcp", "udp", "unix", "io", "netlink", "raw", "other"];
const EDGE_TYPES = ["calls", "references", "reads", "writes", "taints", "bypasses", "routes_to",
  "listens_on", "connects_to", "links_against", "similar_to", "derived_from",
  "duplicate_of", "related_to", "instance_of_pattern", "about", "contains"];

// Module-level cache so the schema fetch happens once across modal opens.
type NodeSchemas = Record<string, { description: string; use_when: string; recommended_attributes: string[]; attributes: Record<string, any> }>;
type EdgeSchemas = Record<string, { description: string; attributes: Record<string, any> }>;
let _nodeSchemas: NodeSchemas | null = null;
let _edgeSchemas: EdgeSchemas | null = null;

function useNodeSchemas(): NodeSchemas | null {
  const [s, setS] = useState<NodeSchemas | null>(_nodeSchemas);
  useEffect(() => {
    if (_nodeSchemas) return;
    api.nodeSchemas().then((r) => { _nodeSchemas = r.nodes; setS(r.nodes); }).catch(() => {});
  }, []);
  return s;
}
function useEdgeSchemas(): EdgeSchemas | null {
  const [s, setS] = useState<EdgeSchemas | null>(_edgeSchemas);
  useEffect(() => {
    if (_edgeSchemas) return;
    api.edgeSchemas().then((r) => { _edgeSchemas = r.edges; setS(r.edges); }).catch(() => {});
  }, []);
  return s;
}

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
  const [sockKind, setSockKind] = useState("tcp");
  const [sockPort, setSockPort] = useState("");
  const [err, setErr] = useState<string>();
  const schemas = useNodeSchemas();
  const needsTarget = TARGET_BOUND.has(nodeType);
  const isSocket = nodeType === "socket";
  const help = schemas?.[nodeType];

  const submit = async () => {
    setErr(undefined);
    try {
      if (isSocket) {
        await api.createSocket(projectId, { kind: sockKind, port: sockPort || undefined, name: sockPort ? undefined : name });
      } else {
        await api.createNode(projectId, { node_type: nodeType, name, target_id: needsTarget ? targetId : undefined });
      }
      onDone(); onClose();
    } catch (e: any) { setErr(String(e.message || e)); }
  };

  return (
    <Modal title="Add node" icon="fn" onClose={onClose}>
      <div className="field">
        <label>type</label>
        <select className="sel" value={nodeType} onChange={(e) => setNodeType(e.target.value)}>
          {MANUAL_NODE_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        {help && (
          <div className="modal-help">
            {help.description}{help.use_when ? ` — ${help.use_when}` : ""}
          </div>
        )}
      </div>
      {isSocket ? (
        <>
          <div className="field"><label>kind</label>
            <select className="sel" value={sockKind} onChange={(e) => setSockKind(e.target.value)}>
              {SOCKET_KINDS.map((k) => <option key={k} value={k}>{k}</option>)}
            </select>
          </div>
          <div className="field"><label>port (tcp/udp)</label>
            <input value={sockPort} onChange={(e) => setSockPort(e.target.value)} placeholder="e.g. 8080" />
          </div>
          <div className="field"><label>name (unix path / id, if no port)</label>
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. /var/run/ctl.sock" />
          </div>
        </>
      ) : (
      <div className="field">
        <label>{nodeType === "hypothesis" ? "statement" : nodeType === "endpoint" ? "route" : "name"}</label>
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder={
          nodeType === "hypothesis" ? "e.g. auth can be bypassed via token reuse"
          : nodeType === "endpoint" ? "e.g. POST /api/login"
          : nodeType === "param" ? "e.g. token"
          : "e.g. parse_request"} />
        {help?.recommended_attributes?.length ? (
          <div className="modal-help muted">After creating, set recommended attributes: {help.recommended_attributes.join(", ")}.</div>
        ) : null}
      </div>
      )}
      {needsTarget && (
        <div className="field">
          <label>binary (required)</label>
          <select className="sel" value={targetId} onChange={(e) => setTargetId(e.target.value)}>
            {targets.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
          </select>
        </div>
      )}
      {err && <div className="err">{err}</div>}
      <div className="foot">
        <button className="btn ghost" onClick={onClose}>Cancel</button>
        <button className="btn primary" onClick={submit} disabled={isSocket ? !(sockPort.trim() || name.trim()) : (!name.trim() || (needsTarget && !targetId))}>Create</button>
      </div>
    </Modal>
  );
}

// Build a clear, grouped option list from the graph: targets first, then
// functions/symbols, then other nodes, then string nodes (de-emphasized), then findings.
type EdgeOpt = { kind: string; id: string; label: string };
function buildEdgeOpts(graph: Graph): { groups: { label: string; opts: EdgeOpt[] }[]; byId: Map<string, EdgeOpt> } {
  const targetName = new Map(graph.nodes.filter((n) => n.type === "target").map((n) => [n.id, n.label] as const));
  const groups: { label: string; key: (n: Graph["nodes"][number]) => boolean; opts: EdgeOpt[] }[] = [
    { label: "targets", key: (n) => n.type === "target", opts: [] },
    { label: "functions & symbols", key: (n) => n.type === "node" && (n.node_type === "function" || n.node_type === "symbol"), opts: [] },
    { label: "other nodes", key: (n) => n.type === "node" && n.node_type !== "function" && n.node_type !== "symbol" && n.node_type !== "string", opts: [] },
    { label: "findings", key: (n) => n.type === "finding", opts: [] },
    { label: "strings", key: (n) => n.type === "node" && n.node_type === "string", opts: [] },
  ];
  const byId = new Map<string, EdgeOpt>();
  for (const n of graph.nodes) {
    const ntype = n.type === "target" ? n.kind : n.type === "finding" ? "finding" : n.node_type;
    const owner = n.type === "node" && n.target_id ? targetName.get(n.target_id) : undefined;
    const label = `${n.label} · ${ntype}${owner ? ` · ${owner}` : ""}`;
    const opt: EdgeOpt = { kind: n.type, id: n.id, label };
    byId.set(n.id, opt);
    const g = groups.find((gr) => gr.key(n));
    if (g) g.opts.push(opt);
  }
  for (const g of groups) g.opts.sort((a, b) => a.label.localeCompare(b.label));
  return { groups: groups.filter((g) => g.opts.length).map((g) => ({ label: g.label, opts: g.opts })), byId };
}

export function AddEdgeModal({ projectId, graph, prefillSrc, prefillDst, onClose, onDone }: {
  projectId: string; graph: Graph; prefillSrc?: string; prefillDst?: string; onClose: () => void; onDone: () => void;
}) {
  const { groups, byId } = useMemo(() => buildEdgeOpts(graph), [graph]);
  const flat = useMemo(() => groups.flatMap((g) => g.opts), [groups]);
  const [src, setSrc] = useState(prefillSrc ?? flat[0]?.id ?? "");
  const [dst, setDst] = useState(prefillDst ?? flat[1]?.id ?? "");
  const [type, setType] = useState("references");
  const [attrsText, setAttrsText] = useState("");
  const [err, setErr] = useState<string>();
  const schemas = useEdgeSchemas();
  const help = schemas?.[type];

  const renderGroups = () => groups.map((g) => (
    <optgroup key={g.label} label={g.label}>
      {g.opts.map((o) => <option key={o.id} value={o.id}>{o.label}</option>)}
    </optgroup>
  ));

  const submit = async () => {
    setErr(undefined);
    const s = byId.get(src), d = byId.get(dst);
    if (!s || !d) { setErr("pick both endpoints"); return; }
    let attrs: any = undefined;
    if (attrsText.trim()) {
      try { attrs = JSON.parse(attrsText); } catch { setErr("attributes must be valid JSON"); return; }
    }
    try {
      await api.createEdge(projectId, { src_kind: s.kind, src_id: s.id, dst_kind: d.kind, dst_id: d.id, type, attrs, merge: true });
      onDone(); onClose();
    } catch (e: any) { setErr(String(e.message || e)); }
  };

  const attrHint = help ? Object.keys(help.attributes || {}) : [];

  return (
    <Modal title="Add edge" icon="link" onClose={onClose}>
      <div className="field"><label>from</label>
        <select className="sel" value={src} onChange={(e) => setSrc(e.target.value)}>{renderGroups()}</select>
      </div>
      <div className="field"><label>type</label>
        <select className="sel" value={type} onChange={(e) => setType(e.target.value)}>{EDGE_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}</select>
        {help && (
          <div className="modal-help">
            {help.description}
            {attrHint.length ? <span className="muted"> · attributes: {attrHint.join(", ")}</span> : null}
          </div>
        )}
      </div>
      <div className="field"><label>to</label>
        <select className="sel" value={dst} onChange={(e) => setDst(e.target.value)}>{renderGroups()}</select>
      </div>
      <div className="field"><label>attributes (optional JSON)</label>
        <input value={attrsText} onChange={(e) => setAttrsText(e.target.value)} placeholder='e.g. {"address":"0x401200","port":8080}' />
      </div>
      {err && <div className="err">{err}</div>}
      <div className="foot">
        <button className="btn ghost" onClick={onClose}>Cancel</button>
        <button className="btn primary" onClick={submit}>Create</button>
      </div>
    </Modal>
  );
}
