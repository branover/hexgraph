import { useEffect, useState } from "react";
import { api } from "../api";
import { Icon } from "./Icon";

// Notes / tags / renames on a graph entity (target | node | finding), with
// confirm/reject for agent-proposed ones. `allowRename` only for function nodes.
export default function Annotations({ projectId, nodeKind, nodeId, allowRename, onChanged }: {
  projectId: string; nodeKind: string; nodeId: string; allowRename?: boolean; onChanged?: () => void;
}) {
  const [list, setList] = useState<any[]>([]);
  const [kind, setKind] = useState(allowRename ? "rename" : "note");
  const [value, setValue] = useState("");

  const reload = () => api.annotations(nodeKind, nodeId).then(setList).catch(() => setList([]));
  useEffect(() => { setValue(""); reload(); }, [nodeKind, nodeId]);

  const add = async () => {
    if (!value.trim()) return;
    await api.createAnnotation(projectId, { node_kind: nodeKind, node_id: nodeId, kind, value });
    setValue(""); await reload(); onChanged?.();
  };
  const setStatus = async (id: string, status: string) => { await api.setAnnotationStatus(id, status); await reload(); onChanged?.(); };
  const kinds = allowRename ? ["rename", "note", "tag"] : ["note", "tag"];

  return (
    <>
      <div className="sec">Annotations</div>
      {list.length > 0 && (
        <div style={{ display: "flex", flexDirection: "column", gap: 5, marginBottom: 8 }}>
          {list.map((a) => (
            <div key={a.id} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12 }}>
              <span className="tag">{a.kind}</span>
              <span style={{ color: a.status === "rejected" ? "var(--muted)" : "var(--fg)", textDecoration: a.status === "rejected" ? "line-through" : "none" }}>{a.value}</span>
              {a.status === "proposed" && (
                <>
                  <span className="grow" />
                  <button className="btn sm icon" title="Confirm" onClick={() => setStatus(a.id, "confirmed")}><Icon name="check" size={11} /></button>
                  <button className="btn sm icon" title="Reject" onClick={() => setStatus(a.id, "rejected")}><Icon name="x" size={11} /></button>
                </>
              )}
              {a.status === "proposed" && <span className="muted" style={{ fontSize: 10 }}>proposed</span>}
            </div>
          ))}
        </div>
      )}
      <div style={{ display: "flex", gap: 6 }}>
        <select className="sel" value={kind} onChange={(e) => setKind(e.target.value)}>
          {kinds.map((k) => <option key={k} value={k}>{k}</option>)}
        </select>
        <div className="input" style={{ flex: 1 }}>
          <input value={value} onChange={(e) => setValue(e.target.value)} onKeyDown={(e) => e.key === "Enter" && add()}
                 placeholder={kind === "rename" ? "new name" : kind === "tag" ? "tag" : "note"} />
        </div>
        <button className="btn sm" onClick={add} disabled={!value.trim()}><Icon name="plus" size={12} /></button>
      </div>
    </>
  );
}
