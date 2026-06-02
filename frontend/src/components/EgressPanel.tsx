import { useEffect, useState } from "react";
import { EgressEvent, api } from "../api";
import { Icon } from "./Icon";

// The egress audit log (docs/design-dynamic-surfaces.md): every outbound action against a
// live target/service when the bounded-network/remote tier is in use — boofuzz sends, HTTP
// probes, remote-fuzz launches — recorded ALLOWED or DENIED. Mandatory once egress is on:
// nothing reaches the network without an EgressEvent. Read-only inspection; the operator
// can see exactly what HexGraph contacted (and what it refused) and why.
export default function EgressPanel({ projectId, onClose }: {
  projectId: string; onClose: () => void;
}) {
  const [events, setEvents] = useState<EgressEvent[] | null>(null);
  const [err, setErr] = useState<string>();
  const load = () => api.egress(projectId).then((r) => setEvents(r.events)).catch((e) => setErr(String(e.message || e)));
  useEffect(() => { load(); /* eslint-disable-next-line */ }, [projectId]);

  const allowed = (events || []).filter((e) => e.allowed).length;
  const denied = (events || []).filter((e) => !e.allowed).length;

  return (
    <div className="modal-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="modal" style={{ maxWidth: 760, width: "92%" }} onClick={(e) => e.stopPropagation()}>
        <h3>
          <Icon name="shield" size={16} /> Egress audit log
          <span className="muted" style={{ fontWeight: 400, fontSize: 12 }}> · every outbound action against a live target</span>
          <span style={{ flex: 1 }} />
          <button className="btn sm ghost icon" title="Refresh" onClick={load}><Icon name="refresh" size={13} /></button>
          <button className="btn sm ghost icon" onClick={onClose}><Icon name="x" size={13} /></button>
        </h3>
        <div className="modal-b" style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          <div className="muted" style={{ fontSize: 11.5 }}>
            When the bounded local-network / remote tier is enabled, every send is audited here
            (loopback/private only; public hosts are refused). An empty log means nothing has
            reached the network — the default <code>--network none</code> posture.
          </div>
          {events && events.length > 0 && (
            <div style={{ display: "flex", gap: 10, fontSize: 11.5 }}>
              <span className="tag" style={{ color: "#2ea043", borderColor: "#2ea043" }}>{allowed} allowed</span>
              {denied > 0 && <span className="tag" style={{ color: "#ff5d6c", borderColor: "#ff5d6c" }}>{denied} denied</span>}
            </div>
          )}
          {err && <div className="err" style={{ fontSize: 11.5 }}>{err}</div>}
          {events === null && !err && <div className="muted" style={{ fontSize: 12 }}>loading…</div>}
          {events && events.length === 0 && (
            <div className="empty" style={{ padding: 16, fontSize: 12 }}>
              No egress events. Nothing has contacted the network for this project.
            </div>
          )}
          {events && events.length > 0 && (
            <div style={{ maxHeight: 460, overflow: "auto", border: "1px solid var(--border)", borderRadius: 6 }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11.5 }}>
                <thead>
                  <tr style={{ textAlign: "left", color: "var(--muted)", position: "sticky", top: 0, background: "var(--surface)" }}>
                    <th style={{ padding: "6px 8px" }}>when</th>
                    <th style={{ padding: "6px 8px" }}>verdict</th>
                    <th style={{ padding: "6px 8px" }}>destination</th>
                    <th style={{ padding: "6px 8px" }}>tool</th>
                    <th style={{ padding: "6px 8px" }}>detail</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((e) => (
                    <tr key={e.id} style={{ borderTop: "1px solid var(--border)" }}>
                      <td style={{ padding: "5px 8px", whiteSpace: "nowrap", color: "var(--muted)" }}>
                        {e.created_at ? new Date(e.created_at).toLocaleString() : "—"}
                      </td>
                      <td style={{ padding: "5px 8px" }}>
                        <span className="tag" style={{ color: e.allowed ? "#2ea043" : "#ff5d6c", borderColor: e.allowed ? "#2ea043" : "#ff5d6c" }}>
                          {e.allowed ? "allowed" : "denied"}
                        </span>
                      </td>
                      <td style={{ padding: "5px 8px", fontFamily: "var(--mono, monospace)" }}>{e.dest}</td>
                      <td style={{ padding: "5px 8px" }}>{e.tool || "—"}</td>
                      <td style={{ padding: "5px 8px", color: "var(--muted)" }}>{e.detail || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
