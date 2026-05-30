import { useMemo, useState } from "react";
import { Finding, SEV_ORDER, TargetNode } from "../api";

// First-class finding management: sort by severity, filter by status/severity/text,
// group by target. Built to stay usable at hundreds+ of findings.
export default function FindingsPanel({
  findings, targets, selectedId, onSelect, onBulk,
}: {
  findings: Finding[]; targets: TargetNode[]; selectedId?: string; onSelect: (f: Finding) => void;
  onBulk?: (ids: string[], status: string) => void;
}) {
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("all");
  const [sev, setSev] = useState("all");
  const [group, setGroup] = useState(true);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const toggle = (id: string) => setPicked((p) => { const n = new Set(p); n.has(id) ? n.delete(id) : n.add(id); return n; });
  const bulk = (st: string) => { onBulk?.([...picked], st); setPicked(new Set()); };
  const targetName = (id: string) => targets.find((t) => t.id === id)?.name ?? id.slice(0, 8);

  const filtered = useMemo(() => {
    let fs = findings.slice();
    if (status !== "all") fs = fs.filter((f) => f.status === status);
    if (sev !== "all") fs = fs.filter((f) => f.severity === sev);
    if (q) fs = fs.filter((f) => (f.title + f.category).toLowerCase().includes(q.toLowerCase()));
    fs.sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));
    return fs;
  }, [findings, status, sev, q]);

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    findings.forEach((f) => (c[f.severity] = (c[f.severity] || 0) + 1));
    return c;
  }, [findings]);

  const groups = useMemo(() => {
    if (!group) return [["", filtered]] as [string, Finding[]][];
    const m = new Map<string, Finding[]>();
    filtered.forEach((f) => { const k = targetName(f.target_id); (m.get(k) ?? m.set(k, []).get(k)!).push(f); });
    return [...m.entries()];
  }, [filtered, group, targets]);

  const Card = (f: Finding) => (
    <div key={f.id} className={"finding" + (f.id === selectedId ? " sel" : "")} onClick={() => onSelect(f)}>
      {onBulk && (
        <input type="checkbox" checked={picked.has(f.id)} onClick={(e) => e.stopPropagation()}
               onChange={() => toggle(f.id)} style={{ marginRight: 6, verticalAlign: "middle" }} />
      )}
      <span className={"chip sev-" + f.severity}>{f.severity}</span>
      <span className="ttl">{f.title}</span>
      <div className="mt">{f.category} · {f.confidence} · {f.status} · {targetName(f.target_id)}</div>
    </div>
  );

  return (
    <>
      <div className="toolbar">
        <input placeholder="filter…" value={q} onChange={(e) => setQ(e.target.value)} style={{ flex: 1 }} />
        <select value={sev} onChange={(e) => setSev(e.target.value)}>
          <option value="all">sev: all</option>
          {SEV_ORDER.map((s) => <option key={s} value={s}>{s}{counts[s] ? ` (${counts[s]})` : ""}</option>)}
        </select>
        <select value={status} onChange={(e) => setStatus(e.target.value)}>
          {["all", "new", "triaging", "confirmed", "dismissed"].map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <button className="btn sm" onClick={() => setGroup(!group)}>{group ? "ungroup" : "group"}</button>
      </div>
      {onBulk && picked.size > 0 && (
        <div className="toolbar" style={{ borderTop: "1px solid var(--border)" }}>
          <span className="muted">{picked.size} selected</span>
          <span className="grow" />
          <button className="btn sm" onClick={() => bulk("confirmed")}>Accept</button>
          <button className="btn sm" onClick={() => bulk("dismissed")}>Dismiss</button>
        </div>
      )}
      <div className="scroll">
        {filtered.length === 0 && <div className="empty">No findings match.</div>}
        {groups.map(([g, fs]) => (
          <div key={g || "all"}>
            {group && g && <div className="group-h">{g} · {fs.length}</div>}
            {fs.map(Card)}
          </div>
        ))}
      </div>
    </>
  );
}
