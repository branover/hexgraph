import { useEffect, useMemo, useRef, useState } from "react";
import { Finding, SEV_ORDER, TargetNode } from "../api";
import { Icon } from "./Icon";

const SEV_VAR: Record<string, string> = {
  info: "var(--info)", low: "var(--low)", medium: "var(--medium)", high: "var(--high)", critical: "var(--critical)",
};

// First-class finding management: sort by severity, filter by status/severity/text,
// group by target. Built to stay usable at hundreds+ of findings.
export default function FindingsPanel({
  findings, hiddenFindings, targets, selectedId, onSelect, onBulk,
}: {
  findings: Finding[]; hiddenFindings?: Finding[]; targets: TargetNode[]; selectedId?: string;
  onSelect: (f: Finding) => void;
  onBulk?: (ids: string[], status: string) => void;
}) {
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("all");
  const [sev, setSev] = useState("all");
  const [tagF, setTagF] = useState("all");
  const [typeF, setTypeF] = useState("all");
  const [group, setGroup] = useState(true);
  const [showHidden, setShowHidden] = useState(false);
  // Findings on hidden firmware children (target not in the Targets pane). Off by default;
  // the toggle folds them in, badged, so the count matches what's actually in the project.
  const hidden = hiddenFindings ?? [];
  const hiddenIds = useMemo(() => new Set((hiddenFindings ?? []).map((f) => f.target_id)), [hiddenFindings]);
  const shown = useMemo(() => (showHidden && hiddenFindings?.length ? findings.concat(hiddenFindings) : findings),
                        [findings, hiddenFindings, showHidden]);
  const allTags = useMemo(() => Array.from(new Set(shown.flatMap((f) => f.tags || []))).sort(), [shown]);
  const allTypes = useMemo(() => Array.from(new Set(shown.map((f) => f.finding_type).filter(Boolean) as string[])).sort(), [shown]);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const toggle = (id: string) => setPicked((p) => { const n = new Set(p); n.has(id) ? n.delete(id) : n.add(id); return n; });
  const bulk = (st: string) => { onBulk?.([...picked], st); setPicked(new Set()); };
  const targetName = (id: string) => targets.find((t) => t.id === id)?.name ?? id.slice(0, 8);
  const selRef = useRef<HTMLDivElement>(null);
  useEffect(() => { selRef.current?.scrollIntoView({ block: "nearest", behavior: "smooth" }); }, [selectedId]);

  const filtered = useMemo(() => {
    let fs = shown.slice();
    if (status !== "all") fs = fs.filter((f) => f.status === status);
    if (sev !== "all") fs = fs.filter((f) => f.severity === sev);
    if (tagF !== "all") fs = fs.filter((f) => (f.tags || []).includes(tagF));
    if (typeF !== "all") fs = fs.filter((f) => (f.finding_type || "vulnerability") === typeF);
    if (q) fs = fs.filter((f) => (f.title + f.category + (f.tags || []).join(" ")).toLowerCase().includes(q.toLowerCase()));
    fs.sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));
    return fs;
  }, [shown, status, sev, tagF, typeF, q]);

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    shown.forEach((f) => (c[f.severity] = (c[f.severity] || 0) + 1));
    return c;
  }, [shown]);

  const groups = useMemo(() => {
    if (!group) return [["", filtered]] as [string, Finding[]][];
    const m = new Map<string, Finding[]>();
    filtered.forEach((f) => { const k = targetName(f.target_id); (m.get(k) ?? m.set(k, []).get(k)!).push(f); });
    return [...m.entries()];
  }, [filtered, group, targets]);

  const Card = (f: Finding) => (
    <div key={f.id} ref={f.id === selectedId ? selRef : undefined}
         className={"finding fade-in" + (f.id === selectedId ? " sel" : "")} onClick={() => onSelect(f)}
         style={{ ["--sev" as any]: SEV_VAR[f.severity] }}>
      <div className="rail" />
      <div className="body">
        <div className="row1">
          {onBulk && (
            <input type="checkbox" checked={picked.has(f.id)} onClick={(e) => e.stopPropagation()}
                   onChange={() => toggle(f.id)} />
          )}
          <span className={"chip sev-" + f.severity}><span className="d" />{f.severity}</span>
          <span className="ttl">{f.title}</span>
        </div>
        <div className="mt">
          {f.finding_type && f.finding_type !== "vulnerability" && (
            <span className="tag" style={{ textTransform: "none" }}>{f.finding_type.replace(/_/g, " ")}</span>
          )}
          {f.verified && <span className="tag" style={{ color: "#2ea043" }}>✓ verified</span>}
          <span>{f.category}</span><span>· conf {f.confidence}</span>
          <span className="tag">{f.status}</span>
          {hiddenIds.has(f.target_id) && (
            <span className="tag" title="Recorded on a hidden firmware child — reveal that target in the Targets pane to manage it there"
                  style={{ color: "var(--muted)" }}><Icon name="eye" size={10} /> hidden target</span>
          )}
          {!group && <span>· {targetName(f.target_id)}</span>}
          {(f.tags || []).map((tg) => <span key={tg} className="tag" style={{ color: "var(--accent)" }}>#{tg}</span>)}
        </div>
      </div>
    </div>
  );

  return (
    <>
      <div className="fbar">
        <div className="input" style={{ flex: 1 }}>
          <Icon name="search" size={13} />
          <input placeholder="filter findings…" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <select className="sel" value={sev} onChange={(e) => setSev(e.target.value)}>
          <option value="all">sev</option>
          {SEV_ORDER.map((s) => <option key={s} value={s}>{s}{counts[s] ? ` (${counts[s]})` : ""}</option>)}
        </select>
        <select className="sel" value={status} onChange={(e) => setStatus(e.target.value)}>
          {["all", "new", "triaging", "confirmed", "dismissed", "reported"].map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        {allTypes.length > 1 && (
          <select className="sel" value={typeF} onChange={(e) => setTypeF(e.target.value)} title="filter by finding type">
            <option value="all">type</option>
            {allTypes.map((tp) => <option key={tp} value={tp}>{tp.replace(/_/g, " ")}</option>)}
          </select>
        )}
        {allTags.length > 0 && (
          <select className="sel" value={tagF} onChange={(e) => setTagF(e.target.value)} title="filter by tag">
            <option value="all">tag</option>
            {allTags.map((tg) => <option key={tg} value={tg}>#{tg}</option>)}
          </select>
        )}
        <button className="btn sm" onClick={() => setGroup(!group)}>{group ? "ungroup" : "group"}</button>
        {hidden.length > 0 && (
          <button className={"btn sm" + (showHidden ? " primary" : "")}
                  title="Show findings recorded on hidden firmware children (unrevealed ELF targets, not in the Targets pane). Reveal a target there to manage its findings normally."
                  onClick={() => setShowHidden((v) => !v)}>
            <Icon name="eye" size={12} /> {showHidden ? `${hidden.length} hidden shown` : `+${hidden.length} on hidden`}
          </button>
        )}
      </div>
      <div className="sevsummary">
        {SEV_ORDER.filter((s) => counts[s]).map((s) => (
          <span key={s} className={"chip sev-" + s}><span className="d" />{counts[s]}</span>
        ))}
      </div>
      {onBulk && picked.size > 0 && (
        <div className="fbar" style={{ borderTop: "1px solid var(--border)" }}>
          <span className="muted">{picked.size} selected</span>
          <span className="grow" />
          <button className="btn sm" onClick={() => bulk("confirmed")}><Icon name="check" size={12} /> Confirm</button>
          <button className="btn sm danger" onClick={() => bulk("dismissed")}><Icon name="x" size={12} /> Dismiss</button>
        </div>
      )}
      <div className="scroll">
        {filtered.length === 0 && <div className="empty">No findings match.</div>}
        {groups.map(([g, fs]) => (
          <div key={g || "all"}>
            {group && g && <div className="group-h"><Icon name="binary" size={12} />{g} · {fs.length}<span className="ln" /></div>}
            {fs.map(Card)}
          </div>
        ))}
      </div>
    </>
  );
}
