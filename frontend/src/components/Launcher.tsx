import { useEffect, useRef, useState } from "react";
import { Icon } from "./Icon";

// Compact "Run ▾" popover: pick a capability-filtered task type, which opens the
// deliberate LaunchModal (objective/model/budget + context preview).
export default function Launcher({ allowed, onChoose }: { allowed: string[]; onChoose: (type: string) => void }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const h = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false); };
    document.addEventListener("mousedown", h);
    return () => document.removeEventListener("mousedown", h);
  }, [open]);

  return (
    <div className="run" ref={ref} onClick={(e) => e.stopPropagation()} style={{ position: "relative" }}>
      <button className="btn sm primary" onClick={() => setOpen((o) => !o)}>
        <Icon name="run" size={12} /> Run <Icon name="chevron" size={12} />
      </button>
      {open && (
        <div className="menu">
          {allowed.map((t) => (
            <div key={t} className="mi" onClick={() => { setOpen(false); onChoose(t); }}>
              <Icon name="task" size={14} /> {t.replace(/_/g, " ")}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
