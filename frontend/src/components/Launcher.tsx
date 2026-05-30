import { useEffect, useRef, useState } from "react";
import { Icon } from "./Icon";

const SCENARIOS = ["(default)", "critical_overflow", "no_findings", "malformed_then_valid", "error_rate_limit"];

// Compact "Run ▾" popover replacing the raw dual-select. Capability-filtered;
// the mock-scenario picker only appears for the mock backend.
export default function Launcher({ allowed, isMock, onLaunch }: {
  allowed: string[]; isMock: boolean; onLaunch: (type: string, scenario?: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [scenario, setScenario] = useState("(default)");
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const h = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false); };
    document.addEventListener("mousedown", h);
    return () => document.removeEventListener("mousedown", h);
  }, [open]);

  const launch = (type: string) => { onLaunch(type, scenario === "(default)" ? undefined : scenario); setOpen(false); };

  return (
    <div className="run" ref={ref} onClick={(e) => e.stopPropagation()} style={{ position: "relative" }}>
      <button className="btn sm primary" onClick={() => setOpen((o) => !o)}>
        <Icon name="run" size={12} /> Run <Icon name="chevron" size={12} />
      </button>
      {open && (
        <div className="menu">
          {isMock && (
            <div className="sub">
              <label className="muted" style={{ fontSize: 11 }}>mock scenario</label>
              <select className="sel" value={scenario} onChange={(e) => setScenario(e.target.value)}>
                {SCENARIOS.map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
          )}
          {allowed.map((t) => (
            <div key={t} className="mi" onClick={() => launch(t)}>
              <Icon name="task" size={14} /> {t.replace(/_/g, " ")}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
