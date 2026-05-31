import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Icon } from "./Icon";

// Compact "Run ▾" popover: pick a capability-filtered task type, which opens the
// deliberate LaunchModal. The menu renders in a portal at fixed coordinates so it
// is never clipped by a pane's overflow (it can sit in the cramped inspector box).
export default function Launcher({ allowed, onChoose }: { allowed: string[]; onChoose: (type: string) => void }) {
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);
  const btnRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);

  const place = () => {
    const b = btnRef.current?.getBoundingClientRect();
    if (!b) return;
    const width = 200;
    setPos({ top: b.bottom + 4, left: Math.max(8, Math.min(b.left, window.innerWidth - width - 8)) });
  };

  useLayoutEffect(() => { if (open) place(); }, [open]);
  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent) => {
      if (btnRef.current?.contains(e.target as Node)) return;
      if (menuRef.current?.contains(e.target as Node)) return;
      setOpen(false);
    };
    const reposition = () => setOpen(false);
    document.addEventListener("mousedown", close);
    window.addEventListener("resize", reposition);
    window.addEventListener("scroll", reposition, true);
    return () => {
      document.removeEventListener("mousedown", close);
      window.removeEventListener("resize", reposition);
      window.removeEventListener("scroll", reposition, true);
    };
  }, [open]);

  return (
    <div className="run" onClick={(e) => e.stopPropagation()} style={{ position: "relative" }}>
      <button ref={btnRef} className="btn sm primary" onClick={() => setOpen((o) => !o)}>
        <Icon name="run" size={12} /> Run <Icon name="chevron" size={12} />
      </button>
      {open && pos && createPortal(
        <div ref={menuRef} className="menu portal" style={{ top: pos.top, left: pos.left, width: 200 }}
             onClick={(e) => e.stopPropagation()}>
          {allowed.map((t) => (
            <div key={t} className="mi" onClick={() => { setOpen(false); onChoose(t); }}>
              <Icon name="task" size={14} /> {t.replace(/_/g, " ")}
            </div>
          ))}
        </div>,
        document.body,
      )}
    </div>
  );
}
