import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Icon } from "./Icon";
import { taskMeta } from "../taskMeta";

// Compact "Run ▾" popover: pick a capability-filtered task type, which opens the
// deliberate LaunchModal. Each row carries a one-line description; hovering a row reveals
// a richer popover explaining exactly what that task does (taskMeta.ts). The menu renders
// in a portal at fixed coordinates so it is never clipped by a pane's overflow (it can sit
// in the cramped inspector box).
//
// `fuzzing` is filtered out of the Run menu on purpose — fuzzing now goes through the
// dedicated Fuzz campaign button/modal. When the caller passes `onFuzz`, the menu shows a
// single guided "Fuzz campaign…" row that routes there, so the menu still advertises the
// capability without the confusing duplicate single-shot task.
export default function Launcher({ allowed, onChoose, onFuzz }: {
  allowed: string[];
  onChoose: (type: string) => void;
  onFuzz?: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);
  const [hover, setHover] = useState<string | null>(null);
  const [hoverTop, setHoverTop] = useState(0);
  const btnRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);

  const MENU_W = 248;
  const place = () => {
    const b = btnRef.current?.getBoundingClientRect();
    if (!b) return;
    setPos({ top: b.bottom + 4, left: Math.max(8, Math.min(b.left, window.innerWidth - MENU_W - 8)) });
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

  // Drop the legacy single-shot `fuzzing` task from the menu — the Fuzz button owns that.
  const items = allowed.filter((t) => t !== "fuzzing");

  const choose = (type: string) => { setOpen(false); setHover(null); onChoose(type); };
  const fuzz = () => { setOpen(false); setHover(null); onFuzz?.(); };

  // The hover popover: a richer explanation for the row under the cursor, pinned to the
  // menu's right edge (it flips left if there's no room).
  const hovered = hover ? taskMeta(hover) : null;
  const popoverLeft = pos ? (pos.left + MENU_W + 8 + 280 > window.innerWidth ? pos.left - 288 : pos.left + MENU_W + 8) : 0;

  return (
    <div className="run" onClick={(e) => e.stopPropagation()} style={{ position: "relative" }}>
      <button ref={btnRef} className="btn sm primary" onClick={() => setOpen((o) => !o)}>
        <Icon name="run" size={12} /> Run <Icon name="chevron" size={12} />
      </button>
      {open && pos && createPortal(
        <>
          <div ref={menuRef} className="menu portal task-menu" style={{ top: pos.top, left: pos.left, width: MENU_W }}
               onClick={(e) => e.stopPropagation()} onMouseLeave={() => setHover(null)}>
            {items.length === 0 && !onFuzz && (
              <div className="mi muted" style={{ cursor: "default", fontSize: 11.5 }}>No tasks for this target kind</div>
            )}
            {items.map((t) => {
              const m = taskMeta(t);
              return (
                <div key={t} className="mi task-mi" onClick={() => choose(t)}
                     onMouseEnter={(e) => { setHover(t); setHoverTop((e.currentTarget as HTMLElement).getBoundingClientRect().top); }}>
                  <Icon name={m.icon} size={15} />
                  <div className="task-mi-text">
                    <div className="task-mi-label">{m.label}</div>
                    {m.summary && <div className="task-mi-sum">{m.summary}</div>}
                  </div>
                </div>
              );
            })}
            {onFuzz && (
              <div className="mi task-mi" onClick={fuzz}
                   onMouseEnter={(e) => { setHover(null); setHoverTop((e.currentTarget as HTMLElement).getBoundingClientRect().top); }}>
                <Icon name="bug" size={15} />
                <div className="task-mi-text">
                  <div className="task-mi-label">Fuzz campaign…</div>
                  <div className="task-mi-sum">Run a detached, reapable fuzz campaign</div>
                </div>
              </div>
            )}
          </div>
          {hovered && hovered.detail && (
            <div className="task-pop" style={{ top: Math.max(8, hoverTop), left: popoverLeft, width: 280 }}>
              <div className="task-pop-h"><Icon name={hovered.icon} size={13} /> {hovered.label}</div>
              <div className="task-pop-b">{hovered.detail}</div>
            </div>
          )}
        </>,
        document.body,
      )}
    </div>
  );
}
