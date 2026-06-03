import { useCallback, useEffect, useRef, useState } from "react";

// Persisted, draggable three-pane workspace layout. Sizes + collapsed state live in
// localStorage (no DB / settings migration) so the chosen geometry survives reloads.
// We deliberately hand-roll the splitter — a lightweight pointer-drag — rather than pull
// in a splitter dependency.

export interface WorkspaceLayout {
  /** left targets pane width, px (when not collapsed) */
  leftW: number;
  /** right findings/detail pane width, px (when not collapsed) */
  rightW: number;
  /** left pane collapsed to a thin edge */
  leftCollapsed: boolean;
  /** right pane collapsed to a thin edge */
  rightCollapsed: boolean;
  /** fraction (0..1) of the right pane given to the bottom DETAIL section */
  detailFrac: number;
}

const KEY = "hexgraph.ws.layout.v1";

// Sensible bounds so a drag can never produce an unusable pane.
export const LIMITS = {
  leftMin: 180,
  leftMax: 480,
  rightMin: 280,
  rightMax: 680,
  detailMin: 0.18,
  detailMax: 0.85,
} as const;

const DEFAULTS: WorkspaceLayout = {
  leftW: 268,
  rightW: 392,
  leftCollapsed: false,
  rightCollapsed: false,
  detailFrac: 0.46,
};

function clamp(v: number, lo: number, hi: number) {
  return Math.max(lo, Math.min(hi, v));
}

function sanitize(p: Partial<WorkspaceLayout>): WorkspaceLayout {
  return {
    leftW: clamp(Number(p.leftW) || DEFAULTS.leftW, LIMITS.leftMin, LIMITS.leftMax),
    rightW: clamp(Number(p.rightW) || DEFAULTS.rightW, LIMITS.rightMin, LIMITS.rightMax),
    leftCollapsed: Boolean(p.leftCollapsed),
    rightCollapsed: Boolean(p.rightCollapsed),
    detailFrac: clamp(Number(p.detailFrac) || DEFAULTS.detailFrac, LIMITS.detailMin, LIMITS.detailMax),
  };
}

function load(): WorkspaceLayout {
  try {
    const raw = localStorage.getItem(KEY);
    if (raw) return sanitize(JSON.parse(raw));
  } catch {
    /* ignore corrupt/unavailable storage */
  }
  return { ...DEFAULTS };
}

export function useWorkspaceLayout() {
  const [layout, setLayout] = useState<WorkspaceLayout>(load);

  // Persist whenever it changes (debounce-free; writes are tiny and infrequent).
  useEffect(() => {
    try {
      localStorage.setItem(KEY, JSON.stringify(layout));
    } catch {
      /* ignore */
    }
  }, [layout]);

  const update = useCallback((patch: Partial<WorkspaceLayout>) => {
    setLayout((cur) => sanitize({ ...cur, ...patch }));
  }, []);

  const toggleLeft = useCallback(() => setLayout((c) => ({ ...c, leftCollapsed: !c.leftCollapsed })), []);
  const toggleRight = useCallback(() => setLayout((c) => ({ ...c, rightCollapsed: !c.rightCollapsed })), []);

  return { layout, update, toggleLeft, toggleRight };
}

// A generic horizontal/vertical pointer-drag. onDelta receives the signed pixel delta
// from the drag origin; the caller resolves it into a new size against its start value.
// Returns an onPointerDown handler to attach to a grab handle.
export function useDrag(opts: {
  axis: "x" | "y";
  onStart?: () => void;
  onDelta: (delta: number) => void;
  onEnd?: () => void;
}) {
  const ref = useRef(opts);
  ref.current = opts;

  return useCallback((e: React.PointerEvent) => {
    e.preventDefault();
    const startX = e.clientX;
    const startY = e.clientY;
    const { axis } = ref.current;
    ref.current.onStart?.();
    // While dragging, kill text-selection + force the resize cursor globally so the
    // pointer doesn't flicker as it crosses other elements.
    const prevCursor = document.body.style.cursor;
    const prevSelect = document.body.style.userSelect;
    document.body.style.cursor = axis === "x" ? "col-resize" : "row-resize";
    document.body.style.userSelect = "none";

    const move = (ev: PointerEvent) => {
      const d = axis === "x" ? ev.clientX - startX : ev.clientY - startY;
      ref.current.onDelta(d);
    };
    const up = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
      document.body.style.cursor = prevCursor;
      document.body.style.userSelect = prevSelect;
      ref.current.onEnd?.();
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  }, []);
}
