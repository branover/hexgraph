// Inline SVG icons (offline; no icon font). Lucide-style 24px stroke paths.
import { ReactNode } from "react";

const P: Record<string, ReactNode> = {
  hex: <path d="M12 2l8.66 5v10L12 22l-8.66-5V7L12 2z" />,
  search: <><circle cx="11" cy="11" r="7" /><path d="M21 21l-4.3-4.3" /></>,
  run: <path d="M6 4l14 8-14 8V4z" />,
  chevron: <path d="M6 9l6 6 6-6" />,
  refresh: <><path d="M21 12a9 9 0 1 1-3-6.7" /><path d="M21 3v5h-5" /></>,
  fit: <><path d="M4 9V4h5" /><path d="M20 9V4h-5" /><path d="M4 15v5h5" /><path d="M20 15v5h-5" /></>,
  plus: <><path d="M12 5v14" /><path d="M5 12h14" /></>,
  minus: <path d="M5 12h14" />,
  doc: <><path d="M14 3v5h5" /><path d="M14 3H6v18h12V8z" /></>,
  link: <><path d="M10 13a5 5 0 0 0 7 0l2-2a5 5 0 0 0-7-7l-1 1" /><path d="M14 11a5 5 0 0 0-7 0l-2 2a5 5 0 0 0 7 7l1-1" /></>,
  check: <path d="M20 6L9 17l-5-5" />,
  x: <><path d="M18 6L6 18" /><path d="M6 6l12 12" /></>,
  spark: <path d="M12 3l1.9 5.6L19.5 10l-5.6 1.9L12 17l-1.9-5.1L4.5 10l5.6-1.4L12 3z" />,
  fn: <><path d="M8 3c-2 0-3 1-3 4s-1 4-2 4c1 0 2 1 2 4s1 4 3 4" /><path d="M16 3c2 0 3 1 3 4s1 4 2 4c-1 0-2 1-2 4s-1 4-3 4" /></>,
  binary: <><rect x="4" y="4" width="16" height="16" rx="2" /><path d="M9 9h1v6" /><rect x="13" y="9" width="3" height="6" rx="1.5" /></>,
  lib: <><path d="M4 19V5l4 2 4-2 4 2 4-2v14l-4-2-4 2-4-2-4 2z" /></>,
  chip: <><rect x="6" y="6" width="12" height="12" rx="1.5" /><path d="M9 3v3M15 3v3M9 18v3M15 18v3M3 9h3M3 15h3M18 9h3M18 15h3" /></>,
  bug: <><rect x="8" y="8" width="8" height="11" rx="4" /><path d="M12 4v4M5 9l3 1M19 9l-3 1M4 15h4M16 15h4M6 20l3-2M18 20l-3-2" /></>,
  task: <><path d="M9 11l3 3 8-8" /><path d="M20 12v7H4V5h11" /></>,
  copy: <><rect x="9" y="9" width="11" height="11" rx="2" /><path d="M5 15V5h10" /></>,
  target: <><circle cx="12" cy="12" r="9" /><circle cx="12" cy="12" r="4" /></>,
  filter: <path d="M3 4h18l-7 8v6l-4 2v-8z" />,
};

export function Icon({ name, size = 16, className }: { name: string; size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor"
         strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}
         style={{ flex: "none" }} aria-hidden>
      {P[name] ?? null}
    </svg>
  );
}

export const NODE_ICON: Record<string, string> = {
  firmware_image: "chip", executable: "binary", shared_library: "lib", unknown: "binary",
  function: "fn", symbol: "spark", string: "doc", finding: "bug", target: "target",
};
