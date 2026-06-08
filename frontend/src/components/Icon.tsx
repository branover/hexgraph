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
  folder: <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7z" />,
  task: <><path d="M9 11l3 3 8-8" /><path d="M20 12v7H4V5h11" /></>,
  trash: <><path d="M3 6h18" /><path d="M8 6V4a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2" /><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6" /><path d="M10 11v6M14 11v6" /></>,
  copy: <><rect x="9" y="9" width="11" height="11" rx="2" /><path d="M5 15V5h10" /></>,
  target: <><circle cx="12" cy="12" r="9" /><circle cx="12" cy="12" r="4" /></>,
  filter: <path d="M3 4h18l-7 8v6l-4 2v-8z" />,
  bulb: <><path d="M9 18h6" /><path d="M10 21h4" /><path d="M12 3a6 6 0 0 0-4 10.5c.7.7 1 1.3 1 2.5h6c0-1.2.3-1.8 1-2.5A6 6 0 0 0 12 3z" /></>,
  plug: <><path d="M9 2v6M15 2v6" /><path d="M7 8h10v3a5 5 0 0 1-10 0z" /><path d="M12 16v6" /></>,
  globe: <><circle cx="12" cy="12" r="9" /><path d="M3 12h18" /><path d="M12 3a15 15 0 0 1 0 18 15 15 0 0 1 0-18z" /></>,
  arrowin: <><path d="M3 12h12" /><path d="M11 8l4 4-4 4" /><path d="M20 4v16" /></>,
  drain: <><path d="M12 3v12" /><path d="M8 11l4 4 4-4" /><path d="M5 21h14" /></>,
  sliders: <><path d="M4 8h16M4 16h16" /><circle cx="9" cy="8" r="2" /><circle cx="15" cy="16" r="2" /></>,
  alert: <><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z" /><path d="M12 9v4" /><path d="M12 17h.01" /></>,
  shield: <><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6l8-3z" /></>,
  gear: <><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" /></>,
  book: <><path d="M4 5a2 2 0 0 1 2-2h13v16H6a2 2 0 0 0-2 2z" /><path d="M19 17H6a2 2 0 0 0-2 2" /></>,
  pencil: <><path d="M12 20h9" /><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z" /></>,
  user: <><circle cx="12" cy="8" r="4" /><path d="M4 21c0-4 4-6 8-6s8 2 8 6" /></>,
  bot: <><rect x="4" y="8" width="16" height="11" rx="2.5" /><path d="M12 4v4M8 13h.01M16 13h.01M9 19v2M15 19v2" /></>,
  clock: <><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></>,
  eye: <><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z" /><circle cx="12" cy="12" r="3" /></>,
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
  hypothesis: "bulb", pattern: "spark", struct: "chip",
  socket: "plug", endpoint: "globe", web_app: "globe", service: "plug", param: "sliders", input: "arrowin", sink: "drain",
};
