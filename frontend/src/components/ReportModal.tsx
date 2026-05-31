import { useEffect, useState } from "react";
import { api } from "../api";
import { Icon } from "./Icon";

const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
// Inline spans on already-escaped text: `code`, **bold**, [text](url).
const inline = (s: string) =>
  esc(s)
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noreferrer">$1</a>');

// Tiny offline Markdown → HTML for the project report (headings, lists, code
// fences, rules, paragraphs). No external renderer; input is locally generated.
function render(md: string): string {
  const out: string[] = [];
  let inCode = false, inList = false;
  const closeList = () => { if (inList) { out.push("</ul>"); inList = false; } };
  for (const raw of md.split("\n")) {
    if (raw.trim().startsWith("```")) {
      if (inCode) { out.push("</code></pre>"); inCode = false; }
      else { closeList(); out.push("<pre><code>"); inCode = true; }
      continue;
    }
    if (inCode) { out.push(esc(raw)); continue; }
    const h = raw.match(/^(#{1,4})\s+(.*)$/);
    if (h) { closeList(); out.push(`<h${h[1].length}>${inline(h[2])}</h${h[1].length}>`); continue; }
    if (/^(-{3,}|\*{3,})$/.test(raw.trim())) { closeList(); out.push("<hr>"); continue; }
    const li = raw.match(/^\s*[-*]\s+(.*)$/);
    if (li) { if (!inList) { out.push("<ul>"); inList = true; } out.push(`<li>${inline(li[1])}</li>`); continue; }
    if (!raw.trim()) { closeList(); continue; }
    closeList(); out.push(`<p>${inline(raw)}</p>`);
  }
  if (inCode) out.push("</code></pre>");
  if (inList) out.push("</ul>");
  return out.join("\n");
}

export default function ReportModal({ projectId, projectName, onClose }: {
  projectId: string; projectName: string; onClose: () => void;
}) {
  const [md, setMd] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  useEffect(() => { api.report(projectId).then(setMd).catch(() => setMd("_failed to load report_")); }, [projectId]);

  const copy = () => { navigator.clipboard?.writeText(md || ""); setCopied(true); setTimeout(() => setCopied(false), 1200); };
  const download = () => {
    const blob = new Blob([md || ""], { type: "text/markdown" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `${projectName.replace(/\s+/g, "_")}_report.md`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  return (
    <div className="modal-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="modal fade-in" style={{ width: 820, maxHeight: "86vh", display: "flex", flexDirection: "column" }}>
        <h3 style={{ marginBottom: 10 }}>
          <Icon name="doc" size={16} /> Report · {projectName}
          <span style={{ flex: 1 }} />
          <button className="btn sm" onClick={copy}><Icon name={copied ? "check" : "copy"} size={12} /> {copied ? "Copied" : "Copy"}</button>
          <button className="btn sm" onClick={download} style={{ marginLeft: 6 }}><Icon name="doc" size={12} /> .md</button>
          <button className="btn sm ghost icon" onClick={onClose} style={{ marginLeft: 6 }}><Icon name="x" size={13} /></button>
        </h3>
        <div className="markdown" style={{ overflow: "auto", paddingRight: 6 }}>
          {md === null
            ? <div className="empty">Rendering report…</div>
            : <div dangerouslySetInnerHTML={{ __html: render(md) }} />}
        </div>
      </div>
    </div>
  );
}
