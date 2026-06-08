import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import { Icon, NODE_ICON } from "./Icon";
import JournalMarkdown from "./JournalMarkdown";

// One typeahead candidate — a graph object the `@` popover can insert as a mention.
interface Cand { kind: "node" | "finding" | "target" | "hypothesis"; id: string; label: string; sub?: string }

// Mirror caret measurement: a hidden div clone of the textarea up to the caret, so an inline
// popover can sit AT the `@` (design §5.3 — caret positioning is the only genuinely new bit).
// Returns { top, left } in the textarea's offset-parent coordinate space.
function caretXY(ta: HTMLTextAreaElement, pos: number): { top: number; left: number } {
  const div = document.createElement("div");
  const cs = window.getComputedStyle(ta);
  for (const p of ["fontSize", "fontFamily", "fontWeight", "lineHeight", "letterSpacing",
    "paddingTop", "paddingRight", "paddingBottom", "paddingLeft", "borderTopWidth",
    "borderLeftWidth", "boxSizing", "whiteSpace", "wordWrap", "textAlign"] as const) {
    (div.style as any)[p] = cs[p as any];
  }
  div.style.position = "absolute";
  div.style.visibility = "hidden";
  div.style.whiteSpace = "pre-wrap";
  div.style.wordWrap = "break-word";
  div.style.width = ta.clientWidth + "px";
  div.textContent = ta.value.slice(0, pos);
  const marker = document.createElement("span");
  marker.textContent = "​";
  div.appendChild(marker);
  ta.parentElement!.appendChild(div);
  const top = marker.offsetTop - ta.scrollTop + parseInt(cs.lineHeight || "16", 10);
  const left = marker.offsetLeft;
  ta.parentElement!.removeChild(div);
  return { top, left };
}

// The lean journal composer (design §12 — markdown source + live preview + an @-typeahead
// popover; NO WYSIWYG). Typing `@` opens an inline popover at the caret that searches the project
// (targets / graph nodes / findings / hypotheses) via the existing search resolver; picking a
// result inserts `@[label](kind:id)`. Used for both new entries and editing an existing body.
export default function JournalComposer({ projectId, initialBody, onSave, onCancel, busy }: {
  projectId: string; initialBody?: string;
  onSave: (body: string) => void; onCancel: () => void; busy?: boolean;
}) {
  const [body, setBody] = useState(initialBody || "");
  const [preview, setPreview] = useState(false);
  const taRef = useRef<HTMLTextAreaElement>(null);
  // @-typeahead state: the trigger position (the `@`'s index), the live query, candidates, the
  // popover anchor, and the keyboard-highlighted row.
  const [trigger, setTrigger] = useState<number | null>(null);
  const [tq, setTq] = useState("");
  const [cands, setCands] = useState<Cand[]>([]);
  const [anchor, setAnchor] = useState<{ top: number; left: number } | null>(null);
  const [hi, setHi] = useState(0);
  const searchTimer = useRef<any>();
  // For preview-time mention rendering, resolve mentions in the draft cheaply by reusing the
  // candidates' labels; danglers can't occur in a fresh draft, so a light client-side resolve
  // (label from the inserted token, never dangling) is enough.

  useEffect(() => () => clearTimeout(searchTimer.current), []);
  useEffect(() => { taRef.current?.focus(); }, []);

  // Detect an active `@token` immediately left of the caret; open/refresh the popover, or close
  // it when the caret leaves the token (a space ends it, matching common @-mention UX).
  const sync = () => {
    const ta = taRef.current; if (!ta) return;
    const pos = ta.selectionStart;
    const upto = ta.value.slice(0, pos);
    const m = /(?:^|\s)@([\w./-]*)$/.exec(upto);
    if (!m) { setTrigger(null); setCands([]); return; }
    const at = pos - m[1].length - 1;
    setTrigger(at);
    setTq(m[1]);
    setAnchor(caretXY(ta, at));
    setHi(0);
    clearTimeout(searchTimer.current);
    const q = m[1];
    searchTimer.current = setTimeout(async () => {
      try {
        const [r, hyps] = await Promise.all([
          api.search(projectId, q || ""),
          api.hypotheses(projectId),
        ]);
        const out: Cand[] = [];
        (r.targets || []).slice(0, 5).forEach((t) => out.push({ kind: "target", id: t.id, label: t.name, sub: t.kind }));
        (r.nodes || []).slice(0, 6).forEach((n: any) => out.push({ kind: "node", id: n.id, label: n.name, sub: n.node_type }));
        (r.findings || []).slice(0, 5).forEach((f: any) => out.push({ kind: "finding", id: f.id, label: f.title, sub: f.severity }));
        const ql = (q || "").toLowerCase();
        hyps.hypotheses
          .filter((h) => !ql || h.statement.toLowerCase().includes(ql))
          .slice(0, 5)
          .forEach((h) => out.push({ kind: "hypothesis", id: h.id, label: h.statement, sub: h.work_state }));
        setCands(out);
      } catch { setCands([]); }
    }, 160);
  };

  // Insert the chosen mention, replacing the live `@token` with `@[label](kind:id)`.
  const pick = (c: Cand) => {
    const ta = taRef.current; if (ta == null || trigger == null) return;
    const pos = ta.selectionStart;
    const label = (c.label ?? "").replace(/[[\]()]/g, " ").trim().slice(0, 80) || c.kind;
    const token = `@[${label}](${c.kind}:${c.id})`;
    const next = body.slice(0, trigger) + token + body.slice(pos);
    setBody(next);
    setTrigger(null); setCands([]);
    // Restore the caret just after the inserted token.
    requestAnimationFrame(() => {
      const p = trigger + token.length;
      ta.focus(); ta.setSelectionRange(p, p);
    });
  };

  const onKey = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (trigger != null && cands.length) {
      if (e.key === "ArrowDown") { e.preventDefault(); setHi((h) => (h + 1) % cands.length); return; }
      if (e.key === "ArrowUp") { e.preventDefault(); setHi((h) => (h - 1 + cands.length) % cands.length); return; }
      if (e.key === "Enter" || e.key === "Tab") { e.preventDefault(); pick(cands[hi]); return; }
      if (e.key === "Escape") { e.preventDefault(); setTrigger(null); setCands([]); return; }
    }
    // Cmd/Ctrl+Enter saves (a calm keyboard path; plain Enter is a newline in markdown).
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") { e.preventDefault(); save(); }
  };

  const save = () => { if (body.trim() && !busy) onSave(body.trim()); };

  // Light preview-time resolve: build pseudo-mentions from the draft tokens so the preview shows
  // chips. They're never dangling (a fresh draft), and the label is the stored one.
  const draftMentions = (() => {
    const re = /@\[([^\]]*)\]\(([a-z]+):([^)]+)\)/g;
    const out: any[] = []; const seen = new Set<string>(); let m: RegExpExecArray | null;
    while ((m = re.exec(body))) {
      const key = `${m[2]}:${m[3]}`;
      if (seen.has(key) || !["node", "finding", "target", "hypothesis"].includes(m[2])) continue;
      seen.add(key);
      out.push({ ref_kind: m[2], ref_id: m[3], resolved_id: m[3], label: m[1], stored_label: m[1], dangling: false });
    }
    return out;
  })();

  return (
    <div className="jcompose">
      <div className="jc-tabs">
        <button className={"btn sm" + (!preview ? " primary" : " ghost")} onClick={() => setPreview(false)}>
          <Icon name="pencil" size={12} /> Write
        </button>
        <button className={"btn sm" + (preview ? " primary" : " ghost")} onClick={() => setPreview(true)} disabled={!body.trim()}>
          <Icon name="doc" size={12} /> Preview
        </button>
        <span className="grow" />
        <span className="muted jc-hint">@ to mention · markdown · ⌘↵ to save</span>
      </div>
      {preview ? (
        <div className="jc-preview">
          {body.trim()
            ? <JournalMarkdown body={body} mentions={draftMentions} />
            : <div className="muted">Nothing to preview yet.</div>}
        </div>
      ) : (
        <div className="jc-area">
          <textarea ref={taRef} className="jc-text" value={body}
                    placeholder="What did you try, what worked or didn't, what did you learn? Type @ to link a finding, node, target, or hypothesis."
                    onChange={(e) => { setBody(e.target.value); sync(); }}
                    onKeyDown={onKey} onClick={sync} onKeyUp={(e) => { if (!["ArrowDown", "ArrowUp", "Enter", "Tab", "Escape"].includes(e.key)) sync(); }} />
          {trigger != null && cands.length > 0 && anchor && (
            <div className="jc-pop" style={{ top: anchor.top, left: Math.min(anchor.left, 280) }}>
              {cands.map((c, i) => (
                <div key={c.kind + c.id} className={"jc-cand" + (i === hi ? " hi" : "")}
                     onMouseEnter={() => setHi(i)} onMouseDown={(e) => { e.preventDefault(); pick(c); }}>
                  <Icon name={c.kind === "finding" ? "bug" : c.kind === "target" ? (NODE_ICON[c.sub || ""] || "binary") : c.kind === "hypothesis" ? "bulb" : (NODE_ICON[c.sub || ""] || "fn")} size={12} />
                  <span className="jc-cand-lbl">{c.label}</span>
                  <span className="muted jc-cand-sub">{c.kind}{c.sub ? " · " + c.sub : ""}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
      <div className="jc-actions">
        <button className="btn sm primary" onClick={save} disabled={!body.trim() || busy}>
          <Icon name="check" size={12} /> {busy ? "saving…" : initialBody ? "Save changes" : "Add entry"}
        </button>
        <button className="btn sm ghost" onClick={onCancel} disabled={busy}>
          <Icon name="x" size={12} /> Cancel
        </button>
      </div>
    </div>
  );
}
