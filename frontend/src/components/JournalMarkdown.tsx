import { useMemo } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import rehypeSanitize, { defaultSchema } from "rehype-sanitize";
import { JournalMention } from "../api";
import { Icon, NODE_ICON } from "./Icon";

// The icon a mention chip wears, by kind. (kind is a navigation hint, so a plain glyph per kind.)
const KIND_ICON: Record<string, string> = {
  finding: "bug", target: "binary", node: "fn", hypothesis: "bulb",
};

// We transform `@[label](kind:id)` into a markdown link with an inert `#` href and the mention
// key carried in the link TITLE (`[label](# "kind:id")`). rehype-sanitize preserves a `#` href
// and the `title` attribute (a custom URL scheme would be stripped), so our custom `a` renderer
// can read the title, look up the resolved mention, and swap in a <MentionChip>.
const MENTION_HREF = "#hexmention";
// `@[label](kind:id)` — mirror of the backend's _MENTION_RE so render and store agree on syntax.
const MENTION_RE = /@\[([^\]]*)\]\(([a-z]+):([^)]+)\)/g;

// A rendered @-mention: a small clickable chip carrying the live label + the kind glyph, or a
// greyed, non-navigating "dangling" pill when the referenced object is archived/merged-away/gone
// (design §5.3 link-stability). `onSelect(kind, resolvedId)` routes into the existing graph
// selection plumbing (focusOn / viewFinding) so a click selects the object.
export function MentionChip({ m, onSelect }: {
  m: JournalMention; onSelect?: (kind: string, id: string) => void;
}) {
  const label = m.label || m.stored_label || m.ref_id.slice(0, 8);
  const icon = m.ref_kind === "node" ? "fn" : (KIND_ICON[m.ref_kind] || "link");
  if (m.dangling) {
    return (
      <span className="mention dangling" title={`${m.ref_kind} no longer in the graph (archived or removed)`}>
        <Icon name={icon} size={11} /> {label}
      </span>
    );
  }
  return (
    <button className="mention" title={`Select this ${m.ref_kind} in the graph`}
            onClick={(e) => { e.preventDefault(); e.stopPropagation(); onSelect?.(m.ref_kind, m.resolved_id); }}>
      <Icon name={icon} size={11} /> {label}
    </button>
  );
}

// Sanitizer schema: the strict rehype-sanitize default (no raw HTML, a tight tag/attribute
// allow-list). We rely only on what the default already permits (a `#`-anchor href + the `title`
// attribute on <a>), so no protocol relaxation is needed — keeping the boundary maximally tight.
// All journal markdown is untrusted (an agent may quote an attacker-controlled string from a
// hostile target into an entry), so this is a security boundary — never `dangerouslySetInnerHTML`.
const SANITIZE_SCHEMA = defaultSchema;

// Render a journal entry body as SANITIZED markdown, with `@[label](kind:id)` tokens turned into
// clickable <MentionChip>s wired to the entry's RESOLVED mention data (so the chip shows the live
// label + dangling state the backend computed through the merge keeper). GFM is on for tables /
// task-lists / strikethrough; raw HTML is disabled by the sanitizer.
export default function JournalMarkdown({ body, mentions, onSelect }: {
  body: string; mentions: JournalMention[]; onSelect?: (kind: string, id: string) => void;
}) {
  // Index resolved mentions by `kind:id` so the renderer can attach the live label/dangling
  // state to each token. The store dedups to one row per (kind,id), matching MENTION_RE here.
  const byKey = useMemo(() => {
    const m = new Map<string, JournalMention>();
    for (const x of mentions) m.set(`${x.ref_kind}:${x.ref_id}`, x);
    return m;
  }, [mentions]);

  // Pre-transform: `@[label](kind:id)` → `[label](#hexmention "kind:id")`. The mention key rides
  // in the link title (survives sanitization); an unknown kind/id (no resolved row) is left as
  // plain prose rather than a broken link. Escape any quote in the label so the title can't break.
  const transformed = useMemo(() => (body || "").replace(MENTION_RE, (whole, label, kind, id) => {
    const key = `${kind}:${id.trim()}`;
    if (!byKey.has(key)) return whole;
    const safeLabel = String(label).replace(/[[\]]/g, "");
    return `[${safeLabel}](${MENTION_HREF} "${key}")`;
  }), [body, byKey]);

  return (
    <div className="md">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        rehypePlugins={[[rehypeSanitize, SANITIZE_SCHEMA]]}
        components={{
          // `node` is react-markdown's AST node — destructured out so it never leaks to the DOM.
          a({ node, href, title, children, ...props }) {
            if (href === MENTION_HREF && title) {
              const m = byKey.get(title);
              if (m) return <MentionChip m={m} onSelect={onSelect} />;
            }
            // A genuine link in an entry: open externally, never in-app (untrusted content).
            return <a href={href} title={title} target="_blank" rel="noopener noreferrer nofollow" {...props}>{children}</a>;
          },
        }}
      >
        {transformed}
      </ReactMarkdown>
    </div>
  );
}

// Re-export so panels can reach the canonical node glyphs without a second import.
export { NODE_ICON };
