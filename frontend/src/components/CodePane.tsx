import { useEffect, useMemo, useRef } from "react";
import { highlightLines } from "../highlight";

// Escape a string for use as a literal inside a RegExp.
const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// Wrap whole-word occurrences of any `names` token in a clickable link span, operating
// ONLY on the text between highlight.js tags (so we never corrupt a tag or its attrs) and
// skipping HTML entities (the `(?<![\w&])` guard keeps `&lt;`/`&gt;`/`&amp;` intact). The
// callee-navigation affordance for the function source viewer: a token that names a known
// project function becomes a link → load that function in place.
//
// SECURITY: the matched text `m` derives from symbol/function names recovered from a HOSTILE
// target binary, and is re-inserted via dangerouslySetInnerHTML. We deliberately carry NO
// attribute (no `data-sym="${m}"` — highlight.js's escape does not escape `"`, so a name like
// `a" onmouseover=…` would break out of the attribute → XSS). `m` is a slice of the already
// highlight.js-escaped text segment (its `<`/`>`/`&` are entities), so re-inserting it as the
// span's text content is the same escaped content, verbatim and safe. The click handler reads
// the clicked span's textContent (the decoded name) — no name ever round-trips through HTML.
function linkify(lineHtml: string, re: RegExp): string {
  // Split tags out; even indices are text, odd indices are verbatim `<...>` tags.
  return lineHtml.split(/(<[^>]*>)/).map((seg, i) => {
    if (i % 2 === 1) return seg; // a tag — leave untouched
    return seg.replace(re, (m) => `<span class="cp-sym">${m}</span>`);
  }).join("");
}

// The shared syntax-highlighted code surface: a single continuous `.codeview` block
// with a dimmed right-aligned line-number gutter, faithful indentation, and per-row
// decoration hooks. Extracted from SourceBrowser so the Source/IDE viewer and the
// function source viewer render identical pixels from one place.
//
// The highlighter (highlight.js, line-split) only colors the text; per-row backgrounds
// (coverage shading, the jump highlight) ride UNDERNEATH it as row classes — so the two
// decorations coexist and the highlighter never clobbers them. The active line wins over
// any caller-supplied class (mirrors SourceBrowser's `hot` > coverage precedence) and is
// scrolled into view when it (or the content) changes.
export function CodePane({ content, lang, activeLine, lineClassFor, linkSymbols, onSymbolClick }: {
  content: string;
  lang: string | null;
  /** 1-based line to highlight (`.hot`) and scroll into view. */
  activeLine?: number;
  /** Extra per-row class (e.g. coverage `cov-y`/`cov-n`); ignored on the active line. */
  lineClassFor?: (lineNo: number) => string | undefined;
  /** Tokens to render as clickable links (e.g. callee names) — paired with onSymbolClick. */
  linkSymbols?: Iterable<string>;
  onSymbolClick?: (sym: string) => void;
}) {
  const activeRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (activeLine && activeRef.current) activeRef.current.scrollIntoView({ block: "center" });
  }, [activeLine, content]);

  // One alternation regex over all link tokens (whole-word, longest-first so a name that
  // is a prefix of another doesn't shadow it). Null when there's nothing to linkify.
  const linkRe = useMemo(() => {
    const names = linkSymbols ? Array.from(new Set(linkSymbols)).filter(Boolean) : [];
    if (!names.length || !onSymbolClick) return null;
    names.sort((a, b) => b.length - a.length);
    return new RegExp(`(?<![\\w&])(${names.map(escapeRe).join("|")})\\b`, "g");
  }, [linkSymbols, onSymbolClick]);

  // Highlighting the whole body is O(content); memoize so unrelated re-renders
  // (e.g. activeLine changes from a jump) don't re-run the highlighter or the linkifier.
  const lines = useMemo(() => {
    const hl = highlightLines(content, lang);
    return linkRe ? hl.map((h) => linkify(h, linkRe)) : hl;
  }, [content, lang, linkRe]);

  const onClick = onSymbolClick
    ? (e: React.MouseEvent) => {
        const el = (e.target as HTMLElement)?.closest?.(".cp-sym") as HTMLElement | null;
        const sym = el?.textContent?.trim();
        if (sym) { e.preventDefault(); onSymbolClick(sym); }
      }
    : undefined;

  return (
    <div className="scrollx">
      <div className="codeview" onClick={onClick}>
        {lines.map((html, i) => {
          const n = i + 1;
          const hot = activeLine === n;
          const extra = hot ? "hot" : lineClassFor?.(n);
          return (
            <div key={i} className={"cl" + (extra ? " " + extra : "")} ref={hot ? activeRef : undefined}>
              <span className="ln">{n}</span>
              <code className="src hljs" dangerouslySetInnerHTML={{ __html: html || " " }} />
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default CodePane;
