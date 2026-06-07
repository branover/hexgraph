import { useEffect, useMemo, useRef } from "react";
import { highlightLines } from "../highlight";

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
export function CodePane({ content, lang, activeLine, lineClassFor }: {
  content: string;
  lang: string | null;
  /** 1-based line to highlight (`.hot`) and scroll into view. */
  activeLine?: number;
  /** Extra per-row class (e.g. coverage `cov-y`/`cov-n`); ignored on the active line. */
  lineClassFor?: (lineNo: number) => string | undefined;
}) {
  const activeRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (activeLine && activeRef.current) activeRef.current.scrollIntoView({ block: "center" });
  }, [activeLine, content]);

  // Highlighting the whole body is O(content); memoize so unrelated re-renders
  // (e.g. activeLine changes from a jump) don't re-run the highlighter.
  const lines = useMemo(() => highlightLines(content, lang), [content, lang]);
  return (
    <div className="scrollx">
      <div className="codeview">
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
