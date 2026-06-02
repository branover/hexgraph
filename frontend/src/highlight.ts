// Lightweight syntax highlighting for the Source viewer.
//
// We use highlight.js *core* and register only the languages we actually display
// (C/C++, Python, JS/TS, plus a few common config formats) — this keeps the bundle
// small (the full hljs auto-bundle ships ~190 languages; we ship ~8).
//
// The viewer needs PER-LINE control (coverage shading + the jump highlight are
// per-row backgrounds), but highlight.js emits HTML with spans that can SPAN
// multiple lines (e.g. a block comment). So we highlight the whole file once, then
// split the emitted HTML into lines while re-opening any spans that were still open
// at the newline. `highlightLines` returns one HTML string per source line, each a
// self-contained, balanced fragment safe to drop into a row's <pre>.

import hljs from "highlight.js/lib/core";
import c from "highlight.js/lib/languages/c";
import cpp from "highlight.js/lib/languages/cpp";
import python from "highlight.js/lib/languages/python";
import javascript from "highlight.js/lib/languages/javascript";
import typescript from "highlight.js/lib/languages/typescript";
import bash from "highlight.js/lib/languages/bash";
import json from "highlight.js/lib/languages/json";
import xml from "highlight.js/lib/languages/xml";

hljs.registerLanguage("c", c);
hljs.registerLanguage("cpp", cpp);
hljs.registerLanguage("python", python);
hljs.registerLanguage("javascript", javascript);
hljs.registerLanguage("typescript", typescript);
hljs.registerLanguage("bash", bash);
hljs.registerLanguage("json", json);
hljs.registerLanguage("xml", xml);

const EXT_LANG: Record<string, string> = {
  c: "c", h: "c",
  cc: "cpp", cpp: "cpp", cxx: "cpp", hpp: "cpp", hh: "cpp",
  py: "python", pyw: "python",
  js: "javascript", mjs: "javascript", cjs: "javascript", jsx: "javascript",
  ts: "typescript", tsx: "typescript",
  sh: "bash", bash: "bash",
  json: "json",
  html: "xml", xml: "xml", htm: "xml",
};

export function langForFile(rel: string): string | null {
  const base = rel.split("/").pop() || "";
  const ext = base.includes(".") ? base.split(".").pop()!.toLowerCase() : "";
  return EXT_LANG[ext] ?? null;
}

// Split highlighted HTML into per-line fragments, carrying open <span> tags across
// newlines (so a multi-line comment/string stays colored on every line). Each
// returned string is independently balanced.
export function highlightLines(content: string, lang: string | null): string[] {
  let html: string;
  if (lang && hljs.getLanguage(lang)) {
    try {
      html = hljs.highlight(content, { language: lang, ignoreIllegals: true }).value;
    } catch {
      html = escapeHtml(content);
    }
  } else {
    html = escapeHtml(content);
  }

  const rawLines = html.split("\n");
  const out: string[] = [];
  // Stack of currently-open opening-tag strings (verbatim, e.g. '<span class="hljs-comment">').
  let openStack: string[] = [];
  const tagRe = /<\/?span[^>]*>/g;

  for (const line of rawLines) {
    // Re-open whatever spans were open at the end of the previous line.
    const prefix = openStack.join("");
    // Track the stack through THIS line's own tags.
    let m: RegExpExecArray | null;
    tagRe.lastIndex = 0;
    while ((m = tagRe.exec(line)) !== null) {
      if (m[0].startsWith("</")) openStack.pop();
      else openStack.push(m[0]);
    }
    // Close, at the end of this line, any spans still open (they continue next line).
    const suffix = "</span>".repeat(openStack.length);
    out.push(prefix + line + suffix);
  }
  return out;
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}
