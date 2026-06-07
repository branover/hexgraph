import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api";
import { Icon } from "./Icon";
import CodePane from "./CodePane";
import { langForArch } from "../highlight";
import { RawResultModal } from "./ToolResults";

// A dedicated, IDE-style viewer for one function's body — the right surface for reading
// long decompiled / disassembled code (the details pane is not). Built on the SAME
// <CodePane> as SourceBrowser so the two read identically. Decompiled (C) ⇄ Disassembly
// tabs (+ a side-by-side toggle), per-line numbers, copy, and click-a-callee-to-navigate:
// a token naming a known project function becomes a link that loads that function in place
// (callees resolve within the same target). Deep-linked from the URL by the workspace.
//
// Bodies are fetched on demand (POST /decompile, /disassemble — sandboxed); nothing is
// stored. The component owns its own navigation history (a back stack) and reports the
// current (target, fn, tab, line) up via onChange so the workspace keeps the URL in sync.

type Ref = { targetId: string; fn: string; address?: string };
type Tab = "decomp" | "disasm";
type Body = {
  loading: boolean;
  pseudocode?: string;
  disasm?: string;
  address?: string;
  callees?: string[];
  functions?: string[]; // the binary's function inventory (incl. sym.imp.* imports)
  backend?: string;
  detail?: string; // unavailable/not-found/error message
};

const keyOf = (r: Ref, kind: Tab) => `${r.targetId}::${r.fn}::${kind}`;
// radare2 imports surface as `sym.imp.NAME`; the bare name (matching a callee token) is the
// PLT stub, not a navigable definition. Collect those so they never become callee links.
const importNames = (functions?: string[]): Set<string> => {
  const out = new Set<string>();
  for (const f of functions || []) if (f.includes("imp.")) out.add(f.split(".").pop()!);
  return out;
};

export default function FunctionSourceViewer({
  projectId, targetId, fn, address, targetName, arch, knownFunctions, provenanceIds,
  initialTab, initialLine, onClose, onChange,
}: {
  projectId: string;
  targetId: string;
  fn: string;
  /** The function node's recorded address — the reliable resolution key (a stripped/renamed/
   *  fast-analysis-missed name won't resolve by name, but its address always does). */
  address?: string;
  targetName?: string;
  arch?: string;
  /** Project function names that become navigable links in the body. */
  knownFunctions?: string[];
  /** Observation ids backing this function node (for the "raw" provenance link), if any. */
  provenanceIds?: string[];
  initialTab?: Tab;
  initialLine?: number;
  onClose: () => void;
  /** Report the current view up so the workspace can keep the URL deep-link in sync. */
  onChange?: (ref: { targetId: string; fn: string; tab: Tab; line?: number }) => void;
}) {
  const [stack, setStack] = useState<Ref[]>([{ targetId, fn, address }]);
  const [tab, setTab] = useState<Tab>(initialTab === "disasm" ? "disasm" : "decomp");
  const [split, setSplit] = useState(false);
  const [activeLine, setActiveLine] = useState<number | undefined>(initialLine);
  const [bodies, setBodies] = useState<Record<string, Body>>({});
  const [rawOpen, setRawOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  const cur = stack[stack.length - 1];

  // Lazily fetch a (function, kind) body once; cache by key. Decompile keeps the
  // configured backend (radare2/Ghidra); disassembly is always radare2 (Ghidra emits none).
  const ensure = (r: Ref, kind: Tab) => {
    const k = keyOf(r, kind);
    setBodies((prev) => (prev[k] ? prev : { ...prev, [k]: { loading: true } }));
    const req = kind === "decomp"
      ? api.decompile(r.targetId, r.fn, r.address)
      : api.disassemble(r.targetId, { function: r.fn, address: r.address });
    req.then((res) => {
      const f = res.focus;
      const body: Body = !res.available
        ? { loading: false, detail: res.detail || "unavailable" }
        : !f
        ? { loading: false, detail: `“${r.fn}” not found in the binary` }
        : {
            loading: false, backend: res.backend, address: f.address,
            callees: f.callees, functions: res.functions, pseudocode: f.pseudocode, disasm: f.disasm,
          };
      setBodies((prev) => ({ ...prev, [k]: body }));
    }).catch((e: any) => {
      setBodies((prev) => ({ ...prev, [k]: { loading: false, detail: String(e?.message || e) } }));
    });
  };

  // Fetch what the current tab(s) need.
  useEffect(() => {
    const want: Tab[] = split ? ["decomp", "disasm"] : [tab];
    for (const kind of want) if (!bodies[keyOf(cur, kind)]) ensure(cur, kind);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cur.targetId, cur.fn, tab, split]);

  // Keep the workspace URL in sync with the live view.
  useEffect(() => {
    onChange?.({ targetId: cur.targetId, fn: cur.fn, tab, line: activeLine });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cur.targetId, cur.fn, tab, activeLine]);

  const navigate = (name: string) => {
    if (!name || name === cur.fn) return;
    setActiveLine(undefined);
    setStack((s) => [...s, { targetId: cur.targetId, fn: name }]);
  };
  const back = () => setStack((s) => (s.length > 1 ? s.slice(0, -1) : s));

  // Tokens that become callee links: the current function's callees + the project's known
  // functions (capped so a pathological binary doesn't build a megabyte-class regex), MINUS
  // imports (a `sym.imp.*` callee is a PLT stub, not a navigable definition) and the active
  // function itself (so it never links to itself).
  const decompBody = bodies[keyOf(cur, "decomp")];
  const linkSymbols = useMemo(() => {
    const imports = importNames(decompBody?.functions);
    const set = new Set<string>();
    for (const c of (decompBody?.callees || [])) if (!imports.has(c)) set.add(c);
    for (const n of (knownFunctions || [])) { if (set.size >= 1500) break; if (!imports.has(n)) set.add(n); }
    set.delete(cur.fn);
    return set;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [decompBody?.callees, decompBody?.functions, knownFunctions, cur.fn]);

  const asmLang = langForArch(arch);
  const bodyText = (kind: Tab) => {
    const b = bodies[keyOf(cur, kind)];
    return (kind === "decomp" ? b?.pseudocode : b?.disasm) || "";
  };
  const copy = () => {
    navigator.clipboard?.writeText(split ? `${bodyText("decomp")}\n\n${bodyText("disasm")}` : bodyText(tab));
    setCopied(true); setTimeout(() => setCopied(false), 1200);
  };

  // A plain render function (NOT a nested component) so CodePane isn't remounted — and its
  // scroll position lost — on every parent re-render.
  const renderPane = (kind: Tab) => {
    const b = bodies[keyOf(cur, kind)];
    if (!b || b.loading) return <div className="muted" style={{ padding: 16, fontSize: 12 }}>{kind === "decomp" ? "decompiling…" : "disassembling…"}</div>;
    const text = kind === "decomp" ? b.pseudocode : b.disasm;
    if (!text) return <div className="muted" style={{ padding: 16, fontSize: 12 }}>{b.detail || (kind === "decomp" ? "no pseudocode" : "no disassembly")}</div>;
    return (
      <CodePane content={text} lang={kind === "decomp" ? "c" : asmLang} activeLine={split ? undefined : activeLine}
                linkSymbols={linkSymbols} onSymbolClick={navigate} />
    );
  };

  const backend = decompBody?.backend || bodies[keyOf(cur, "disasm")]?.backend;
  // The address the focus actually RESOLVED to (for the header) — not cur.address, so a header
  // address never sits next to a "not found" pane when resolution missed.
  const focusAddress = decompBody?.address || bodies[keyOf(cur, "disasm")]?.address;
  const hasRaw = !!(provenanceIds && provenanceIds.length && stack.length === 1);

  return (
    <div className="fnviewer" style={{ display: "flex", flexDirection: "column", height: "100%", minHeight: 0 }}>
      <div className="filehdr" style={{ gap: 7 }}>
        {stack.length > 1 && (
          <button className="btn sm ghost" title="Back to the previous function" onClick={back}>← back</button>
        )}
        <Icon name="fn" size={13} />
        <span className="path" style={{ fontWeight: 600, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{cur.fn}</span>
        {focusAddress && <code className="muted" style={{ fontSize: 10.5, whiteSpace: "nowrap" }}>{focusAddress}</code>}
        {targetName && <span className="tag" title="target" style={{ whiteSpace: "nowrap" }}>{targetName}</span>}
        {backend && <span className="tag" style={{ color: "var(--accent)", whiteSpace: "nowrap" }} title="analysis backend">{backend}</span>}
        <span style={{ flex: 1 }} />
        {/* Right cluster stays together (Decompiled ⇄ Disassembly tabs + side-by-side + actions). */}
        <div style={{ display: "flex", alignItems: "center", gap: 6, flex: "none" }}>
          <div className="seg tgroup" style={{ gap: 2, border: "1px solid var(--border)", borderRadius: 7, padding: 2 }}>
            <button className={"btn sm" + (!split && tab === "decomp" ? " primary" : " ghost")} onClick={() => { setSplit(false); setTab("decomp"); }} title="Decompiled pseudocode (C)">Decompiled</button>
            <button className={"btn sm" + (!split && tab === "disasm" ? " primary" : " ghost")} onClick={() => { setSplit(false); setTab("disasm"); }} title="Disassembly (radare2)">Disassembly</button>
            <button className={"btn sm" + (split ? " primary" : " ghost")} onClick={() => setSplit((s) => !s)} title="Side-by-side: decompiled + disassembly"><Icon name="copy" size={12} /> Split</button>
          </div>
          {hasRaw && (
            <button className="btn sm ghost" title="View the raw tool-result Observation this function was derived from" onClick={() => setRawOpen(true)}><Icon name="task" size={12} /> Raw</button>
          )}
          <button className="btn sm icon ghost" title="Copy the visible code" onClick={copy}><Icon name={copied ? "check" : "copy"} size={12} /></button>
          <button className="btn sm icon ghost" title="Close the source viewer" onClick={onClose}><Icon name="x" size={13} /></button>
        </div>
      </div>
      <div style={{ flex: 1, minHeight: 0, overflow: "hidden", display: "flex" }}>
        {split ? (
          <>
            <div style={{ flex: 1, minWidth: 0, overflow: "auto", borderRight: "1px solid var(--border)" }}>
              <div className="sec" style={{ padding: "4px 12px" }}>Decompiled</div>
              {renderPane("decomp")}
            </div>
            <div style={{ flex: 1, minWidth: 0, overflow: "auto" }}>
              <div className="sec" style={{ padding: "4px 12px" }}>Disassembly</div>
              {renderPane("disasm")}
            </div>
          </>
        ) : (
          <div style={{ flex: 1, minWidth: 0, overflow: "auto" }}>
            {renderPane(tab)}
          </div>
        )}
      </div>
      {rawOpen && hasRaw && <RawResultModal obsId={provenanceIds![0]} onClose={() => setRawOpen(false)} />}
    </div>
  );
}
