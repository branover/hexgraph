import { useState } from "react";
import { GraphNode, TargetNode, api } from "../api";
import { Icon, NODE_ICON } from "./Icon";
import Launcher from "./Launcher";
import Annotations from "./Annotations";
import HypothesisPanel from "./HypothesisPanel";
import FilesystemBrowser from "./FilesystemBrowser";
import ToolResults from "./ToolResults";
import Provenance from "./Provenance";
import Mitigations from "./Mitigations";

// Node-type-aware detail shown when a target/function/symbol/string node is
// selected in the graph (findings use the richer Inspector instead).
export default function NodeInspector({ node, target, allowed, projectId, onLaunch, onFuzz, onChanged, onViewFinding, onOpenSourceViewer }: {
  node: GraphNode; target?: TargetNode; allowed: string[]; isMock?: boolean; projectId?: string;
  onLaunch: (type: string) => void; onFuzz?: () => void; onChanged?: () => void; onViewFinding?: (fid: string) => void;
  onOpenSourceViewer?: (node: GraphNode) => void;
}) {
  const isHypothesis = node.type === "node" && node.node_type === "hypothesis";
  const isFunction = node.type === "node" && node.node_type === "function";
  const icon = node.type === "target" ? NODE_ICON[node.kind] : NODE_ICON[node.node_type] || "fn";
  const [added, setAdded] = useState<Set<string>>(new Set());
  const [decomp, setDecomp] = useState<{ loading: boolean; focus?: any; detail?: string } | null>(null);
  const [editing, setEditing] = useState(false);
  const [eName, setEName] = useState("");
  const [eAddr, setEAddr] = useState("");
  const [eAttrs, setEAttrs] = useState("");
  const [eErr, setEErr] = useState<string>();
  const [eSaving, setESaving] = useState(false);
  const exports: string[] = (target?.metadata?.exports as string[]) || [];

  const startEdit = () => {
    setEName(node.label);
    setEAddr(node.address || "");
    setEAttrs(JSON.stringify(node.attrs || {}, null, 2));
    setEErr(undefined); setEditing(true);
  };
  const saveEdit = async () => {
    if (!projectId) return;
    let attrs: any;
    try { attrs = eAttrs.trim() ? JSON.parse(eAttrs) : {}; }
    catch { setEErr("attributes must be valid JSON"); return; }
    setESaving(true); setEErr(undefined);
    try {
      await api.patchNode(projectId, node.id, { name: eName, address: eAddr, attrs });
      setEditing(false); onChanged?.();
    } catch (e: any) { setEErr(String(e.message || e)); }
    finally { setESaving(false); }
  };

  const doDecompile = async () => {
    if (!node.target_id) return;
    setDecomp({ loading: true });
    try {
      const r = await api.decompile(node.target_id, node.label);
      setDecomp({ loading: false, focus: r.focus, detail: r.available ? (r.focus ? undefined : "function not found in the binary") : r.detail });
    } catch (e: any) { setDecomp({ loading: false, detail: String(e.message || e) }); }
  };

  const addNode = async (name: string, kind: string, attrs?: Record<string, any>) => {
    if (!projectId || !target) return;
    try { await api.createNode(projectId, { node_type: kind, name, target_id: target.id, attrs }); } catch { /* dup ok */ }
    setAdded((prev) => new Set(prev).add(name));
    onChanged?.();
  };

  const removeNode = async () => {
    if (!projectId) return;
    if (!confirm(`Remove “${node.label}” from the graph? Its edges are hidden too. Re-adding the same node (or a task that finds it) brings it and its edges back — nothing is deleted.`)) return;
    await api.removeNode(projectId, node.id);
    onChanged?.();
  };

  return (
    <div className="insp scroll fade-in">
      <div className="head"><Icon name={icon || "binary"} size={17} /><h3>{node.label}</h3></div>
      <div className="chips">
        <span className="tag">{node.type === "target" ? node.kind : node.node_type}</span>
        {target?.arch && <span className="tag">{target.arch}</span>}
        {target?.format && <span className="tag">{target.format}</span>}
      </div>

      {node.type === "target" && target && (
        <>
          <div className="actions"><Launcher allowed={allowed} onChoose={onLaunch} onFuzz={onFuzz} /></div>
          <div className="sec">Recon facts</div>
          <div className="kvs">
            {target.metadata?.mitigations && <><span className="k">mitigations</span><Mitigations mitigations={target.metadata.mitigations as any} /></>}
            {target.metadata?.libraries?.length ? <><span className="k">libraries</span><span>{target.metadata.libraries.join(", ")}</span></> : null}
            {target.metadata?.hashes?.sha256 && <><span className="k">sha256</span><code>{String(target.metadata.hashes.sha256).slice(0, 16)}…</code></>}
            {typeof target.metadata?.size === "number" && <><span className="k">size</span><span>{target.metadata.size} B</span></>}
          </div>
          {target.metadata?.imports?.length ? (
            <><div className="sec">Imports ({target.metadata.imports.length}) <span className="muted">· click + to add as a node</span></div>
              <div style={{ display: "flex", gap: 5, flexWrap: "wrap" }}>
                {target.metadata.imports.slice(0, 80).map((i: string) => (
                  <button key={i} className="tag addable" disabled={added.has(i)}
                          title={added.has(i) ? "added" : "Add as a symbol node (auto-tagged a sink if a prior tool flagged it dangerous)"}
                          onClick={() => addNode(i, "symbol", { kind: "import" })}>
                    {added.has(i) ? <Icon name="check" size={10} /> : <Icon name="plus" size={10} />} {i}
                  </button>
                ))}
              </div></>
          ) : null}
          {exports.length > 0 && (
            <>
              <div className="sec">Exported functions ({exports.length}) <span className="muted">· click + to add as a node</span></div>
              <div style={{ display: "flex", gap: 5, flexWrap: "wrap" }}>
                {exports.slice(0, 80).map((e) => (
                  <button key={e} className="tag addable" disabled={added.has(e)}
                          title={added.has(e) ? "added" : "Add as a function node"}
                          onClick={() => addNode(e, "function")}>
                    {added.has(e) ? <Icon name="check" size={10} /> : <Icon name="plus" size={10} />} {e}
                  </button>
                ))}
              </div>
            </>
          )}
          {node.kind === "firmware_image" && projectId && (
            <FilesystemBrowser projectId={projectId} targetId={node.id} onChanged={onChanged} />
          )}
          {projectId && <ToolResults projectId={projectId} targetId={node.id} />}
        </>
      )}

      {isHypothesis && (
        <HypothesisPanel hypothesisId={node.id} onViewFinding={onViewFinding} onChanged={onChanged} />
      )}

      {isFunction && (
        <>
          <div className="actions">
            {allowed.length > 0 && <Launcher allowed={allowed} onChoose={onLaunch} onFuzz={onFuzz} />}
            {node.target_id && onOpenSourceViewer && (
              <button className="btn sm primary" onClick={() => onOpenSourceViewer(node)}
                      title="Open this function in the source viewer (decompiled + disassembly, navigable callees)">
                <Icon name="doc" size={12} /> Open in source viewer
              </button>
            )}
            {node.target_id && (
              <button className="btn sm ghost" onClick={doDecompile} disabled={decomp?.loading}>
                <Icon name="fn" size={12} /> {decomp?.loading ? "decompiling…" : "Decompile"}
              </button>
            )}
          </div>
          {decomp && !decomp.loading && (
            decomp.focus?.pseudocode ? (
              <>
                <div className="sec">Decompiled {decomp.focus.callees?.length ? `· calls: ${decomp.focus.callees.join(", ")}` : ""}</div>
                <pre className="codewrap" style={{ whiteSpace: "pre-wrap" }}>{decomp.focus.pseudocode}</pre>
              </>
            ) : <div className="muted" style={{ fontSize: 11 }}>{decomp.detail || "no pseudocode"}</div>
          )}
        </>
      )}

      {node.type === "node" && !isHypothesis && (
        <>
          <div className="sec" style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span>Attributes</span>
            <span style={{ flex: 1 }} />
            {projectId && !editing && (
              <button className="btn sm ghost" onClick={startEdit}><Icon name="sliders" size={11} /> Edit</button>
            )}
          </div>
          {editing ? (
            <div className="edit-finding" style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              <label className="fld"><span className="k">name</span>
                <input value={eName} onChange={(e) => setEName(e.target.value)} /></label>
              <label className="fld"><span className="k">address</span>
                <input value={eAddr} onChange={(e) => setEAddr(e.target.value)} placeholder="e.g. 0x401200" /></label>
              <label className="fld"><span className="k">attributes (JSON)</span>
                <textarea rows={6} value={eAttrs} onChange={(e) => setEAttrs(e.target.value)} style={{ fontFamily: "monospace", fontSize: 11 }} /></label>
              {eErr && <div className="err">{eErr}</div>}
              <div className="actions">
                <button className="btn sm primary" onClick={saveEdit} disabled={eSaving}><Icon name="check" size={12} /> {eSaving ? "saving…" : "Save"}</button>
                <button className="btn sm ghost" onClick={() => { setEditing(false); setEErr(undefined); }} disabled={eSaving}><Icon name="x" size={12} /> Discard</button>
              </div>
            </div>
          ) : (
            <div className="kvs">
              {node.address && <><span className="k">address</span><code>{node.address}</code></>}
              {/* `provenance` is rendered as its own "Derived from these tool results"
                  section below — keep it out of the raw attribute dump (a long id array). */}
              {Object.entries(node.attrs || {}).filter(([k]) => k !== "provenance").map(([k, v]) => (
                <span key={k} style={{ display: "contents" }}><span className="k">{k}</span><code>{String(typeof v === "object" ? JSON.stringify(v) : v)}</code></span>
              ))}
            </div>
          )}
          <div className="muted" style={{ fontSize: 11, marginTop: 12 }}>
            {["function", "symbol", "string", "struct"].includes(node.node_type)
              ? `Tip: launch a task from the binary in the Targets pane to analyze this ${node.node_type}.`
              : node.node_type === "socket"
              ? "A network/IPC endpoint shared across binaries — its listens_on / connects_to peers are shown as edges in the graph."
              : node.node_type === "endpoint"
              ? "A web route on a dynamic surface — its params and its routes_to handler are linked as edges in the graph."
              : ["input", "sink"].includes(node.node_type)
              ? "Part of a dataflow path — follow its taints / bypasses edges in the graph to the source or sink."
              : "Explore this node's edges in the graph for its relationships."}
          </div>
          <Provenance ids={(node.attrs as any)?.provenance} />
          {projectId && (
            <div className="actions" style={{ marginTop: 12 }}>
              <button className="btn sm ghost danger" onClick={removeNode} title="Soft-remove (reversible)">
                <Icon name="x" size={12} /> Remove node
              </button>
            </div>
          )}
        </>
      )}

      {projectId && !isHypothesis && (
        <Annotations projectId={projectId} nodeKind={node.type === "target" ? "target" : "node"} nodeId={node.id}
                     allowRename={node.type === "node" && node.node_type === "function"} onChanged={onChanged} />
      )}
    </div>
  );
}
