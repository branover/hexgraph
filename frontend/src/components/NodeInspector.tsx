import { useState } from "react";
import { GraphNode, TargetNode, api } from "../api";
import { Icon, NODE_ICON } from "./Icon";
import Launcher from "./Launcher";
import Annotations from "./Annotations";
import HypothesisPanel from "./HypothesisPanel";
import FilesystemBrowser from "./FilesystemBrowser";

// Node-type-aware detail shown when a target/function/symbol/string node is
// selected in the graph (findings use the richer Inspector instead).
export default function NodeInspector({ node, target, allowed, projectId, onLaunch, onChanged, onViewFinding }: {
  node: GraphNode; target?: TargetNode; allowed: string[]; isMock?: boolean; projectId?: string;
  onLaunch: (type: string) => void; onChanged?: () => void; onViewFinding?: (fid: string) => void;
}) {
  const isHypothesis = node.type === "node" && node.node_type === "hypothesis";
  const isFunction = node.type === "node" && node.node_type === "function";
  const icon = node.type === "target" ? NODE_ICON[node.kind] : NODE_ICON[node.node_type] || "fn";
  const [added, setAdded] = useState<Set<string>>(new Set());
  const [decomp, setDecomp] = useState<{ loading: boolean; focus?: any; detail?: string } | null>(null);
  const exports: string[] = (target?.metadata?.exports as string[]) || [];

  const doDecompile = async () => {
    if (!node.target_id) return;
    setDecomp({ loading: true });
    try {
      const r = await api.decompile(node.target_id, node.label);
      setDecomp({ loading: false, focus: r.focus, detail: r.available ? (r.focus ? undefined : "function not found in the binary") : r.detail });
    } catch (e: any) { setDecomp({ loading: false, detail: String(e.message || e) }); }
  };

  const addNode = async (name: string, kind: string) => {
    if (!projectId || !target) return;
    try { await api.createNode(projectId, { node_type: kind, name, target_id: target.id }); } catch { /* dup ok */ }
    setAdded((prev) => new Set(prev).add(name));
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
          <div className="actions"><Launcher allowed={allowed} onChoose={onLaunch} /></div>
          <div className="sec">Recon facts</div>
          <div className="kvs">
            {target.metadata?.mitigations && <><span className="k">mitigations</span><code>{JSON.stringify(target.metadata.mitigations)}</code></>}
            {target.metadata?.libraries?.length ? <><span className="k">libraries</span><span>{target.metadata.libraries.join(", ")}</span></> : null}
            {target.metadata?.hashes?.sha256 && <><span className="k">sha256</span><code>{String(target.metadata.hashes.sha256).slice(0, 16)}…</code></>}
            {typeof target.metadata?.size === "number" && <><span className="k">size</span><span>{target.metadata.size} B</span></>}
          </div>
          {target.metadata?.imports?.length ? (
            <><div className="sec">Imports ({target.metadata.imports.length})</div>
              <div style={{ display: "flex", gap: 5, flexWrap: "wrap" }}>
                {target.metadata.imports.slice(0, 40).map((i: string) => <span className="tag" key={i}>{i}</span>)}
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
        </>
      )}

      {isHypothesis && (
        <HypothesisPanel hypothesisId={node.id} onViewFinding={onViewFinding} onChanged={onChanged} />
      )}

      {isFunction && (
        <>
          <div className="actions">
            {allowed.length > 0 && <Launcher allowed={allowed} onChoose={onLaunch} />}
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
          <div className="sec">Attributes</div>
          <div className="kvs">
            {node.address && <><span className="k">address</span><code>{node.address}</code></>}
            {Object.entries(node.attrs || {}).map(([k, v]) => (
              <span key={k} style={{ display: "contents" }}><span className="k">{k}</span><code>{String(typeof v === "object" ? JSON.stringify(v) : v)}</code></span>
            ))}
          </div>
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
        </>
      )}

      {projectId && !isHypothesis && (
        <Annotations projectId={projectId} nodeKind={node.type === "target" ? "target" : "node"} nodeId={node.id}
                     allowRename={node.type === "node" && node.node_type === "function"} onChanged={onChanged} />
      )}
    </div>
  );
}
