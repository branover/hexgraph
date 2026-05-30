import { GraphNode, TargetNode } from "../api";
import { Icon, NODE_ICON } from "./Icon";
import Launcher from "./Launcher";
import Annotations from "./Annotations";
import HypothesisPanel from "./HypothesisPanel";

// Node-type-aware detail shown when a target/function/symbol/string node is
// selected in the graph (findings use the richer Inspector instead).
export default function NodeInspector({ node, target, allowed, projectId, onLaunch, onChanged, onViewFinding }: {
  node: GraphNode; target?: TargetNode; allowed: string[]; isMock?: boolean; projectId?: string;
  onLaunch: (type: string) => void; onChanged?: () => void; onViewFinding?: (fid: string) => void;
}) {
  const isHypothesis = node.type === "node" && node.node_type === "hypothesis";
  const icon = node.type === "target" ? NODE_ICON[node.kind] : NODE_ICON[node.node_type] || "fn";

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
        </>
      )}

      {isHypothesis && (
        <HypothesisPanel hypothesisId={node.id} onViewFinding={onViewFinding} onChanged={onChanged} />
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
            Tip: launch a task from the binary in the Targets pane to analyze this {node.node_type}.
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
