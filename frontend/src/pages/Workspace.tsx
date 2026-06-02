import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import { api, Finding, Graph, GraphNode, ProjectDetail, SettingsView, TargetNode } from "../api";
import Header from "../components/Header";
import GraphView, { NODE_T, EDGE_C, KIND } from "../components/GraphView";
import FindingsPanel from "../components/FindingsPanel";
import Inspector from "../components/Inspector";
import NodeInspector from "../components/NodeInspector";
import { TasksPanel, TaskDetail } from "../components/TasksPanel";
import Launcher from "../components/Launcher";
import LaunchModal from "../components/LaunchModal";
import { AddNodeModal, AddEdgeModal } from "../components/Author";
import ReportModal from "../components/ReportModal";
import RunCompareModal from "../components/RunCompareModal";
import GhidraImportModal from "../components/GhidraImportModal";
import SourceBrowser from "../components/SourceBrowser";
import { CampaignsPanel } from "../components/CampaignsPanel";
import ArtifactsView from "../components/ArtifactsView";
import FuzzModal from "../components/FuzzModal";
import EgressPanel from "../components/EgressPanel";
import { Icon, NODE_ICON } from "../components/Icon";

export default function Workspace() {
  const { projectId } = useParams();
  const [detail, setDetail] = useState<ProjectDetail | null>(null);
  const [graph, setGraph] = useState<Graph | null>(null);
  const [caps, setCaps] = useState<{ target?: Record<string, string[]>; node?: Record<string, string[]>; edge?: Record<string, string[]>; features?: { build?: boolean; build_fetch?: boolean; source_edit?: boolean; fuzzing?: boolean; poc?: boolean } }>({});
  const [selFinding, setSelFinding] = useState<Finding | null>(null);
  const [selNode, setSelNode] = useState<GraphNode | null>(null);
  const [selEdge, setSelEdge] = useState<any | null>(null);
  const [selGraphId, setSelGraphId] = useState<string>();
  const [busy, setBusy] = useState<string>();
  const [tab, setTab] = useState<"findings" | "tasks" | "campaigns">(
    new URLSearchParams(window.location.search).get("tab") === "campaigns" ? "campaigns" : "findings");
  const [tasks, setTasks] = useState<any[]>([]);
  const [selTask, setSelTask] = useState<string>();
  const [selCampaign, setSelCampaign] = useState<string | undefined>(
    new URLSearchParams(window.location.search).get("campaign") || undefined);
  const [settings, setSettings] = useState<SettingsView | null>(null);
  const [fuzzFor, setFuzzFor] = useState<TargetNode | null>(null);
  const [q, setQ] = useState("");
  const [results, setResults] = useState<any | null>(null);
  const [modal, setModal] = useState<"node" | "edge" | "report" | "compare" | "ghidra" | "egress" | null>(null);
  const [edgePrefill, setEdgePrefill] = useState<{ src: string; dst: string } | null>(null);
  const [ghidraBridge, setGhidraBridge] = useState(false);
  const [fuzzingEnabled, setFuzzingEnabled] = useState(false);
  const [launchFor, setLaunchFor] = useState<{ target: TargetNode; type: string; objective?: string; params?: any; parentFindingId?: string; anchorKind?: string; anchorId?: string } | null>(null);
  const [maxed, setMaxed] = useState(false);
  const [detailBig, setDetailBig] = useState(false);
  // Center-pane mode switch (Graph ⇆ Source) — a mode, not a route, so selection
  // state is shared and finding→source jump is instantaneous (design §6.1).
  const [view, setView] = useState<"graph" | "source">(
    new URLSearchParams(window.location.search).get("view") === "source" ? "source" : "graph");
  const [openSource, setOpenSource] = useState<{ treeId?: string; rel?: string; line?: number } | null>(null);
  const searchTimer = useRef<any>();
  const fileRef = useRef<HTMLInputElement>(null);

  const load = useCallback(async () => {
    if (!projectId) return;
    const [d, g, tk] = await Promise.all([api.project(projectId), api.graph(projectId), api.projectTasks(projectId)]);
    setDetail(d); setGraph(g); setTasks(tk);
    // Refresh the open detail with the reloaded data so triage (Accept/Dismiss,
    // status pills, annotations) re-renders instead of showing a stale finding.
    setSelFinding((prev) => (prev ? d.findings.find((f) => f.id === prev.id) ?? prev : prev));
  }, [projectId]);

  useEffect(() => {
    load();
    api.capabilities().then(setCaps).catch(() => {});
    api.getSettings().then((s) => {
      setSettings(s);
      const g = s.settings.features.ghidra;
      setGhidraBridge(g.enabled && g.mode === "bridge");
      setFuzzingEnabled(Boolean(s.settings.features.fuzzing?.enabled));
    }).catch(() => {});
  }, [load]);

  const pollThenReload = async (taskId: string) => {
    setBusy("running task…");
    for (let i = 0; i < 90; i++) {
      await new Promise((r) => setTimeout(r, 700));
      const t = await api.task(taskId);
      if (t.status !== "queued" && t.status !== "running") break;
    }
    setBusy(undefined);
    await load();
    if (selFinding) api.finding(selFinding.id).then(setSelFinding).catch(() => {});
    setSelTask(taskId); // surface the new task (scrolls into view when the Tasks tab is showing)
  };

  const findingCounts = useMemo(() => {
    const m: Record<string, { n: number; hot: boolean }> = {};
    (detail?.findings || []).forEach((f) => {
      const e = (m[f.target_id] ??= { n: 0, hot: false });
      e.n++; if (f.severity === "critical" || f.severity === "high") e.hot = true;
    });
    return m;
  }, [detail]);

  const hypotheses = useMemo(
    () => (graph?.nodes || [])
      .filter((n) => n.type === "node" && n.node_type === "hypothesis")
      .map((n) => ({ id: n.id, statement: (n.attrs?.statement as string) || n.label })),
    [graph],
  );

  // Deep-link sync: every reveal updates the URL so the view is addressable/linkable
  // and restorable on reload (design §6.3 deep-links).
  const setUrl = (kv: Record<string, string | undefined>) => {
    const u = new URL(window.location.href);
    for (const [k, v] of Object.entries(kv)) { if (v) u.searchParams.set(k, v); else u.searchParams.delete(k); }
    window.history.replaceState(null, "", u.toString());
  };

  const switchView = (v: "graph" | "source") => {
    setView(v);
    setUrl({ view: v === "source" ? "source" : undefined });
  };
  const selectCampaign = (id?: string) => {
    setSelCampaign(id); setTab("campaigns"); setSelTask(undefined); setSelNode(null); setSelFinding(null); setSelEdge(null);
    setUrl({ tab: "campaigns", campaign: id });
  };
  const viewTask = (tid: string) => { setSelTask(tid); setTab("tasks"); setUrl({ tab: undefined }); };
  const viewFinding = (fid: string) => { setSelTask(undefined); setSelNode(null); setSelCampaign(undefined); api.finding(fid).then((f) => { setSelFinding(f); setSelGraphId(f.id); }); setUrl({ tab: undefined, campaign: undefined }); };

  // Finding → source jump: open the file in Source mode at the line (design §6.3).
  const revealSource = (ref: { tree_id?: string; rel?: string; line?: number }) => {
    if (!ref?.tree_id || !ref?.rel) return;
    setOpenSource({ treeId: ref.tree_id, rel: ref.rel, line: ref.line });
    switchView("source");
    setUrl({ view: "source", file: ref.rel, line: ref.line != null ? String(ref.line) : undefined });
  };

  // The single navigation primitive (design §6.3): every entity routes through reveal()
  // so "reveal in graph" / "open in source" / "show campaign" share one path.
  const reveal = (kind: "finding" | "node" | "target" | "campaign" | "artifact" | "source",
                  id: string, extra?: any) => {
    if (kind === "finding") return viewFinding(id);
    if (kind === "campaign" || kind === "artifact") return selectCampaign(id);
    if (kind === "source") return revealSource(extra);
    // node / target → select in the graph
    setView("graph"); setSelTask(undefined); setSelCampaign(undefined);
    onGraphSelect(id, kind === "target" ? "target" : "node");
  };
  const bulk = async (ids: string[], status: string) => { await api.bulkStatus(ids, status); await load(); };
  const removeTarget = async (t: TargetNode) => {
    if (!projectId) return;
    if (!window.confirm(`Remove "${t.name}" from the project? Its nodes and findings will be hidden `
      + `(not deleted) — re-add the same file to restore them.`)) return;
    await api.removeTarget(projectId, t.id);
    if (selGraphId === t.id) { setSelGraphId(undefined); setSelNode(null); setSelFinding(null); }
    await load();
  };
  const clearTasks = async () => { if (projectId) { await api.clearTasks(projectId); setSelTask(undefined); await load(); } };

  const onGraphSelect = (id: string, type: string) => {
    setSelGraphId(id); setSelTask(undefined);
    if (type === "finding") {
      const f = detail!.findings.find((x) => x.id === id);
      if (f) { setSelNode(null); setSelFinding(f); }
    } else {
      const n = graph!.nodes.find((x) => x.id === id);
      if (n) { setSelFinding(null); setSelNode(n); }
    }
  };

  const doSearch = (text: string) => {
    setQ(text);
    clearTimeout(searchTimer.current);
    if (!text.trim()) { setResults(null); return; }
    searchTimer.current = setTimeout(() => { if (projectId) api.search(projectId, text).then(setResults).catch(() => {}); }, 200);
  };
  const exportGraph = () => {
    if (!graph || !detail) return;
    const blob = new Blob([JSON.stringify(graph, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `${detail.project.name.replace(/\s+/g, "_")}_graph.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  };
  const mergeDupes = async () => {
    if (!projectId) return;
    setBusy("merging duplicates…");
    const r = await api.mergeDuplicates(projectId);
    setBusy(undefined);
    await load();
    alert(`Merged ${r.nodes_merged} duplicate node(s) and ${r.targets_merged} duplicate binary(ies).`);
  };
  const linkSameCode = async () => {
    if (!projectId) return;
    setBusy("linking…"); const r = await api.linkSameCode(projectId); setBusy(undefined);
    await load(); alert(`Linked ${r.created} same-code pair(s).`);
  };
  const onUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0]; if (!f || !projectId) return;
    setBusy(`analyzing ${f.name}…`);
    try { await api.addTarget(projectId, f, true); } catch (err: any) { alert(String(err.message || err)); }
    setBusy(undefined); e.target.value = ""; await load();
  };

  if (!detail || !graph) {
    return <><Header /><div className="workspace">{[0, 1, 2].map((i) => <div key={i} className="pane skel" />)}</div></>;
  }

  const isMock = detail.project.backend === "mock";
  const roots = detail.targets.filter((t) => !t.parent_id);
  const childrenOf = (id: string) => detail.targets.filter((t) => t.parent_id === id);
  // The best DEFAULT fuzz target for the Campaigns-tab launch button: the raw ingested
  // root (roots[0]) is usually the WRONG choice (it's the source, not the live/instrumented
  // surface). Prefer, in order: an instrumented derived target → a live web_app/remote/service
  // surface → a target carrying fuzz_target_sources → the first non-firmware root → roots[0].
  const bestFuzzTarget = (): TargetNode | undefined => {
    const ts = detail.targets;
    return ts.find((t) => t.metadata?.instrumented)
        || ts.find((t) => t.kind === "web_app" || t.kind === "remote" || t.kind === "service")
        || ts.find((t) => (t.metadata?.fuzz_target_sources || []).length > 0)
        || roots.find((t) => t.kind !== "firmware_image")
        || roots[0];
  };

  const TreeRow = (t: TargetNode, child: boolean) => {
    const allowed = caps.target?.[t.kind] ?? ["recon"];
    const fc = findingCounts[t.id];
    return (
      <div key={t.id}>
        <div className={"tree-row" + (child ? " child" : "") + (selGraphId === t.id ? " sel" : "")}
             onClick={() => onGraphSelect(t.id, "target")}>
          <div className="nm">
            <Icon name={NODE_ICON[t.kind] || "binary"} size={15} /> {t.name}
            {fc && <span className={"tbadge" + (fc.hot ? " hot" : "")} style={{ marginLeft: "auto" }}>{fc.n}</span>}
          </div>
          <div className="mt">{t.kind}{t.arch ? " · " + t.arch : ""}</div>
          <Launcher allowed={allowed} onChoose={(type) => setLaunchFor({ target: t, type })} />
          {caps.features?.fuzzing && t.kind !== "firmware_image" && (
            <button className="btn sm icon ghost" title="Start a detached fuzz campaign on this target"
                    onClick={(e) => { e.stopPropagation(); setFuzzFor(t); }}>
              <Icon name="bug" size={12} />
            </button>
          )}
          <button className="btn sm icon ghost trash" title="Remove target (hides its nodes/findings)"
                  onClick={(e) => { e.stopPropagation(); removeTarget(t); }}>
            <Icon name="x" size={12} />
          </button>
        </div>
        {childrenOf(t.id).map((c) => TreeRow(c, true))}
      </div>
    );
  };

  const fuzzingFeature = !!caps.features?.fuzzing;
  const renderTabs = () => (
    <div className="pane-h">
      <button className={"btn sm" + (tab === "findings" ? " primary" : " ghost")} onClick={() => { setTab("findings"); setUrl({ tab: undefined }); }}>
        <Icon name="bug" size={12} /> Findings · {detail.findings.length}
      </button>
      <button className={"btn sm" + (tab === "tasks" ? " primary" : " ghost")} onClick={() => { setTab("tasks"); setUrl({ tab: undefined }); }}>
        <Icon name="task" size={12} /> Tasks · {tasks.length}
      </button>
      {fuzzingFeature && (
        <button className={"btn sm" + (tab === "campaigns" ? " primary" : " ghost")} onClick={() => { setTab("campaigns"); setUrl({ tab: "campaigns" }); }}>
          <Icon name="bug" size={12} /> Campaigns
        </button>
      )}
      <span className="grow" />
      <button className="btn sm icon" title={maxed ? "Restore" : "Expand to full screen"} onClick={() => setMaxed((m) => !m)}>
        <Icon name={maxed ? "minus" : "fit"} size={13} />
      </button>
    </div>
  );
  const renderList = () => tab === "findings" ? (
    <FindingsPanel findings={detail.findings} targets={detail.targets} selectedId={selFinding?.id} onBulk={bulk}
                   onSelect={(f) => { setSelTask(undefined); setSelNode(null); setSelCampaign(undefined); setSelFinding(f); setSelGraphId(f.id); }} />
  ) : tab === "campaigns" ? (
    <CampaignsPanel projectId={projectId!} selectedId={selCampaign} onSelect={(id) => selectCampaign(id)}
                    onStartCampaign={bestFuzzTarget() ? () => setFuzzFor(bestFuzzTarget()!) : undefined} />
  ) : (
    <TasksPanel tasks={tasks} selectedId={selTask} onSelect={(id) => setSelTask(id)} onClear={clearTasks} />
  );
  // Open the deliberate LaunchModal for a finding follow-up (prefilled + parent link).
  const openLaunchForFinding = (type: string, opts: { objective?: string; params?: any } = {}) => {
    if (!selFinding) return;
    const t = detail.targets.find((x) => x.id === selFinding.target_id);
    if (t) setLaunchFor({ target: t, type, objective: opts.objective, params: opts.params, parentFindingId: selFinding.id });
  };

  const deleteEdge = async () => {
    if (!selEdge) return;
    if (!confirm(`Delete the ${selEdge.type} edge? This is permanent (re-create it with the Edge button to restore). To remove a node's edges reversibly, remove the node instead.`)) return;
    await api.deleteEdge(selEdge.id);
    setSelEdge(null);
    await load();
  };

  const renderDetail = () => {
    if (selEdge) {
      return (
        <div className="insp scroll fade-in">
          <div className="head"><Icon name="link" size={17} /><h3>{selEdge.type}</h3></div>
          <div className="chips"><span className="tag">{selEdge.src_kind} → {selEdge.dst_kind}</span>
            {selEdge.origin && <span className="tag">{selEdge.origin}</span>}
            {typeof selEdge.confidence === "number" && <span className="tag">conf {selEdge.confidence}</span>}</div>
          {Object.keys(selEdge.attrs || {}).length > 0 && (
            <><div className="sec">Attributes</div>
              <div className="kvs">{Object.entries(selEdge.attrs).map(([k, v]) => (
                <span key={k} style={{ display: "contents" }}><span className="k">{k}</span><code>{String(typeof v === "object" ? JSON.stringify(v) : v)}</code></span>
              ))}</div></>
          )}
          <div className="actions" style={{ marginTop: 12 }}>
            <button className="btn sm ghost danger" onClick={deleteEdge}><Icon name="x" size={12} /> Delete edge</button>
          </div>
        </div>
      );
    }
    if (tab === "campaigns" && selCampaign) {
      // The Artifacts / triage view for the selected campaign (crash dedup groups,
      // Reproduce/Minimize/Promote, source-mapped stacks, assurance chips, re-verify).
      return <ArtifactsViewLoader campaignId={selCampaign} onViewFinding={viewFinding} onOpenSource={revealSource} />;
    }
    if (selTask) return <TaskDetail taskId={selTask} onViewFinding={viewFinding} onRerun={pollThenReload} />;
    if (selNode) {
      const tgt = selNode.type === "target" ? detail.targets.find((t) => t.id === selNode.id) : undefined;
      const owner = selNode.type === "node" ? detail.targets.find((t) => t.id === selNode.target_id) : undefined;
      const allowed = tgt
        ? (caps.target?.[tgt.kind] ?? ["recon"])
        : (selNode.type === "node" ? (caps.node?.[selNode.node_type] ?? []) : []);
      const onLaunch = (type: string) => {
        if (tgt) setLaunchFor({ target: tgt, type });
        else if (owner) setLaunchFor({
          target: owner, type, params: { function: selNode.label },
          anchorKind: "node", anchorId: selNode.id,
        });
      };
      return <NodeInspector node={selNode} target={tgt} allowed={allowed} isMock={isMock} projectId={projectId}
                            onChanged={load} onViewFinding={viewFinding} onLaunch={onLaunch} />;
    }
    return <Inspector finding={selFinding} projectId={projectId} hypotheses={hypotheses} onChanged={load}
                      onLaunch={pollThenReload} onOpenLaunch={openLaunchForFinding} onViewTask={viewTask}
                      fuzzingEnabled={fuzzingEnabled} onOpenSource={revealSource}
                      onHighlight={(ids) => ids[0] && setSelGraphId(ids[0])} />;
  };

  return (
    <>
      <Header project={detail.project} cost={detail.cost} />
      <div className="workspace">
        <aside className="pane">
          <div className="pane-h">
            <Icon name="chip" size={14} /><span className="ttl">Targets</span>
            <span className="grow" />
            <button className="btn sm" onClick={() => fileRef.current?.click()}><Icon name="plus" size={12} /> Add</button>
            {ghidraBridge && (
              <button className="btn sm" title="Import a program open in Ghidra" onClick={() => setModal("ghidra")}>
                <Icon name="bulb" size={12} /> Ghidra
              </button>
            )}
            <input ref={fileRef} type="file" style={{ display: "none" }} onChange={onUpload} />
          </div>
          <div className="scroll">
            {roots.length === 0 && <div className="empty">No targets. Click <b>Add</b> to upload a binary or firmware image.</div>}
            {roots.map((t) => TreeRow(t, false))}
          </div>
        </aside>

        <section className="pane">
          <div className="toolbar">
            <div className="seg" style={{ display: "flex", gap: 2, border: "1px solid var(--border)", borderRadius: 6, padding: 2 }}>
              <button className={"btn sm" + (view === "graph" ? " primary" : " ghost")} title="Graph view" onClick={() => switchView("graph")}>
                <Icon name="hex" size={12} /> Graph
              </button>
              <button className={"btn sm" + (view === "source" ? " primary" : " ghost")} title="Source / IDE view (read-only)" onClick={() => switchView("source")}>
                <Icon name="doc" size={12} /> Source
              </button>
            </div>
            <div className="input" style={{ flex: 1 }}>
              <Icon name="search" size={14} />
              <input placeholder="Search functions, strings, findings…" value={q} onChange={(e) => doSearch(e.target.value)} />
            </div>
            <button className="btn sm" title="Add a node to the graph (function/symbol/hypothesis/…)" onClick={() => setModal("node")}><Icon name="plus" size={12} /> Node</button>
            <button className="btn sm" title="Connect two graph entities with an edge" onClick={() => setModal("edge")}><Icon name="link" size={13} /> Edge</button>
            <button className="btn sm" title="Markdown report of confirmed/reported findings" onClick={() => setModal("report")}><Icon name="doc" size={13} /> Report</button>
            <button className="btn sm" title="Diff two analysis runs over a target (added/dropped/changed findings)" onClick={() => setModal("compare")}><Icon name="refresh" size={13} /> Compare</button>
            <button className="btn sm" title="Link identical functions across targets (n-day clone detection)" onClick={linkSameCode}><Icon name="link" size={13} /> Same-code</button>
            <button className="btn sm" title="Merge duplicate binaries/nodes (e.g. sym.foo == foo)" onClick={mergeDupes}><Icon name="refresh" size={13} /> Merge dupes</button>
            <button className="btn sm" title="Download the project graph as JSON" onClick={exportGraph}><Icon name="doc" size={13} /> Export</button>
            <button className="btn sm" title="Egress audit log — every outbound action against a live target (allowed/denied)" onClick={() => setModal("egress")}><Icon name="shield" size={13} /> Audit</button>
            {busy && <span className="badge"><Icon name="refresh" size={12} className="spin" /> {busy}</span>}
          </div>
          {results && q.trim() && (
            <div className="search-pop">
              {results.targets?.length > 0 && <div className="res-head">Targets</div>}
              {(results.targets || []).map((t: any) => (
                <div className="res" key={t.id} onClick={() => { setResults(null); setQ(""); onGraphSelect(t.id, "target"); }}>
                  <Icon name={NODE_ICON[t.kind] || "binary"} size={13} /> {t.name} <span className="muted">{t.kind}{t.arch ? " · " + t.arch : ""}</span>
                </div>
              ))}
              {results.nodes.length > 0 && <div className="res-head">Graph nodes</div>}
              {results.nodes.map((n: any) => (
                <div className="res" key={n.id} onClick={() => { setResults(null); setQ(""); onGraphSelect(n.id, "node"); }}>
                  <Icon name={NODE_ICON[n.node_type] || "fn"} size={13} /> {n.name} <span className="muted">{n.node_type}</span>
                </div>
              ))}
              {results.findings.length > 0 && <div className="res-head">Findings</div>}
              {results.findings.map((f: any) => (
                <div className="res" key={f.id} onClick={() => { setResults(null); setQ(""); viewFinding(f.id); }}>
                  <span className={"chip sev-" + f.severity}>{f.severity}</span> {f.title}
                </div>
              ))}
              {results.findings.length === 0 && results.nodes.length === 0 && !(results.targets?.length) && <div className="res muted">No matches</div>}
              <div className="cov">{results.coverage?.note}</div>
            </div>
          )}
          {view === "source" ? (
            <div style={{ flex: 1, minHeight: 0, overflow: "hidden" }}>
              <SourceBrowser projectId={projectId!} open={openSource} buildEnabled={!!caps.features?.build}
                             buildFetchEnabled={!!caps.features?.build_fetch}
                             fuzzEnabled={!!caps.features?.fuzzing} sourceEditEnabled={!!caps.features?.source_edit}
                             onChanged={() => load()} />
            </div>
          ) : (
          <>
          <GraphView graph={graph} selectedId={selGraphId} onSelect={onGraphSelect}
                     onEdgeSelect={(e) => { setSelEdge(e); if (e) { setSelNode(null); setSelFinding(null); setSelTask(undefined); } }}
                     onDrawEdge={(src, dst) => { setEdgePrefill({ src, dst }); setModal("edge"); }} />
          {(() => {
            // Legend driven from the SAME color maps GraphView uses, showing only the
            // node/edge types actually present in this graph (single source of truth).
            const nodeKeys: { label: string; color: string }[] = [];
            const seen = new Set<string>();
            let hasFinding = false;
            for (const n of graph.nodes) {
              if (n.type === "finding") { hasFinding = true; continue; }
              const key = n.type === "target" ? (n.kind as string) : (n.node_type as string);
              const color = (n.type === "target" ? KIND[key] : NODE_T[key]);
              if (!key || seen.has(key) || !color) continue;
              seen.add(key);
              nodeKeys.push({ label: key === "firmware_image" ? "firmware" : key === "shared_library" ? "library" : key, color });
            }
            const edgeKeys = [...new Set(graph.edges.map((e) => e.type))]
              .filter((t) => EDGE_C[t]).map((t) => ({ label: t, color: EDGE_C[t] }));
            return (
              <div className="legend">
                {nodeKeys.map((k) => (
                  <span className="it" key={"n-" + k.label}><span className="sw" style={{ background: k.color }} />{k.label}</span>
                ))}
                {hasFinding && <span className="it"><span className="sw" style={{ background: "#ff5d6c", transform: "rotate(45deg)" }} />finding</span>}
                {edgeKeys.length > 0 && <span className="it sep" />}
                {edgeKeys.map((k) => (
                  <span className="it" key={"e-" + k.label}><span className="ln" style={{ background: k.color }} />{k.label}</span>
                ))}
              </div>
            );
          })()}
          </>
          )}
        </section>

        {!maxed && (
          <aside className="pane">
            {!detailBig && renderTabs()}
            {!detailBig && renderList()}
            <div className="detailbox" style={{
              borderTop: "1px solid var(--border)",
              flex: detailBig ? 1 : "none",
              maxHeight: detailBig ? "none" : "46%",
              display: "flex", flexDirection: "column", overflow: "hidden",
            }}>
              <div className="pane-h sub">
                <span className="ttl">Detail</span>
                <span className="grow" />
                <button className="btn sm icon ghost" title={detailBig ? "Collapse detail" : "Expand detail"}
                        onClick={() => setDetailBig((b) => !b)}>
                  <Icon name={detailBig ? "minus" : "fit"} size={13} />
                </button>
              </div>
              <div style={{ flex: 1, overflow: "auto", display: "flex", flexDirection: "column" }}>
                {renderDetail()}
              </div>
            </div>
          </aside>
        )}
      </div>

      {maxed && (
        <div className="maxscreen">
          <div className="pane">{renderTabs()}{renderList()}</div>
          <div className="pane"><div className="pane-h"><span className="ttl">Detail</span></div>{renderDetail()}</div>
        </div>
      )}

      {modal === "node" && <AddNodeModal projectId={projectId!} targets={detail.targets} onClose={() => setModal(null)} onDone={load} />}
      {modal === "edge" && <AddEdgeModal projectId={projectId!} graph={graph}
                                         prefillSrc={edgePrefill?.src} prefillDst={edgePrefill?.dst}
                                         onClose={() => { setModal(null); setEdgePrefill(null); }}
                                         onDone={load} />}
      {modal === "report" && <ReportModal projectId={projectId!} projectName={detail.project.name} onClose={() => setModal(null)} />}
      {modal === "egress" && <EgressPanel projectId={projectId!} onClose={() => setModal(null)} />}
      {modal === "compare" && <RunCompareModal targets={detail.targets} onClose={() => setModal(null)} />}
      {modal === "ghidra" && <GhidraImportModal projectId={projectId!} onClose={() => setModal(null)} onDone={load} />}
      {launchFor && (
        <LaunchModal target={launchFor.target} taskType={launchFor.type} isMock={isMock}
                     initialObjective={launchFor.objective} initialParams={launchFor.params}
                     parentFindingId={launchFor.parentFindingId}
                     anchorKind={launchFor.anchorKind} anchorId={launchFor.anchorId}
                     harnesses={detail.findings
                       .filter((f) => f.task_type === "harness_generation" && f.target_id === launchFor.target.id)
                       .map((f) => ({ id: f.id, label: f.title }))}
                     onClose={() => setLaunchFor(null)} onLaunched={pollThenReload} />
      )}
      {fuzzFor && (
        <FuzzModal projectId={projectId!} target={fuzzFor} targets={detail.targets} settings={settings}
                   onClose={() => setFuzzFor(null)}
                   onStarted={(cid) => { setFuzzFor(null); selectCampaign(cid); }} />
      )}
    </>
  );
}

// Loads a campaign by id and renders its Artifacts/triage view. Keeps the campaign
// fresh (polls while live) so newly-streamed crashes appear.
function ArtifactsViewLoader({ campaignId, onViewFinding, onOpenSource }: {
  campaignId: string;
  onViewFinding?: (fid: string) => void;
  onOpenSource?: (ref: { tree_id?: string; rel?: string; line?: number }) => void;
}) {
  const [c, setC] = useState<import("../api").Campaign | null>(null);
  useEffect(() => {
    let live = true;
    let t: any;
    // Poll only while the campaign is still live; stop the interval once it finalizes
    // (the closure read the seed `c`, so gate on the freshly-fetched status instead).
    const tick = () => api.campaign(campaignId).then((x) => {
      if (!live) return;
      setC(x);
      if (t && !["running", "building"].includes(x.status)) { clearInterval(t); t = undefined; }
    }).catch(() => {});
    tick();
    t = setInterval(tick, 3000);
    return () => { live = false; if (t) clearInterval(t); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [campaignId]);
  if (!c) return <div className="muted" style={{ padding: 12, fontSize: 12 }}>loading campaign…</div>;
  return <ArtifactsView campaign={c} onViewFinding={onViewFinding} onOpenSource={onOpenSource} />;
}
