import { useCallback, useEffect, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import { api, Finding, Graph, ProjectDetail, TargetNode } from "../api";
import Header from "../components/Header";
import GraphView from "../components/GraphView";
import FindingsPanel from "../components/FindingsPanel";
import Inspector from "../components/Inspector";
import { TasksPanel, TaskDetail } from "../components/TasksPanel";
import Launcher from "../components/Launcher";
import { AddNodeModal, AddEdgeModal } from "../components/Author";
import { Icon, NODE_ICON } from "../components/Icon";

export default function Workspace() {
  const { projectId } = useParams();
  const [detail, setDetail] = useState<ProjectDetail | null>(null);
  const [graph, setGraph] = useState<Graph | null>(null);
  const [caps, setCaps] = useState<Record<string, Record<string, string[]>>>({});
  const [selFinding, setSelFinding] = useState<Finding | null>(null);
  const [selGraphId, setSelGraphId] = useState<string>();
  const [busy, setBusy] = useState<string>();
  const [tab, setTab] = useState<"findings" | "tasks">("findings");
  const [tasks, setTasks] = useState<any[]>([]);
  const [selTask, setSelTask] = useState<string>();
  const [q, setQ] = useState("");
  const [results, setResults] = useState<any | null>(null);
  const [modal, setModal] = useState<"node" | "edge" | null>(null);
  const searchTimer = useRef<any>();
  const fileRef = useRef<HTMLInputElement>(null);

  const load = useCallback(async () => {
    if (!projectId) return;
    const [d, g, tk] = await Promise.all([api.project(projectId), api.graph(projectId), api.projectTasks(projectId)]);
    setDetail(d); setGraph(g); setTasks(tk);
  }, [projectId]);

  useEffect(() => { load(); api.capabilities().then(setCaps).catch(() => {}); }, [load]);

  const pollThenReload = async (taskId: string) => {
    setBusy("running task…");
    for (let i = 0; i < 60; i++) {
      await new Promise((r) => setTimeout(r, 700));
      const t = await api.task(taskId);
      if (t.status !== "queued" && t.status !== "running") break;
    }
    setBusy(undefined);
    await load();
    if (selFinding) api.finding(selFinding.id).then(setSelFinding).catch(() => {});
  };

  const launch = async (target: TargetNode, type: string, scenario?: string) => {
    const body: any = { target_id: target.id, type };
    if (scenario) body.mock_scenario = scenario;
    const { task_id } = await api.launch(body);
    pollThenReload(task_id);
  };
  const viewTask = (tid: string) => { setSelTask(tid); setTab("tasks"); };
  const viewFinding = (fid: string) => { setSelTask(undefined); api.finding(fid).then((f) => { setSelFinding(f); setSelGraphId(f.id); }); };
  const bulk = async (ids: string[], status: string) => { await api.bulkStatus(ids, status); await load(); };

  const doSearch = (text: string) => {
    setQ(text);
    clearTimeout(searchTimer.current);
    if (!text.trim()) { setResults(null); return; }
    searchTimer.current = setTimeout(() => { if (projectId) api.search(projectId, text).then(setResults).catch(() => {}); }, 200);
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

  const TreeRow = (t: TargetNode, child: boolean) => {
    const allowed = caps.target?.[t.kind] ?? ["recon"];
    return (
      <div key={t.id}>
        <div className={"tree-row" + (child ? " child" : "") + (selGraphId === t.id ? " sel" : "")}
             onClick={() => setSelGraphId(t.id)}>
          <div className="nm"><Icon name={NODE_ICON[t.kind] || "binary"} size={15} /> {t.name}</div>
          <div className="mt">{t.kind}{t.arch ? " · " + t.arch : ""}</div>
          <Launcher allowed={allowed} isMock={isMock} onLaunch={(type, sc) => launch(t, type, sc)} />
        </div>
        {childrenOf(t.id).map((c) => TreeRow(c, true))}
      </div>
    );
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
            <input ref={fileRef} type="file" style={{ display: "none" }} onChange={onUpload} />
          </div>
          <div className="scroll">
            {roots.length === 0 && <div className="empty">No targets. Click <b>Add</b> to upload a binary or firmware image.</div>}
            {roots.map((t) => TreeRow(t, false))}
          </div>
        </aside>

        <section className="pane">
          <div className="toolbar">
            <div className="input" style={{ flex: 1 }}>
              <Icon name="search" size={14} />
              <input placeholder="Search functions, strings, findings…" value={q} onChange={(e) => doSearch(e.target.value)} />
            </div>
            <button className="btn sm" onClick={() => setModal("node")}><Icon name="plus" size={12} /> Node</button>
            <button className="btn sm" onClick={() => setModal("edge")}><Icon name="link" size={13} /> Edge</button>
            <button className="btn sm" onClick={() => window.open(api.reportUrl(projectId!), "_blank")}><Icon name="doc" size={13} /> Report</button>
            <button className="btn sm" onClick={linkSameCode}><Icon name="link" size={13} /> Same-code</button>
            {busy && <span className="badge"><Icon name="refresh" size={12} className="spin" /> {busy}</span>}
          </div>
          {results && q.trim() && (
            <div className="search-pop">
              {results.findings.map((f: any) => (
                <div className="res" key={f.id} onClick={() => { setResults(null); setQ(""); viewFinding(f.id); }}>
                  <span className={"chip sev-" + f.severity}>{f.severity}</span> {f.title}
                </div>
              ))}
              {results.nodes.map((n: any) => (
                <div className="res" key={n.id} onClick={() => { setResults(null); setQ(""); setSelGraphId(n.id); }}>
                  <Icon name={NODE_ICON[n.node_type] || "fn"} size={13} /> {n.name} <span className="muted">{n.node_type}</span>
                </div>
              ))}
              {results.findings.length === 0 && results.nodes.length === 0 && <div className="res muted">No matches</div>}
              <div className="cov">{results.coverage?.note}</div>
            </div>
          )}
          <GraphView graph={graph} selectedId={selGraphId}
                     onSelect={(id, type) => {
                       setSelGraphId(id);
                       if (type === "finding") { const f = detail.findings.find((x) => x.id === id); if (f) { setSelTask(undefined); setSelFinding(f); } }
                     }} />
          <div className="legend">
            {[["firmware", "#a371f7"], ["executable", "#6aa3ff"], ["library", "#39c5cf"], ["function", "#7ee787"], ["finding", "#ff5d6c"]].map(([l, c]) => (
              <span className="it" key={l}><span className="sw" style={{ background: c as string }} />{l}</span>
            ))}
          </div>
        </section>

        <aside className="pane">
          <div className="pane-h">
            <button className={"btn sm" + (tab === "findings" ? " primary" : " ghost")} onClick={() => setTab("findings")}>
              <Icon name="bug" size={12} /> Findings · {detail.findings.length}
            </button>
            <button className={"btn sm" + (tab === "tasks" ? " primary" : " ghost")} onClick={() => setTab("tasks")}>
              <Icon name="task" size={12} /> Tasks · {tasks.length}
            </button>
          </div>
          {tab === "findings" ? (
            <FindingsPanel findings={detail.findings} targets={detail.targets} selectedId={selFinding?.id} onBulk={bulk}
                           onSelect={(f) => { setSelTask(undefined); setSelFinding(f); setSelGraphId(f.id); }} />
          ) : (
            <TasksPanel tasks={tasks} selectedId={selTask} onSelect={setSelTask} />
          )}
          <div style={{ borderTop: "1px solid var(--border)", maxHeight: "46%", display: "flex", flexDirection: "column", overflow: "hidden" }}>
            {selTask ? (
              <TaskDetail taskId={selTask} onViewFinding={viewFinding} onRerun={pollThenReload} />
            ) : (
              <Inspector finding={selFinding} onChanged={load} onLaunch={pollThenReload}
                         onViewTask={viewTask} onHighlight={(ids) => ids[0] && setSelGraphId(ids[0])} />
            )}
          </div>
        </aside>
      </div>
      {modal === "node" && <AddNodeModal projectId={projectId!} targets={detail.targets} onClose={() => setModal(null)} onDone={load} />}
      {modal === "edge" && <AddEdgeModal projectId={projectId!} graph={graph} onClose={() => setModal(null)} onDone={load} />}
    </>
  );
}
