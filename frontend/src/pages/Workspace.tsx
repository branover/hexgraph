import { useCallback, useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { api, Finding, Graph, ProjectDetail, TargetNode } from "../api";
import Header from "../components/Header";
import GraphView from "../components/GraphView";
import FindingsPanel from "../components/FindingsPanel";
import Inspector from "../components/Inspector";
import { TasksPanel, TaskDetail } from "../components/TasksPanel";

const SCENARIOS = ["(default)", "critical_overflow", "no_findings", "malformed_then_valid", "error_rate_limit"];

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

  const load = useCallback(async () => {
    if (!projectId) return;
    const [d, g, tk] = await Promise.all([api.project(projectId), api.graph(projectId), api.projectTasks(projectId)]);
    setDetail(d); setGraph(g); setTasks(tk);
  }, [projectId]);

  const viewTask = (tid: string) => { setSelTask(tid); setTab("tasks"); };
  const viewFinding = (fid: string) => { setSelTask(undefined); api.finding(fid).then((f) => { setSelFinding(f); setSelGraphId(f.id); }); };
  const bulk = async (ids: string[], status: string) => { await api.bulkStatus(ids, status); await load(); };

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

  const launch = async (target: TargetNode, type: string, scenario: string) => {
    const body: any = { target_id: target.id, type };
    if (scenario !== "(default)") body.mock_scenario = scenario;
    const { task_id } = await api.launch(body);
    pollThenReload(task_id);
  };

  if (!detail || !graph) return <><Header /><main>Loading…</main></>;

  const roots = detail.targets.filter((t) => !t.parent_id);
  const childrenOf = (id: string) => detail.targets.filter((t) => t.parent_id === id);

  const TreeRow = (t: TargetNode, child: boolean) => {
    const allowed = caps.target?.[t.kind] ?? ["recon"];
    return (
      <div key={t.id}>
        <div className={"tree-row" + (child ? " child" : "") + (selGraphId === t.id ? " sel" : "")}
             onClick={() => setSelGraphId(t.id)}>
          <div className="nm">{t.name}</div>
          <div className="mt">{t.kind}{t.arch ? " · " + t.arch : ""}</div>
          <Launcher target={t} allowed={allowed} onLaunch={launch} />
        </div>
        {childrenOf(t.id).map((c) => TreeRow(c, true))}
      </div>
    );
  };

  return (
    <>
      <Header subtitle={detail.project.name} cost={detail.cost} />
      <div className="workspace">
        <aside className="pane">
          <h2>Targets</h2>
          <div className="scroll">{roots.map((t) => TreeRow(t, false))}</div>
        </aside>
        <section className="pane">
          <h2>Graph {busy && <span className="muted">· {busy}</span>}</h2>
          <GraphView graph={graph} selectedId={selGraphId}
                     onSelect={(id, type) => {
                       setSelGraphId(id);
                       if (type === "finding") { const f = detail.findings.find((x) => x.id === id); if (f) setSelFinding(f); }
                     }} />
          <div className="legend">
            <span><span className="dot" style={{ background: "#a371f7" }} />firmware</span>
            <span><span className="dot" style={{ background: "#5aa2ff" }} />executable</span>
            <span><span className="dot" style={{ background: "#39c5cf" }} />library</span>
            <span><span className="dot" style={{ background: "#7ee787" }} />function</span>
            <span><span className="dot" style={{ background: "#f85149" }} />finding</span>
          </div>
        </section>
        <aside className="pane">
          <div className="toolbar" style={{ paddingBottom: 0 }}>
            <button className={"btn sm" + (tab === "findings" ? " primary" : "")} onClick={() => setTab("findings")}>Findings · {detail.findings.length}</button>
            <button className={"btn sm" + (tab === "tasks" ? " primary" : "")} onClick={() => setTab("tasks")}>Tasks · {tasks.length}</button>
          </div>
          {tab === "findings" ? (
            <FindingsPanel findings={detail.findings} targets={detail.targets}
                           selectedId={selFinding?.id} onBulk={bulk}
                           onSelect={(f) => { setSelTask(undefined); setSelFinding(f); setSelGraphId(f.id); }} />
          ) : (
            <TasksPanel tasks={tasks} selectedId={selTask} onSelect={setSelTask} />
          )}
          <div style={{ borderTop: "1px solid var(--border)", maxHeight: "44%", display: "flex", flexDirection: "column" }}>
            {selTask ? (
              <TaskDetail taskId={selTask} onViewFinding={viewFinding} onRerun={pollThenReload} />
            ) : (
              <Inspector finding={selFinding} onChanged={load} onLaunch={pollThenReload}
                         onViewTask={viewTask} onHighlight={(ids) => ids[0] && setSelGraphId(ids[0])} />
            )}
          </div>
        </aside>
      </div>
    </>
  );
}

function Launcher({ target, allowed, onLaunch }: { target: TargetNode; allowed: string[]; onLaunch: (t: TargetNode, type: string, sc: string) => void }) {
  const [type, setType] = useState(allowed[0] ?? "recon");
  const [sc, setSc] = useState("(default)");
  return (
    <div className="toolbar" style={{ padding: "6px 0 0" }} onClick={(e) => e.stopPropagation()}>
      <select value={type} onChange={(e) => setType(e.target.value)}>
        {allowed.map((a) => <option key={a} value={a}>{a}</option>)}
      </select>
      <select value={sc} onChange={(e) => setSc(e.target.value)} title="mock scenario">
        {SCENARIOS.map((s) => <option key={s} value={s}>{s}</option>)}
      </select>
      <button className="btn sm primary" onClick={() => onLaunch(target, type, sc)}>Run</button>
    </div>
  );
}
