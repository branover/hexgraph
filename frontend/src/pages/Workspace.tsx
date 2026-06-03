import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import { api, Finding, Graph, GraphNode, ProjectDetail, SavedLens, SettingsView, TargetNode } from "../api";
import Header from "../components/Header";
import GraphView, { NODE_T, EDGE_C, KIND, NODE_SHAPE, FocusSpec, GroupBy } from "../components/GraphView";
import TableView from "../components/TableView";
import MatrixView from "../components/MatrixView";
import {
  LayerState, FilterState, defaultLayers, defaultFilters, anyFilterActive,
} from "../components/graphLayers";
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
import { useWorkspaceLayout, useDrag } from "../hooks/useWorkspaceLayout";

// A reversible focus frame (design §4.2): the anchor node, the hop radius of its focused
// neighborhood, and a human label for the breadcrumb crumb.
interface FocusFrame { id: string; hop: number; label: string }

export default function Workspace() {
  const { projectId } = useParams();
  const [detail, setDetail] = useState<ProjectDetail | null>(null);
  const [graph, setGraph] = useState<Graph | null>(null);
  // ── Skeleton-first loading (real-firmware scale, ~13k nodes) ────────────────────────
  // Above the backend's size threshold we DON'T ship the whole graph: we load the
  // SKELETON (rooms + sockets + aggregated meta-edges), then merge a room's interior into
  // `graph` only when the user expands it. So the browser never holds ~13k nodes at once.
  const [skeletonMode, setSkeletonMode] = useState(false);
  const [loadedRooms, setLoadedRooms] = useState<Set<string>>(new Set());
  const [roomLoading, setRoomLoading] = useState<Set<string>>(new Set());
  const [caps, setCaps] = useState<{ target?: Record<string, string[]>; node?: Record<string, string[]>; edge?: Record<string, string[]>; features?: { build?: boolean; build_fetch?: boolean; source_edit?: boolean; fuzzing?: boolean; poc?: boolean } }>({});
  const [selFinding, setSelFinding] = useState<Finding | null>(null);
  const [selNode, setSelNode] = useState<GraphNode | null>(null);
  const [selEdge, setSelEdge] = useState<any | null>(null);
  const [selGraphId, setSelGraphId] = useState<string>();
  // Legend isolate-by-type: a hovered chip previews (transient), a clicked chip pins.
  // The pinned type wins; otherwise the hovered one drives the graph dim.
  const [hoverType, setHoverType] = useState<string | null>(null);
  const [pinType, setPinType] = useState<string | null>(null);
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
  // Center-pane mode switch (Map ⇆ Graph ⇆ Table ⇆ Matrix ⇆ Source) — a mode, not a route,
  // so selection state is shared and finding→source jump is instantaneous (design §6.1).
  // Map/Table/Matrix are Phase-5 complementary views; Graph stays the default.
  const VIEWS = ["map", "graph", "table", "matrix", "source"] as const;
  type ViewMode = typeof VIEWS[number];
  const [view, setView] = useState<ViewMode>(() => {
    const v = new URLSearchParams(window.location.search).get("view") as ViewMode | null;
    return v && (VIEWS as readonly string[]).includes(v) ? v : "graph";
  });
  // ── Phase 5: layers / filters / grouping / scope are lifted HERE so the view switcher,
  // the Table/Matrix views, and Saved Lenses all share one coherent presentation state.
  const [layers, setLayers] = useState<LayerState>(defaultLayers);
  const [filters, setFilters] = useState<FilterState>(defaultFilters);
  const [groupBy, setGroupBy] = useState<GroupBy>("target");
  const [findingsLayer, setFindingsLayer] = useState<"all" | "unresolved" | "none">("all");
  // panels-drive-scope (§6.3): a target id the center view is scoped to (set by a left-tree
  // row click). Distinct from `focus` (the finer node-neighborhood gesture).
  const [scope, setScope] = useState<string | null>(null);
  // Saved Lenses (§6.2): named snapshots persisted in settings.json (no DB change).
  const [lenses, setLenses] = useState<SavedLens[]>([]);
  const [lensMenuOpen, setLensMenuOpen] = useState(false);
  const [activeLens, setActiveLens] = useState<string | null>(
    new URLSearchParams(window.location.search).get("lens") || null);
  const [openSource, setOpenSource] = useState<{ treeId?: string; rel?: string; line?: number } | null>(null);
  // Phase-2 focus stack (design §4.2): focusing a node pushes a reversible frame; the
  // breadcrumb trail lets you pop back. The TOP frame is the live focus driving the graph.
  // Seeded from the URL (?focus=<id>&hop=N) so a focused view is shareable + reload-restorable.
  const [focusStack, setFocusStack] = useState<FocusFrame[]>(() => {
    const sp = new URLSearchParams(window.location.search);
    const id = sp.get("focus");
    if (!id) return [];
    const hop = Math.max(1, Math.min(3, Number(sp.get("hop")) || 1));
    return [{ id, hop, label: id.slice(0, 8) }];
  });
  const searchTimer = useRef<any>();
  const fileRef = useRef<HTMLInputElement>(null);
  // Apply a deep-linked ?lens=<name> exactly once on first load (the live applyLens is
  // defined below, so route through a ref the settings-load effect can call).
  const lensApplied = useRef(false);
  const applyLensRef = useRef<((l: SavedLens) => void) | null>(null);

  // ── Resizable / collapsible workspace layout (persisted to localStorage). The grid
  // columns are driven by the persisted widths; collapsing a side pane hands its space
  // to the center graph. Each drag captures the size at grab time so the delta resolves
  // cleanly even if React re-renders mid-drag.
  const { layout, update: setLayout, toggleLeft, toggleRight } = useWorkspaceLayout();
  const dragStart = useRef(0);
  const rightPaneRef = useRef<HTMLElement>(null);
  const [dragging, setDragging] = useState<"left" | "right" | "detail" | null>(null);
  const onDragLeft = useDrag({
    axis: "x",
    onStart: () => { dragStart.current = layout.leftW; setDragging("left"); },
    onDelta: (d) => setLayout({ leftW: dragStart.current + d }),
    onEnd: () => setDragging(null),
  });
  const onDragRight = useDrag({
    axis: "x",
    // The right divider sits to the LEFT of the right pane, so dragging right SHRINKS it.
    onStart: () => { dragStart.current = layout.rightW; setDragging("right"); },
    onDelta: (d) => setLayout({ rightW: dragStart.current - d }),
    onEnd: () => setDragging(null),
  });
  const onDragDetail = useDrag({
    axis: "y",
    onStart: () => { dragStart.current = layout.detailFrac; setDragging("detail"); },
    onDelta: (d) => {
      const h = rightPaneRef.current?.clientHeight || 1;
      // Dragging the DETAIL divider DOWN shrinks the detail section (it's the bottom region).
      setLayout({ detailFrac: dragStart.current - d / h });
    },
    onEnd: () => setDragging(null),
  });

  const load = useCallback(async () => {
    if (!projectId) return;
    // Cheap size probe FIRST so we never blind-fetch ~13k nodes. Above the threshold,
    // load the skeleton (rooms only) and lazily fetch interiors on expand; otherwise the
    // full graph exactly as before (SMALL/MEDIUM/LARGE-but-bounded behave identically).
    const [d, sz, tk] = await Promise.all([
      api.project(projectId), api.graphSize(projectId), api.projectTasks(projectId),
    ]);
    if (sz.skeleton_recommended) {
      const sk = await api.graphSkeleton(projectId);
      setSkeletonMode(true);
      setLoadedRooms(new Set());
      setRoomLoading(new Set());
      setGraph({ project_id: sk.project_id, nodes: sk.nodes, edges: sk.edges });
    } else {
      const g = await api.graph(projectId);
      setSkeletonMode(false);
      setLoadedRooms(new Set());
      setGraph(g);
    }
    setDetail(d); setTasks(tk);
    // Refresh the open detail with the reloaded data so triage (Accept/Dismiss,
    // status pills, annotations) re-renders instead of showing a stale finding.
    setSelFinding((prev) => (prev ? d.findings.find((f) => f.id === prev.id) ?? prev : prev));
  }, [projectId]);

  // ── Skeleton-first: fetch ONE room's interior on demand and merge it into `graph`.
  // The room's target node already lives in the skeleton; merge dedups by id. The
  // interior's functions/strings/findings + intra-room edges (and edges to the shared
  // sockets) are appended; cross-room meta-edges from the skeleton stay as-is. Idempotent
  // (a second expand of the same room is a no-op).
  const expandRoom = useCallback(async (targetId: string) => {
    if (!projectId) return;
    setLoadedRooms((prev) => {
      if (prev.has(targetId)) return prev;          // already loaded — nothing to fetch
      // mark loading + kick the fetch (guarded against double-fetch by the loaded set)
      setRoomLoading((l) => new Set(l).add(targetId));
      api.graphRoom(projectId, targetId).then((room) => {
        setGraph((g) => {
          if (!g) return g;
          const haveNodes = new Set(g.nodes.map((n) => n.id));
          const haveEdges = new Set(g.edges.map((e) => e.id));
          const newNodes = room.nodes.filter((n) => !haveNodes.has(n.id));
          const newEdges = room.edges.filter((e) => !haveEdges.has(e.id));
          if (!newNodes.length && !newEdges.length) return g;
          return { ...g, nodes: [...g.nodes, ...newNodes], edges: [...g.edges, ...newEdges] };
        });
      }).finally(() => {
        setRoomLoading((l) => { const x = new Set(l); x.delete(targetId); return x; });
      });
      return new Set(prev).add(targetId);
    });
  }, [projectId]);

  useEffect(() => {
    load();
    api.capabilities().then(setCaps).catch(() => {});
    api.getSettings().then((s) => {
      setSettings(s);
      const g = s.settings.features.ghidra;
      setGhidraBridge(g.enabled && g.mode === "bridge");
      setFuzzingEnabled(Boolean(s.settings.features.fuzzing?.enabled));
      const ls = s.settings.ui?.lenses || [];
      setLenses(ls);
      // Deep-link: apply ?lens=<name> once on load so a saved view is shareable/restorable.
      if (!lensApplied.current && activeLens) {
        const l = ls.find((x) => x.name === activeLens);
        if (l) { lensApplied.current = true; applyLensRef.current?.(l); }
      }
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

  // ── Phase 2: the focus stack (design §4.2 — reversible navigation) ────────────────────
  // The TOP frame drives the graph (anchor + hop). Focusing pushes; a crumb pops; clear
  // empties. The focus id + hop are serialized to the URL so the view is shareable/restorable.
  const focus = focusStack.length ? { id: focusStack[focusStack.length - 1].id, hop: focusStack[focusStack.length - 1].hop } as FocusSpec : null;
  const labelFor = (id: string): string => {
    const n = graph?.nodes.find((x) => x.id === id);
    if (n) return n.label;
    const t = detail?.targets.find((x) => x.id === id);
    if (t) return t.name;
    const f = detail?.findings.find((x) => x.id === id);
    if (f) return f.title;
    return id.slice(0, 8);
  };
  // Focus a node: ensure Graph view, push (or replace-top if same anchor — e.g. hop change),
  // select it, and serialize. This is the single entry every focus path routes through
  // (double-tap, search, the verb menu, hop +/-).
  const focusOn = (id: string, hop = 1) => {
    const h = Math.max(1, Math.min(3, hop));
    setView("graph"); setSelTask(undefined); setSelCampaign(undefined);
    onGraphSelect(id, (graph?.nodes.find((n) => n.id === id)?.type === "target") ? "target" : "node");
    setFocusStack((prev) => {
      const top = prev[prev.length - 1];
      const frame: FocusFrame = { id, hop: h, label: labelFor(id) };
      // same anchor → replace top (a hop change / re-focus), never grow the stack uselessly
      if (top && top.id === id) return [...prev.slice(0, -1), frame];
      return [...prev, frame];
    });
    setUrl({ focus: id, hop: h > 1 ? String(h) : undefined });
  };
  // Pop back to a given depth (a breadcrumb click): index -1 = Overview (clear).
  const popFocusTo = (index: number) => {
    setFocusStack((prev) => {
      const next = index < 0 ? [] : prev.slice(0, index + 1);
      const top = next[next.length - 1];
      setUrl({ focus: top?.id, hop: top && top.hop > 1 ? String(top.hop) : undefined });
      return next;
    });
  };
  const clearFocus = () => popFocusTo(-1);

  const switchView = (v: ViewMode) => {
    setView(v);
    setUrl({ view: v === "graph" ? undefined : v });
  };

  // ── Phase 5: panels-drive-scope (§6.3) ────────────────────────────────────────────────
  // Clicking a left-tree target row SELECTS it (today's behavior) AND scopes the center view
  // to it (a toggle: clicking the scoped target again clears scope). A no-op duplication of
  // the panels — they DRIVE, the center DISPLAYS.
  const scopeToTarget = (id: string) => {
    setScope((cur) => (cur === id ? null : id));
    setActiveLens(null);
  };

  // ── Phase 5: Saved Lenses (§6.2) ──────────────────────────────────────────────────────
  // A lens captures {view, scope, group-by, findings, layers, filters, focus}. Apply restores
  // them; save snapshots the current state; delete drops it. Persisted via the settings API.
  const persistLenses = async (next: SavedLens[]) => {
    setLenses(next);
    try { await api.patchSettings({ "ui.lenses": next }); }
    catch (e: any) { alert("Could not save lens: " + (e?.message || e)); }
  };
  const currentLensSnapshot = (name: string): SavedLens => ({
    name, view, scope, groupBy, findings: findingsLayer,
    layers: { nodes: { ...layers.nodes }, edges: { ...layers.edges } },
    filters: { severity: filters.severity, targets: [...filters.targets], findingType: filters.findingType, mode: filters.mode },
    focus: focus?.id ?? null, hop: focus?.hop,
  });
  const saveLens = async () => {
    const name = window.prompt("Name this lens (a saved view — group-by + filters + layers + focus):");
    if (!name?.trim()) return;
    const snap = currentLensSnapshot(name.trim());
    const next = [...lenses.filter((l) => l.name !== snap.name), snap];
    await persistLenses(next);
    setActiveLens(snap.name);
    setUrl({ lens: snap.name });
    setLensMenuOpen(false);
  };
  const deleteLens = async (name: string) => {
    await persistLenses(lenses.filter((l) => l.name !== name));
    if (activeLens === name) { setActiveLens(null); setUrl({ lens: undefined }); }
  };
  const applyLens = (l: SavedLens) => {
    setView((l.view as ViewMode) || "graph");
    setScope(l.scope ?? null);
    setGroupBy((l.groupBy as GroupBy) || "target");
    setFindingsLayer(l.findings || "all");
    setLayers(l.layers ? { nodes: { ...defaultLayers().nodes, ...(l.layers.nodes || {}) }, edges: { ...defaultLayers().edges, ...(l.layers.edges || {}) } } : defaultLayers());
    setFilters(l.filters ? { ...defaultFilters(), ...l.filters } : defaultFilters());
    if (l.focus) setFocusStack([{ id: l.focus, hop: Math.max(1, Math.min(3, l.hop || 1)), label: labelFor(l.focus) }]);
    else setFocusStack([]);
    setActiveLens(l.name);
    setUrl({ view: (l.view && l.view !== "graph") ? l.view : undefined, lens: l.name,
             focus: l.focus || undefined, hop: l.focus && (l.hop || 1) > 1 ? String(l.hop) : undefined });
    setLensMenuOpen(false);
  };
  applyLensRef.current = applyLens;
  // Any manual change to a presentation facet diverges from a saved lens → drop the badge.
  const onLayers = (l: LayerState) => { setLayers(l); setActiveLens(null); };
  const onFilters = (f: FilterState) => { setFilters(f); setActiveLens(null); };
  const onGroupBy = (g: GroupBy) => { setGroupBy(g); setActiveLens(null); };
  const onFindingsLayer = (f: "all" | "unresolved" | "none") => { setFindingsLayer(f); setActiveLens(null); };
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
    return <><Header /><div className="workspace skel-grid">{[0, 1, 2].map((i) => <div key={i} className="pane skel" />)}</div></>;
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
        <div className={"tree-row" + (child ? " child" : "") + (selGraphId === t.id ? " sel" : "") + (scope === t.id ? " scoped" : "")}
             onClick={() => { onGraphSelect(t.id, "target"); if (view !== "source" && view !== "matrix") scopeToTarget(t.id); }}>
          <div className="nm">
            <Icon name={NODE_ICON[t.kind] || "binary"} size={15} /> {t.name}
            {fc && <span className={"tbadge" + (fc.hot ? " hot" : "")} style={{ marginLeft: "auto" }}>{fc.n}</span>}
          </div>
          <div className="mt">{t.kind}{t.arch ? " · " + t.arch : ""}</div>
          {/* Action cluster: Run (+ its in-menu Fuzz row) and Remove, in one aligned top-right
              row. The standalone fuzz button was removed — it duplicated the Launcher menu's
              "Fuzz campaign…" row and the two absolutely-positioned controls collided (issue 7). */}
          <div className="row-actions" onClick={(e) => e.stopPropagation()}>
            <Launcher allowed={allowed} onChoose={(type) => setLaunchFor({ target: t, type })}
                      onFuzz={caps.features?.fuzzing && t.kind !== "firmware_image" ? () => setFuzzFor(t) : undefined} />
            <button className="btn sm icon ghost trash" title="Remove target (hides its nodes/findings)"
                    onClick={(e) => { e.stopPropagation(); removeTarget(t); }}>
              <Icon name="x" size={12} />
            </button>
          </div>
        </div>
        {childrenOf(t.id).map((c) => TreeRow(c, true))}
      </div>
    );
  };

  const fuzzingFeature = !!caps.features?.fuzzing;
  const renderTabs = (collapsible = false) => (
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
      {collapsible && (
        <button className="btn sm icon ghost pane-collapse" title="Collapse panel" onClick={toggleRight}>
          <span style={{ transform: "rotate(-90deg)", display: "inline-flex" }}><Icon name="chevron" size={13} /></span>
        </button>
      )}
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
      const fuzzTarget = tgt || owner;
      const onFuzz = caps.features?.fuzzing && fuzzTarget && fuzzTarget.kind !== "firmware_image"
        ? () => setFuzzFor(fuzzTarget) : undefined;
      return <NodeInspector node={selNode} target={tgt} allowed={allowed} isMock={isMock} projectId={projectId}
                            onChanged={load} onViewFinding={viewFinding} onLaunch={onLaunch} onFuzz={onFuzz} />;
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
        {layout.leftCollapsed ? (
          <div className="pane-edge" title="Show Targets panel" onClick={toggleLeft}>
            <span className="arrow" style={{ transform: "rotate(-90deg)", display: "inline-flex" }}><Icon name="chevron" size={13} /></span>
            <span className="lbl">Targets</span>
            <span className="arrow" style={{ display: "inline-flex" }}><Icon name="chip" size={13} /></span>
          </div>
        ) : (
        <aside className="pane side" style={{ width: layout.leftW }}>
          <div className="pane-h">
            <Icon name="chip" size={14} /><span className="ttl">Targets</span>
            <span className="grow" />
            <button className="btn sm" onClick={() => fileRef.current?.click()}><Icon name="plus" size={12} /> Add</button>
            {ghidraBridge && (
              <button className="btn sm" title="Import a program open in Ghidra" onClick={() => setModal("ghidra")}>
                <Icon name="bulb" size={12} /> Ghidra
              </button>
            )}
            <button className="btn sm icon ghost pane-collapse" title="Collapse Targets panel" onClick={toggleLeft}>
              <span style={{ transform: "rotate(90deg)", display: "inline-flex" }}><Icon name="chevron" size={13} /></span>
            </button>
            <input ref={fileRef} type="file" style={{ display: "none" }} onChange={onUpload} />
          </div>
          <div className="scroll">
            {roots.length === 0 && <div className="empty">No targets. Click <b>Add</b> to upload a binary or firmware image.</div>}
            {roots.map((t) => TreeRow(t, false))}
          </div>
        </aside>
        )}

        {!layout.leftCollapsed && (
          <div className={"wsplit" + (dragging === "left" ? " dragging" : "")} onPointerDown={onDragLeft}
               role="separator" aria-orientation="vertical"
               title="Drag to resize · double-click to collapse" onDoubleClick={toggleLeft}>
            <span className="grip"><i /><i /><i /></span>
          </div>
        )}

        <section className="pane center">
          <div className="toolbar">
            {/* ── Phase 5: center-pane view switcher (§6.1) — Map / Graph / Table / Matrix /
                Source. Graph stays the obvious DEFAULT; Map = the §1 skeleton given a name;
                Table/Matrix are the scalable alternatives for dense targets. */}
            <div className="seg tgroup" style={{ gap: 2, border: "1px solid var(--border)", borderRadius: 7, padding: 2 }}>
              <button className={"btn sm" + (view === "map" ? " primary" : " ghost")} title="Map — finding-weighted territory overview (the skeleton)" onClick={() => switchView("map")}>
                <Icon name="fit" size={12} /> Map
              </button>
              <button className={"btn sm" + (view === "graph" ? " primary" : " ghost")} title="Graph view (default)" onClick={() => switchView("graph")}>
                <Icon name="hex" size={12} /> Graph
              </button>
              <button className={"btn sm" + (view === "table" ? " primary" : " ghost")} title="Table — sortable/filterable nodes & edges (scales to PATHOLOGICAL)" onClick={() => switchView("table")}>
                <Icon name="doc" size={12} /> Table
              </button>
              <button className={"btn sm" + (view === "matrix" ? " primary" : " ghost")} title="Matrix — cross-target relationship adjacency (dense N×N)" onClick={() => switchView("matrix")}>
                <Icon name="copy" size={12} /> Matrix
              </button>
              <button className={"btn sm" + (view === "source" ? " primary" : " ghost")} title="Source / IDE view (read-only)" onClick={() => switchView("source")}>
                <Icon name="doc" size={12} /> Source
              </button>
            </div>
            {/* ── Phase 5: Saved Lenses (§6.2) — named view snapshots in settings.json. */}
            <div className="tgroup" style={{ position: "relative" }}>
              <button className={"btn sm" + (activeLens ? " primary" : "")} title="Saved lenses — named views (group-by + filters + layers + focus)"
                      onClick={() => setLensMenuOpen((o) => !o)}>
                <Icon name="sliders" size={12} /> {activeLens || "Lenses"} <Icon name="chevron" size={10} />
              </button>
              {lensMenuOpen && (
                <div className="menu" style={{ left: 0, top: 34, minWidth: 220, zIndex: 30 }} onMouseLeave={() => setLensMenuOpen(false)}>
                  {lenses.length === 0 && <div className="mi muted" style={{ cursor: "default" }}>No saved lenses yet.</div>}
                  {lenses.map((l) => (
                    <div className={"mi" + (activeLens === l.name ? " sel" : "")} key={l.name} onClick={() => applyLens(l)}>
                      <Icon name="fit" size={12} /> <span style={{ flex: 1 }}>{l.name}</span>
                      <button className="btn sm icon ghost danger" title="Delete lens"
                              onClick={(e) => { e.stopPropagation(); deleteLens(l.name); }}><Icon name="x" size={11} /></button>
                    </div>
                  ))}
                  <div style={{ height: 1, background: "var(--border)", margin: "4px 0" }} />
                  <div className="mi" onClick={saveLens}><Icon name="plus" size={12} /> Save current view…</div>
                </div>
              )}
            </div>
            {/* search — grows to fill the row */}
            <div className="input" style={{ flex: 1, minWidth: 180 }}>
              <Icon name="search" size={14} />
              <input placeholder="Search functions, strings, findings…" value={q} onChange={(e) => doSearch(e.target.value)} />
            </div>
            <div className="tsep" />
            {/* create */}
            <div className="tgroup">
              <button className="btn sm" title="Add a node to the graph (function/symbol/hypothesis/…)" onClick={() => setModal("node")}><Icon name="plus" size={12} /> Node</button>
              <button className="btn sm" title="Connect two graph entities with an edge" onClick={() => setModal("edge")}><Icon name="link" size={13} /> Edge</button>
            </div>
            <div className="tsep" />
            {/* analyze */}
            <div className="tgroup">
              <button className="btn sm" title="Diff two analysis runs over a target (added/dropped/changed findings)" onClick={() => setModal("compare")}><Icon name="refresh" size={13} /> Compare</button>
              <button className="btn sm" title="Link identical functions across targets (n-day clone detection)" onClick={linkSameCode}><Icon name="copy" size={13} /> Same-code</button>
              <button className="btn sm" title="Merge duplicate binaries/nodes (e.g. sym.foo == foo)" onClick={mergeDupes}><Icon name="copy" size={13} /> Merge dupes</button>
            </div>
            <div className="tsep" />
            {/* report / export / audit */}
            <div className="tgroup">
              <button className="btn sm" title="Markdown report of confirmed/reported findings" onClick={() => setModal("report")}><Icon name="doc" size={13} /> Report</button>
              <button className="btn sm" title="Download the project graph as JSON" onClick={exportGraph}><Icon name="arrowin" size={13} /> Export</button>
              <button className="btn sm" title="Egress audit log — every outbound action against a live target (allowed/denied)" onClick={() => setModal("egress")}><Icon name="shield" size={13} /> Audit</button>
            </div>
            {busy && <span className="badge"><Icon name="refresh" size={12} className="spin" /> {busy}</span>}
          </div>
          {results && q.trim() && (
            <div className="search-pop">
              {results.targets?.length > 0 && <div className="res-head">Targets</div>}
              {(results.targets || []).map((t: any) => (
                <div className="res" key={t.id} onClick={() => { setResults(null); setQ(""); focusOn(t.id); }}>
                  <Icon name={NODE_ICON[t.kind] || "binary"} size={13} /> {t.name} <span className="muted">{t.kind}{t.arch ? " · " + t.arch : ""}</span>
                </div>
              ))}
              {results.nodes.length > 0 && <div className="res-head">Graph nodes</div>}
              {results.nodes.map((n: any) => (
                <div className="res" key={n.id} onClick={() => { setResults(null); setQ(""); focusOn(n.id); }}>
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
          ) : view === "table" ? (
            <TableView graph={graph} layers={layers} filters={filters} scope={scope}
                       onReveal={(id, type) => { if (type === "finding") viewFinding(id); else { switchView("graph"); onGraphSelect(id, type); } }} />
          ) : view === "matrix" ? (
            <MatrixView graph={graph}
                        onReveal={(id) => { switchView("graph"); scopeToTarget(id); onGraphSelect(id, "target"); }} />
          ) : (
          <>
          {/* Focus breadcrumb (design §4.2): the reversible navigation trail. Overview ›
              crumb › crumb. A crumb pops to that frame; ↺ clears to the full graph. Pinned
              top-left of the canvas, shown only once a focus has been pushed. */}
          {(focusStack.length > 0 || scope) && (
            <div className="focus-crumbs">
              <button className="crumb home" title="Back to the full graph" onClick={() => { clearFocus(); setScope(null); }}>
                <Icon name="hex" size={12} /> Overview
              </button>
              {scope && (
                <span style={{ display: "inline-flex", alignItems: "center" }}>
                  <span className="crumb-sep">›</span>
                  <button className="crumb active" title="Scoped to this target (click to clear)" onClick={() => setScope(null)}>
                    {labelFor(scope)} <Icon name="x" size={10} />
                  </button>
                </span>
              )}
              {focusStack.map((f, i) => (
                <span key={f.id + "-" + i} style={{ display: "inline-flex", alignItems: "center" }}>
                  <span className="crumb-sep">›</span>
                  <button className={"crumb" + (i === focusStack.length - 1 ? " active" : "")}
                          title={i === focusStack.length - 1 ? f.label : `Back to ${f.label}`}
                          onClick={() => popFocusTo(i)}>{f.label}</button>
                </span>
              ))}
              <button className="crumb reset" title="Clear focus" onClick={() => { clearFocus(); setScope(null); }}>↺</button>
            </div>
          )}
          <GraphView graph={graph} selectedId={selGraphId} onSelect={onGraphSelect}
                     isolateType={pinType || hoverType}
                     focus={focus} onFocus={(id, hop) => focusOn(id, hop)} onClearFocus={clearFocus}
                     groupBy={view === "map" ? "target" : groupBy} onGroupBy={onGroupBy}
                     mapMode={view === "map"}
                     onRoomDrill={(tid) => { switchView("graph"); scopeToTarget(tid); onGraphSelect(tid, "target"); }}
                     layers={layers} onLayers={onLayers}
                     filters={filters} onFilters={onFilters}
                     findings={findingsLayer} onFindings={onFindingsLayer}
                     scope={scope}
                     skeletonMode={skeletonMode} onRoomExpand={expandRoom} roomLoading={roomLoading}
                     onEdgeSelect={(e) => { setSelEdge(e); if (e) { setSelNode(null); setSelFinding(null); setSelTask(undefined); } }}
                     onDrawEdge={(src, dst) => { setEdgePrefill({ src, dst }); setModal("edge"); }} />
          {(() => {
            // Legend driven from the SAME color maps GraphView uses, showing only the
            // node/edge types actually present in this graph (single source of truth).
            // Each chip carries its type SHAPE (not just color) and is interactive: hover
            // previews that type (dims the rest), click pins the isolation (click again to
            // clear). `key` is the raw type value (the isolate key GraphView matches on).
            const nodeKeys: { label: string; color: string; key: string; shape: string }[] = [];
            const seen = new Set<string>();
            let hasFinding = false;
            for (const n of graph.nodes) {
              if (n.type === "finding") { hasFinding = true; continue; }
              const key = n.type === "target" ? (n.kind as string) : (n.node_type as string);
              const color = (n.type === "target" ? KIND[key] : NODE_T[key]);
              if (!key || seen.has(key) || !color) continue;
              seen.add(key);
              const shape = n.type === "target" ? "circle" : (NODE_SHAPE[key] || "rrect");
              nodeKeys.push({ label: key === "firmware_image" ? "firmware" : key === "shared_library" ? "library" : key, color, key, shape });
            }
            const edgeKeys = [...new Set(graph.edges.map((e) => e.type))]
              .filter((t) => EDGE_C[t]).map((t) => ({ label: t, color: EDGE_C[t] }));
            const chip = (key: string, content: React.ReactNode, extraClass = "") => (
              <span className={"it chip" + (pinType === key ? " pinned" : "") + (extraClass ? " " + extraClass : "")}
                    key={extraClass + "-" + key}
                    onMouseEnter={() => setHoverType(key)} onMouseLeave={() => setHoverType(null)}
                    onClick={() => setPinType((p) => {
                      // Un-pinning must visibly clear NOW — otherwise the still-hovered chip's
                      // hoverType keeps the same type isolated until the pointer leaves.
                      if (p === key) { setHoverType(null); return null; }
                      return key;
                    })}
                    title={pinType === key ? "Click to show all types" : `Isolate ${key} (click)`}>
                {content}
              </span>
            );
            return (
              <div className="legend">
                {nodeKeys.map((k) => chip(k.key,
                  <><span className={"sw shape-" + k.shape} style={{ background: k.color }} />{k.label}</>, "n"))}
                {hasFinding && chip("finding",
                  <><span className="sw shape-diamond" style={{ background: "#ff5d6c" }} />finding</>, "n")}
                {edgeKeys.length > 0 && <span className="it sep" />}
                {edgeKeys.map((k) => chip(k.label,
                  <><span className="ln" style={{ background: k.color }} />{k.label}</>, "e"))}
              </div>
            );
          })()}
          </>
          )}
        </section>

        {!maxed && !layout.rightCollapsed && (
          <div className={"wsplit" + (dragging === "right" ? " dragging" : "")} onPointerDown={onDragRight}
               role="separator" aria-orientation="vertical"
               title="Drag to resize · double-click to collapse" onDoubleClick={toggleRight}>
            <span className="grip"><i /><i /><i /></span>
          </div>
        )}

        {!maxed && (layout.rightCollapsed ? (
          <div className="pane-edge" title="Show Findings & Detail panel" onClick={toggleRight}>
            <span className="arrow" style={{ transform: "rotate(90deg)", display: "inline-flex" }}><Icon name="chevron" size={13} /></span>
            <span className="lbl">Findings</span>
            <span className="arrow" style={{ display: "inline-flex" }}><Icon name="bug" size={13} /></span>
          </div>
        ) : (
          <aside className="pane side" ref={rightPaneRef} style={{ width: layout.rightW }}>
            {!detailBig && renderTabs(true)}
            {!detailBig && renderList()}
            {!detailBig && (
              <div className={"dsplit" + (dragging === "detail" ? " dragging" : "")} onPointerDown={onDragDetail}
                   role="separator" aria-orientation="horizontal" title="Drag to resize the Detail section">
                <span className="grip"><i /><i /><i /></span>
              </div>
            )}
            <div className="detailbox" style={{
              flex: detailBig ? 1 : "none",
              height: detailBig ? "auto" : `${Math.round(layout.detailFrac * 100)}%`,
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
        ))}
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
