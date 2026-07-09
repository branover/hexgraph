import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import { api, Finding, Graph, GraphNode, ProjectDetail, SavedLens, SettingsView, TargetNode } from "../api";
import Header from "../components/Header";
import ErrorBoundary from "../components/ErrorBoundary";
import GraphView, { NODE_T, EDGE_C, KIND, NODE_SHAPE, FocusSpec, GroupBy } from "../components/GraphView";
import TableView from "../components/TableView";
import MatrixView from "../components/MatrixView";
import {
  LayerState, FilterState, defaultLayers, defaultFilters, anyFilterActive,
} from "../components/graphLayers";
import FindingsPanel from "../components/FindingsPanel";
import HypothesesPanel from "../components/HypothesesPanel";
import JournalPanel from "../components/JournalPanel";
import Inspector from "../components/Inspector";
import NodeInspector from "../components/NodeInspector";
import { TasksPanel, TaskDetail } from "../components/TasksPanel";
import Launcher from "../components/Launcher";
import LaunchModal from "../components/LaunchModal";
import { AddNodeModal, AddEdgeModal } from "../components/Author";
import ReportModal from "../components/ReportModal";
import RunCompareModal from "../components/RunCompareModal";
import GhidraImportModal from "../components/GhidraImportModal";
import ImportDirModal from "../components/ImportDirModal";
import SourceBrowser from "../components/SourceBrowser";
import FunctionSourceViewer from "../components/FunctionSourceViewer";
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
  // The FULL TargetNode for a selected HIDDEN target (never in `detail.targets`, which is
  // visible-only) — renderDetail() needs more than selNode's minimal GraphNode shape
  // (arch/format/metadata/visible) to populate the inspector. Cleared on any non-hinted
  // selection so a stale hint never leaks onto an unrelated node.
  const [selTargetHint, setSelTargetHint] = useState<TargetNode | undefined>(undefined);
  const [selEdge, setSelEdge] = useState<any | null>(null);
  const [selGraphId, setSelGraphId] = useState<string>();
  // Legend isolate-by-type: a hovered chip previews (transient), a clicked chip pins.
  // The pinned type wins; otherwise the hovered one drives the graph dim.
  const [hoverType, setHoverType] = useState<string | null>(null);
  const [pinType, setPinType] = useState<string | null>(null);
  const [busy, setBusy] = useState<string>();
  const [tab, setTab] = useState<"findings" | "tasks" | "campaigns" | "hypotheses" | "journal">(
    new URLSearchParams(window.location.search).get("tab") === "campaigns" ? "campaigns"
      : new URLSearchParams(window.location.search).get("tab") === "hypotheses" ? "hypotheses"
      : new URLSearchParams(window.location.search).get("tab") === "journal" ? "journal" : "findings");
  // Bumped after a hypothesis worklist mutation so the panel re-fetches and the graph reloads
  // (a pin toggle changes canvas visibility).
  const [hypReload, setHypReload] = useState(0);
  const [tasks, setTasks] = useState<any[]>([]);
  const [selTask, setSelTask] = useState<string>();
  const [selCampaign, setSelCampaign] = useState<string | undefined>(
    new URLSearchParams(window.location.search).get("campaign") || undefined);
  const [settings, setSettings] = useState<SettingsView | null>(null);
  const [fuzzFor, setFuzzFor] = useState<TargetNode | null>(null);
  const [q, setQ] = useState("");
  const [results, setResults] = useState<any | null>(null);
  const [modal, setModal] = useState<"node" | "edge" | "report" | "compare" | "ghidra" | "egress" | "dir" | null>(null);
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
  // Function source viewer (the IDE-style decompiled/disassembled body reader). `seq` keys
  // the component so internal callee-navigation (which only updates the URL) never remounts
  // it, while an explicit re-open does. Seeded from ?fn=<name>&fnt=<targetId> on first load.
  const [openFn, setOpenFn] = useState<{ seq: number; targetId: string; fn: string; tab?: "decomp" | "disasm"; line?: number } | null>(() => {
    const sp = new URLSearchParams(window.location.search);
    const fn = sp.get("fn"), fnt = sp.get("fnt");
    if (!fn || !fnt) return null;
    const tab = sp.get("fntab") === "disasm" ? "disasm" : undefined;
    const line = Number(sp.get("fnline")) || undefined;
    return { seq: 0, targetId: fnt, fn, tab, line };
  });
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
  // ── Phase 1 (curatable targets, docs/design/design-curatable-targets.md): the firmware
  // TARGETS pane groups path-named children (e.g. "usr/sbin/telnetd") into collapsible FS
  // directory folders. Folders are PURE UI grouping — derived client-side, no target rows,
  // no backend. `expandedDirs` tracks which folder keys are open; the default-collapse
  // heuristic (a large firmware opens collapsed) is applied once per firmware via
  // `dirDefaultsApplied`.
  const [expandedDirs, setExpandedDirs] = useState<Set<string>>(new Set());
  const dirDefaultsApplied = useRef<Set<string>>(new Set());
  // ── Targets tree: lazy per-target children (independent of the graph's own visible-only
  // filtering — a firmware can unpack into thousands of HIDDEN children, so the tree fetches
  // one target's direct children only when its row is expanded, via GET .../target-children
  // (include_hidden=true — everything extracted is browsable here; the GRAPH stays the thing
  // that's discriminating). `expandedTargets` (which target rows are open) is separate from
  // `expandedDirs` (the synthetic FS-folder grouping above, which operates on already-fetched
  // children). `childrenCache[id]` is undefined until fetched, `[]` once fetched-but-empty.
  // `childrenError` is a DISTINCT signal from "confirmed empty" — a fetch failure (network
  // blip, transient DB lock) must render a retry affordance, not silently look like a target
  // with zero children (which `child_count` might disagree with).
  const [expandedTargets, setExpandedTargets] = useState<Set<string>>(new Set());
  const [childrenCache, setChildrenCache] = useState<Record<string, TargetNode[]>>({});
  const [childrenLoading, setChildrenLoading] = useState<Set<string>>(new Set());
  const [childrenError, setChildrenError] = useState<Set<string>>(new Set());
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
    // Same "refresh starts over" convention as loadedRooms above: a reload discards any
    // fetched target-children pages rather than trying to reconcile them (a reveal/promote/
    // archive elsewhere in the tree may have changed counts we'd otherwise show stale).
    setExpandedTargets(new Set());
    setChildrenCache({});
    setChildrenLoading(new Set());
    setChildrenError(new Set());
    setDetail(d); setTasks(tk);
    // Refresh the open detail with the reloaded data so triage (Accept/Dismiss,
    // status pills, annotations) re-renders instead of showing a stale finding —
    // checking the hidden-target bucket too, so a selected hidden finding also re-renders.
    setSelFinding((prev) => (prev
      ? d.findings.find((f) => f.id === prev.id)
        ?? d.hidden_findings?.find((f) => f.id === prev.id)
        ?? prev
      : prev));
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

  // ── Targets tree: fetch ONE target's direct children on demand (mirrors expandRoom's
  // idempotent-via-checking-inside-the-setter idiom). include_hidden=true always — the tree's
  // whole point is showing everything extracted, not just what's already in the graph.
  // Only fetches the first page (500 children) today; a directory bigger than that shows a
  // "N more" affordance rather than silently truncating (see FolderRow/TreeRow below).
  const CHILDREN_PAGE_SIZE = 500;
  const expandTarget = useCallback((targetId: string) => {
    if (!projectId) return;
    setExpandedTargets((prev) => new Set(prev).add(targetId));
    setChildrenCache((prev) => {
      if (prev[targetId] !== undefined) return prev;   // already fetched — nothing to do
      setChildrenError((e) => (e.has(targetId) ? new Set([...e].filter((x) => x !== targetId)) : e));
      setChildrenLoading((l) => new Set(l).add(targetId));
      api.targetChildren(projectId, targetId, { includeHidden: true, limit: CHILDREN_PAGE_SIZE })
        .then((page) => setChildrenCache((c) => ({ ...c, [targetId]: page.items })))
        // Leave the cache entry unset (not `[]`) on failure — that stays a DISTINCT state
        // from "confirmed zero children" and lets a retry (re-expanding this row) fetch
        // again, instead of a network blip / transient DB lock permanently looking like a
        // target with zero children (which `child_count` might disagree with anyway).
        .catch(() => setChildrenError((e) => new Set(e).add(targetId)))
        .finally(() => setChildrenLoading((l) => { const x = new Set(l); x.delete(targetId); return x; }));
      return prev;
    });
  }, [projectId]);
  const collapseTarget = (targetId: string) => setExpandedTargets((prev) => {
    const next = new Set(prev); next.delete(targetId); return next;
  });
  // Reveal a hidden target directly from the tree row (no need to open the inspector's
  // separate Filesystem browser first) — same onChanged={load} full-refresh convention
  // NodeInspector's own reveal path already uses (load() resets the tree's expand/cache
  // state too, same as loadedRooms above; consistent, if not the most surgical UX).
  const revealFromTree = async (t: TargetNode) => {
    if (!projectId) return;
    await api.setTargetVisible(projectId, t.id, true);
    await load();
  };

  // SURFACE target kinds (web_app/service/remote) have NO byte artifact, so byte 'recon'
  // is wrong for them — the server now advertises a surface-appropriate set (web_app →
  // surface_recon, service/remote → only their network/remote tasks when enabled, else
  // none). Trust the server set verbatim for any kind it knows (including an empty list);
  // the byte 'recon' fallback applies ONLY to a kind the table has no entry for at all,
  // and NEVER to a surface kind. Keeps the menu honest per kind.
  const SURFACE_KINDS = ["web_app", "service", "remote"];
  const targetCaps = (kind: string): string[] => {
    const set = caps.target?.[kind];
    if (set) return set;                       // server knows this kind — use it as-is
    if (SURFACE_KINDS.includes(kind)) return [];  // a surface with no advertised tasks → none, never byte recon
    return ["recon"];                          // genuine unknown byte kind → safe byte default
  };

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

  // ── Phase 1: default folder-expansion heuristic (design-curatable-targets.md §2.1). Run
  // once per firmware (a target with path-named children): a SMALL firmware (≤12 binaries)
  // opens its top-level folders so the structure is visible at a glance; a LARGE firmware
  // opens fully collapsed so the pane is calm. Done in an effect (not during render) so we
  // never set state mid-render; the `dirDefaultsApplied` ref makes it idempotent.
  useEffect(() => {
    if (!detail) return;
    const childrenByParent = new Map<string, TargetNode[]>();
    for (const t of detail.targets) {
      if (!t.parent_id) continue;
      (childrenByParent.get(t.parent_id) ?? childrenByParent.set(t.parent_id, []).get(t.parent_id)!).push(t);
    }
    const toOpen: string[] = [];
    for (const [pid, kids] of childrenByParent) {
      if (dirDefaultsApplied.current.has(pid)) continue;
      // grouped firmware = has FS byte children with rootfs paths (surfaces excluded)
      const fsKids = kids.filter((c) => !["web_app", "service", "remote"].includes(c.kind) && (c.name || "").includes("/"));
      if (!fsKids.length) continue;
      dirDefaultsApplied.current.add(pid);
      if (kids.length <= 12) {
        // open just the top-level directory segment of each FS child
        const top = new Set<string>();
        for (const c of fsKids) { const seg = (c.name || "").split("/").filter(Boolean); if (seg.length > 1) top.add(seg[0]); }
        for (const seg of top) toOpen.push(pid + "::" + seg);
      }
    }
    if (toOpen.length) setExpandedDirs((prev) => { const next = new Set(prev); for (const k of toOpen) next.add(k); return next; });
  }, [detail]);

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
    // Disambiguate target vs node for onGraphSelect. Prefer the loaded graph; when the id
    // isn't loaded (skeleton/LOD), fall back to detail.targets so a target still selects as
    // a target (a node/hypothesis defaults to "node", which onGraphSelect fetches by id).
    const inGraph = graph?.nodes.find((n) => n.id === id);
    const isTarget = inGraph ? inGraph.type === "target" : !!detail?.targets.find((t) => t.id === id);
    onGraphSelect(id, isTarget ? "target" : "node");
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
  // Select a hypothesis from the worklist (or an @-mention) → render the existing (singular)
  // HypothesisPanel in the detail split (NodeInspector already routes a node_type='hypothesis'
  // node to it). On a large project the graph loads skeleton-first, so the hypothesis node may
  // NOT be in graph.nodes — on a miss, fetch it by id (api.getNode, same as onGraphSelect) so the
  // inspector opens regardless of graph LOD. Async, but every caller is fire-and-forget. Same
  // last-write-wins guard as onGraphSelect: a late fetch only wins if it's still the latest pick.
  const viewHypothesis = async (hid: string) => {
    setSelTask(undefined); setSelFinding(null); setSelCampaign(undefined); setSelEdge(null);
    setSelGraphId(hid);
    const n = graph?.nodes.find((x) => x.id === hid);
    if (n) { setSelNode(n); return; }
    try {
      const fetched = await api.getNode(projectId!, hid);
      setSelGraphId((cur) => {
        if (cur === hid) setSelNode(fetched);
        return cur;
      });
    } catch { /* hypothesis not found / removed — leave the pane as-is */ }
  };
  // A journal @-mention chip was clicked → select the referenced object via the SAME plumbing
  // every other navigation uses: a finding opens in the Inspector; a node/target/hypothesis
  // routes through focusOn (selects + serializes + focuses the camera when the object is
  // loaded). On a large project the graph loads skeleton-first, so the mentioned object may
  // NOT be in graph.nodes — onGraphSelect then fetches it by id (api.getNode) / falls back to
  // detail.targets, so the inspector opens regardless of graph LOD. Danglers never call this.
  const selectMention = (kind: string, id: string) => {
    if (kind === "finding") viewFinding(id);
    else focusOn(id);  // node / target / hypothesis — fetched by id if not loaded in the graph
  };

  // Finding → source jump: open the file in Source mode at the line (design §6.3).
  const revealSource = (ref: { tree_id?: string; rel?: string; line?: number }) => {
    if (!ref?.tree_id || !ref?.rel) return;
    setOpenSource({ treeId: ref.tree_id, rel: ref.rel, line: ref.line });
    switchView("source");
    setUrl({ view: "source", file: ref.rel, line: ref.line != null ? String(ref.line) : undefined });
  };

  // Open the function source viewer on a function NODE (by name + its target). Bumps `seq`
  // so an explicit open always (re)mounts the viewer at the requested function.
  const openFunctionViewer = (fnNode: GraphNode) => {
    if (fnNode.type !== "node" || !fnNode.target_id) return;
    setOpenFn((prev) => ({ seq: (prev?.seq ?? 0) + 1, targetId: fnNode.target_id!, fn: fnNode.label }));
    setUrl({ fn: fnNode.label, fnt: fnNode.target_id, fntab: undefined, fnline: undefined });
  };
  const closeFunctionViewer = () => { setOpenFn(null); setUrl({ fn: undefined, fnt: undefined, fntab: undefined, fnline: undefined }); };
  // The viewer reports its live (target, fn, tab, line) so the deep-link stays addressable.
  const syncFnUrl = (r: { targetId: string; fn: string; tab: "decomp" | "disasm"; line?: number }) =>
    setUrl({ fn: r.fn, fnt: r.targetId, fntab: r.tab === "disasm" ? "disasm" : undefined, fnline: r.line != null ? String(r.line) : undefined });

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

  // Open an entity in the detail/inspector pane. The graph loads skeleton-first / a
  // subset on large projects (graphSkeleton), so `graph.nodes` does NOT contain every
  // node — when a node is selected (a journal @-mention click, a toolbar-search hit) but
  // isn't loaded, fall back to fetching it by id (api.getNode) so the inspector still
  // opens regardless of graph LOD. Async, but every caller is fire-and-forget setState,
  // so none relies on it resolving synchronously.
  // `targetHint` lets a caller that already has the TargetNode in hand (the lazy Targets
  // tree, whose HIDDEN rows are never in `detail.targets`/`graph.nodes` — a hidden target
  // contributes nothing to the graph by design) select it without needing a lookup that
  // would otherwise silently fail (id set, inspector left showing the stale prior selection).
  const onGraphSelect = async (id: string, type: string, targetHint?: TargetNode) => {
    setSelGraphId(id); setSelTask(undefined);
    // Every branch below either sets a fresh hint (the `target` branch) or must clear a
    // stale one from a PRIOR hidden-target selection — otherwise renderDetail's fallback
    // would attach the wrong target's arch/format/metadata to this new selection.
    setSelTargetHint(undefined);
    if (type === "finding") {
      const f = detail!.findings.find((x) => x.id === id);
      if (f) { setSelNode(null); setSelFinding(f); }
      return;
    }
    const n = graph?.nodes.find((x) => x.id === id);
    if (n) { setSelFinding(null); setSelNode(n); return; }
    // A `target` ref not in the loaded graph: build a GraphNode from the loaded targets (or
    // the caller-supplied hint for a target the graph/`detail.targets` doesn't carry at all —
    // a HIDDEN target, by design never in either). Stash the full TargetNode too: renderDetail
    // needs more than a GraphNode's minimal shape (arch/format/metadata/visible) to populate
    // the inspector, and `detail.targets.find` there would miss the same way this one would.
    if (type === "target") {
      const t = targetHint || detail?.targets.find((x) => x.id === id);
      if (t) {
        setSelFinding(null); setSelNode({ id: t.id, type: "target", label: t.name, kind: t.kind, parent_id: t.parent_id });
        setSelTargetHint(t);
      }
      return;
    }
    // A node (or hypothesis, which is a node_type='hypothesis' node) not in the loaded
    // graph: fetch it by id so the inspector opens anyway (NodeInspector routes a
    // hypothesis node to the HypothesisPanel). Last-write-wins guard: a rapid click of an
    // unloaded item A then B must not let A's late fetch clobber B — apply the result only
    // if `id` is still the latest requested selection (`selGraphId`) when it resolves.
    try {
      const fetched = await api.getNode(projectId!, id);
      setSelGraphId((cur) => {
        if (cur === id) { setSelFinding(null); setSelNode(fetched); }
        return cur;
      });
    } catch { /* node not found / removed — leave the pane as-is */ }
  };

  const doSearch = (text: string) => {
    setQ(text);
    clearTimeout(searchTimer.current);
    if (!text.trim()) { setResults(null); return; }
    searchTimer.current = setTimeout(() => { if (projectId) api.search(projectId, text).then(setResults).catch(() => {}); }, 200);
  };
  // Enter in the toolbar search lands the TOP result via the SAME reveal path the popover
  // click uses (focusOn for a target/node, viewFinding for a finding) and closes the popover —
  // so "find X and show me its world" is one keystroke (SEARCH-01). Ranking mirrors the
  // popover order: targets, then graph nodes, then findings. Awaits the debounced fetch if the
  // user hits Enter before results have landed, so the first Enter never no-ops.
  const revealTopResult = async () => {
    if (!projectId || !q.trim()) return;
    let r = results;
    if (!r) { try { r = await api.search(projectId, q); } catch { return; } }
    const top = r?.targets?.[0] ?? r?.nodes?.[0];
    const topFinding = r?.findings?.[0];
    setResults(null); setQ("");
    if (top) focusOn(top.id);
    else if (topFinding) viewFinding(topFinding.id);
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
  // Only FILESYSTEM byte targets carry a meaningful rootfs path in their name. A dynamic
  // SURFACE child (web_app/service/remote) may have a slash in its label by coincidence
  // (e.g. "upnpd control (tcp/5000)") — never fold those into folders.
  const SURFACE_KIND_SET = new Set(["web_app", "service", "remote"]);
  const isFsChild = (t: TargetNode) => !SURFACE_KIND_SET.has(t.kind) && (t.name || "").includes("/");
  // The display label for a leaf target inside its FS folder: the final path segment of an
  // FS byte child ("usr/sbin/telnetd" → "telnetd"). Surfaces and plain names pass through.
  const leafName = (t: TargetNode) => {
    if (SURFACE_KIND_SET.has(t.kind)) return t.name;
    const s = (t.name || "").split("/").filter(Boolean);
    return s.length ? s[s.length - 1] : t.name;
  };
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

  // ── Phase 1: filesystem-hierarchical targets pane (design-curatable-targets.md §2) ──────
  // A firmware names each extracted child by its rootfs-relative path ("usr/sbin/telnetd"),
  // so its children otherwise render as a flat wall of hundreds of siblings. We split those
  // names on "/" and present the leading segments as collapsible directory FOLDERS. Folders
  // are pure UI grouping derived here, client-side — never target rows, never a backend hit.
  interface DirNode { name: string; path: string; subdirs: DirNode[]; files: TargetNode[] }

  // Build a directory tree from a target's children. An FS child's `name` is split on "/":
  // the leading segments nest folders, the final segment is the leaf label. Anything that
  // isn't an FS child (a surface, or a plain-named binary) sits as a file at the root.
  const buildDirTree = (children: TargetNode[]): DirNode => {
    const root: DirNode = { name: "", path: "", subdirs: [], files: [] };
    for (const c of children) {
      const segs = isFsChild(c) ? (c.name || "").split("/").filter(Boolean) : [];
      if (segs.length <= 1) { root.files.push(c); continue; }
      let cur = root;
      for (let i = 0; i < segs.length - 1; i++) {
        const seg = segs[i];
        const p = cur.path ? cur.path + "/" + seg : seg;
        let next = cur.subdirs.find((d) => d.name === seg);
        if (!next) { next = { name: seg, path: p, subdirs: [], files: [] }; cur.subdirs.push(next); }
        cur = next;
      }
      cur.files.push(c);
    }
    return root;
  };
  // Does this firmware's child set actually carry path-style names worth grouping?
  const hasDirNames = (children: TargetNode[]) => children.some(isFsChild);
  // Every leaf target reachable under a folder (for counts + a status rollup).
  const dirLeaves = (d: DirNode): TargetNode[] => [...d.files, ...d.subdirs.flatMap(dirLeaves)];
  // Worst finding heat under a folder → the rolled-up status badge (count + hot flag).
  const dirRollup = (d: DirNode) => {
    let n = 0, hot = false;
    for (const leaf of dirLeaves(d)) { const fc = findingCounts[leaf.id]; if (fc) { n += fc.n; hot = hot || fc.hot; } }
    return { n, hot };
  };
  const toggleDir = (key: string) => setExpandedDirs((prev) => {
    const next = new Set(prev); next.has(key) ? next.delete(key) : next.add(key); return next;
  });

  // Whether a target row should offer an expand chevron. Non-root targets came from the
  // lazy target-children fetch (`t.child_count` is exact); ROOTS come from `detail.targets`
  // (the eager project payload), which doesn't carry child_count — show the chevron
  // optimistically for those and let expanding reveal the truth (an empty expand just shows
  // nothing further, same as a folder with 0 matches).
  const targetHasChildren = (t: TargetNode) => t.child_count === undefined || t.child_count > 0;

  // The bare leaf-target row (everything below the name). `displayName` is the FS leaf
  // ("telnetd") when grouped under a folder; `title` keeps the full path on hover. `depth`
  // sets indentation in units of the existing 16px `child` step, so a binary three folders
  // deep still aligns with its folder. `expandCtl` wires the row's OWN expand chevron (a
  // target's children are lazy-fetched now — see TreeRow); undefined for a folder-grouped
  // FS leaf (those are already inside an expanded parent, and are ELF files, not containers).
  const TargetRow = (t: TargetNode, depth: number, displayName?: string,
                      expandCtl?: { expanded: boolean; loading: boolean; onToggle: (e: React.MouseEvent) => void }) => {
    const allowed = targetCaps(t.kind);
    const fc = findingCounts[t.id];
    const hidden = t.visible === false;
    return (
      <div className={"tree-row" + (depth > 0 ? " child" : "") + (selGraphId === t.id ? " sel" : "")
                      + (scope === t.id ? " scoped" : "") + (hidden ? " hidden-target" : "")}
           style={depth > 1 ? { marginLeft: depth * 16 } : undefined}
           title={[displayName && displayName !== t.name ? t.name : null,
                  hidden ? "extracted but not revealed into the curated graph" : null]
                  .filter(Boolean).join(" — ") || undefined}
           onClick={() => {
             onGraphSelect(t.id, "target", t);
             // A hidden target has no graph presence yet — nothing to scope the graph to.
             if (!hidden && view !== "source" && view !== "matrix") scopeToTarget(t.id);
           }}>
        <div className="nm">
          {expandCtl && targetHasChildren(t) && (
            <span className="dir-chev" style={{ transform: expandCtl.expanded ? "none" : "rotate(-90deg)", display: "inline-flex" }}
                  onClick={expandCtl.onToggle}>
              <Icon name="chevron" size={13} />
            </span>
          )}
          <Icon name={NODE_ICON[t.kind] || "binary"} size={15} /> {displayName || t.name}
          {fc && <span className={"tbadge" + (fc.hot ? " hot" : "")} style={{ marginLeft: "auto" }}>{fc.n}</span>}
        </div>
        {/* "hidden" lives on the .mt subline (own row, small font) rather than inline next to
            the name — at deep tree indentation a long name + a badge both competing for
            space in the .nm flex row collided with the absolutely-positioned row-actions
            that appear on hover. Dimmed opacity (.hidden-target) is the primary signal;
            this + the row's title tooltip are the explicit ones. */}
        <div className="mt">
          {t.kind}{t.arch ? " · " + t.arch : ""}{hidden ? " · hidden" : ""}{expandCtl?.loading ? " · loading…" : ""}
        </div>
        {/* Action cluster: Run (+ its in-menu Fuzz row) and Remove, in one aligned top-right
            row. The standalone fuzz button was removed — it duplicated the Launcher menu's
            "Fuzz campaign…" row and the two absolutely-positioned controls collided (issue 7).
            A HIDDEN target gets a Reveal action instead of Run (nothing to run/fuzz until
            it's in the graph) — the sidebar's own path to "make this visible", not just the
            inspector's separate Filesystem browser. */}
        <div className="row-actions" onClick={(e) => e.stopPropagation()}>
          {hidden ? (
            <button className="btn sm icon ghost" title="Reveal into the curated graph"
                    onClick={() => revealFromTree(t)}>
              <Icon name="eye" size={12} />
            </button>
          ) : (
            <Launcher allowed={allowed} onChoose={(type) => setLaunchFor({ target: t, type })}
                      onFuzz={caps.features?.fuzzing && t.kind !== "firmware_image" ? () => setFuzzFor(t) : undefined} />
          )}
          <button className="btn sm icon ghost trash" title="Remove target (hides its nodes/findings)"
                  onClick={(e) => { e.stopPropagation(); removeTarget(t); }}>
            <Icon name="x" size={12} />
          </button>
        </div>
      </div>
    );
  };

  // A collapsible directory folder + (when open) its sorted contents: subdirs first
  // (alpha), then leaf files (alpha). `keyPrefix` scopes the folder's expand key to its
  // firmware so two firmwares' "lib/" don't share collapse state.
  const FolderRow = (d: DirNode, depth: number, keyPrefix: string): React.ReactNode => {
    const key = keyPrefix + "::" + d.path;
    const open = expandedDirs.has(key);
    const roll = dirRollup(d);
    const count = dirLeaves(d).length;
    const subdirs = [...d.subdirs].sort((a, b) => a.name.localeCompare(b.name));
    const files = [...d.files].sort((a, b) => leafName(a).localeCompare(leafName(b)));
    return (
      <div key={key}>
        <div className={"tree-row dir" + (open ? " open" : "")} style={depth > 1 ? { marginLeft: depth * 16 } : undefined}
             onClick={() => toggleDir(key)} title={d.path + "/"}>
          <div className="nm">
            <span className="dir-chev" style={{ transform: open ? "none" : "rotate(-90deg)", display: "inline-flex" }}>
              <Icon name="chevron" size={13} />
            </span>
            <Icon name="folder" size={15} /> {d.name}<span className="dir-slash">/</span>
            <span className="dir-count">{count}</span>
            {roll.n > 0 && <span className={"tbadge" + (roll.hot ? " hot" : "")}>{roll.n}</span>}
          </div>
        </div>
        {open && (
          <>
            {subdirs.map((s) => FolderRow(s, depth + 1, keyPrefix))}
            {/* A folder-grouped FS leaf can ITSELF be a container with its own children
                (e.g. a nested .pkg promoted from inside this directory) — route through
                TreeRow, not TargetRow directly, so it gets the same lazy expand chevron. */}
            {files.map((f) => TreeRow(f, depth + 1, leafName(f)))}
          </>
        )}
      </div>
    );
  };

  // A target row + its LAZILY-FETCHED children (fetched only once this row is expanded —
  // see expandTarget). Firmware children with path-style names group into folders once
  // fetched; everything else renders flat. `displayName` threads the FS-leaf label through
  // when this target is itself a grouped folder leaf (called from FolderRow above).
  //
  // Trade-off, deliberate: nothing auto-expands, not even a small project's few targets —
  // a real firmware can have thousands of (mostly hidden) direct children, and there's no
  // cheap way to tell "few" from "thousands" before fetching. One extra click for the common
  // small case buys never flooding the tree for the case that actually broke (a promoted
  // container with 4000+ children rendered as 4000+ DOM rows).
  const TreeRow = (t: TargetNode, depth: number, displayName?: string): React.ReactNode => {
    const expanded = expandedTargets.has(t.id);
    const kids = childrenCache[t.id];
    const loading = childrenLoading.has(t.id);
    const failed = childrenError.has(t.id);
    const toggle = (e: React.MouseEvent) => {
      e.stopPropagation();
      if (expanded) collapseTarget(t.id); else expandTarget(t.id);
    };
    const row = TargetRow(t, depth, displayName, { expanded, loading, onToggle: toggle });
    // A failed fetch is NOT "zero children" — show a retry row instead of silently
    // collapsing to empty (a fetch error would otherwise look identical to a target that
    // genuinely has none, even though child_count may say otherwise).
    if (expanded && failed) {
      return (
        <div key={t.id}>
          {row}
          <div className="tree-row dir" style={{ marginLeft: (depth + 1) * 16, color: "var(--muted)" }}
               onClick={(e) => { e.stopPropagation(); expandTarget(t.id); }}>
            <div className="nm"><Icon name="refresh" size={13} /> failed to load — retry</div>
          </div>
        </div>
      );
    }
    if (!expanded || !kids || kids.length === 0) {
      return <div key={t.id}>{row}</div>;
    }
    const grouped = hasDirNames(kids);
    if (grouped) {
      const tree = buildDirTree(kids);
      const subdirs = [...tree.subdirs].sort((a, b) => a.name.localeCompare(b.name));
      const files = [...tree.files].sort((a, b) => leafName(a).localeCompare(leafName(b)));
      return (
        <div key={t.id}>
          {row}
          {subdirs.map((s) => FolderRow(s, depth + 1, t.id))}
          {files.map((f) => TreeRow(f, depth + 1, leafName(f)))}
        </div>
      );
    }
    return (
      <div key={t.id}>
        {row}
        {kids.map((c) => TreeRow(c, depth + 1))}
      </div>
    );
  };

  const fuzzingFeature = !!caps.features?.fuzzing;
  const renderTabs = (collapsible = false) => (
    <div className="pane-h">
      <div className="rp-tabs">
        <button className={"btn sm" + (tab === "findings" ? " primary" : " ghost")} onClick={() => { setTab("findings"); setUrl({ tab: undefined }); }}
                title={detail.hidden_findings?.length ? `${detail.hidden_findings.length} more on hidden targets — open Findings and toggle "on hidden"` : undefined}>
          <Icon name="bug" size={12} /> Findings · {detail.findings.length}
          {detail.hidden_findings?.length ? <span style={{ opacity: 0.6 }}> +{detail.hidden_findings.length}</span> : null}
        </button>
        <button className={"btn sm" + (tab === "hypotheses" ? " primary" : " ghost")} onClick={() => { setTab("hypotheses"); setUrl({ tab: "hypotheses" }); }}
                title="Hypotheses — the research-question worklist">
          <Icon name="bulb" size={12} /> Hypotheses
        </button>
        <button className={"btn sm" + (tab === "journal" ? " primary" : " ghost")} onClick={() => { setTab("journal"); setUrl({ tab: "journal" }); }}
                title="Journal — the research notebook (ideas, attempts, dead ends, lessons)">
          <Icon name="book" size={12} /> Journal
        </button>
        <button className={"btn sm" + (tab === "tasks" ? " primary" : " ghost")} onClick={() => { setTab("tasks"); setUrl({ tab: undefined }); }}>
          <Icon name="task" size={12} /> Tasks · {tasks.length}
        </button>
        {fuzzingFeature && (
          <button className={"btn sm" + (tab === "campaigns" ? " primary" : " ghost")} onClick={() => { setTab("campaigns"); setUrl({ tab: "campaigns" }); }}>
            <Icon name="bug" size={12} /> Campaigns
          </button>
        )}
      </div>
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
    <FindingsPanel findings={detail.findings} hiddenFindings={detail.hidden_findings}
                   targets={detail.hidden_targets?.length ? [...detail.targets, ...detail.hidden_targets] : detail.targets}
                   selectedId={selFinding?.id} onBulk={bulk}
                   onSelect={(f) => { setSelTask(undefined); setSelNode(null); setSelCampaign(undefined); setSelFinding(f); setSelGraphId(f.id); }} />
  ) : tab === "hypotheses" ? (
    <HypothesesPanel projectId={projectId!} reloadKey={hypReload}
                     selectedId={selNode?.node_type === "hypothesis" ? selNode.id : undefined}
                     onSelect={(h) => viewHypothesis(h.id)}
                     onChanged={() => { setHypReload((k) => k + 1); load(); }} />
  ) : tab === "journal" ? (
    <JournalPanel projectId={projectId!} onSelectMention={selectMention} />
  ) : tab === "campaigns" ? (
    <CampaignsPanel projectId={projectId!} selectedId={selCampaign} onSelect={(id) => selectCampaign(id)}
                    onStartCampaign={bestFuzzTarget() ? () => setFuzzFor(bestFuzzTarget()!) : undefined} />
  ) : (
    <TasksPanel tasks={tasks} selectedId={selTask} onSelect={(id) => setSelTask(id)} onClear={clearTasks} />
  );
  // Open the deliberate LaunchModal for a finding follow-up (prefilled + parent link).
  const openLaunchForFinding = (type: string, opts: { objective?: string; params?: any } = {}) => {
    if (!selFinding) return;
    // The finding may sit on a hidden child (not in `detail.targets`) — fall back to the
    // hidden-target names so a follow-up still launches against the right target.
    const t = detail.targets.find((x) => x.id === selFinding.target_id)
      ?? detail.hidden_targets?.find((x) => x.id === selFinding.target_id);
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
      // `detail.targets` is visible-only — a HIDDEN target selected from the lazy tree
      // (or a search hit; search doesn't filter by visible either) misses here and falls
      // back to the hint onGraphSelect stashed, so the inspector still populates instead of
      // rendering near-empty (NodeInspector gates its whole target-info block on `tgt`).
      const tgt = selNode.type === "target"
        ? (detail.targets.find((t) => t.id === selNode.id) ?? (selTargetHint?.id === selNode.id ? selTargetHint : undefined))
        : undefined;
      const owner = selNode.type === "node" ? detail.targets.find((t) => t.id === selNode.target_id) : undefined;
      const allowed = tgt
        ? targetCaps(tgt.kind)
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
                            onChanged={load} onViewFinding={viewFinding} onLaunch={onLaunch} onFuzz={onFuzz}
                            onOpenSourceViewer={openFunctionViewer} onSelectMention={selectMention} />;
    }
    return <Inspector finding={selFinding} projectId={projectId} hypotheses={hypotheses} onChanged={load}
                      onDeleted={() => { setSelFinding(null); setSelGraphId(undefined); load(); }}
                      onLaunch={pollThenReload} onOpenLaunch={openLaunchForFinding} onViewTask={viewTask}
                      fuzzingEnabled={fuzzingEnabled} onOpenSource={revealSource} onSelectMention={selectMention}
                      onHighlight={(ids) => ids[0] && setSelGraphId(ids[0])} />;
  };
  // Keyed so selecting a different (well-formed) entity remounts the boundary clean; a
  // malformed one stays showing the graceful fallback instead of the same item re-throwing.
  const detailKey = selFinding?.id ?? (selNode ? `${selNode.type}:${selNode.id}` : undefined) ?? selTask ?? selCampaign ?? "detail";

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
            <button className="btn sm" title="Import an already-extracted/mounted filesystem directory" onClick={() => setModal("dir")}>
              <Icon name="folder" size={12} /> Import dir
            </button>
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
            {roots.map((t) => TreeRow(t, 0))}
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
              <input placeholder="Search functions, strings, findings…" value={q} onChange={(e) => doSearch(e.target.value)}
                     onKeyDown={(e) => {
                       if (e.key === "Enter") { e.preventDefault(); void revealTopResult(); }
                       else if (e.key === "Escape") { setResults(null); setQ(""); }
                     }} />
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
          {openFn ? (
            // The function source viewer overlays whatever center view is active; closing
            // returns to it. knownFunctions / arch / provenance are scoped to its target.
            (() => {
              const fnNodes = graph.nodes.filter((n) => n.type === "node" && n.node_type === "function" && n.target_id === openFn.targetId);
              const tgt = detail.targets.find((t) => t.id === openFn.targetId);
              const fnNode = fnNodes.find((n) => n.label === openFn.fn);
              const prov = (fnNode?.attrs as any)?.provenance as string[] | undefined;
              return (
                <div style={{ flex: 1, minHeight: 0, overflow: "hidden" }}>
                  <FunctionSourceViewer key={openFn.seq} projectId={projectId!} targetId={openFn.targetId} fn={openFn.fn}
                                        address={fnNode?.address} targetName={tgt?.name} arch={tgt?.arch}
                                        knownFunctions={fnNodes.map((n) => n.label)}
                                        provenanceIds={prov} initialTab={openFn.tab} initialLine={openFn.line}
                                        onClose={closeFunctionViewer} onChange={syncFnUrl} />
                </div>
              );
            })()
          ) : view === "source" ? (
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
                     onOpenSourceViewer={(id) => { const n = graph.nodes.find((x) => x.id === id); if (n) openFunctionViewer(n); }}
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
                <ErrorBoundary key={detailKey} label="this finding">{renderDetail()}</ErrorBoundary>
              </div>
            </div>
          </aside>
        ))}
      </div>

      {maxed && (
        <div className="maxscreen">
          <div className="pane">{renderTabs()}{renderList()}</div>
          <div className="pane"><div className="pane-h"><span className="ttl">Detail</span></div><ErrorBoundary key={detailKey} label="this finding">{renderDetail()}</ErrorBoundary></div>
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
      {modal === "dir" && <ImportDirModal projectId={projectId!} onClose={() => setModal(null)} onDone={load} />}
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
