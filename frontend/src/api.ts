// Typed client for the HexGraph JSON API (the SPA's only backend contract).

export interface Project { id: string; name: string; backend: string; created_at: string; }
export interface TargetNode { id: string; name: string; kind: string; format?: string; arch?: string; parent_id?: string | null; metadata?: any; }
export interface Finding {
  id: string; target_id: string; task_id: string; status: string;
  title: string; severity: string; confidence: string; category: string;
  summary: string; reasoning: string; evidence: any;
  suggested_followups?: any[]; related_target_refs?: string[]; created_at?: string;
  origin?: string; dismissed_reason?: string | null; human_notes?: string | null; tags?: string[];
  task_type?: string; finding_type?: string; verified?: boolean;
}
export interface EvidenceRef { finding_id: string; title: string; severity: string; status: string; origin: string; }
export interface Hypothesis {
  id: string; statement: string; rationale?: string | null; status: string; status_origin: string;
  supports: EvidenceRef[]; refutes: EvidenceRef[];
}
export interface AnalysisRunRow {
  id: string; task_id: string; task_type: string; backend: string; model?: string | null;
  bundle_sha?: string | null; finding_count: number; created_at: string;
}
export interface RunDiff {
  run_a: string; run_b: string;
  added: { title: string; severity: string; category: string }[];
  dropped: { title: string; severity: string; category: string }[];
  changed: { title: string; from: string; to: string }[];
}
export interface SecretStatus { present: boolean; source: string | null; }
// A Saved Lens (design-graph-presentation §6.2): a named, non-secret snapshot of
// the center-pane presentation — view + scope + group-by + filters + layer
// visibility + focus — persisted in settings.json (no DB/schema change).
export interface SavedLens {
  name: string;
  view?: "map" | "graph" | "table" | "matrix" | "source";
  scope?: string | null;          // target id the view is scoped to (panels-drive-scope)
  groupBy?: "target" | "type" | "finding" | "none";
  findings?: "all" | "unresolved" | "none";
  layers?: { nodes?: Record<string, boolean>; edges?: Record<string, boolean> };
  filters?: { severity?: string | null; targets?: string[]; findingType?: string | null; mode?: "fade" | "hide" };
  focus?: string | null;
  hop?: number;
}
// Docker per-container resource ceilings. `default` is the shared baseline every container
// type inherits; the per-type sections override only the keys they set (empty ⇒ same as
// default). `unconstrained` lifts mem/cpu/pids ONLY — never a security relaxation.
export interface ResourceSpec { mem: string; cpus: number; pids: number; tmpfs: string; timeout: number; unconstrained: boolean }
export interface ResourcesView { default: ResourceSpec; sandbox?: Partial<ResourceSpec>; build?: Partial<ResourceSpec>; fuzzing?: Partial<ResourceSpec> }
export interface SettingsView {
  settings: {
    llm: { backend: string; model: string | null };
    server: { host: string; port: number };
    ui: { lenses: SavedLens[] };
    resources: ResourcesView;
    features: {
      ghidra: { enabled: boolean; mode: string; enrich_recon: boolean; timeout: number; bridge: { host: string; port: number } };
      fuzzing: { enabled: boolean; max_total_time: number; max_len: number; max_crashes: number; timeout: number; image?: string };
      build: { enabled: boolean; image?: string; timeout?: number };
      poc: { enabled: boolean; timeout: number };
      network: { enabled: boolean; timeout: number };
      fuzz_remote?: { enabled: boolean };
      mcp: { read: boolean; write: boolean; run: boolean };
      agent: { enabled: boolean; cli: string; binary: string; timeout: number };
    };
  };
  secrets: Record<string, SecretStatus>;
  availability: { docker: boolean; ghidra: { enabled: boolean; mode: string; bridge_client_installed: boolean } };
  policy: PolicyView;
  paths: { config_toml: string; settings_json: string };
}
// Per policy gate: what's saved in settings.json vs. what the RUNNING server enforces.
// `pending_restart` is true when a gate is configured-on but the server's startup
// ceiling has it off — saved, but inactive until the next restart.
export interface PolicyFeatureState { configured: boolean; effective: boolean; pending_restart: boolean }
export interface PolicyView { restart_required: boolean; pending: string[]; features: Record<string, PolicyFeatureState> }
export interface GhidraStatus { enabled: boolean; ok: boolean; detail: string; mode?: string; [k: string]: any; }
export interface FsEntry { rel: string; size?: number; is_elf?: boolean; child_target_id?: string | null; added?: boolean; }
export interface SourceTreeRow { id: string; name: string; origin: string; editable: boolean; can_edit?: boolean; vcs_rev?: string | null; content_hash?: string | null; file_count: number; archived: boolean; target_ids: string[]; }
export interface SourceFileEntry { rel: string; size?: number; role: string; node_id?: string | null; is_harness?: boolean; }
export interface BuildSpecBody { source_tree_id: string; system?: string; phases?: any[]; instrumentation?: { sanitizers?: string[]; coverage?: string[]; engine?: string }; artifacts?: string[]; env?: Record<string, string>; arch?: string; name?: string; network?: string; fetch_phases?: any[]; }
export interface BuildPreview { system: string; phases: { argv: string[]; shell?: boolean }[]; fetch_phases?: { argv: string[] }[]; instrumentation: any; artifacts: string[]; recipe_sha: string; injected_env: Record<string, string>; base_image: string; arch: string; network: string; cross?: boolean; }
export interface BuildRow { id: string; status: string; recipe_sha?: string | null; source_content_hash?: string | null; toolchain_digest?: string | null; artifacts: Record<string, string>; instrumentation: any; returncode?: number | null; duration: number; error?: string | null; derived_target_id?: string | null; source_tree_id: string; created_at?: string | null; lockfile?: Record<string, any>; sbom?: any[]; reproducible?: boolean; cache_hit?: boolean; cache_key?: string | null; source_revision_id?: string | null; }
export interface SourceRevision { id: string; tree_id: string; rel: string; seq: number; role: string; size: number; origin: string; note?: string | null; has_diff?: boolean; created_at?: string | null; diff?: string | null; content?: string; }
// ── Fuzz campaigns / artifacts (Phase 4 triage) ───────────────────────────────
export interface Assurance { standard: string; method: string; precondition: string; precondition_inferred?: boolean; detail?: string; }
export interface CampaignStats { execs?: number; edges_covered?: number; crash_count?: number; peak_rss?: number; coverage_percent?: number; last_run_at?: string; }
export interface Campaign {
  id: string; project_id: string; target_id: string; name: string; surface: string; engine: string;
  status: string; instances: number; stats: CampaignStats; resources: Record<string, any>;
  coverage_instrumented?: boolean | null; build_spec_id?: string | null; task_id?: string | null;
  corpus_ref?: string | null; coverage_ref?: string | null; error?: string | null;
  // First-class degradation signal: a campaign that did 0 work / hit engine instability
  // finalizes `degraded` (not `completed`) and carries the WHY here.
  warning?: string | null; engine_note?: string | null;
  created_at?: string | null; finished_at?: string | null;
}
// One outbound action against a live target (allowed or denied) — the egress audit log.
export interface EgressEvent { id: string; dest: string; allowed: boolean; tool: string; target_id?: string | null; task_id?: string | null; detail?: string | null; created_at?: string | null; }
export interface StackFrame { idx: number; func: string; file: string; line: number; col?: number | null; }
export interface FuzzArtifact {
  id: string; campaign_id: string; kind: string; content_cas?: string | null; size: number;
  sanitizer?: string | null; dedup_key?: string | null; dupe_count: number;
  faulting_function?: string | null; exploitability: { rating?: string; access?: string; signals?: string[] };
  finding_id?: string | null; created_at?: string | null;
  finding?: { id: string; title: string; severity: string; status: string; verified: boolean; has_poc: boolean };
  assurance?: Assurance | null; frames?: StackFrame[]; source_ref?: { tree_id?: string; rel?: string; line?: number } | null;
}
export interface Coverage { available: boolean; percent?: number | null; files: Record<string, { covered: number[]; uncovered?: number[]; total?: number }>; }
export interface FuzzEngines { surface?: string; inferred?: boolean; engines?: string[]; default?: string | null; surfaces?: Record<string, { engines: string[]; default: string | null }>; }
// Remote fuzz environments (Phase 6) — WHERE a campaign's container runs. NON-SECRET only:
// `connection_present` is presence-only (the DOCKER_HOST/creds live in env/config.toml).
export interface FuzzEnvHealth { ok?: boolean; reachable?: boolean; authorized?: boolean; image_present?: boolean; docker_version?: string | null; detail?: string; checked_at?: string; }
export interface FuzzEnvironment { id: string; name: string; transport: string; host_descriptor?: string | null; is_local: boolean; connection_present: boolean; resources: Record<string, any>; health: FuzzEnvHealth; created_at?: string | null; }

// A Tool Result (Phase O Observation, design §5.6): one recorded deterministic tool
// call on a target — the call (tool + args), a short summary, what bytes it analyzed,
// and the full payload in CAS (returned only on the single-get). List/search omit it.
export interface Observation {
  id: string; project_id: string; target_id: string; created_at: string | null;
  source: string; tool: string; args: Record<string, any>; content_hash: string | null;
  result_kind: string; summary: string; status: string; size: number;
  node_refs: any[]; payload?: any;  // payload present only on get_observation
}
export interface GraphNode { id: string; type: "target" | "node" | "finding"; label: string; [k: string]: any; }
export interface GraphEdge { id: string; source: string; target: string; type: string; src_kind?: string; dst_kind?: string; origin?: string; confidence?: number | null; attrs?: Record<string, any>; count?: number; }
export interface Graph { project_id: string; nodes: GraphNode[]; edges: GraphEdge[]; }
// Cheap node/edge counts so the client picks skeleton-first vs full load WITHOUT
// first fetching the whole (~13k-node) graph (engine/graph.graph_size).
export interface GraphSize { project_id: string; targets: number; nodes: number; findings: number; edges: number; total: number; skeleton_recommended: boolean; threshold: number; }
// The structural SKELETON: rooms (byte targets, `room:true` + per-room counts +
// worst_severity) + shared sockets + aggregated cross-room meta-edges. No interiors.
export interface Skeleton { project_id: string; skeleton: true; nodes: GraphNode[]; edges: GraphEdge[]; }
// One room's interior on demand (engine/graph.build_room).
export interface RoomGraph { project_id: string; target_id: string; nodes: GraphNode[]; edges: GraphEdge[]; }
export interface ProjectDetail {
  project: Project; targets: TargetNode[]; findings: Finding[];
  cost: { total_usd: number; cost_source: string; task_count: number };
}

// Turn a failed Response into a human-readable Error. FastAPI puts the real reason in
// the JSON `detail` body (a plain string, or a 422 validation list) — surface THAT, not
// a bare `400 /api/…/campaigns`, so modals can show the actual cause. Falls back to the
// status code only when there's no parseable body.
async function httpError(r: Response): Promise<Error> {
  let detail: unknown;
  try { detail = (await r.json())?.detail; } catch { /* no/!JSON body */ }
  let msg: string | undefined;
  if (typeof detail === "string") msg = detail;
  else if (Array.isArray(detail)) msg = detail.map((d: any) => d?.msg || JSON.stringify(d)).join("; ");
  else if (detail && typeof detail === "object") msg = JSON.stringify(detail);
  return new Error(msg || `request failed (${r.status})`);
}

async function getJSON<T>(url: string): Promise<T> {
  const r = await fetch(url);
  if (!r.ok) throw await httpError(r);
  return r.json() as Promise<T>;
}
async function postJSON<T>(url: string, body: unknown): Promise<T> {
  const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  if (!r.ok) throw await httpError(r);
  return r.json() as Promise<T>;
}
async function patchJSON<T>(url: string, body: unknown): Promise<T> {
  const r = await fetch(url, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  if (!r.ok) throw await httpError(r);
  return r.json() as Promise<T>;
}
async function delJSON<T>(url: string): Promise<T> {
  const r = await fetch(url, { method: "DELETE" });
  if (!r.ok) throw await httpError(r);
  return r.json() as Promise<T>;
}

export const api = {
  projects: () => getJSON<Project[]>("/api/projects"),
  project: (id: string) => getJSON<ProjectDetail>(`/api/projects/${id}`),
  graph: (id: string) => getJSON<Graph>(`/graph/${id}`),
  graphSize: (id: string) => getJSON<GraphSize>(`/graph/${id}/size`),
  graphSkeleton: (id: string) => getJSON<Skeleton>(`/graph/${id}/skeleton`),
  graphRoom: (id: string, targetId: string) => getJSON<RoomGraph>(`/graph/${id}/room/${targetId}`),
  finding: (id: string) => getJSON<Finding>(`/api/findings/${id}`),
  capabilities: () => getJSON<{ target: Record<string, string[]>; node: Record<string, string[]>; edge: Record<string, string[]>; features?: { build?: boolean; build_fetch?: boolean; source_edit?: boolean; fuzzing?: boolean; poc?: boolean } }>("/api/capabilities"),
  suggestions: (fid: string) => getJSON<any[]>(`/api/findings/${fid}/suggestions`),
  setStatus: (fid: string, status: string) => postJSON(`/api/findings/${fid}/status`, { status }),
  deleteFinding: (fid: string) => delJSON<{ deleted_finding: string; found: boolean; edges: number; annotations: number; tasks_detached: number }>(`/api/findings/${fid}`),
  patchFinding: (fid: string, body: Partial<{ title: string; severity: string; confidence: string; category: string; summary: string; reasoning: string; status: string; human_notes: string; evidence: any }>) => patchJSON<Finding>(`/api/findings/${fid}`, body),
  verifyFinding: (fid: string) => postJSON<Finding & { verified: boolean; detail: string }>(`/api/findings/${fid}/verify`, {}),
  launch: (body: any) => postJSON<{ task_id: string; status: string }>("/api/tasks", body),
  spawnFollowup: (fid: string, i: number) => postJSON<{ task_id: string }>(`/api/findings/${fid}/followups/${i}`, {}),
  task: (tid: string) => getJSON<{ id: string; status: string; type: string }>(`/api/tasks/${tid}`),
  projectTasks: (pid: string) => getJSON<any[]>(`/api/projects/${pid}/tasks`),
  taskDetail: (tid: string) => getJSON<{ task: any; findings: Finding[]; trace_files: string[]; error?: string | null }>(`/api/tasks/${tid}/detail`),
  async taskTrace(tid: string, name: string): Promise<string> {
    const r = await fetch(`/api/tasks/${tid}/trace/${encodeURIComponent(name)}`);
    if (!r.ok) throw new Error(`${r.status}`);
    return r.text();
  },
  rerun: (tid: string) => postJSON<{ task_id: string }>(`/api/tasks/${tid}/rerun`, {}),
  previewTask: (body: any) => postJSON<any>("/api/tasks/preview", body),
  clearTasks: (pid: string) => postJSON<{ removed: number }>(`/api/projects/${pid}/tasks/clear`, {}),
  components: (fid: string) => getJSON<any[]>(`/api/findings/${fid}/components`),
  bulkStatus: (ids: string[], status: string) => postJSON<{ updated: number }>("/api/findings/bulk-status", { ids, status }),
  search: (pid: string, q: string) => getJSON<{ findings: any[]; nodes: any[]; targets: { id: string; name: string; kind: string; format?: string; arch?: string }[]; coverage: any }>(`/api/projects/${pid}/search?q=${encodeURIComponent(q)}`),
  linkSameCode: (pid: string) => postJSON<{ created: number }>(`/api/projects/${pid}/link-same-code`, {}),
  mergeDuplicates: (pid: string) => postJSON<{ targets_merged: number; nodes_merged: number }>(`/api/projects/${pid}/merge-duplicates`, {}),
  reportUrl: (pid: string) => `/api/projects/${pid}/report`,
  egress: (pid: string, limit = 500) => getJSON<{ events: EgressEvent[] }>(`/api/projects/${pid}/egress?limit=${limit}`),
  async report(pid: string): Promise<string> {
    const r = await fetch(`/api/projects/${pid}/report`);
    if (!r.ok) throw new Error(`${r.status}`);
    return r.text();
  },
  targetRuns: (tid: string) => getJSON<AnalysisRunRow[]>(`/api/targets/${tid}/runs`),
  // Tool Results (Phase O Observations) — read-only browse + provenance lookups.
  observations: (pid: string, tid: string, opts: { tool?: string; kind?: string; since?: string; limit?: number } = {}) => {
    const qs = new URLSearchParams();
    if (opts.tool) qs.set("tool", opts.tool);
    if (opts.kind) qs.set("kind", opts.kind);
    if (opts.since) qs.set("since", opts.since);
    if (opts.limit) qs.set("limit", String(opts.limit));
    return getJSON<{ observations: Observation[] }>(`/api/projects/${pid}/targets/${tid}/observations${qs.toString() ? "?" + qs.toString() : ""}`);
  },
  observation: (oid: string) => getJSON<Observation>(`/api/observations/${oid}`),
  searchObservations: (pid: string, q: string, targetId?: string) => {
    const qs = new URLSearchParams({ q });
    if (targetId) qs.set("target_id", targetId);
    return getJSON<{ observations: Observation[] }>(`/api/projects/${pid}/observations/search?${qs.toString()}`);
  },
  runsDiff: (run_a: string, run_b: string) => postJSON<RunDiff>("/api/runs/diff", { run_a, run_b }),
  // Authoring (no CLI required)
  createProject: (name: string, backend: string) => postJSON<Project>("/api/projects", { name, backend }),
  async removeTarget(pid: string, tid: string): Promise<{ archived: number }> {
    const r = await fetch(`/api/projects/${pid}/targets/${tid}`, { method: "DELETE" });
    if (!r.ok) throw await httpError(r);
    return r.json();
  },
  deleteProject: (pid: string) => delJSON<{ deleted_project: string; rows: Record<string, number> }>(`/api/projects/${pid}`),
  createNode: (pid: string, body: any) => postJSON<any>(`/api/projects/${pid}/nodes`, body),
  patchNode: (pid: string, nid: string, body: Partial<{ name: string; address: string; attrs: any }>) => patchJSON<any>(`/api/projects/${pid}/nodes/${nid}`, body),
  readFile: (tid: string, rel: string) => getJSON<{ rel: string; size: number; encoding: "text" | "binary"; content: string; truncated: boolean }>(`/api/targets/${tid}/file?rel=${encodeURIComponent(rel)}`),
  removeNode: (pid: string, nid: string) => delJSON<{ archived: boolean; id: string }>(`/api/projects/${pid}/nodes/${nid}`),
  restoreNode: (pid: string, nid: string) => postJSON<{ archived: boolean; id: string }>(`/api/projects/${pid}/nodes/${nid}/restore`, {}),
  deleteEdge: (eid: string) => delJSON<{ deleted: boolean; id: string }>(`/api/edges/${eid}`),
  decompile: (tid: string, fn: string) => postJSON<{ available: boolean; detail?: string; focus?: any; functions?: string[] }>(`/api/targets/${tid}/decompile`, { function: fn }),
  filesystem: (tid: string) => getJSON<{ unpacked: boolean; method?: string; files: FsEntry[] }>(`/api/targets/${tid}/filesystem`),
  addFromFs: (pid: string, fwId: string, rel: string) => postJSON<any>(`/api/projects/${pid}/targets/${fwId}/add-from-fs`, { rel }),
  // Source trees (Phase 1 — read-only IDE browse)
  sourceTrees: (pid: string) => getJSON<{ source_trees: SourceTreeRow[] }>(`/api/projects/${pid}/source-trees`),
  createSourceTree: (pid: string, body: { name: string; origin?: string; target_id?: string }) => postJSON<{ id: string; name: string; origin: string }>(`/api/projects/${pid}/source-trees`, body),
  sourceFiles: (treeId: string) => getJSON<{ id: string; name: string; origin: string; editable: boolean; files: SourceFileEntry[] }>(`/api/source-trees/${treeId}/files`),
  sourceFile: (treeId: string, rel: string) => getJSON<{ rel: string; size: number; role: string; origin: string; encoding: "text" | "binary"; content: string; truncated: boolean }>(`/api/source-trees/${treeId}/file?rel=${encodeURIComponent(rel)}`),
  backfillHarnesses: (pid: string) => postJSON<{ promoted: number; scanned: number }>(`/api/projects/${pid}/backfill-harnesses`, {}),
  buildPreview: (pid: string, body: BuildSpecBody) => postJSON<BuildPreview>(`/api/projects/${pid}/build/preview`, body),
  createBuild: (pid: string, body: { build_spec_id?: string; spec?: BuildSpecBody; source_revision_id?: string }) => postJSON<BuildRow>(`/api/projects/${pid}/builds`, body),
  builds: (pid: string, sourceTreeId?: string) => getJSON<{ builds: BuildRow[] }>(`/api/projects/${pid}/builds${sourceTreeId ? `?source_tree_id=${sourceTreeId}` : ""}`),
  buildLog: (bid: string) => getJSON<{ build_id: string; log: string }>(`/api/builds/${bid}/log`),
  importOssFuzz: (pid: string, body: { source_tree_id: string; build_sh: string; instrumentation?: any; artifacts?: string[] }) => postJSON<any>(`/api/projects/${pid}/builds/import-oss-fuzz`, body),
  // Editable IDE: revisioned saves + history + rebuild-from-revision (Phase 7)
  saveSourceRevision: (treeId: string, body: { rel: string; content: string; role?: string; note?: string }) => postJSON<SourceRevision>(`/api/source-trees/${treeId}/revisions`, body),
  sourceRevisions: (treeId: string, rel?: string) => getJSON<{ revisions: SourceRevision[] }>(`/api/source-trees/${treeId}/revisions${rel ? `?rel=${encodeURIComponent(rel)}` : ""}`),
  sourceRevision: (rid: string) => getJSON<SourceRevision>(`/api/source-revisions/${rid}`),
  revertSourceRevision: (treeId: string, rid: string) => postJSON<SourceRevision>(`/api/source-trees/${treeId}/revisions/${rid}/revert`, {}),
  // Run-to-run coverage diff (Phase 7)
  coverageDiff: (cid: string, other: string) => getJSON<any>(`/api/campaigns/${cid}/coverage-diff?other=${other}`),
  // Fuzz campaigns + artifacts (Phase 4 triage)
  campaigns: (pid: string, targetId?: string) => getJSON<{ campaigns: Campaign[] }>(`/api/projects/${pid}/campaigns${targetId ? `?target_id=${targetId}` : ""}`),
  campaign: (cid: string) => getJSON<Campaign>(`/api/campaigns/${cid}`),
  startCampaign: (pid: string, body: { target_id: string; surface?: string | null; engine?: string | null; function?: string | null; max_total_time?: number; max_len?: number; max_crashes?: number; instances?: number; seeds?: string[]; dictionary?: string[]; build_spec_id?: string | null; net?: { host?: string | null; port?: number | null; protocol?: string | null; proto_spec?: Record<string, any> | null } | null; resources?: Record<string, any>; environment?: string | null }) => postJSON<Campaign>(`/api/projects/${pid}/campaigns`, body),
  stopCampaign: (cid: string) => postJSON<Campaign>(`/api/campaigns/${cid}/stop`, {}),
  resumeCampaign: (cid: string) => postJSON<Campaign>(`/api/campaigns/${cid}/resume`, {}),
  campaignArtifacts: (cid: string) => getJSON<{ artifacts: FuzzArtifact[] }>(`/api/campaigns/${cid}/artifacts`),
  campaignCoverage: (cid: string) => getJSON<Coverage>(`/api/campaigns/${cid}/coverage`),
  verifyArtifact: (aid: string) => postJSON<{ artifact_id: string; verified: boolean; detail?: string; assurance?: Assurance; output?: string }>(`/api/artifacts/${aid}/verify`, {}),
  minimizeArtifact: (aid: string) => postJSON<{ artifact_id: string; verified: boolean; detail?: string; assurance?: Assurance }>(`/api/artifacts/${aid}/minimize`, {}),
  promoteArtifact: (aid: string, toPoc: boolean) => postJSON<{ artifact_id: string; finding_id: string; status: string; to_poc: boolean; verified?: boolean; verify_detail?: string; assurance?: Assurance }>(`/api/artifacts/${aid}/promote`, { to_poc: toPoc }),
  fuzzEngines: (surface?: string, targetId?: string) => {
    const qs = new URLSearchParams();
    if (surface) qs.set("surface", surface);
    if (targetId) qs.set("target_id", targetId);
    return getJSON<FuzzEngines>(`/api/fuzz/engines${qs.toString() ? "?" + qs.toString() : ""}`);
  },
  campaignEventsUrl: (cid: string) => `/api/campaigns/${cid}/events`,
  // Remote fuzz environments (Phase 6). Secrets are presence-only — never sent/echoed.
  fuzzEnvironments: () => getJSON<{ environments: FuzzEnvironment[] }>(`/api/fuzz/environments`),
  registerFuzzEnvironment: (body: { name: string; transport?: string; host_descriptor?: string; resources?: Record<string, any> }) => postJSON<FuzzEnvironment>(`/api/fuzz/environments`, body),
  fuzzEnvironmentHealth: (id: string) => postJSON<FuzzEnvHealth>(`/api/fuzz/environments/${id}/health`, {}),
  deleteFuzzEnvironment: (id: string) => fetch(`/api/fuzz/environments/${id}`, { method: "DELETE" }).then((r) => r.json()),
  createEdge: (pid: string, body: any) => postJSON<any>(`/api/projects/${pid}/edges`, body),
  updateEdge: (eid: string, body: { attrs: Record<string, any>; merge?: boolean }) => patchJSON<any>(`/api/edges/${eid}`, body),
  createSocket: (pid: string, body: { kind?: string; port?: number | string | null; name?: string | null; bind_addr?: string | null; attrs?: any }) => postJSON<any>(`/api/projects/${pid}/sockets`, body),
  edgeSchemas: () => getJSON<{ edges: Record<string, any>; socket_kinds: string[] }>(`/api/edge-schemas`),
  nodeSchemas: () => getJSON<{ nodes: Record<string, { description: string; use_when: string; recommended_attributes: string[]; attributes: Record<string, any> }> }>(`/api/node-schemas`),
  createAnnotation: (pid: string, body: any) => postJSON<any>(`/api/projects/${pid}/annotations`, body),
  annotations: (nodeKind: string, nodeId: string) => getJSON<any[]>(`/api/annotations/${nodeKind}/${nodeId}`),
  setAnnotationStatus: (id: string, status: string) => postJSON<any>(`/api/annotations/${id}/status`, { status }),
  // Hypotheses (research questions evidenced by findings)
  createHypothesis: (pid: string, body: any) => postJSON<Hypothesis>(`/api/projects/${pid}/hypotheses`, body),
  hypothesis: (hid: string) => getJSON<Hypothesis>(`/api/hypotheses/${hid}`),
  linkEvidence: (hid: string, finding_id: string, relation: string) => postJSON<Hypothesis>(`/api/hypotheses/${hid}/evidence`, { finding_id, relation }),
  setHypothesisStatus: (hid: string, status: string) => postJSON<Hypothesis>(`/api/hypotheses/${hid}/status`, { status }),
  // Settings (optional features + non-secret prefs; secrets are status-only)
  getSettings: () => getJSON<SettingsView>("/api/settings"),
  async patchSettings(patch: Record<string, any>): Promise<SettingsView> {
    const r = await fetch("/api/settings", { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(patch) });
    if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `${r.status}`);
    return r.json();
  },
  testGhidra: () => postJSON<GhidraStatus>("/api/settings/ghidra/test", {}),
  ghidraPrograms: () => getJSON<{ name: string; path: string; language: string; functions: number }[]>("/api/ghidra/programs"),
  ghidraImport: (pid: string, path: string, name?: string) => postJSON<any>(`/api/projects/${pid}/ghidra/import`, { path, name }),
  async addTarget(pid: string, file: File, recon: boolean): Promise<any> {
    const fd = new FormData();
    fd.append("file", file);
    fd.append("recon", String(recon));
    const r = await fetch(`/api/projects/${pid}/targets`, { method: "POST", body: fd });
    if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `${r.status}`);
    return r.json();
  },
};

export const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
