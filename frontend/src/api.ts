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
export interface SettingsView {
  settings: {
    llm: { backend: string; model: string | null };
    server: { host: string; port: number };
    features: {
      ghidra: { enabled: boolean; mode: string; enrich_recon: boolean; timeout: number; bridge: { host: string; port: number } };
      fuzzing: { enabled: boolean; max_total_time: number; max_len: number; max_crashes: number; timeout: number };
      poc: { enabled: boolean; timeout: number };
      network: { enabled: boolean; timeout: number };
      mcp: { read: boolean; write: boolean; run: boolean };
      agent: { enabled: boolean; cli: string; binary: string; timeout: number };
    };
  };
  secrets: Record<string, SecretStatus>;
  availability: { docker: boolean; ghidra: { enabled: boolean; mode: string; bridge_client_installed: boolean } };
  paths: { config_toml: string; settings_json: string };
}
export interface GhidraStatus { enabled: boolean; ok: boolean; detail: string; mode?: string; [k: string]: any; }
export interface FsEntry { rel: string; size?: number; is_elf?: boolean; child_target_id?: string | null; added?: boolean; }
export interface GraphNode { id: string; type: "target" | "node" | "finding"; label: string; [k: string]: any; }
export interface GraphEdge { id: string; source: string; target: string; type: string; src_kind?: string; dst_kind?: string; origin?: string; confidence?: number | null; attrs?: Record<string, any>; count?: number; }
export interface Graph { project_id: string; nodes: GraphNode[]; edges: GraphEdge[]; }
export interface ProjectDetail {
  project: Project; targets: TargetNode[]; findings: Finding[];
  cost: { total_usd: number; cost_source: string; task_count: number };
}

async function getJSON<T>(url: string): Promise<T> {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`${r.status} ${url}`);
  return r.json() as Promise<T>;
}
async function postJSON<T>(url: string, body: unknown): Promise<T> {
  const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  if (!r.ok) throw new Error(`${r.status} ${url}`);
  return r.json() as Promise<T>;
}
async function patchJSON<T>(url: string, body: unknown): Promise<T> {
  const r = await fetch(url, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  if (!r.ok) throw new Error(`${r.status} ${url}`);
  return r.json() as Promise<T>;
}

export const api = {
  projects: () => getJSON<Project[]>("/api/projects"),
  project: (id: string) => getJSON<ProjectDetail>(`/api/projects/${id}`),
  graph: (id: string) => getJSON<Graph>(`/graph/${id}`),
  finding: (id: string) => getJSON<Finding>(`/api/findings/${id}`),
  capabilities: () => getJSON<Record<string, Record<string, string[]>>>("/api/capabilities"),
  suggestions: (fid: string) => getJSON<any[]>(`/api/findings/${fid}/suggestions`),
  setStatus: (fid: string, status: string) => postJSON(`/api/findings/${fid}/status`, { status }),
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
  search: (pid: string, q: string) => getJSON<{ findings: any[]; nodes: any[]; coverage: any }>(`/api/projects/${pid}/search?q=${encodeURIComponent(q)}`),
  linkSameCode: (pid: string) => postJSON<{ created: number }>(`/api/projects/${pid}/link-same-code`, {}),
  mergeDuplicates: (pid: string) => postJSON<{ targets_merged: number; nodes_merged: number }>(`/api/projects/${pid}/merge-duplicates`, {}),
  reportUrl: (pid: string) => `/api/projects/${pid}/report`,
  async report(pid: string): Promise<string> {
    const r = await fetch(`/api/projects/${pid}/report`);
    if (!r.ok) throw new Error(`${r.status}`);
    return r.text();
  },
  targetRuns: (tid: string) => getJSON<AnalysisRunRow[]>(`/api/targets/${tid}/runs`),
  runsDiff: (run_a: string, run_b: string) => postJSON<RunDiff>("/api/runs/diff", { run_a, run_b }),
  // Authoring (no CLI required)
  createProject: (name: string, backend: string) => postJSON<Project>("/api/projects", { name, backend }),
  async removeTarget(pid: string, tid: string): Promise<{ archived: number }> {
    const r = await fetch(`/api/projects/${pid}/targets/${tid}`, { method: "DELETE" });
    if (!r.ok) throw new Error(`${r.status}`);
    return r.json();
  },
  createNode: (pid: string, body: any) => postJSON<any>(`/api/projects/${pid}/nodes`, body),
  decompile: (tid: string, fn: string) => postJSON<{ available: boolean; detail?: string; focus?: any; functions?: string[] }>(`/api/targets/${tid}/decompile`, { function: fn }),
  filesystem: (tid: string) => getJSON<{ unpacked: boolean; method?: string; files: FsEntry[] }>(`/api/targets/${tid}/filesystem`),
  addFromFs: (pid: string, fwId: string, rel: string) => postJSON<any>(`/api/projects/${pid}/targets/${fwId}/add-from-fs`, { rel }),
  createEdge: (pid: string, body: any) => postJSON<any>(`/api/projects/${pid}/edges`, body),
  updateEdge: (eid: string, body: { attrs: Record<string, any>; merge?: boolean }) => patchJSON<any>(`/api/edges/${eid}`, body),
  createSocket: (pid: string, body: { kind?: string; port?: number | string | null; name?: string | null; bind_addr?: string | null; attrs?: any }) => postJSON<any>(`/api/projects/${pid}/sockets`, body),
  edgeSchemas: () => getJSON<{ edges: Record<string, any>; socket_kinds: string[] }>(`/api/edge-schemas`),
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
