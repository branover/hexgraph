// Typed client for the HexGraph JSON API (the SPA's only backend contract).

export interface Project { id: string; name: string; backend: string; created_at: string; }
export interface TargetNode { id: string; name: string; kind: string; format?: string; arch?: string; parent_id?: string | null; metadata?: any; }
export interface Finding {
  id: string; target_id: string; task_id: string; status: string;
  title: string; severity: string; confidence: string; category: string;
  summary: string; reasoning: string; evidence: any;
  suggested_followups?: any[]; related_target_refs?: string[]; created_at?: string;
  origin?: string; dismissed_reason?: string | null; human_notes?: string | null; tags?: string[];
}
export interface EvidenceRef { finding_id: string; title: string; severity: string; status: string; origin: string; }
export interface Hypothesis {
  id: string; statement: string; rationale?: string | null; status: string; status_origin: string;
  supports: EvidenceRef[]; refutes: EvidenceRef[];
}
export interface GraphNode { id: string; type: "target" | "node" | "finding"; label: string; [k: string]: any; }
export interface GraphEdge { id: string; source: string; target: string; type: string; src_kind?: string; dst_kind?: string; origin?: string; confidence?: number | null; }
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
  taskDetail: (tid: string) => getJSON<{ task: any; findings: Finding[]; trace_files: string[] }>(`/api/tasks/${tid}/detail`),
  rerun: (tid: string) => postJSON<{ task_id: string }>(`/api/tasks/${tid}/rerun`, {}),
  previewTask: (body: any) => postJSON<any>("/api/tasks/preview", body),
  clearTasks: (pid: string) => postJSON<{ removed: number }>(`/api/projects/${pid}/tasks/clear`, {}),
  components: (fid: string) => getJSON<any[]>(`/api/findings/${fid}/components`),
  bulkStatus: (ids: string[], status: string) => postJSON<{ updated: number }>("/api/findings/bulk-status", { ids, status }),
  search: (pid: string, q: string) => getJSON<{ findings: any[]; nodes: any[]; coverage: any }>(`/api/projects/${pid}/search?q=${encodeURIComponent(q)}`),
  linkSameCode: (pid: string) => postJSON<{ created: number }>(`/api/projects/${pid}/link-same-code`, {}),
  reportUrl: (pid: string) => `/api/projects/${pid}/report`,
  // Authoring (no CLI required)
  createProject: (name: string, backend: string) => postJSON<Project>("/api/projects", { name, backend }),
  createNode: (pid: string, body: any) => postJSON<any>(`/api/projects/${pid}/nodes`, body),
  createEdge: (pid: string, body: any) => postJSON<any>(`/api/projects/${pid}/edges`, body),
  createAnnotation: (pid: string, body: any) => postJSON<any>(`/api/projects/${pid}/annotations`, body),
  annotations: (nodeKind: string, nodeId: string) => getJSON<any[]>(`/api/annotations/${nodeKind}/${nodeId}`),
  setAnnotationStatus: (id: string, status: string) => postJSON<any>(`/api/annotations/${id}/status`, { status }),
  // Hypotheses (research questions evidenced by findings)
  createHypothesis: (pid: string, body: any) => postJSON<Hypothesis>(`/api/projects/${pid}/hypotheses`, body),
  hypothesis: (hid: string) => getJSON<Hypothesis>(`/api/hypotheses/${hid}`),
  linkEvidence: (hid: string, finding_id: string, relation: string) => postJSON<Hypothesis>(`/api/hypotheses/${hid}/evidence`, { finding_id, relation }),
  setHypothesisStatus: (hid: string, status: string) => postJSON<Hypothesis>(`/api/hypotheses/${hid}/status`, { status }),
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
