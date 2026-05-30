"use strict";
const PROJECT = document.querySelector(".workspace").dataset.project;
const $ = (s) => document.querySelector(s);

const SEV_COLOR = {
  info: "#6e7681", low: "#3fb950", medium: "#d29922", high: "#f85149", critical: "#ff5c8a",
};
const KIND_COLOR = {
  firmware_image: "#a371f7", executable: "#58a6ff", shared_library: "#39c5cf", unknown: "#7d8590",
};

let cy = null;

async function getJSON(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`${r.status} ${url}`);
  return r.json();
}
async function postJSON(url, body) {
  const r = await fetch(url, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  return r.json();
}

function renderTree(targets) {
  const tree = $("#tree");
  tree.innerHTML = "";
  const roots = targets.filter((t) => !t.parent_id);
  const childrenOf = (id) => targets.filter((t) => t.parent_id === id);
  const TASK_TYPES = ["recon", "static_analysis", "reverse_engineering", "pattern_sweep", "harness_generation"];
  const SCENARIOS = ["(default)", "critical_overflow", "no_findings", "malformed_then_valid", "error_rate_limit", "error_timeout"];
  const row = (t, isChild) => {
    const div = document.createElement("div");
    div.className = "node-row" + (isChild ? " child" : "");
    div.innerHTML =
      `<div class="name">${t.name}</div>` +
      `<div class="meta">${t.kind}${t.arch ? " · " + t.arch : ""}</div>`;
    const controls = document.createElement("div");
    controls.className = "task-controls";
    const typeSel = document.createElement("select");
    TASK_TYPES.forEach((tt) => typeSel.add(new Option(tt, tt)));
    const scenSel = document.createElement("select");
    SCENARIOS.forEach((sc) => scenSel.add(new Option(sc, sc)));
    scenSel.title = "mock scenario (mock backend only)";
    const btn = document.createElement("button");
    btn.className = "btn";
    btn.textContent = "Run";
    btn.onclick = () => {
      const scenario = scenSel.value === "(default)" ? null : scenSel.value;
      launch(t.id, typeSel.value, scenario);
    };
    controls.append(typeSel, scenSel, btn);
    div.appendChild(controls);
    tree.appendChild(div);
    childrenOf(t.id).forEach((c) => row(c, true));
  };
  roots.forEach((t) => row(t, false));
}

function renderFindings(findings) {
  const box = $("#findings");
  box.innerHTML = "";
  if (!findings.length) { box.innerHTML = '<p class="muted">No findings yet.</p>'; return; }
  findings.forEach((f) => {
    const div = document.createElement("div");
    div.className = "finding";
    div.innerHTML =
      `<span class="chip sev-${f.severity}">${f.severity}</span>` +
      `<span class="title">${f.title}</span>` +
      `<div class="meta">${f.category} · ${f.confidence} confidence · ${f.status}</div>`;
    div.onclick = () => showDetail(f.id);
    box.appendChild(div);
  });
}

async function showDetail(fid) {
  const f = await getJSON(`/api/findings/${fid}`);
  const ev = f.evidence || {};
  const parts = [`<h3>${f.title}</h3>`];
  parts.push(
    `<div class="triage">status: <b>${f.status}</b> ` +
    `<button class="btn" data-status="accepted">Accept</button> ` +
    `<button class="btn" data-status="dismissed">Dismiss</button></div>`
  );
  parts.push(`<p>${f.summary}</p>`);
  parts.push(`<p class="kv">Reasoning:</p><p>${f.reasoning}</p>`);
  if (ev.function) parts.push(`<p class="kv">function: <code>${ev.function}</code></p>`);
  if (ev.sink) parts.push(`<p class="kv">sink: <code>${ev.sink}</code></p>`);
  if (ev.decompiled_snippet) parts.push(`<pre>${escapeHtml(ev.decompiled_snippet)}</pre>`);
  if (ev.extra && ev.extra.mitigations)
    parts.push(`<p class="kv">mitigations: <code>${JSON.stringify(ev.extra.mitigations)}</code></p>`);
  if (f.suggested_followups && f.suggested_followups.length) {
    parts.push(`<p class="kv">Suggested follow-ups:</p>`);
    f.suggested_followups.forEach((s, i) => {
      parts.push(`<button class="btn" data-fu="${i}">${escapeHtml(s.label)}</button> `);
    });
  }
  const detail = $("#detail");
  detail.innerHTML = parts.join("");
  detail.querySelectorAll("button[data-fu]").forEach((b) => {
    b.onclick = () => spawnFollowup(f.id, +b.dataset.fu);
  });
  detail.querySelectorAll("button[data-status]").forEach((b) => {
    b.onclick = async () => {
      await postJSON(`/api/findings/${f.id}/status`, { status: b.dataset.status });
      await loadAll();
      await showDetail(f.id);
    };
  });
}

function escapeHtml(s) {
  return String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
}

async function pollAndReload(task_id) {
  for (let i = 0; i < 60; i++) {
    await new Promise((r) => setTimeout(r, 700));
    const t = await getJSON(`/api/tasks/${task_id}`);
    if (t.status !== "queued" && t.status !== "running") break;
  }
  await loadAll();
}

async function launch(targetId, type, scenario) {
  const body = { target_id: targetId, type };
  if (scenario) body.mock_scenario = scenario;
  const { task_id } = await postJSON("/api/tasks", body);
  await pollAndReload(task_id);
}

async function spawnFollowup(findingId, index) {
  const { task_id } = await postJSON(`/api/findings/${findingId}/followups/${index}`, {});
  await pollAndReload(task_id);
}

async function loadGraph() {
  const g = await getJSON(`/graph/${PROJECT}`);
  const elements = [];
  g.nodes.forEach((n) => {
    elements.push({
      data: { id: n.id, label: n.label, type: n.type, severity: n.severity, kind: n.kind },
    });
  });
  g.edges.forEach((e) => {
    elements.push({ data: { id: e.id, source: e.source, target: e.target, etype: e.type } });
  });
  cy = cytoscape({
    container: $("#cy"),
    elements,
    style: [
      { selector: "node", style: {
        "label": "data(label)", "color": "#c9d1d9", "font-size": "9px",
        "text-valign": "bottom", "text-wrap": "wrap", "text-max-width": "120px",
        "width": 22, "height": 22,
        "background-color": (n) => n.data("type") === "finding"
          ? (SEV_COLOR[n.data("severity")] || "#6e7681")
          : (KIND_COLOR[n.data("kind")] || "#7d8590"),
        "shape": (n) => n.data("type") === "finding" ? "diamond" : "ellipse",
      }},
      { selector: "edge", style: {
        "width": 1.5, "line-color": "#39414f", "target-arrow-color": "#39414f",
        "target-arrow-shape": "triangle", "curve-style": "bezier",
        "label": "data(etype)", "font-size": "7px", "color": "#7d8590",
      }},
    ],
    layout: { name: "breadthfirst", directed: true, padding: 20, spacingFactor: 1.1 },
  });
}

function renderSummary(data) {
  const el = $("#summary");
  if (!el) return;
  const cost = data.cost || {};
  const usd = (cost.total_usd || 0).toFixed(4);
  const src = cost.cost_source === "mock" ? "mock · $0" : `${cost.cost_source} · $${usd}`;
  el.textContent = `· ${data.findings.length} findings · ${cost.task_count || 0} tasks · ${src}`;
}

async function loadAll() {
  const data = await getJSON(`/api/projects/${PROJECT}`);
  renderSummary(data);
  renderTree(data.targets);
  renderFindings(data.findings);
  await loadGraph();
}

$("#refresh").onclick = loadAll;
loadAll().catch((e) => { $("#tree").innerHTML = `<p class="muted">${e}</p>`; });
