import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, Project } from "../api";
import Header from "../components/Header";
import { Icon } from "../components/Icon";

type Row = Project & { targets?: number; findings?: number };

export default function Projects() {
  const [projects, setProjects] = useState<Row[] | null>(null);
  const [err, setErr] = useState<string>();

  useEffect(() => {
    api.projects().then(async (ps) => {
      setProjects(ps);
      const enriched = await Promise.all(ps.map(async (p) => {
        try { const d = await api.project(p.id); return { ...p, targets: d.targets.length, findings: d.findings.length }; }
        catch { return p; }
      }));
      setProjects(enriched);
    }).catch((e) => setErr(String(e)));
  }, []);

  return (
    <>
      <Header />
      <main>
        <h1>Projects</h1>
        <p className="muted" style={{ marginTop: 4 }}>Local-only vulnerability-research workbench — point it at a binary or firmware image.</p>
        {err && <p className="muted">{err}</p>}
        {projects && projects.length === 0 && (
          <div className="card empty" style={{ marginTop: 18 }}>
            No projects yet. Ingest a target (mock backend, no key needed):
            <pre style={{ marginTop: 12, textAlign: "left" }}>hexgraph ingest tests/fixtures/synthetic_fw.bin --name demo</pre>
          </div>
        )}
        {!projects && <div className="proj-grid">{[0, 1, 2].map((i) => <div key={i} className="card skel" style={{ height: 96 }} />)}</div>}
        <div className="proj-grid">
          {projects?.map((p) => (
            <Link className="card proj-card link fade-in" to={`/projects/${p.id}`} key={p.id}>
              <span className="name"><Icon name="chip" size={15} /> {p.name}</span>
              <span className="muted" style={{ fontSize: 12 }}>{p.backend} · {p.id.slice(0, 8)}</span>
              <div className="stats">
                <span className="stat"><b>{p.targets ?? "–"}</b> targets</span>
                <span className="stat"><b>{p.findings ?? "–"}</b> findings</span>
              </div>
            </Link>
          ))}
        </div>
      </main>
    </>
  );
}
