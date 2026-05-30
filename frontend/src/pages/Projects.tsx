import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, Project } from "../api";
import Header from "../components/Header";

export default function Projects() {
  const [projects, setProjects] = useState<Project[] | null>(null);
  const [err, setErr] = useState<string>();

  useEffect(() => { api.projects().then(setProjects).catch((e) => setErr(String(e))); }, []);

  return (
    <>
      <Header />
      <main>
        <h1>Projects</h1>
        {err && <p className="muted">{err}</p>}
        {projects && projects.length === 0 && (
          <div className="card empty">
            No projects yet. Ingest a target (mock backend, no key needed):
            <pre style={{ marginTop: 10 }}>hexgraph ingest tests/fixtures/synthetic_fw.bin --name demo</pre>
          </div>
        )}
        {projects?.map((p) => (
          <div className="card project-row" key={p.id}>
            <Link className="name" to={`/projects/${p.id}`}>{p.name}</Link>
            <span className="grow" />
            <span className="badge">{p.backend}</span>
            <span className="muted" style={{ fontSize: 12 }}>{p.id.slice(0, 8)}</span>
          </div>
        ))}
      </main>
    </>
  );
}
