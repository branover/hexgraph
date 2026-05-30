import { Link } from "react-router-dom";
import { Icon } from "./Icon";

export default function Header({ project, cost }: {
  project?: { name: string; backend: string };
  cost?: { total_usd: number; cost_source: string };
}) {
  return (
    <header className="app">
      <Link to="/" className="brand"><Icon name="hex" size={20} /> HexGraph</Link>
      {project && <span className="crumb"><span className="sep">/</span>{project.name}</span>}
      <span className="grow" />
      {project && <span className="badge"><span className="dot" />{project.backend}</span>}
      {cost && (
        <span className="badge cost">
          <span className="dot" />
          {cost.cost_source === "mock" ? "$0 · mock" : `$${cost.total_usd.toFixed(4)} · ${cost.cost_source}`}
        </span>
      )}
      <span className="badge">local · 127.0.0.1</span>
    </header>
  );
}
