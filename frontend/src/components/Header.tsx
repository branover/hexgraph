import { Link } from "react-router-dom";

export default function Header({ subtitle, cost }: { subtitle?: string; cost?: { total_usd: number; cost_source: string } }) {
  return (
    <header className="app">
      <Link to="/" className="brand"><span className="hex">⬡</span> HexGraph</Link>
      {subtitle && <span className="muted">{subtitle}</span>}
      <span className="grow" />
      {cost && (
        <span className="badge cost">
          {cost.cost_source === "mock" ? "mock · $0" : `${cost.cost_source} · $${cost.total_usd.toFixed(4)}`}
        </span>
      )}
      <span className="badge">local · 127.0.0.1</span>
    </header>
  );
}
