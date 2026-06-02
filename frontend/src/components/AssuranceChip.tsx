import { Assurance } from "../api";

// The assurance triple as a compact chip: {standard · method · precondition}. This is
// the two-standards ladder the assurance work exists to keep honest:
//   code_present/static  <  code_present/dynamic   (lab-confirmed in isolation)
//   input_reachable/static < input_reachable/dynamic (reachable via the live boundary)
// Green = reachable+dynamic (the ceiling); amber = lab-confirmed in isolation;
// muted = static / suspected.
const human = (s: any) => String(s ?? "").replace(/_/g, " ");

export function assuranceColor(a?: Assurance | null): string {
  if (!a) return "var(--muted)";
  const dyn = a.method === "dynamic";
  if (a.standard === "input_reachable" && dyn) return "#2ea043";
  if (a.standard === "code_present" && dyn) return "#d29922";
  return "var(--muted)";
}

export function assuranceNote(a?: Assurance | null): string {
  if (!a) return "";
  const dyn = a.method === "dynamic";
  if (a.standard === "input_reachable" && dyn) return "reachable through the live deployed input boundary";
  if (a.standard === "code_present" && dyn) return "lab-confirmed in isolation — production input path not established";
  if (a.standard === "unconfirmed") return "unconfirmed";
  return "static / suspected";
}

export default function AssuranceChip({ a, showNote = false }: { a?: Assurance | null; showNote?: boolean }) {
  if (!a) return null;
  const color = assuranceColor(a);
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}
          title={assuranceNote(a)}>
      <code style={{ color, borderColor: color, fontSize: 10.5 }}>
        {human(a.standard)} · {human(a.method)} · {human(a.precondition)}
        {a.precondition_inferred ? " (inferred)" : ""}
      </code>
      {showNote && <span className="muted" style={{ fontSize: 10.5 }}>{assuranceNote(a)}</span>}
    </span>
  );
}
