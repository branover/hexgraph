// A binary's exploit mitigations as per-flag, color-coded badges instead of a raw
// JSON blob — so "weak, not silently ok" reads at a glance. Mirrors the honest
// wording the binutils observation summary uses ("weak: nx, canary, relro=partial").
//   green / ok  = the protection is present
//   red / weak  = the protection is missing (the exploitable gap)
//   amber       = partial RELRO (present but not the full guarantee)
// Shared by the finding Inspector (EVIDENCE) and NodeInspector (RECON FACTS).

type Mit = Record<string, boolean | string | null | undefined>;

const OK = "#2ea043";
const WEAK = "#ff5d6c";
const AMBER = "#d29922";

// The boolean protections: true => present (ok), false => missing (weak).
// Order is the conventional checklist order.
const BOOL_FLAGS: { key: string; on: string; off: string }[] = [
  { key: "nx", on: "NX", off: "NX off" },
  { key: "canary", on: "canary", off: "no canary" },
  { key: "pie", on: "PIE", off: "no PIE" },
  { key: "fortify", on: "FORTIFY", off: "no FORTIFY" },
];

// Does this mitigations map carry at least one RECOGNIZED protection (a boolean flag or
// relro)? <Mitigations> renders null when none are recognized, so a caller must guard its
// sibling "mitigations" label on this — otherwise an all-unrecognized map leaves a label
// with no badges dangling beside it.
export function hasKnownMitigations(mitigations?: Mit | null): boolean {
  if (!mitigations || typeof mitigations !== "object") return false;
  return BOOL_FLAGS.some((f) => f.key in mitigations) || "relro" in mitigations;
}

function Badge({ label, color, title }: { label: string; color: string; title: string }) {
  return (
    <span
      title={title}
      style={{
        display: "inline-flex", alignItems: "center", gap: 5,
        fontSize: 10.5, fontWeight: 700, textTransform: "uppercase", letterSpacing: ".04em",
        padding: "2px 8px", borderRadius: 999,
        color, background: "transparent", border: `1px solid ${color}`,
      }}
    >
      <span style={{ width: 6, height: 6, borderRadius: "50%", background: "currentColor" }} />
      {label}
    </span>
  );
}

export default function Mitigations({ mitigations }: { mitigations?: Mit | null }) {
  if (!mitigations || typeof mitigations !== "object") return null;
  const badges: { label: string; color: string; title: string }[] = [];

  for (const f of BOOL_FLAGS) {
    if (!(f.key in mitigations)) continue;
    const on = mitigations[f.key] === true;
    badges.push(on
      ? { label: f.on, color: OK, title: `${f.on} enabled` }
      : { label: f.off, color: WEAK, title: `${f.on} missing — exploit mitigation weak` });
  }

  // RELRO is a tri-state string (none / partial / full): full is ok, partial is
  // a present-but-incomplete amber, anything else (none/no) is weak.
  if ("relro" in mitigations) {
    const r = String(mitigations.relro ?? "").toLowerCase();
    if (r === "full") badges.push({ label: "RELRO full", color: OK, title: "Full RELRO" });
    else if (r === "partial") badges.push({ label: "RELRO partial", color: AMBER, title: "Partial RELRO — GOT not fully protected" });
    else badges.push({ label: "RELRO off", color: WEAK, title: "No RELRO" });
  }

  if (!badges.length) return null;
  return (
    <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
      {badges.map((b, i) => <Badge key={i} {...b} />)}
    </div>
  );
}
