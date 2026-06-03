// Human-facing copy for each task TYPE the Run menu offers. The set of types is still
// SERVER-DRIVEN (the capability table per target/node kind) — this only adds the label,
// one-line summary, and a richer "what happens when you click" explanation the Launcher
// shows on hover. Keep these in sync with engine task types; an unknown type falls back
// to a humanized name with no description (so a new type never breaks the menu).

export interface TaskMeta {
  label: string;        // short menu title
  icon: string;         // Icon name (see Icon.tsx)
  summary: string;      // one-line description shown under the title
  detail: string;       // richer hover explanation of what the task does
}

export const TASK_META: Record<string, TaskMeta> = {
  recon: {
    label: "Recon",
    icon: "search",
    summary: "Fingerprint the target — fast, no LLM",
    detail:
      "Statically fingerprints the binary in the sandbox: format/arch, hashes, " +
      "imports/exports, strings, linked libraries and mitigations (NX/PIE/RELRO). " +
      "Cheap, deterministic, and a good first pass that seeds the graph for everything else.",
  },
  unpack: {
    label: "Unpack firmware",
    icon: "binary",
    summary: "Extract the firmware filesystem into child targets",
    detail:
      "Carves the firmware image inside the sandbox (squashfs / cpio / disk image / " +
      "vendor blobs), recovers the root filesystem, and registers the interesting files " +
      "as child targets you can then recon and analyze individually.",
  },
  static_analysis: {
    label: "Static analysis",
    icon: "shield",
    summary: "LLM hunts for vulnerabilities — no execution",
    detail:
      "Runs the analysis agent loop: HexGraph feeds the model sandboxed tool output " +
      "(decompilation, strings, imports, call graph) and the model reasons about " +
      "memory-safety and logic bugs, emitting structured findings. The target is never " +
      "executed and the model never sees raw bytes.",
  },
  reverse_engineering: {
    label: "Reverse engineering",
    icon: "fn",
    summary: "LLM explains how a function / structure works",
    detail:
      "Asks the agent to recover intent: what a function does, its arguments and data " +
      "structures, control/dataflow and the role it plays. Produces explanatory findings " +
      "and graph nodes/edges (functions, structs, calls) rather than vuln claims — useful " +
      "before you decide what to attack.",
  },
  harness_generation: {
    label: "Generate fuzz harness",
    icon: "spark",
    summary: "LLM writes a libFuzzer harness for a target/function",
    detail:
      "The agent writes a libFuzzer-style harness that drives a chosen entry point, " +
      "recorded as a harness finding. This is the PREREQUISITE for fuzzing — once a " +
      "harness exists, start a fuzz campaign with the Fuzz button to actually run it.",
  },
  surface_recon: {
    label: "Surface recon",
    icon: "search",
    summary: "Map a web surface's routes — offline, no egress",
    detail:
      "The surface analogue of byte recon for a web_app target (which has no bytes at " +
      "rest). Deterministically materialises the surface's route spec into endpoint / " +
      "param nodes and routes_to handler edges. Offline and deterministic — no network " +
      "request is made.",
  },
  web_recon: {
    label: "Web recon (live)",
    icon: "search",
    summary: "Probe the live web surface — bounded, audited egress",
    detail:
      "Sends bounded, audited requests from the sandbox to the live web surface to confirm " +
      "endpoints and fingerprint the app. Requires the network feature (loopback/private " +
      "hosts only); every outbound request is recorded as an egress event.",
  },
  web_discover: {
    label: "Web discover (live)",
    icon: "filter",
    summary: "Crawl the live surface for routes — bounded egress",
    detail:
      "Crawls the live web surface (bounded, audited egress) to discover routes beyond a " +
      "supplied spec, materialising new endpoint / param nodes. Requires the network " +
      "feature; loopback/private hosts only.",
  },
  pattern_sweep: {
    label: "Pattern sweep",
    icon: "filter",
    summary: "Match this node against known bug patterns",
    detail:
      "Sweeps the selected symbol/string/pattern across the graph for known-dangerous " +
      "patterns and look-alikes, flagging matches as findings. A fast, targeted check " +
      "anchored on a single node.",
  },
  poc: {
    label: "Verify PoC",
    icon: "target",
    summary: "Execute the target to PROVE a vulnerability",
    detail:
      "Runs the target in the sandbox with an attacker input and confirms exploitation " +
      "via an unforgeable nonce oracle (foreign arch under qemu-user). Requires the PoC " +
      "feature to be enabled — execution is opt-in and still fully sandboxed " +
      "(--network none, capped, timed).",
  },
  agent_delegate: {
    label: "Delegate to coding agent",
    icon: "plug",
    summary: "Hand the target to an external agent CLI (sandboxed)",
    detail:
      "Launches your configured coding agent (Claude Code / Codex / gemini-cli) headless, " +
      "wired to HexGraph's MCP tools and restricted to the sandboxed primitives — it " +
      "populates the graph but never gets a shell on the target. Requires the agent feature.",
  },
  // `fuzzing` is intentionally NOT offered in the Run menu — fuzzing now goes through the
  // dedicated Fuzz campaign button/modal (a detached, hardened, reapable campaign). The
  // metadata stays here only so finding follow-ups / the Launch modal can humanize the
  // type if it ever surfaces.
  fuzzing: {
    label: "Fuzz (single run)",
    icon: "bug",
    summary: "Use the Fuzz button — runs a managed campaign instead",
    detail:
      "Legacy single-shot fuzz task. Prefer the Fuzz button on the target, which starts a " +
      "detached, reapable campaign with live status in the Campaigns tab.",
  },
};

export function taskMeta(type: string): TaskMeta {
  return (
    TASK_META[type] || {
      label: type.replace(/_/g, " "),
      icon: "task",
      summary: "",
      detail: "",
    }
  );
}
