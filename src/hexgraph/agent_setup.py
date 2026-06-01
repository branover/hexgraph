"""Connect a coding agent (Claude Code / Codex / gemini-cli) to HexGraph's MCP
server, and the VR skill that teaches it the workflow + the hostile-target rules.

`hexgraph mcp install [--agent ...]` prints the registration steps; it never edits
the user's agent config silently.
"""

from __future__ import annotations

import json
import shutil

# The agent's standing instructions. Whether HexGraph launches the agent
# (delegate task) or the user drives it themselves, this is the context that makes
# it use HexGraph safely and productively.
SKILL = """\
# HexGraph vulnerability-research agent

You do vulnerability research through HexGraph (MCP server `hexgraph`), a sandboxed
workbench. Use ONLY the `hexgraph` tools to touch the target — they run every tool
inside an isolated, network-less sandbox.

**The graph + findings are shared, durable memory — they are your real
deliverable, not just your final chat message.** Everything useful you learn
should be written back as nodes, edges, findings, hypotheses, and annotations, so:
- the human analyst can review your reasoning, triage it, and decide which
  follow-up tasks to launch;
- a future agent run picks up where you left off instead of re-deriving the same
  facts (no duplicated effort).

## Hard rules (non-negotiable)
- **Never execute, unpack, or open the target binary yourself.** No Bash/shell on
  the target, no downloading it, no running it. The bytes are hostile. All target
  handling goes through `hexgraph` tools.
- **Never exfiltrate target bytes** off the machine.
- Back every claim with tool output; don't invent findings.

## 0. Read the write-API contract
Call **`get_schemas`** once up front. It lists the allowed enums (node types,
edge types + endpoint kinds, finding categories/severities/statuses, annotation
kinds) and the Finding shape — so you don't guess field names. Key facts it
encodes: `evidence.extra` is a free-form object (put the PoC spec, verification,
CWE, dataflow there); a hypothesis is a `node`; structured data goes in `extra`,
not new top-level evidence keys.

## 1. Read what's already known FIRST
Before analyzing anything, orient on prior work so you don't repeat it and you can
see where to go next:
- `list_targets(project_id)`, `target_facts` (note its `dangerous_imports` — start
  there), `read_imports` — scope + recon facts.
- `list_findings(project_id)` — what's already found, **verified**, confirmed, or
  **dismissed** (don't re-report dismissed issues).
- `search(project_id, q)` — locate functions/strings/findings by keyword.
Let the existing graph and any open findings/hypotheses steer your next move: pick
up unfinished threads, follow related findings to siblings, and target functions
that haven't been analyzed yet.

## 2. Investigate (all sandboxed)
- `xrefs` (no symbol) maps the dangerous sinks (system/popen/strcpy/sprintf/…) and
  who reaches them — start there to find the attack surface fast. `xrefs <sink>`
  lists exactly which functions call a given sink and where.
- `list_functions`, then `decompile_function` / `disassemble` the suspicious ones;
  follow callees and `list_strings`. Trace untrusted input → dangerous sink. (These use
  the operator-configured decompiler automatically — radare2 by default, Ghidra if the
  operator enabled it; you don't pick it. `get_schemas.decompiler.active` shows which is
  live. If you want Ghidra and it's not active, ask the operator to enable it — there's no
  tool to flip it yourself.)
- Go deeper with `run_task` (`static_analysis`, `harness_generation`, `fuzzing`),
  and **`verify_poc`** to PROVE exploitability (a confirmed PoC is the gold bar).

## 2b. Live web / service surfaces (routers, admin consoles, APIs)
Many firmware bugs live in a web app, not just the binary. If you're given a base
URL (or a `web_app` target already exists), assess it dynamically:
- **Rehosted firmware**: if you have a firmware target and want its *live* web UI,
  **`rehost(firmware_target_id)`** boots it under emulation (auto-selecting qemu+KVM for a
  full-OS disk image, or FirmAE for a vendor firmware blob) and registers its web server as a
  `web_app` surface child — then assess that surface with the tools below. Needs
  features.rehost (to boot) + features.network (to talk to it); best-effort, since not every
  image boots cleanly.
- **`register_surface(project_id, base_url, endpoints?)`** registers the surface as a
  `web_app` target (a Channel, no bytes). `run_task(id, "surface_recon")` maps a route spec
  YOU supply into `endpoint`/`param` nodes + `routes_to` edges to the handler function (the
  static↔dynamic bridge). To DISCOVER routes on a live surface you didn't hand-spec (e.g. a
  freshly rehosted device), `run_task(id, "web_discover")` crawls it (links + forms + common
  paths, bounded) and materialises what it finds. `run_task(id, "web_recon")` is a bounded
  liveness probe. (web_discover/web_recon need `features.network`.)
- **`http_request(target_id, method, path, params?, headers?, body?, json_body?)`** is
  your hands on the live target: send a login, probe an auth check, fire an injection
  payload, and READ the response body. (Bounded, sandboxed, local-only egress, audited.)
  Pass `session="<label>"` to keep a cookie jar across calls, so you can log in once and
  then explore protected routes interactively without re-sending the cookie (the response
  lists the jar in `session_cookies`).
- Two oracles to PROVE web bugs with **`verify_poc(target_id, {steps, oracle})`** (cookies
  carry across `steps`, so login→protected-route works in one shot):
  - **Auth bypass**: log in with the bypass credential, then GET a protected route;
    `oracle:{type:"body_contains","value":"<a secret only an authed user sees>"}` — seeing
    the secret is unforgeable proof. (Or `status_differs` from the unauth baseline.)
  - **Command/SQL injection (RCE)**: inject `; echo {{NONCE}}` (or equivalent) in a param;
    `oracle:{type:"body_contains","value":"{{NONCE}}"}`. HexGraph substitutes a fresh token,
    so the echoed nonce proves your command really ran.
  Requires **features.network** enabled in Settings (bounded to the target's loopback/
  private host). Record the route as an `endpoint` node, the injectable field as a `param`
  (or `input`) node, and `taints` the param → the handler/sink; the verified PoC is a
  `poc` finding `confirms`→ the vulnerability, same rhythm as below.

## 3. Record AS YOU GO — write to the graph BEFORE you've confirmed things
Capture the moment you have a lead, not after you've proven it. The graph is a
live worklog: a suspicion recorded early is visible to the analyst and other
agents and is what you come back to confirm. **Do NOT wait until a PoC verifies
to add the finding** — that hides work in progress and risks losing it. The rhythm
is **record → explore → verify → update**:

1. **Suspect → record immediately.** When you spot a likely bug, `record_finding`
   right away at your current confidence (e.g. "low"/"medium", status `new`), with
   the function, sink, and reasoning so far. `create_node` the relevant entities and
   **populate the attributes the type expects** — read `node_attribute_schemas` in
   `get_schemas` for each type's `recommended` fields, so two runs of the same analysis
   produce the same graph instead of varying:
   - **functions**: pass `address`; `attrs={"summary":"…","params":[{"name","type",
     "note":"attacker-controlled?"}]}`.
   - **inputs** (`node_type:"input"`): the untrusted SOURCE; `attrs={"source":"HTTP
     param host"}`.
   - **dangerous calls**: a known risky libc call (system/exec/strcpy/sprintf) is a
     `symbol` (or `function`) node with **`attrs={"is_sink":true}`** — do NOT also make a
     separate `sink` node for it. Reserve `node_type:"sink"` for an abstract dangerous
     point that isn't already a node (e.g. "the shell string built at 0x401200"), with
     `attrs={"operation","why"}`.
   Always pass `target_id` for target-bound nodes (else they float as orphans).
   `create_hypothesis` for the open question, then **`link_evidence(hypothesis_id,
   finding_id, "supports")`** to connect the finding to it (this also drives the
   hypothesis's status — it's how you later confirm it).
2. **Explore → keep adding.** As you decompile/trace, wire the path with
   `create_edge`: `calls`, `references`, `reads`/`writes`, and **`taints`** for the
   untrusted-input → sink dataflow (input node → parser → sink node). **Edges carry
   attributes** — put `call_sites`/`arg_constraints` on a `calls` edge, an `address`
   on a `taints`/`bypasses` edge (see get_schemas → edge_attribute_schemas;
   `create_edge(merge=True)` accumulates list attrs). For network services, model
   endpoints as **`socket` nodes** (`create_socket(kind, port|name)`) and wire
   `listens_on` (server) / `connects_to` (client) edges with the listen/connect
   `address` — both sides of a firmware that share a port resolve to one socket, so
   `list_sockets` shows who talks to whom. `xrefs` (no symbol) surfaces the
   bind/listen/connect sites. `annotate` nodes with what you learn (clearer name,
   "reachable pre-auth", a CWE tag).
   **Record the PoC as its own finding BEFORE you run it** (it will be typed
   `poc`), containing the attacker input/spec you intend to try, marked unverified,
   and `create_edge` it `confirms`→ the vulnerability finding.
3. **Verify → update in place.** Run `verify_poc(target_id, poc,
   finding_id=<the PoC finding>)` (it attaches the result to that finding) / or
   `run_task`. Then update the SAME findings — don't make duplicates: on success
   `update_finding` the vulnerability to higher confidence/severity and
   status `confirmed`, and `link_evidence(..., "supports")` so the hypothesis
   flips to supported/confirmed. On failure, `update_finding` to lower confidence
   and `link_evidence(..., "refutes")`.

**Rule: a confirmed vulnerability finding MUST have a verified PoC finding linked
to it** (PoC `confirms`→ vulnerability). A vulnerability without a linked, verified
PoC is "suspected", not "confirmed" — say so in its confidence/reasoning.

**n-day across binaries.** After confirming a bug, run `link_same_code(project_id)`
— it links functions with identical code across the project's other binaries and
flags which side already has findings. For each matched binary that's still bare,
`propagate_finding(finding_id, target_id)` clones the finding onto it (wired
`derived_from`→ the source) to triage, then verify a PoC there too. Firmware reuses
the same routine across components; one bug is usually several.

Pin every function/symbol/string/struct you reasoned about (even benign-but-
relevant ones). Aim: at any moment — even mid-investigation — someone opening the
project sees the attack surface, the input→sink paths, what's suspected vs
confirmed vs refuted, and the obvious next tasks, without re-reading the binary.
Leave unfinished threads as hypotheses or unanalyzed nodes so the user (or the
next agent) can launch follow-up tasks on them.

A finding object looks like:
{"title": "...", "severity": "critical|high|medium|low|info",
 "confidence": "high|medium|low", "category": "memory-safety|command-injection|...",
 "summary": "...", "reasoning": "...",
 "evidence": {"function": "...", "sink": "...", "decompiled_snippet": "..."}}
"""


def skill_markdown() -> str:
    """The VR skill as a Claude Code skill file (YAML frontmatter + body)."""
    return (
        "---\n"
        "name: hexgraph-vr\n"
        "description: Vulnerability research through HexGraph's sandboxed MCP tools — "
        "inspect targets, decompile, run analysis/fuzz tasks, and record findings/nodes/edges. "
        "Use whenever analyzing a binary or firmware that has been ingested into HexGraph.\n"
        "---\n\n"
        + SKILL
    )


def write_skill(base_dir: str) -> str:
    """Write the skill to <base_dir>/hexgraph-vr/SKILL.md and return the path."""
    import os

    d = os.path.join(base_dir, "hexgraph-vr")
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, "SKILL.md")
    with open(path, "w") as fh:
        fh.write(skill_markdown())
    return path


def mcp_command() -> tuple[str, list[str]]:
    """How to launch the MCP server, as an ABSOLUTE command the agent can spawn.

    The agent (Claude Code/Codex) runs this with its own PATH/cwd, so bare names
    like `hexgraph`/`python` won't resolve to this install. Prefer the absolute
    path to the `hexgraph` console script; otherwise use this interpreter
    (`sys.executable` — e.g. the venv's python, which has HexGraph installed)."""
    import sys

    exe = shutil.which("hexgraph")
    if exe:
        return exe, ["mcp"]
    return sys.executable, ["-m", "hexgraph.cli", "mcp"]


def mcp_server_entry() -> dict:
    cmd, args = mcp_command()
    return {"command": cmd, "args": args}


AGENTS = ("claude", "codex", "gemini")


def install_help(agent: str | None = None) -> str:
    """Human-readable registration steps for one agent (or all)."""
    entry = mcp_server_entry()
    cmd_str = entry["command"] + " " + " ".join(entry["args"])
    blocks = []

    if agent in (None, "claude"):
        blocks.append(
            "Claude Code:\n"
            f"  claude mcp add hexgraph -- {cmd_str}\n"
            "  # or add to .mcp.json / ~/.claude.json:\n"
            "  " + json.dumps({"mcpServers": {"hexgraph": entry}}) + "\n"
            "  Restrict it to HexGraph + read-only tools when delegating:\n"
            '    --allowedTools "mcp__hexgraph Read Glob Grep" --disallowedTools "Bash"'
        )
    if agent in (None, "codex"):
        blocks.append(
            "Codex CLI (~/.codex/config.toml):\n"
            "  [mcp_servers.hexgraph]\n"
            f"  command = {json.dumps(entry['command'])}\n"
            f"  args = {json.dumps(entry['args'])}"
        )
    if agent in (None, "gemini"):
        blocks.append(
            "gemini-cli (~/.gemini/settings.json):\n"
            "  " + json.dumps({"mcpServers": {"hexgraph": entry}})
        )

    if not blocks:
        return f"unknown agent {agent!r}; choose one of {AGENTS}"
    import sys

    header = (
        "Register HexGraph as an MCP server with your coding agent. Then point\n"
        "the agent at a project and let it use the `hexgraph` tools.\n\n"
        f"First install the MCP SDK INTO THIS ENVIRONMENT (note the venv's pip):\n"
        f"  {sys.executable} -m pip install \"mcp\"\n"
        f"Confirm it's wired up (lists the tools and exits — no client needed):\n"
        f"  {cmd_str} --check\n"
        f"(`{cmd_str}` with no flag prints a 'ready, waiting for a client' line to stderr then\n"
        f" blocks — that's correct; your agent launches it. `hexgraph serve` (the web UI) can run\n"
        f" at the same time; they're separate processes sharing the DB.)\n\n")
    footer = ("\n\nInstall the VR skill so the agent knows the workflow + the hostile-target rules:\n"
              "  hexgraph mcp install --write-skill .claude/skills   # Claude Code (project-local)\n"
              "  hexgraph mcp install --write-skill ~/.claude/skills  # Claude Code (global)\n"
              "(For Codex/gemini, paste the same guidance into AGENTS.md / your system prompt — "
              "print it with `hexgraph mcp install --print-skill`.)")
    return header + "\n\n".join(blocks) + footer
