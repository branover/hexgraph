"""The MCP tool catalog — the agent-facing prompt copy, separated from the wiring.

`_CATALOG` is the registry of `(group, name, fn, description, json_schema)` tuples
that the MCP server advertises to a coding agent; the descriptions and schemas here
are effectively prompt text the agent reads, so they're worth keeping in one place
apart from the ~50 thin tool implementations (those live in `mcp_tools`).

The dependency is strictly one-way: this module imports the tool functions from
`mcp_tools`; `mcp_tools` re-exports `GROUPS`/`catalog` from here for back-compat, but
never the other way around — so there is no import cycle.
"""

from __future__ import annotations

from hexgraph.engine import mcp_tools as _t

# Tool groups let a user expose only what they need so an agent's context isn't
# polluted with tools they won't use:
#   read  — inspect the graph / target (no side effects)
#   write — populate the graph (findings, nodes, edges, hypotheses, annotations)
#   run   — execute HexGraph tasks in the sandbox (recon/analysis/fuzz)
GROUPS = ("read", "write", "run")

_CATALOG = [
    ("read", "list_projects", _t.list_projects, "List HexGraph projects (id, name, backend) — start here to find the project_id other tools need.",
     {"type": "object", "properties": {}}),
    ("read", "list_targets", _t.list_targets, "List targets in a project (binaries, libraries, firmware children, and web_app surfaces) with id/kind/arch — the entry point for picking what to analyze.",
     {"type": "object", "properties": {"project_id": {"type": "string"}}, "required": ["project_id"]}),
    ("read", "target_facts", _t.target_facts, "Recon facts for a target (imports/exports/mitigations).",
     {"type": "object", "properties": {"target_id": {"type": "string"}}, "required": ["target_id"]}),
    ("read", "list_functions", _t.list_functions, "List the functions in a target (name + address), discovered in the sandbox — use to find what to decompile next.",
     {"type": "object", "properties": {"target_id": {"type": "string"}}, "required": ["target_id"]}),
    ("read", "decompile_function", _t.decompile_function, "Decompile one function to pseudo-C in the sandbox (radare2/Ghidra) — the primary way to read a target's logic without touching its bytes.",
     {"type": "object", "properties": {"target_id": {"type": "string"}, "function": {"type": "string"}}, "required": ["target_id", "function"]}),
    ("read", "disassemble", _t.disassemble, "Disassemble one function to assembly in the sandbox — when you need instruction-level detail the decompiler smooths over.",
     {"type": "object", "properties": {"target_id": {"type": "string"}, "function": {"type": "string"}}, "required": ["target_id", "function"]}),
    ("read", "read_imports", _t.read_imports, "Imports, libraries, and mitigation flags of a target.",
     {"type": "object", "properties": {"target_id": {"type": "string"}}, "required": ["target_id"]}),
    ("read", "list_strings", _t.list_strings, "Notable strings in a target (optional substring filter).",
     {"type": "object", "properties": {"target_id": {"type": "string"}, "pattern": {"type": "string"}}, "required": ["target_id"]}),
    ("read", "xrefs", _t.xrefs, "Cross-references: which functions CALL a symbol/sink and where (omit `symbol` to map dangerous sinks, format-string sinks, AND network/socket surface bind/listen/connect/recv). Trace a sink back to its caller, or find listen/connect sites to model as socket nodes.",
     {"type": "object", "properties": {"target_id": {"type": "string"}, "symbol": {"type": "string"}}, "required": ["target_id"]}),
    ("read", "search", _t.search, "Search the project graph (findings + functions).",
     {"type": "object", "properties": {"project_id": {"type": "string"}, "q": {"type": "string"}}, "required": ["project_id", "q"]}),
    ("read", "list_findings", _t.list_findings, "Existing findings in a project (with finding_type + verified flag).",
     {"type": "object", "properties": {"project_id": {"type": "string"}}, "required": ["project_id"]}),
    ("read", "get_finding", _t.get_finding, "Read ONE finding in full incl. complete evidence (evidence.extra holds the verify_poc result) — confirm a write landed (finding analog of get_node).",
     {"type": "object", "properties": {"finding_id": {"type": "string"}}, "required": ["finding_id"]}),
    ("read", "get_node", _t.get_node, "Read a node back in full (address + attrs/params you set) — confirm what you wrote.",
     {"type": "object", "properties": {"node_id": {"type": "string"}}, "required": ["node_id"]}),
    ("read", "list_nodes", _t.list_nodes, "List graph nodes (filter by target/node_type) with address + attrs.",
     {"type": "object", "properties": {"project_id": {"type": "string"}, "target_id": {"type": "string"}, "node_type": {"type": "string"}}, "required": ["project_id"]}),
    ("read", "list_edges", _t.list_edges, "List edges (optionally those touching a node) to confirm the dataflow/relationships you wired.",
     {"type": "object", "properties": {"project_id": {"type": "string"}, "node_id": {"type": "string"}}, "required": ["project_id"]}),
    ("read", "list_egress", _t.list_egress, "The egress audit log — every outbound network action (allowed/denied) the bounded-network tier recorded for the project.",
     {"type": "object", "properties": {"project_id": {"type": "string"}}, "required": ["project_id"]}),
    ("read", "list_sockets", _t.list_sockets, "List socket endpoints (tcp/udp/unix/…) with who listens/connects on each — the firmware's network map (server↔client over shared sockets).",
     {"type": "object", "properties": {"project_id": {"type": "string"}}, "required": ["project_id"]}),
    ("read", "list_filesystem", _t.list_filesystem, "List a firmware target's unpacked filesystem (paths/sizes/which are ELFs or already child targets) — find config files, scripts, keys, web assets to read with read_file.",
     {"type": "object", "properties": {"target_id": {"type": "string"}}, "required": ["target_id"]}),
    ("read", "read_file", _t.read_file, "Read ONE file from a firmware target's unpacked filesystem (config/script/key/web template — NOT the raw binary; use decompile_function for code). Bounded 256 KiB, path-traversal safe; text as-is, binary as hex. `path` is relative to the extracted root (see list_filesystem).",
     {"type": "object", "properties": {"target_id": {"type": "string"}, "path": {"type": "string"}}, "required": ["target_id", "path"]}),
    ("read", "get_schemas", _t.get_schemas, "The write-API contract: allowed enums, the Finding shape, per-type NODE attribute schemas (what to populate, the sink-vs-symbol rule), edge/socket attribute schemas, and the active decompiler. Read before record_finding/create_node/create_edge/annotate to avoid guessing.",
     {"type": "object", "properties": {}}),
    ("write", "record_finding", _t.record_finding, "Record a new finding (the `finding` dict must match the Finding schema — call get_schemas). `finding_type` is a SEPARATE arg (vulnerability|poc|…), not a finding field. Pass task_id in delegate mode.",
     {"type": "object", "properties": {"project_id": {"type": "string"}, "target_id": {"type": "string"}, "finding": {"type": "object"}, "finding_type": {"type": "string"}, "task_id": {"type": "string"}}, "required": ["project_id", "target_id", "finding"]}),
    ("write", "update_finding", _t.update_finding, "Update an EXISTING finding in place (status/severity/confidence/human_notes) — e.g. confirm it after a PoC verifies. Don't create a duplicate.",
     {"type": "object", "properties": {"finding_id": {"type": "string"}, "status": {"type": "string"}, "severity": {"type": "string"}, "confidence": {"type": "string"}, "human_notes": {"type": "string"}}, "required": ["finding_id"]}),
    ("write", "create_node", _t.create_node, "Add a node (function/symbol/string/struct/input/sink/endpoint/param/hypothesis/pattern). ALWAYS pass target_id for target-bound types (else it's an orphan); it auto-links to its target. Populate `attrs` with the type's recommended fields from get_schemas.node_attribute_schemas (function->summary+params, input->source, sink->operation+why). A dangerous call (system/strcpy) is a symbol/function node with is_sink=true — NOT a separate `sink` node. Pass `address` for code nodes.",
     {"type": "object", "properties": {"project_id": {"type": "string"}, "node_type": {"type": "string"}, "name": {"type": "string"}, "target_id": {"type": "string"}, "address": {"type": "string"}, "attrs": {"type": "object"}}, "required": ["project_id", "node_type", "name"]}),
    ("write", "create_edge", _t.create_edge, "Connect two graph entities (target|node|finding|task) with a typed, attributed edge. `attrs` carries edge-type facts (see get_schemas: e.g. calls→call_sites/arg_constraints, listens_on→address). merge=True accumulates list attrs. A hypothesis is a 'node'; or use link_evidence to attach a finding to one.",
     {"type": "object", "properties": {"project_id": {"type": "string"}, "src_kind": {"type": "string"}, "src_id": {"type": "string"}, "dst_kind": {"type": "string"}, "dst_id": {"type": "string"}, "type": {"type": "string"}, "attrs": {"type": "object"}, "merge": {"type": "boolean"}}, "required": ["project_id", "src_kind", "src_id", "dst_kind", "dst_id", "type"]}),
    ("write", "update_edge", _t.update_edge, "Add/update attributes on an EXISTING edge by id (merge=True accumulates list attrs like call_sites; merge=False replaces). See get_schemas for per-type attributes.",
     {"type": "object", "properties": {"edge_id": {"type": "string"}, "attrs": {"type": "object"}, "merge": {"type": "boolean"}}, "required": ["edge_id", "attrs"]}),
    ("write", "create_socket", _t.create_socket, "Create/reuse a SOCKET node (network/IPC endpoint shared across binaries). kind=tcp|udp|unix|io|…, give port or name. A server listens_on it, a client connects_to it — both resolve to one node.",
     {"type": "object", "properties": {"project_id": {"type": "string"}, "kind": {"type": "string"}, "port": {"type": ["integer", "string"]}, "name": {"type": "string"}, "bind_addr": {"type": "string"}, "attrs": {"type": "object"}}, "required": ["project_id"]}),
    ("write", "create_hypothesis", _t.create_hypothesis, "Record a research hypothesis anchored to a target.",
     {"type": "object", "properties": {"project_id": {"type": "string"}, "statement": {"type": "string"}, "rationale": {"type": "string"}, "target_id": {"type": "string"}}, "required": ["project_id", "statement"]}),
    ("write", "link_evidence", _t.link_evidence, "Attach a finding to a hypothesis as supporting/refuting evidence (recomputes the hypothesis status). relation = supports|refutes. This is how you confirm a hypothesis.",
     {"type": "object", "properties": {"hypothesis_id": {"type": "string"}, "finding_id": {"type": "string"}, "relation": {"type": "string"}}, "required": ["hypothesis_id", "finding_id", "relation"]}),
    ("write", "set_hypothesis_status", _t.set_hypothesis_status, "Pin a hypothesis verdict: confirmed|rejected|open|supported|refuted. Pass `rationale` to record why.",
     {"type": "object", "properties": {"hypothesis_id": {"type": "string"}, "status": {"type": "string"}, "rationale": {"type": "string"}}, "required": ["hypothesis_id", "status"]}),
    ("write", "annotate", _t.annotate, "Attach a note/tag/rename/type_decl to a graph entity (agent proposal, pending analyst approval). For parameters/explanations on a function, prefer create_node attrs.",
     {"type": "object", "properties": {"project_id": {"type": "string"}, "node_kind": {"type": "string"}, "node_id": {"type": "string"}, "kind": {"type": "string"}, "value": {"type": "string"}}, "required": ["project_id", "node_kind", "node_id", "kind", "value"]}),
    ("write", "merge_duplicates", _t.merge_duplicates, "Collapse duplicate binaries/nodes (e.g. sym.foo == foo) in a project, preserving all edges/findings.",
     {"type": "object", "properties": {"project_id": {"type": "string"}}, "required": ["project_id"]}),
    ("write", "archive_node", _t.archive_node, "Soft-remove a node from the graph (REVERSIBLE): hides the node and the edges touching it. Re-adding the same node (create_node/a task) or restore_node brings it and its edges back — nothing is deleted.",
     {"type": "object", "properties": {"project_id": {"type": "string"}, "node_id": {"type": "string"}}, "required": ["project_id", "node_id"]}),
    ("write", "restore_node", _t.restore_node, "Un-archive a previously soft-removed node; its hidden edges reappear.",
     {"type": "object", "properties": {"project_id": {"type": "string"}, "node_id": {"type": "string"}}, "required": ["project_id", "node_id"]}),
    ("write", "delete_edge", _t.delete_edge, "Permanently delete ONE edge by id (hard delete — recreate with create_edge to restore). To remove a node's edges reversibly, archive the node instead.",
     {"type": "object", "properties": {"edge_id": {"type": "string"}}, "required": ["edge_id"]}),
    ("write", "archive_target", _t.archive_target, "Soft-remove a target + its whole subtree (children/nodes/findings) from the graph (REVERSIBLE) — declutter an irrelevant component; re-ingesting the bytes or restore_target brings it back. (Whole-project deletion is operator-only, not an MCP tool.)",
     {"type": "object", "properties": {"project_id": {"type": "string"}, "target_id": {"type": "string"}}, "required": ["project_id", "target_id"]}),
    ("write", "restore_target", _t.restore_target, "Un-archive a previously soft-removed target subtree (its nodes/findings reappear).",
     {"type": "object", "properties": {"project_id": {"type": "string"}, "target_id": {"type": "string"}}, "required": ["project_id", "target_id"]}),
    ("write", "link_same_code", _t.link_same_code, "Cross-target n-day primitive: link functions with identical code (same content_hash) across DIFFERENT binaries via similar_to edges, and return the matches (each side flags has_findings). Run after confirming a bug to find the same routine reused elsewhere.",
     {"type": "object", "properties": {"project_id": {"type": "string"}}, "required": ["project_id"]}),
    ("write", "propagate_finding", _t.propagate_finding, "N-day: clone an existing finding onto another binary that shares the same code (per link_same_code) as a fresh finding to triage, wired derived_from→ the source. Avoids re-typing the whole finding for 'same bug, other binary'.",
     {"type": "object", "properties": {"finding_id": {"type": "string"}, "target_id": {"type": "string"}, "function": {"type": "string"}, "notes": {"type": "string"}}, "required": ["finding_id", "target_id"]}),
    ("run", "reachability", _t.reachability, "Argue STATIC input-reachability (Standard B, static): search the typed graph for a directed source→sink path so a finding can claim input_reachable/static even when you CAN'T trigger it live (a real sink, but the service won't boot — the DIR-823G case). Pass finding_id (resolves the sink it cites, RECORDS the path + upgraded assurance on the finding) and/or sink_node_id (reports a path to that sink). Sources = input/param/endpoint/socket nodes (or a function/symbol you marked attrs.entry); follows taints/calls/routes_to/reads/writes/references FORWARD (taints is the strongest signal), depth-bounded + cycle-safe. Precondition is derived from the path (crosses an auth boundary / a `bypasses` edge => requires_credentials; starts at an unauth boundary => unauthenticated; else unspecified). An ARGUMENT, not a trigger — it only UPGRADES a code_present/static floor and NEVER downgrades a dynamic claim. Build the input/sink nodes + taints/calls edges first.",
     {"type": "object", "properties": {"finding_id": {"type": "string"}, "sink_node_id": {"type": "string"}, "max_depth": {"type": "integer"}}, "required": []}),
    ("run", "verify_poc", _t.verify_poc, "Prove an exploit and report verified true/false. Binary target -> runs it in the sandbox (spec {argv?,env?,stdin?,oracle:{output_contains|exit_code|crash}}, needs features.poc). Web surface -> sends HTTP steps (spec {steps:[{method,path,body?,...}],oracle:{body_contains|status_is|status_differs}}, cookies carry across steps for auth flows, needs features.network). Raw TCP service -> spec {transport:'tcp', port, payload, oracle:{response_contains}} sends payload to the device's port and matches the response (needs features.network); use for a rehosted/remote device's non-HTTP daemon. Put {{NONCE}} in BOTH the payload and the oracle value for an unforgeable check. THREE oracles prove vuln classes BEYOND reflected cmdi by observing an INDEPENDENT channel (call get_schemas['verify_poc_oracles'] for the spec): blind cmdi/SSRF/blind RCE -> oracle {type:'callback', timeout?} + a {{CALLBACK}} token in the payload (the target dials a bounded local listener); arbitrary READ (traversal/disclosure) -> {plant:{channel:'rootfs',path}|{known_value}} + oracle {type:'canary_read'} (HexGraph plants a random canary out-of-band, the read must return it); arbitrary WRITE (file/config/NVRAM) -> write {{NONCE}} then oracle {type:'oob_write', channel:'rootfs'|'remote'|'http', path?|request?} (HexGraph reads the location back out-of-band). Pass finding_id to attach the result (always do this for a confirmed vuln).",
     {"type": "object", "properties": {"target_id": {"type": "string"}, "poc": {"type": "object"}, "finding_id": {"type": "string"}}, "required": ["target_id", "poc"]}),
    ("run", "http_request", _t.http_request, "Send ONE crafted HTTP request to a registered web surface and return {status,headers,body} (body capped at 64 KiB) — your hands for live web testing (log in, probe an auth check, fire an injection payload, read the response). body is form-encoded unless json_body=true. Pass `session` (any label) to keep a cookie jar across calls so an auth flow works (log in, then explore protected routes) — response lists the jar in session_cookies. Bounded, sandboxed, local-only egress, audited. Requires features.network.",
     {"type": "object", "properties": {"target_id": {"type": "string"}, "method": {"type": "string"}, "path": {"type": "string"}, "params": {"type": "object"}, "headers": {"type": "object"}, "body": {}, "json_body": {"type": "boolean"}, "session": {"type": "string"}}, "required": ["target_id", "method", "path"]}),
    ("run", "tcp_request", _t.tcp_request, "Talk to a raw TCP service on a live device (rehosted surface or remote target) — the non-HTTP http_request. Connect to the device's port (through the emulator netns when rehosted), optionally send `payload` bytes, read the bounded response; omit payload to banner-grab. Fingerprint a listening socket, or drive a binary-protocol bug — to PROVE one use verify_poc with a tcp spec (it strips your sent bytes before matching). Bounded to the device host:port, audited. Requires features.network.",
     {"type": "object", "properties": {"target_id": {"type": "string"}, "port": {"type": "integer"}, "payload": {"type": "string"}, "read_bytes": {"type": "integer"}}, "required": ["target_id", "port"]}),
    ("run", "remote_launch", _t.remote_launch, "Start a service on a live remote/rehosted device that didn't auto-start, by BINARY PATH (+ optional args), backgrounded — so its socket comes up for live testing (e.g. a rehosted firmware's vulnerable daemon emulation didn't launch). path + args are shell-quoted; the one non-read-only remote op (no arbitrary shell). Then reach it with tcp_request / verify_poc (tcp spec). Requires features.remote; egress pinned + audited.",
     {"type": "object", "properties": {"target_id": {"type": "string"}, "path": {"type": "string"}, "args": {"type": "array"}}, "required": ["target_id", "path"]}),
    ("run", "ingest", _t.ingest, "Ingest a binary/firmware from a local path as a target (firmware unpacks into children); creates a project if none given.",
     {"type": "object", "properties": {"path": {"type": "string"}, "name": {"type": "string"}, "project_id": {"type": "string"}}, "required": ["path"]}),
    ("run", "run_task", _t.run_task, "Run a HexGraph task and return its findings. Types: recon, static_analysis, harness_generation, fuzzing, poc, surface_recon (offline route->handler map from a supplied spec), web_discover (LIVE crawl that DISCOVERS routes/params from links+forms+common paths — use this on a rehosted/registered surface, needs features.network), web_recon (live liveness probe, needs features.network).",
     {"type": "object", "properties": {"target_id": {"type": "string"}, "type": {"type": "string"}, "objective": {"type": "string"}, "params": {"type": "object"}}, "required": ["target_id", "type"]}),
    ("run", "rehost", _t.rehost, "Boot a FIRMWARE target under full-system emulation — auto-selects qemu+KVM for a full-OS disk image (.vmdk/.qcow2/partitioned .img) or FirmAE for a vendor blob (squashfs/cramfs/…) — and register its live web server as a web_app surface child, then assess the running device with surface_recon/web_discover/http_request/verify_poc, fused to the firmware's static graph. For a FirmAE/vendor image, pass `brand` (linksys/netgear/dlink/tplink/tenda/…) if it reports it couldn't bring up the network (FirmAE's profile is vendor-keyed; auto-inferred when the firmware names its vendor). Requires features.rehost (boot) + features.network (assess). Heavy + best-effort.",
     {"type": "object", "properties": {"target_id": {"type": "string"}, "brand": {"type": "string"}}, "required": ["target_id"]}),
    ("run", "register_remote", _t.register_remote, "Register a LIVE remote device (physical box or rehosted device) as a `remote` target reached over SSH/telnet — then analyze it read-only with remote_list_files/remote_read_file/remote_run. Creds come from operator env/config (HEXGRAPH_REMOTE_PASSWORD/KEY or config.toml [remote]), never stored. Requires features.remote.",
     {"type": "object", "properties": {"project_id": {"type": "string"}, "host": {"type": "string"}, "port": {"type": "integer"}, "username": {"type": "string"}, "transport": {"type": "string"}, "name": {"type": "string"}}, "required": ["project_id", "host"]}),
    ("run", "remote_list_files", _t.remote_list_files, "Enumerate files on a live remote target (SSH/telnet) under `path` (bounded depth/count) — list_filesystem for a box you don't have firmware for. Read-only. Requires features.remote.",
     {"type": "object", "properties": {"target_id": {"type": "string"}, "path": {"type": "string"}, "max_depth": {"type": "integer"}, "max_entries": {"type": "integer"}}, "required": ["target_id"]}),
    ("run", "remote_read_file", _t.remote_read_file, "Read ONE file from a live remote target (bounded; text as-is, binary as hex) — configs/scripts/keys//etc/passwd. The device's own bytes, read-only. Requires features.remote.",
     {"type": "object", "properties": {"target_id": {"type": "string"}, "path": {"type": "string"}, "max_bytes": {"type": "integer"}}, "required": ["target_id", "path"]}),
    ("run", "remote_run", _t.remote_run, "Run ONE allowlisted READ-ONLY recon tool on a live remote target — tool in {uname,id,ps,netstat,mount,ifconfig,df,env,passwd,release,ls}. No arbitrary shell (a path for ls is shell-quoted). Same recon we'd run on a rehosted rootfs. Requires features.remote.",
     {"type": "object", "properties": {"target_id": {"type": "string"}, "tool": {"type": "string"}, "path": {"type": "string"}}, "required": ["target_id", "tool"]}),
    ("run", "register_surface", _t.register_surface, "Register a WEB attack surface (web_app target via an HTTP Channel, no bytes); pass an optional offline route spec, then run_task(surface_recon) to map endpoints/params + routes_to→handler edges. Offline (no egress).",
     {"type": "object", "properties": {"project_id": {"type": "string"}, "base_url": {"type": "string"}, "name": {"type": "string"}, "endpoints": {"type": "array"}}, "required": ["project_id", "base_url"]}),
]


def catalog(enabled_groups: set[str] | None = None) -> list[dict]:
    """Tool specs for the MCP server, filtered to the enabled groups (default: all).
    Trimming groups keeps the agent's tool list small when only part of HexGraph
    is wanted (e.g. write-only, to populate the graph from a UI-driven session)."""
    groups = set(GROUPS) if enabled_groups is None else enabled_groups
    return [
        {"group": g, "name": n, "fn": fn, "description": d, "schema": sch}
        for (g, n, fn, d, sch) in _CATALOG if g in groups
    ]
