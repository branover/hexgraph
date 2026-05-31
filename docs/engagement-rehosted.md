# Engagement brief — rehosted firmware admin console (live)

You are a vulnerability researcher. A **real firmware image** has been booted under
full-system emulation, and its **web admin console** is reachable as a registered HexGraph
`web_app` surface. This is a LIVE target — the actual firmware's HTTP server, not a mock.
Your operator gives you the **project_id** and the **surface (web_app) target id**.

Goal: **find serious vulnerabilities in the running device and deliver WORKING, VERIFIED
proofs-of-concept**, recorded in HexGraph so a teammate can reproduce them from the graph.

## Rules of engagement
- Work **only** through the HexGraph `hexgraph` MCP tools. Never run your own
  shell/curl/browser against the target — all HTTP goes through `http_request` /
  `verify_poc`, which run in a bounded, audited, local-only sandbox that reaches the
  emulated device over its private IP. (Your `hexgraph-vr` skill §2b covers the web flow.)
- The firmware is hostile and emulated; the operator has already gated this (features.rehost
  to boot, features.network to assess).

## What to do
0. **Orient.** `list_projects` / `list_targets(project_id)` — find the `web_app` surface
   (it's a child of the firmware image target). `get_schemas` for the write-API contract.
   The firmware's binaries are already ingested, so its static graph (functions, imports)
   exists — your dynamic findings can link to it.
1. **Map the surface.** `run_task(surface_id, "surface_recon")` to materialize known routes,
   then `run_task(surface_recon, "web_recon")` for liveness. Probe interactively with
   **`http_request(surface_id, method, path, …, session="admin")`** — pass a `session` label
   so cookies persist across calls (log in once, then explore protected routes). Read the
   response bodies; map the login, the admin pages, any CGI/diagnostic endpoints.
2. **Hunt** the usual router classes: an **authentication bypass** (reach a protected page
   without valid creds), **command injection / RCE** (a parameter reaching a shell — common
   in diagnostic/ping/network-config handlers), path traversal, info leaks. Record each lead
   immediately as a finding + `endpoint`/`param`/`input` nodes + a `taints` edge to the sink,
   at low/medium confidence; populate node attrs per `get_schemas`.
3. **Prove it** with `verify_poc(surface_id, {steps, oracle}, finding_id=…)`:
   - **RCE**: inject `; echo {{NONCE}}` (or the platform equivalent) → `oracle:
     {type:"body_contains","value":"{{NONCE}}"}`. The echoed nonce proves execution.
   - **Auth bypass**: reach a protected page → `oracle:{type:"body_contains","value":"<a
     string only an authed user sees>"}` or `status_differs` from the unauth baseline.
4. **Make the graph tell the story.** A confirmed vuln MUST have a verified `poc` finding
   linked (`confirms`→). Where the route maps to a handler binary in the firmware, the
   `routes_to` edge already bridges the live surface to the static function — note it.

## Deliverable
A short report: each vulnerability (route, parameter, trigger, pre-auth?, impact), its
**verified PoC** (steps + `verify_poc` returned `verified: true`), the one-line fix, and the
`project_id` so everything is in HexGraph.

Begin by listing the `hexgraph` tools, then orient with `list_projects` / `list_targets`.
