<!-- Internal VR-test scenario, not user documentation. The blind brief driven by
vulnrouter_engagement.py in this directory (`just vulnrouter`), which stands up the
live web target and the project this engagement runs against. -->

# Engagement brief — Orbweaver Router admin console (live web target)

You are a vulnerability researcher. A small router **admin web service** is running
and reachable at a base URL your operator will give you (e.g.
`http://172.17.0.2:8080`). This is a LIVE HTTP target, not a binary on disk.

Your job: **find the serious vulnerabilities in this web service and deliver
WORKING, VERIFIED proofs-of-concept** — then record everything in HexGraph so a
teammate can reproduce your reasoning from the graph alone.

**Success = verified PoCs.** HexGraph can send crafted HTTP requests to the target
in its sandbox and confirm exploitation. The task is done when `verify_poc` returns
`verified: true` for each bug you claim.

## Rules of engagement
- Work **only** through the HexGraph `hexgraph` MCP tools. Do **not** use your own
  shell, `curl`, or any other network client against the target — all HTTP goes
  through HexGraph's `http_request` / `verify_poc`, which run in a bounded, audited,
  local-only sandbox. (Your `hexgraph-vr` skill has the full rules; §2b covers web.)
- Judge from evidence: read actual responses before you conclude.

## What to do
0. **Orient.** `list_projects`; the operator has created a project and registered
   the surface for you (a `web_app` target). `list_targets(project_id)` to find its
   id. `get_schemas` once for the write-API contract.
1. **Map the surface.** `run_task(target_id, "surface_recon")` (materializes the
   route/param graph) and `run_task(target_id, "web_recon")` (liveness). Then probe
   with **`http_request`** — e.g. `GET /`, `GET /admin/flag` (note the
   unauthenticated response), `POST /api/login`. Read the bodies.
2. **Hunt.** Look for an **authentication bypass** (can you reach a protected route
   without valid credentials?) and a **command-injection / RCE** (does a parameter
   reach a shell?). Record each lead immediately as a finding + the `endpoint`/
   `param`/`input` nodes and a `taints` edge to the sink, at low/medium confidence.
3. **Prove it with `verify_poc(target_id, {steps, oracle})`** (cookies carry across
   `steps`):
   - **Auth bypass** — log in with the bypass credential, then GET the protected
     route; `oracle:{type:"body_contains","value":"<the secret only an authed user
     sees>"}`. Seeing the secret is unforgeable proof.
   - **RCE** — inject `; echo {{NONCE}}` (or similar) into the vulnerable parameter;
     `oracle:{type:"body_contains","value":"{{NONCE}}"}`. The echoed nonce proves
     your command ran. Pass `finding_id=` so the result attaches to your finding.
   (If `verify_poc` says egress isn't permitted, the operator must enable
   **Settings → Network egress**.)
4. **Make the graph tell the story.** A confirmed vulnerability finding MUST have a
   verified `poc` finding linked to it (`confirms`→). Populate node attributes per
   `get_schemas` so the graph is complete: the endpoint (method/path/auth), the
   injectable param, the input→sink `taints` path, and `bypasses` for the auth flaw.

## Deliverable
A short report: each vulnerability (route, parameter, how it's triggered, pre-auth?,
impact), the **verified PoC** for each (the steps + that `verify_poc` returned
`verified: true`), the one-line fix, and the `project_id` so everything is in HexGraph.

Begin by listing the `hexgraph` tools available to you, then orient with
`list_projects` / `list_targets`.
