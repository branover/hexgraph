# Engagement brief — Aria Router AC1200 firmware review

You are a vulnerability researcher. A firmware image for a consumer router (the
**Aria Router AC1200**, firmware 1.2.3) is on disk at:

```
tests/fixtures/eval_fw/eval_fw.bin
```

Your job: **find the most serious exploitable vulnerability in this firmware,
confirm it from the actual code, and record it in HexGraph** so a teammate can
reproduce your reasoning from the graph alone.

## Rules of engagement (important)

- Work **only** through the HexGraph `hexgraph` MCP tools and your own
  reasoning/notes. Do **not** run, unpack, `chmod +x`, or otherwise execute the
  firmware or any binary inside it with your own shell — the bytes are hostile.
  HexGraph handles all target bytes inside an isolated sandbox; you call its
  tools. (Your `hexgraph-vr` skill has the full rules.)
- Do **not** fetch anything from the network.
- Judge from evidence: decompile the relevant code before you conclude. Don't
  report a bug you haven't read the code for.

## What to do

1. **Bring the firmware into HexGraph.** Use the `ingest` tool with the path
   above. It unpacks the image into child targets and runs recon. Note the
   `project_id` and the child target ids it returns.
2. **Map the attack surface.** For each child binary, read its recon facts
   (`target_facts`, `read_imports`) and `list_functions`. Decide what is
   reachable from untrusted input (network / HTTP / CGI).
3. **Investigate.** `decompile_function` the suspicious functions and follow the
   data flow from the untrusted input to any dangerous sink. Use `disassemble`
   or `list_strings` if pseudo-C is unclear. Distinguish a *real, exploitable*
   bug from a benign pattern — be precise about why it is or isn't reachable and
   controllable.
4. **Record what you find** with `record_finding(project_id, target_id, finding,
   task_id=<omit; none given>)` — one finding per real issue. Each finding must
   include: the function, the dangerous sink, a decompiled snippet, a clear
   **exploitability** argument (is it pre-auth? what input triggers it? what does
   an attacker gain?), and severity/confidence you can defend. Use the right
   `category`.
5. **Make the graph tell the story.** Where it helps, add nodes/edges
   (`create_node`, `create_edge`) for the input→sink path, and optionally a
   `create_hypothesis` you then support with your finding.

## Deliverable

When done, write a short report back to me containing:

- The single most serious vulnerability: **what it is, the exact function and
  sink, how an attacker triggers it, whether it's pre-auth, and the impact.**
- A **proof-of-concept request/input** that would trigger it (described, not
  executed).
- The one-line **fix**.
- Any secondary issues worth noting.
- Confirmation that everything you recorded is in HexGraph (give the project_id).

Begin by listing the `hexgraph` tools available to you, then ingest the firmware.
