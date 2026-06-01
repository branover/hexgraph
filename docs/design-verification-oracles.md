# Design — Verification oracles beyond command-injection

**Status:** proposed (this doc) → Phase 1 to implement. Captures how HexGraph proves a
*broad* class of vulnerabilities — not just command-injection — with **unforgeable** oracles.

## The problem

Today `engine/poc.py::verify_poc` proves an exploit by substituting a fresh random
`{{NONCE}}` into the PoC spec, running it, and checking the nonce appears in output the
target had to **produce** (reflection-stripped). Flavours: **binary** (exec in the sandbox;
oracle `output_contains`/`exit_code`/`crash`), **web** (HTTP steps; `body_contains`/
`status_is`/`status_differs`), **tcp** (raw socket; `response_contains`). This is excellent
for **command-injection**, because the exploit naturally produces attacker-chosen output the
nonce can ride in.

It does **not** cover the other vuln classes worth proving: memory-corruption RCE, denial of
service, arbitrary read primitives (path traversal / info disclosure / memory disclosure),
arbitrary write primitives (file/config/NVRAM/persistence), SSRF, and blind variants of all of
the above where nothing is reflected in the response. We must not box VR into cmdi.

## The principle (the thing to internalize)

> **An unforgeable oracle = HexGraph observes a vulnerability-specific side effect on a channel
> *independent of the exploit's own request*.** The `{{NONCE}}`-in-output check is one instance;
> the general rule is "verify through a channel the attacker/model does not control."

A result is forgeable exactly when the *only* evidence is something the producing model could
have written into its own answer. It is unforgeable when an **independent observer** confirms a
side effect that occurs *only if* the vulnerability genuinely triggered.

## Two standards of "verified" (what are we even claiming?)

Orthogonal to *how* we observe a trigger is *what* we are claiming. A vulnerability can be
"verified" against two distinct standards of proof, and HexGraph must **differentiate them
explicitly** and never let the weaker masquerade as the stronger:

- **Standard A — code-present (the flaw exists in code).** The unsafe construct genuinely exists
  — `io.popen(user_var)` as root, a `strcpy` into a fixed buffer whose source the attacker can
  influence — not a false pattern match. Largely a STATIC claim, cited to the exact sink
  (function/file/line + decompiled snippet). It says nothing about reachability or trigger.
- **Standard B — input-reachable (triggerable via user-provided input in normal operation).**
  A feasible path exists from an untrusted **input boundary** (a network endpoint/param, a
  socket, CLI argv, a parsed file/IPC message) through normal control flow to the sink, with the
  attacker able to influence the dangerous operand, under a realistic principal/configuration.
  This is the claim that actually matters for risk.

The IoTGoat engagement is the cautionary tale: the `webcmd` cmdi was **Standard A** (a real flaw
in code) AND reachable *given a root web session*, but **not** reachable for any obtainable
principal — so its honest Standard-B claim is "input-reachable ONLY with root creds we couldn't
get," far weaker than "unauth-reachable." A finding that blurred those overstates risk.

### Two axes + a precondition, recorded on every finding

Tag each finding's verification with:
1. **Standard claimed** — `code_present` (A) and/or `input_reachable` (B).
2. **Method** — `static` (argued from the graph/decompilation) vs `dynamic` (demonstrated by a
   live trigger + an unforgeable oracle, per the taxonomy below).
3. **Precondition** — the principal/config Standard B requires (`unauthenticated` /
   `requires_credentials:<which>` / `requires_config:<x>`). "Reachable in normal operation" is
   meaningless without stating *for whom*.

**Crucially, `method` cuts across BOTH standards** — so `code_present` has a static *and* a
dynamic form, and the dynamic form is the "verified in laboratory conditions" rung:

|                     | **static** (observed/argued)                                  | **dynamic** (executed)                                                                 |
|---------------------|---------------------------------------------------------------|----------------------------------------------------------------------------------------|
| **code_present**    | "looks vulnerable" — decompilation/pattern only; may be a false positive. The FLOOR. | **LAB-CONFIRMED** — a harness/fuzzer *fired the bug* by executing the code in ISOLATION. The flaw is **proven real**; the production input path is NOT established (which ≠ unreachable — it may exist directly, or via composition with other bugs / unexpected state). |
| **input_reachable** | a source→sink path from a real input is *argued* over the graph; not triggered. | triggered END-TO-END through the live deployed input boundary. Reached AND fires. STRONGEST. |

The distinction the engine must make is therefore the **SCOPE of a dynamic test**:
- **harness** — the code was run in isolation (an extracted binary in the sandbox fed crafted
  argv/stdin; a libFuzzer harness calling the function). ⇒ `code_present / dynamic`. We proved the
  *code* is vulnerable; we did **not** prove the deployed system routes user input to it.
- **entrypoint** — the trigger went through the LIVE deployed input boundary (the running
  service's real network/socket input — a rehosted/remote web or tcp surface). ⇒ `input_reachable
  / dynamic`.

So an isolated binary/fuzz PoC is `code_present/dynamic` (lab-confirmed), and only a live
web/socket-surface PoC is `input_reachable/dynamic`. `code_present/dynamic` is strictly stronger
than `code_present/static` ("the bug is real" vs "the bug might be real"); the reason it isn't
`input_reachable` is **honesty about the path, not doubt about the bug**.

The assurance ladder, weakest → strongest (the middle two aren't strictly comparable — one proves
it *fires* but not that it's *reached*; the other argues *reach* but not that it fires):
- **code_present / static** — the sink exists in code (cited); not executed. Lowest; may be a false positive.
- **code_present / dynamic** — lab-confirmed: executed in isolation and the bug fired. Proven real; production path unestablished.
- **input_reachable / static** — a source→sink path from a real input boundary is argued over the graph; not triggered.
- **input_reachable / dynamic** — triggered end-to-end through the live deployed input boundary. Highest.

These live in `evidence.extra` (`assurance: {standard, method, precondition[, detail]}`) — the DB
envelope, not the frozen finding schema — and drive how the UI/report phrases the claim.

### Proving each standard in HexGraph's terms

- **Standard A (code-present):** static_analysis + decompile evidence citing the sink; optionally
  re-confirm the construct exists (re-decompile) to kill false pattern matches. Largely supported
  — formalize "cite the sink" as the bar.
- **Standard A, dynamic — LAB-CONFIRMED (harness scope):** execute the vulnerable code in
  ISOLATION and observe the bug fire — a libFuzzer/ASan harness (`fuzzing` task), or a binary PoC
  run in the sandbox with crafted argv/stdin (`poc` task). Proves the *code* is genuinely
  vulnerable (kills the false-positive doubt) without asserting the deployed input path. This is
  strictly above "looks vulnerable" and is what `fuzz_crash` and isolated binary PoCs record today.
- **Standard B, static (reachability argument):** mark **input-source** nodes (endpoint/param/
  input/socket = the untrusted boundary) and compute a path to the sink over the typed graph's
  `taints`/`calls`/`routes_to` edges + xrefs, recording the path and any auth/guard gating it
  (the precondition). The typed graph + taint/xref primitives already exist; this adds an explicit
  **source→sink reachability** record. It is an *argument*, not a trigger.
- **Standard B, dynamic (trigger):** verify_poc drives the actual input boundary so the vuln
  fires, confirmed by an unforgeable oracle (the taxonomy below extends this beyond cmdi). Record
  the precondition actually used (did the PoC authenticate? with what?).

### The plan: prove one or both, label honestly

- A static finding defaults to **A (static)** and SHOULD attempt **B (static)** — is there a
  source→sink path, and behind what precondition? If no input path is found, say so: a
  code-present-but-unreached finding is lower risk and must be labeled as such.
- When the dynamic tiers are available (network/exec/rehost/remote), **escalate to B (dynamic)**
  via verify_poc, recording the precondition. The gold standard.
- A finding's headline verification = the **highest standard achieved + method + precondition**,
  and NEVER claims input-reachable merely because it is code-present. The UI/report render all
  three so a triager sees exactly what was proven and what was not.

## HexGraph's structural advantage

HexGraph already holds several observation channels the exploit's single request does **not**
control. This is what lets us generalize the oracle:

- **Sandbox exec result** — exit code, signal, timeout, and (with sanitizers) an ASan/UBSan report.
- **The extracted rootfs** (`engine/filesystem`, `read_file`) — read/write target state out-of-band.
- **The live rehosted/remote device** (`remote_read_file`, `remote_run`, `remote_launch`) —
  inspect the device after an exploit, over a *separate* channel.
- **The bounded-egress network** — we can stand up a HexGraph-controlled **listener** the target
  reaches (the ingress mirror of the existing egress tier).
- **The HTTP/TCP response** — the in-band channel (what we use today).

Verification is unforgeable when it uses a channel *different from* the exploit's request.

## Oracle taxonomy (vuln class → oracle → channel)

| Vuln class | Unforgeable oracle | Channel | Status |
|---|---|---|---|
| Command injection (reflected) | computed/`{{NONCE}}` in output (reflection-stripped) | HTTP/TCP response | **have** |
| Blind cmdi / SSRF / blind RCE / OOB exfil | **callback**: target connects/requests back to a HexGraph canary carrying the nonce | bounded canary listener (new) | new |
| Read primitive (traversal, file/mem disclosure) | **planted canary**: HexGraph writes a random secret out-of-band; the exploit must read it back verbatim | rootfs/remote write → response compare | new (reuses channels) |
| Write primitive (file/config/NVRAM/persistence) | **OOB side-effect read**: exploit writes `{{NONCE}}`; HexGraph reads that location independently | `remote_read_file`/`read_file`/follow-up GET | new (reuses channels) |
| Denial of service | **liveness transition**: service UP (baseline) → DOWN, re-probed with hysteresis | independent re-probe | new |
| Memory-corruption RCE | **spectrum** (below) | sandbox/qemu + callback | partial |
| Auth bypass / privesc | **differential**: perform a privileged action, observe its privileged effect | response / state read-back | partial (`status_differs`) |

## Per-oracle design

### 1. Callback / canary listener (new capability — highest reach)
The "collaborator"/interactsh pattern, kept **local**. HexGraph stands up a small listener,
mints a per-run token, hands the target a `host:port` + token to reach (substituted into the
PoC like `{{NONCE}}`/`{{CALLBACK}}`), and confirms receipt. Receiving the token = unforgeable
proof the injected code/SSRF ran, even with **zero** reflected output. Covers blind cmdi, blind
RCE, SSRF, OOB exfil.

- **Policy-seam placement:** this is the *ingress* mirror of the bounded-egress tier — the
  target reaches a HexGraph-controlled endpoint on the **loopback/private** net (or inside the
  rehost emulator netns). It is gated and **audited to `EgressEvent`** exactly like egress, and
  bounded to the same loopback/private scope (`local_network_scope`/the rehost netns). No gate
  is relaxed outside the policy seam.
- **Mechanics:** a listener probe (or a host-side bounded listener reachable in the target's
  scope) records hits keyed by token; `verify_poc` waits a bounded time for the token, then
  tears the listener down. Oracle type `callback`.

### 2. Planted-canary read (read primitives)
For arbitrary/relative file read, path traversal, info disclosure, memory disclosure: HexGraph
**plants a random secret** the model cannot know — e.g. writes a `{{NONCE}}` to a file at a
known path on the target via the out-of-band channel (rootfs/remote), or independently reads an
existing secret (a `/etc/shadow` line) so it knows the ground truth. The exploit then reads it,
and the oracle checks the retrieved content equals the planted/known value. Unforgeable because
HexGraph established the ground truth on a separate channel. Oracle type `canary_read`. Prefer a
*planted random* canary over a guessable file so the result can't be confabulated.

### 3. OOB side-effect read (write primitives)
For arbitrary file/config/NVRAM write and persistence: the exploit writes `{{NONCE}}` to a
target-controlled location; HexGraph then **independently reads that location** (`remote_read_file`,
`read_file`, or a follow-up GET of a written webroot file) and checks the nonce landed.
Unforgeable because the verifier reads the side-effect location out-of-band. Oracle type `oob_write`.
This is mostly *wiring* — the read-back channels already exist.

### 4. Liveness / unavailable (denial of service)
Oracle = a **liveness transition** the model can't fake: probe the service is UP (baseline 200/
accept), send the DoS input, then re-probe that it is DOWN (connection-refused/timeout/5xx) and
**stays** down across N probes (hysteresis), so a transient hiccup ≠ a verified DoS. For a
binary, the sandbox `crash` oracle (signal/exit/timeout) already covers process death. Oracle
type `liveness`/`unavailable`.

### 5. Crash / ASan + the RCE spectrum (memory corruption)
Full weaponized RCE (ASLR/NX bypass → shell) is often not worth it. Verify memory-corruption as
a **spectrum of rungs**, each independently unforgeable and high-value:
1. **Crash-confirmed** — the sandbox/qemu exec detects a signal/timeout; building the target/
   harness with **ASan/UBSan** (we already do this in the fuzzing harness path) yields a
   sanitizer report = unforgeable proof of the memory-safety bug.
2. **Controlled crash** — capture the **faulting state** (PC / registers) from qemu/the sandbox;
   `PC = 0x41414141` proves *control* of the corruption, not just a crash.
3. **Code-exec** — the ROP/shellcode performs an observable side effect carrying the nonce via
   the **callback** (#1) or **oob_write** (#3) oracle, bridging memory-corruption into the same
   nonce model without reflected output.

### 6. Differential (auth bypass / privesc)
Generalize the existing `status_differs`/secret-in-body checks: perform an action only an
authorized principal can and observe its privileged *effect* (read a per-user secret; change a
setting then read it back changed). Largely have; document as a first-class oracle.

## Where it lives (and what stays frozen)

- New oracle types extend `verify_poc`'s spec/evaluators. They live in the **PoC spec** and
  `evidence.extra` — the **DB envelope** — **not** the frozen `finding.schema.json`
  (per CLAUDE.md: new structure goes in the envelope, not the schema).
- The **canary listener** is a new sandbox/executor capability, but bounded by the **policy
  seam** (loopback/private/rehost-netns) and **audited** — same discipline as egress.
- Read/write oracles **reuse** existing channels (`read_file`, `remote_read_file`, follow-up
  HTTP), so they are mostly wiring.
- Sanitizer builds + crash-state capture **reuse** the existing harness/exec probe path.
- Everything stays inside the existing tiers (exec / bounded-network / rehost / remote); no gate
  is relaxed anywhere except the seam.

## Phasing (by value-per-effort)

- **Phase 0 (cross-cutting, small):** record the **assurance triple** `{standard, method,
  precondition}` on every finding (`evidence.extra.assurance`) and surface it in the UI/report,
  so the two standards are differentiated from day one and no finding overstates its claim. Done
  alongside Phase 1.
- **Phase 1 (small, biggest reach):** the **callback/canary listener** + the `callback`,
  `canary_read`, and `oob_write` oracles. Unlocks blind cmdi, SSRF, read primitives, and write
  primitives — a large fraction of real bugs — with modest new code (the read/write oracles
  reuse existing channels). These produce **Standard B, dynamic** results.
- **Phase 2:** the **DoS liveness** oracle (baseline-up → sustained-down, hysteresis).
- **Phase 3:** **ASan/sanitizer builds + crash-state capture** for the memory-corruption rungs.
- **Phase 4:** **Standard B, static** — explicit **source→sink reachability** over the typed
  graph (mark input-source nodes; record the `taints`/`calls`/`routes_to` path + the gating
  precondition), so a finding can argue reachability even when a dynamic trigger isn't available,
  and so a code-present-but-unreached flaw is labeled honestly.

## Non-goals / open questions

- Not building a public/internet collaborator — the canary is **local-only**, bounded to the
  target's loopback/private/rehost-netns scope.
- Full weaponized memory-corruption exploitation (ASLR/NX/stack-cookie bypass) is out of scope;
  the verified rungs (crash → controlled-crash → exec-callback) are the goal.
- Open: the cleanest place to host the canary listener for the rehost-netns case (a sidecar in
  the emulator netns vs. a host-side bound socket the device can reach) — decided in Phase 1.
