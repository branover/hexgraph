# Verification, the assurance ladder & the policy model

A HexGraph finding is more than a claim. It carries an **assurance level** that says how well
established it is, and when you opt in, HexGraph can actually execute the target to prove it against an
unforgeable oracle.

![A verified, unauthenticated command-injection finding](images/finding-verified-poc.png)

## The assurance ladder

Every finding's evidence records a two-part ladder, a **standard** crossed with a **method**:

| | `static` (argued) | `dynamic` (observed) |
|---|---|---|
| **`code_present`** | the vulnerable code is present (the floor) | lab-confirmed in isolation: the bug fires, but the input path is not yet established |
| **`input_reachable`** | a source-to-sink path is argued over the typed graph | reached *and* triggered end to end through the live input boundary |

An optional access qualifier (`unauthenticated`, `authenticated`, and so on) sharpens it further. The
UI renders all of this as an assurance chip on every finding and crash, and green marks reachability
through the live boundary. The point of the four rungs is to let you sort a backlog by how real each
claim is, rather than treating a static guess and a verified PoC as if they were equals.

The rationale and the full oracle taxonomy are in
[design/design-verification-oracles.md](design/design-verification-oracles.md).

## PoC verification (`features.poc`)

With PoC verification enabled, the `poc` task and the `finding_verify_poc` MCP tool execute the target in the
sandbox against an attacker input and confirm exploitation through an unforgeable `{{NONCE}}` oracle.
HexGraph substitutes a fresh random token, runs the PoC, and "verified" means the injected behavior
really happened: the nonce showed up in output the target itself had to produce. A confirmed PoC is
surfaced as a `verified` finding.

```bash
hexgraph config set features.poc.enabled true     # flips the policy to allow sandboxed execution
# then launch a `poc` task from the UI Run menu, or over MCP:
#   finding_verify_poc(target_id, poc, finding_id=...)  with a spec like
#   {"stdin": "...{{NONCE}}...", "oracle": {"type": "output_contains", "value": "{{NONCE}}"}}
```

Foreign-arch targets run under qemu-user automatically. `poc_probe` picks `qemu-<arch>` from the ELF
header, and `finding_verify_poc` mounts the parent firmware's extracted rootfs as the qemu sysroot (`-L`), so
a dynamically-linked MIPS or ARM binary can find its libraries. This has been verified end to end on
real MIPS firmware. Beyond command injection, the oracle set includes `callback`, `canary_read`,
`oob_write`, and a DoS `liveness`/`unavailable` oracle, plus a web-flavored `finding_verify_poc` with
`body_contains` and `status` checks.

## The graduated, opt-in policy model

Static-only is the enforced default, not an absolute ban. Each capability tier is a separate, explicit
opt-in that flips the single policy seam (`policy.current_policy()` and the `assert_allows_*`
helpers), and nothing relaxes anywhere else. The same sandbox hardening (a `--network none` baseline,
a read-only root, resource caps, a timeout, a non-root user, and foreign-arch work under qemu-user)
holds for every tier, and none of it ever runs on the host.

- **static-only** (the default) does no execution and runs `--network none`.
- **build from source** (`features.build`, gated by `assert_allows_build`) permits compiling a source
  tree into an instrumented artifact in that same `--network none`, capped, read-only-source, non-root
  sandbox. It is a sub-capability of sandboxed execution but has its own gate, so you can build and
  inspect without permitting the target to run. See [build-from-source.md](build-from-source.md).
- **bounded dependency fetch** (`features.build_fetch`, with its own fail-closed gate
  `assert_allows_build_fetch`, never `features.network`) raises a separate, audited, allowlisted fetch
  phase, then drops the network and compiles `--network none`. Fetch first, then offline.
- **sandboxed execution** (`features.poc` or `features.fuzzing`) allows running the target inside that
  same capped, timed, `--network none` sandbox, foreign-arch via qemu-user. See [fuzzing.md](fuzzing.md).
- **bounded local-network** (`features.network`) permits egress only to loopback and private hosts,
  through a per-target deny-all-but-this allowlist that admits no public addresses, with every request
  audited to an `EgressEvent`. See
  [dynamic-surfaces-rehosting-remote.md](dynamic-surfaces-rehosting-remote.md).
- **rehost** (`assert_allows_rehost`) boots a firmware image under full-system emulation.
- **remote** (`assert_allows_remote`) reaches one operator-authorized live device over SSH or telnet.
- **remote fuzz environment** (`assert_allows_fuzz_remote`) lets a campaign's container run on a
  user-owned remote Docker host. This one governs *where* compute runs, not *what* the sandbox may do:
  the same hardening applies on the remote, and the control plane stays on loopback.

![Every outbound action recorded — public hosts refused](images/egress-audit.png)

Resource ceilings (the `ResourceSpec` and the `unconstrained` knob) are never a policy relaxation.
They only lift the memory, CPU, and PID limits; they never touch a security flag. The editable IDE is
confined and reversible in the same spirit: only HexGraph-authored files can be edited, an edit creates
a new content-addressed revision, and imported, extracted, or vendor source stays read-only.
