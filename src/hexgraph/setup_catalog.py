"""The canonical optional-feature / policy-gate registry the setup wizard reads.

A single declarative table — one entry per optional `features.*` toggle — that the
interactive wizard (`setup_wizard.py`) renders. Each entry carries:

- `key`        the dotted `features.*` settings path the toggle writes (validated
               against `settings.ALLOWED`),
- `label`      a short human title,
- `unlocks`    one line on what the feature *enables*,
- `security`   the SECURITY IMPLICATION in the user's words — which policy gate /
               tier it relaxes (sourced from `policy.py` + CLAUDE.md). Empty for the
               handful of toggles that never touch `policy.py`,
- `policy_changing`  True iff enabling it relaxes a `policy.py` gate/tier (these
               require an explicit, separate confirmation in the wizard),
- `tier`       the `policy.TIER_*` the feature raises to (None if it raises no tier),
- `builds`     the build-step keys (see `BUILD_STEPS`) the feature needs to actually
               run — e.g. fuzzing → the dedicated fuzz image,
- `default_off` whether the shipped default is off (all optional features are).

**This table is documentation that the code reads.** It states gate semantics; it
never *implements* policy — `policy.py` remains the only place a gate is decided.
Keeping it accurate to `policy.py` is enforced by a unit test
(`tests/test_setup_wizard.py`) that asserts every `features.*` `enabled` toggle in
`settings.ALLOWED` has a catalog entry with a non-empty security implication.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hexgraph import policy


@dataclass(frozen=True)
class BuildStep:
    """A heavy build step a feature may require to actually run.

    `recipe` is the `just` recipe (also runnable as the raw command in `command`)
    that produces the artifact; `cost` warns the user it is large/slow.
    """

    key: str
    label: str
    recipe: str                 # the `just` recipe name (with any args)
    command: list[str]          # the underlying command (so the wizard can run it without `just`)
    cost: str                   # human note on size/time
    needs_docker: bool = True


# The build steps the wizard can run. The sandbox image + SPA are part of the base
# bootstrap; the rest are opt-in and only triggered when a feature that needs them is
# enabled. Commands mirror the justfile recipes exactly (kept in sync by a test).
BUILD_STEPS: dict[str, BuildStep] = {
    "ui": BuildStep(
        key="ui",
        label="Web UI (React SPA)",
        recipe="ui",
        command=["npm", "--prefix", "frontend", "run", "build"],
        cost="~1 min, needs Node/npm",
        needs_docker=False,
    ),
    "sandbox": BuildStep(
        key="sandbox",
        label="Analysis sandbox image (radare2 + extractors + qemu-user)",
        recipe="sandbox-build",
        command=["docker", "build", "-f", "Dockerfile.sandbox",
                 "--build-arg", "WITH_GHIDRA=0", "-t", "hexgraph-sandbox:latest", "."],
        cost="large, several minutes",
    ),
    "sandbox_ghidra": BuildStep(
        key="sandbox_ghidra",
        label="Analysis sandbox image WITH headless Ghidra (+JDK, ~400 MB more)",
        recipe="sandbox-build with_ghidra=1",
        command=["docker", "build", "-f", "Dockerfile.sandbox",
                 "--build-arg", "WITH_GHIDRA=1", "-t", "hexgraph-sandbox:latest", "."],
        cost="very large (adds a JDK + Ghidra, ~400 MB), slow",
    ),
    "fuzz": BuildStep(
        key="fuzz",
        label="Coverage-guided fuzz image (AFL++ / libFuzzer / sanitizers)",
        recipe="fuzz-build",
        command=["docker", "build", "-f", "Dockerfile.fuzz", "-t", "hexgraph-fuzz:latest", "."],
        cost="large, several minutes",
    ),
    "build": BuildStep(
        key="build",
        label="Build-from-source image (clang/LLVM + sanitizers + AFL++ compilers)",
        recipe="build-image",
        command=["docker", "build", "-f", "Dockerfile.build",
                 "--build-arg", "WITH_CROSS=0", "-t", "hexgraph-build:latest", "."],
        cost="large, several minutes",
    ),
    "firmae": BuildStep(
        key="firmae",
        label="FirmAE rehosting image (vendor firmware blobs; privileged)",
        recipe="firmae-build",
        command=["docker", "build", "-f", "docker/firmae/Dockerfile", "-t", "hexgraph-firmae:latest", "."],
        cost="very large, slow",
    ),
    "qemu": BuildStep(
        key="qemu",
        label="QEMU+KVM rehosting image (full-OS disk images; needs /dev/kvm to run)",
        recipe="qemu-build",
        command=["docker", "build", "-f", "docker/qemu/Dockerfile", "-t", "hexgraph-qemu:latest", "."],
        cost="very large, slow",
    ),
}


@dataclass(frozen=True)
class Feature:
    key: str                        # the features.* `enabled`/`edit` toggle written to settings.json
    label: str
    unlocks: str
    security: str                   # the security implication, in the user's words ("" if none)
    policy_changing: bool           # relaxes a policy.py gate/tier → needs explicit confirmation
    tier: int | None = None         # the policy.TIER_* this raises to, if any
    builds: tuple[str, ...] = ()    # BUILD_STEPS keys this feature needs to RUN
    default_off: bool = True
    # An optional dependency the feature can't run without (informational; never blocks).
    requires_note: str = ""
    extra: dict = field(default_factory=dict)


# Tier names for display (mirrors policy.TIER_* constants).
TIER_NAMES: dict[int, str] = {
    policy.TIER_STATIC_ONLY: "static-only (tier 0)",
    policy.TIER_SANDBOXED_EXEC: "sandboxed execution (tier 1)",
    policy.TIER_LOCAL_NETWORK: "bounded local-network egress (tier 2)",
    policy.TIER_LIVE_REMOTE: "live remote device (tier 3)",
}


# The registry. Order = the order the wizard presents them (roughly: decompiler upgrade,
# then exec, then network, then the heavy/remote tiers, then the agent-integration knobs).
# Every security string is written to be ACCURATE to policy.py — never understating a gate.
FEATURES: tuple[Feature, ...] = (
    Feature(
        key="features.ghidra.enabled",
        label="Ghidra decompiler",
        unlocks="Use Ghidra (headless in the sandbox, or a bridge to a running Ghidra) "
                "instead of radare2 for decompilation and richer recon.",
        security="",  # decompiler upgrade only — does NOT touch policy.py / relax any gate.
        policy_changing=False,
        tier=None,
        builds=("sandbox_ghidra",),  # headless mode needs the with_ghidra sandbox image
        requires_note="headless mode needs the sandbox image built with Ghidra; "
                      "bridge mode needs a running Ghidra + the ghidra_bridge client.",
    ),
    Feature(
        key="features.poc.enabled",
        label="PoC verification (execute the target)",
        unlocks="The `poc` task + `verify_poc` tool run an attacker-style input against "
                "the target and confirm exploitation via an unforgeable nonce oracle.",
        security="RELAXES THE STATIC-ONLY DEFAULT: this flips the analysis policy to permit "
                 "EXECUTING the target inside the sandbox (raises the sandboxed-execution "
                 "tier). The sandbox stays locked down — --network none, cap-drop, "
                 "no-new-privileges, read-only rootfs, resource caps, hard timeout, "
                 "disposable — and foreign-arch targets run under qemu-user. Only the "
                 "exec gate is opened; network egress stays denied.",
        policy_changing=True,
        tier=policy.TIER_SANDBOXED_EXEC,
        builds=(),  # poc runs in the shared sandbox image
    ),
    Feature(
        key="features.fuzzing.enabled",
        label="Fuzzing (execute the target)",
        unlocks="The `fuzzing` task: compile a harness with libFuzzer/AFL++ + sanitizers "
                "and run a coverage-guided campaign, auto-filing a finding per crash.",
        security="RELAXES THE STATIC-ONLY DEFAULT: like PoC, enabling this flips the policy "
                 "to permit EXECUTING the target (sandboxed-execution tier). The sandbox "
                 "stays --network none, capped, timed, disposable; it only opens the exec "
                 "gate. (Enabling exec also implies the build gate — compiling a harness — "
                 "but compile always runs --network none.)",
        policy_changing=True,
        tier=policy.TIER_SANDBOXED_EXEC,
        builds=("fuzz",),  # the dedicated fuzz image
    ),
    Feature(
        key="features.build.enabled",
        label="Build from source (run a compiler in the sandbox)",
        unlocks="Compile a managed source tree into an instrumented artifact in the sandbox "
                "via a recorded, reproducible recipe (the Builder seam).",
        security="OPENS THE BUILD GATE: HexGraph may run a compiler (configure/make — "
                 "arbitrary third-party code) inside the sandbox. This is a SEPARATE gate "
                 "from executing the TARGET (you can build-and-inspect without running it). "
                 "The compile phase ALWAYS runs --network none, non-root, read-only source, "
                 "ephemeral. The only network a build can touch is the separate, opt-in "
                 "build-fetch tier below.",
        policy_changing=True,
        tier=policy.TIER_SANDBOXED_EXEC,
        builds=("build",),  # the dedicated build image
    ),
    Feature(
        key="features.build_fetch.enabled",
        label="Build dependency fetch (bounded, audited network)",
        unlocks="A separate, audited build phase that fetches declared dependencies and "
                "produces a hash-pinned lockfile, BEFORE the offline compile.",
        security="HIGHEST RESIDUAL SUPPLY-CHAIN RISK, so it is its OWN fail-closed gate "
                 "(never folded into the network tier). It permits a SEPARATE sandbox run "
                 "with network ON but ONLY to a deny-all-but-ALLOWLIST of package registries "
                 "(crates.io / pypi.org / npm / github.com / …, never 'any host'); every "
                 "download is hash-pinned + audited (EgressEvent). HexGraph then DROPS "
                 "network and compiles --network none against the snapshot. Meaningless "
                 "without Build (a sub-capability of it); raises no tier.",
        policy_changing=True,
        tier=None,  # build_fetch raises no tier in policy.py
        builds=("build",),
        requires_note="requires Build from source.",
    ),
    Feature(
        key="features.network.enabled",
        label="Network egress (bounded local-network tier)",
        unlocks="A sandboxed probe may reach a live web/service surface target (e.g. a "
                "rehosted device's web UI) to assess it.",
        security="RELAXES --network none for the BOUNDED LOCAL-NETWORK tier (tier 2): a "
                 "probe may make outbound connections, but ONLY to a loopback/PRIVATE "
                 "destination on a per-target deny-all-but-this allowlist. Public/external "
                 "hosts are structurally refused (they need the separate live-remote tier), "
                 "the cloud-metadata endpoint is blocked, and EVERY outbound action is "
                 "audited to EgressEvent.",
        policy_changing=True,
        tier=policy.TIER_LOCAL_NETWORK,
        builds=(),
    ),
    Feature(
        key="features.rehost.enabled",
        label="Firmware rehosting (full-system emulation)",
        unlocks="Boot a whole firmware image (kernel + userland + web server) under "
                "full-system emulation (FirmAE for vendor blobs, qemu+KVM for disk images) "
                "and register its live web surface.",
        security="STRONGEST EXECUTION CAPABILITY, its own gate: full-system emulation runs "
                 "in a PRIVILEGED container (FirmAE needs --privileged + /dev/net/tun; qemu "
                 "needs /dev/kvm). It boots and runs the firmware's real code. The control "
                 "plane stays loopback; assessing the booted device's web surface ALSO needs "
                 "the Network egress tier above (it is a private-IP surface).",
        policy_changing=True,
        tier=policy.TIER_SANDBOXED_EXEC,
        builds=("firmae", "qemu"),
        requires_note="assessing the booted device also needs Network egress.",
    ),
    Feature(
        key="features.remote.enabled",
        label="Remote live device (SSH/telnet)",
        unlocks="Connect to ONE operator-authorized live device over SSH/telnet and run the "
                "same read-only analysis (enumerate FS, read files, fixed recon allowlist).",
        security="RAISES THE LIVE-REMOTE tier (tier 3): egress is permitted to ONE EXTERNAL "
                 "host you explicitly authorize (this is the only tier that may reach a "
                 "non-private host — it is the operator's responsibility), pinned to that "
                 "host:port and audited. Only a fixed read-only tool allowlist runs there "
                 "(no arbitrary shell). CREDENTIALS ARE SECRETS — never stored in the DB or "
                 "settings; read at connect from env (HEXGRAPH_REMOTE_PASSWORD / _KEY) or "
                 "config.toml [remote].",
        policy_changing=True,
        tier=policy.TIER_LIVE_REMOTE,
        builds=(),
        requires_note="SSH/telnet credentials come from env or config.toml — NOT this wizard.",
    ),
    Feature(
        key="features.fuzz_remote.enabled",
        label="Remote fuzz environments",
        unlocks="Run a fuzz campaign on a user-owned remote Docker host (beefier compute) "
                "instead of locally.",
        security="Governs WHERE a campaign's container runs (a remote Docker host you own + "
                 "authorize), NOT what the sandbox may do — the SAME sandbox boundary "
                 "(--network none, cap-drop, no-new-privileges, read-only, caps) applies on "
                 "the remote, and the control plane (API/UI) stays bound to 127.0.0.1. "
                 "CONNECTION DETAILS ARE SECRETS — read from env / config.toml [fuzz_remote.*], "
                 "never the DB or logs. Fail-closed: off ⇒ a remote campaign is refused.",
        policy_changing=True,
        tier=None,  # orthogonal to the tier ladder
        builds=(),
        requires_note="remote connection details come from env or config.toml — NOT this wizard.",
    ),
    Feature(
        key="features.source.edit",
        label="Editable source IDE",
        unlocks="Make the Source tab editable for HexGraph-authored files (harness/PoC/"
                "script + scratch); a save creates a new revision (never in-place).",
        security="",  # a UI/capability flag — never touches policy.py.
        policy_changing=False,
        tier=None,
        builds=(),
    ),
    Feature(
        key="features.agent.enabled",
        label="Coding-agent delegate",
        unlocks="Delegate a task to a coding-agent CLI (claude/codex/gemini) from the UI, "
                "wired to HexGraph's MCP tools + VR skill, restricted to sandboxed tools.",
        security="The delegated agent is RESTRICTED to HexGraph's sandboxed MCP tools — it "
                 "gets no shell on the target. It does not itself relax any policy gate; "
                 "what it can run is still bounded by the other gates (exec/network/etc.). "
                 "Register the MCP server first with `hexgraph mcp install`.",
        policy_changing=False,
        tier=None,
        builds=(),
    ),
    Feature(
        key="features.mcp.read",
        label="MCP: expose READ tools to a coding agent",
        unlocks="Expose HexGraph's read/inspect tools (browse graph, findings, filesystem) "
                "over the `hexgraph mcp` stdio server to a connected coding agent.",
        security="Exposes inspection tools to a connected agent. Read-only; does not relax a "
                 "policy gate. (Trim the groups to keep the agent's tool list small.)",
        policy_changing=False,
        tier=None,
        builds=(),
        default_off=False,  # ships ON in DEFAULTS
    ),
    Feature(
        key="features.mcp.write",
        label="MCP: expose WRITE tools to a coding agent",
        unlocks="Expose graph/finding authoring tools (create nodes/edges/findings/"
                "hypotheses/annotations) over the MCP server.",
        security="Lets a connected agent WRITE to your project graph (findings, nodes, "
                 "edges). It does not relax a target-execution/network gate. Trim if you "
                 "only want the agent to read.",
        policy_changing=False,
        tier=None,
        builds=(),
        default_off=False,
    ),
    Feature(
        key="features.mcp.run",
        label="MCP: expose RUN tools to a coding agent",
        unlocks="Expose the run-a-sandboxed-task tools over the MCP server so a connected "
                "agent can launch analysis tasks.",
        security="Lets a connected agent LAUNCH sandboxed tasks. Each task it launches is "
                 "still bounded by the policy gates above (a task that would execute the "
                 "target still requires PoC/fuzzing; network still requires the network "
                 "tier) — this only exposes the launcher, it relaxes no gate itself.",
        policy_changing=False,
        tier=None,
        builds=(),
        default_off=False,
    ),
)


def features_by_key() -> dict[str, Feature]:
    return {f.key: f for f in FEATURES}


def policy_changing_features() -> tuple[Feature, ...]:
    return tuple(f for f in FEATURES if f.policy_changing)


def build_steps_for(enabled_keys) -> list[str]:
    """The ordered, de-duplicated BUILD_STEPS keys required by the enabled feature keys.

    Ghidra is special: it only needs the with-Ghidra sandbox image when its mode is
    `headless` — the caller resolves that and passes the right key set. Here we map
    purely from the feature's declared `builds`.
    """
    seen: list[str] = []
    by_key = features_by_key()
    for k in enabled_keys:
        feat = by_key.get(k)
        if not feat:
            continue
        for b in feat.builds:
            if b not in seen:
                seen.append(b)
    return seen
