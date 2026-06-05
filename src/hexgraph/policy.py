"""The analysis-policy seam (v2 P0-4).

v1 is static-only: targets are never executed, sandboxes have no network. This
policy makes that an explicit, enforced setting rather than a scattered
assumption — so future dynamic/emulated execution and fuzzing land by flipping a
policy + selecting a capable executor, not by unwinding hard-coded behavior.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlparse


class PolicyViolation(RuntimeError):
    """An operation was attempted that the active analysis policy forbids."""


@dataclass(frozen=True)
class NetworkScope:
    """The ONLY destinations (`host:port`) egress is permitted to — a deny-all-but-this
    allowlist. Empty == deny-all. Built per-target from its Channel; see
    docs/design/design-dynamic-surfaces.md."""
    allow: frozenset[str] = frozenset()
    rationale: str = ""


# Graduated, opt-in tiers (docs/design/design-dynamic-surfaces.md). Each is derived ONLY
# from features.* — there is no settable "tier" knob — so enabling a capability is
# the sole way to raise it, and any settings error fails closed at tier 0.
TIER_STATIC_ONLY = 0       # no exec, no network (default)
TIER_SANDBOXED_EXEC = 1    # exec (PoC/fuzzing), still --network none
TIER_LOCAL_NETWORK = 2     # bounded egress to loopback/private targets (features.network)
TIER_LIVE_REMOTE = 3       # bounded egress to ONE operator-authorized remote host (features.remote)

# Hostnames treated as local (the Docker bridge gateway / loopback aliases). Any
# other hostname that doesn't resolve to a literal private/loopback IP is refused
# at this tier — external hosts need the deferred, separately-gated live-remote tier.
_LOCAL_HOSTNAMES = frozenset({"localhost", "host.docker.internal", "gateway.docker.internal"})


@dataclass(frozen=True)
class AnalysisPolicy:
    static_only: bool = True
    allow_execution: bool = False  # never run the target (v1)
    allow_build: bool = False      # compile source in the sandbox (features.build) — D5
    allow_build_fetch: bool = False  # bounded, audited, ALLOWLISTED dependency fetch BEFORE an offline compile (features.build_fetch) — D6
    allow_network: bool = False    # sandboxes run --network none unless this is on
    allow_rehost: bool = False     # full-system emulation of the firmware (features.rehost)
    allow_remote: bool = False     # connect to ONE live remote device (features.remote)
    allow_fuzz_remote: bool = False  # run a campaign on a user-owned remote Docker host (features.fuzz_remote)
    tier: int = TIER_STATIC_ONLY
    # The bounded egress scope, when one applies. None == --network none. The scope is
    # built per-target (local_network_scope); the policy only authorizes "network at all".
    network: NetworkScope | None = None


# ── Startup policy ceiling (a long-lived process freezes what it may relax) ──────────
# The features.* gates that RELAX the policy. Enabling any of these widens the
# sandbox / execution / egress boundary, so a long-lived server (the API server, an MCP
# session) snapshots the set that was enabled at *startup* and refuses to widen past it
# until the next restart — `snapshot_ceiling()`. This closes the escalation where an
# agent (or any host-local writer) flips a `features.*` toggle in settings.json
# mid-session to grant itself execution/egress: the running process honors the frozen
# ceiling, not the live write. NARROWING is always live (disabling takes effect at
# once); only ENABLING a gate that was off at startup is deferred to a restart. Short-
# lived processes (the CLI, tests) never snapshot, so `_ceiling is None` and the policy
# reads live settings exactly as before — each invocation is its own "boot".
POLICY_GATES = ("fuzzing", "poc", "build", "build_fetch", "network", "rehost", "remote", "fuzz_remote")

# None ⇒ no ceiling captured (read live settings — the historical behavior). A frozenset
# ⇒ the gates enabled at this process's startup; current_policy() refuses to enable
# anything outside it.
_ceiling: frozenset[str] | None = None


def _configured_gates() -> frozenset[str]:
    """The policy gates currently enabled in settings (no ceiling clamp). A settings
    problem on any single gate is swallowed → that gate reads as off (fail-closed)."""
    from hexgraph import settings

    on: set[str] = set()
    for g in POLICY_GATES:
        try:
            if bool(settings.get(f"features.{g}.enabled")):
                on.add(g)
        except Exception:  # noqa: BLE001 — a settings problem must never widen the policy
            pass
    return frozenset(on)


def snapshot_ceiling() -> frozenset[str]:
    """Freeze the policy gates enabled right now as this process's ceiling. Call once at
    server / MCP-session startup. Afterwards, enabling a gate that was OFF at startup is
    written to settings.json (so the next restart picks it up) but does NOT take effect
    in this process; disabling stays live. Returns the captured set."""
    global _ceiling
    _ceiling = _configured_gates()
    return _ceiling


def reset_ceiling() -> None:
    """Drop the ceiling, restoring live-settings behavior. For tests and any short-lived
    process that re-reads settings every run."""
    global _ceiling
    _ceiling = None


def current_ceiling() -> frozenset[str] | None:
    """The frozen startup ceiling, or None if this process never snapshotted."""
    return _ceiling


def _gate_effective(feat: str, configured: bool) -> bool:
    """Clamp a single gate to the startup ceiling: a gate may be ON only if it is also
    within the frozen ceiling (or no ceiling was captured). Disabling is always honored
    — `configured=False` ⇒ off regardless of the ceiling."""
    if _ceiling is not None and feat not in _ceiling:
        return False
    return configured


def effective_gates() -> frozenset[str]:
    """The policy gates whose own toggle is enabled AND within the startup ceiling — i.e.
    the gates the RUNNING process honors right now. A gate flipped on in settings.json
    mid-session but clamped by the ceiling is NOT here until a restart. This is the single
    source of truth any non-policy consumer (the capability table, the UI) must read when
    it advertises or branches on a gate, so it never promises a capability the clamped
    policy will refuse. NOTE: this is the per-toggle clamped set; it does NOT resolve the
    inter-gate dependencies current_policy() enforces (build implied by exec, build_fetch
    needs build) — callers that care about those compose them explicitly (as the capability
    table does for build_fetch)."""
    conf = _configured_gates()
    return conf if _ceiling is None else (conf & _ceiling)


def policy_feature_states() -> dict:
    """Per policy gate, for the Settings UI: `configured` (the toggle in settings.json),
    `effective` (whether the capability is actually active in the RUNNING policy — this
    folds in the inter-gate dependencies current_policy() enforces, so e.g. build_fetch is
    only effective when build is too), and `pending_restart` (the toggle is on but the
    startup ceiling is clamping THIS gate off — a restart is what would change that). The
    two axes differ on purpose: pending_restart tracks only what a restart changes (the
    ceiling), while effective tracks the real policy outcome including dependencies, so a
    saved-but-inactive toggle is never mistaken for a live one. `restart_required` /
    `pending` summarize the gates a restart would newly honor."""
    from hexgraph import settings

    p = current_policy()  # the resolved running outcome (already ceiling-clamped + deps)
    # gates whose real per-capability outcome carries a cross-gate dependency the bare
    # ceiling clamp can't express; the rest map 1:1 to their clamped own-toggle.
    policy_outcome = {"build": p.allow_build, "build_fetch": p.allow_build_fetch}

    states: dict[str, dict] = {}
    pending: list[str] = []
    for g in POLICY_GATES:
        try:
            configured = bool(settings.get(f"features.{g}.enabled"))
        except Exception:  # noqa: BLE001
            configured = False
        within_ceiling = _gate_effective(g, configured)  # this gate's own toggle, clamped
        effective = policy_outcome.get(g, within_ceiling)
        # A restart only changes the ceiling, so pending_restart keys off the clamp of the
        # gate's OWN toggle — never off `effective` (build_fetch can be ineffective because
        # build is off, which no restart fixes). Suppress it if the capability is already
        # active anyway (build implied by exec): nothing to wait for.
        is_pending = configured and not within_ceiling and not effective
        states[g] = {"configured": configured, "effective": effective, "pending_restart": is_pending}
        if is_pending:
            pending.append(g)
    return {"restart_required": bool(pending), "pending": pending, "features": states}


def current_policy() -> AnalysisPolicy:
    # Static-only by default. Enabling PoC/fuzzing flips on execution; enabling
    # `features.build` permits compiling source in the sandbox (a sub-capability of
    # the sandboxed-exec tier — D5); enabling `features.network` flips on bounded
    # egress (the local-network tier); enabling `features.rehost` permits full-system
    # emulation. This is the single, explicit place the static-only invariant is
    # relaxed; a settings error fails closed at tier 0. Every gate is read through
    # `_gate_effective`, which clamps it to the frozen startup ceiling (a no-op when no
    # ceiling was captured) — so a mid-session widen of settings.json can't raise it.
    try:
        from hexgraph import settings

        def on(feat: str) -> bool:
            return _gate_effective(feat, bool(settings.get(f"features.{feat}.enabled")))

        exec_on = on("fuzzing") or on("poc")
        # Building runs UNTRUSTED third-party code (configure/make is arbitrary execution
        # and the highest supply-chain risk in the design), so it is gated — but it is NOT
        # the same as executing the TARGET: a useful workflow is "build instrumented,
        # inspect, don't run yet" (D5). features.build alone permits building; enabling
        # exec (fuzzing/poc) implies you'll build, so it also lifts allow_build. Running
        # the produced artifact still hits assert_allows_execution() — two independent,
        # fail-closed checks.
        build_on = on("build") or exec_on
        # features.build_fetch is its OWN opt-in gate (D6), NEVER folded into
        # features.network (fetching a public package registry is categorically
        # different from the loopback/private local-network tier). It is a
        # sub-capability of building (you can't fetch deps for a build you can't run),
        # so it is meaningless without build_on; it raises NO tier (the fetch is a
        # SEPARATE sandbox run on a registry-allowlist egress, and the compile that
        # follows is still --network none). Fail-closed: off ⇒ a fetch build is refused.
        build_fetch_on = build_on and on("build_fetch")
        net_on = on("network")
        rehost_on = on("rehost")
        remote_on = on("remote")
        # features.fuzz_remote is ORTHOGONAL to the tier ladder (like allow_build /
        # allow_rehost): it governs WHERE a campaign's container runs (a user-owned remote
        # Docker host the operator authorizes), NOT what the sandbox may do. It does not
        # raise the tier — the SAME sandbox boundary applies on the remote — so it is a
        # peer flag, fail-closed (off => a remote-environment campaign is refused). Like
        # build, it is implied by enabling exec OR can stand alone (register + health-check
        # a remote without yet running a campaign that executes the target).
        fuzz_remote_on = on("fuzz_remote")
        if exec_on or build_on or net_on or rehost_on or remote_on or fuzz_remote_on:
            # features.remote raises the live-remote tier and inherently permits egress (to the
            # one operator-authorized host — enforced by remote_scope, not by allow_network alone).
            # Building is a sub-capability of the sandboxed-exec tier, so build-only still sits
            # at TIER_SANDBOXED_EXEC (it runs a compiler in the box) without permitting target exec.
            tier = (TIER_LIVE_REMOTE if remote_on else
                    TIER_LOCAL_NETWORK if net_on else TIER_SANDBOXED_EXEC)
            return AnalysisPolicy(static_only=False, allow_execution=exec_on, allow_build=build_on,
                                  allow_build_fetch=build_fetch_on,
                                  allow_network=net_on or remote_on, allow_rehost=rehost_on,
                                  allow_remote=remote_on, allow_fuzz_remote=fuzz_remote_on, tier=tier)
    except Exception:  # noqa: BLE001 — a settings problem must never widen the policy
        pass
    return AnalysisPolicy()


def assert_allows_execution(policy: AnalysisPolicy | None = None) -> None:
    policy = policy or current_policy()
    if not policy.allow_execution:
        raise PolicyViolation("analysis policy is static-only; executing the target is not permitted")


def assert_allows_build(policy: AnalysisPolicy | None = None) -> None:
    """Gate compiling source in the sandbox (the `Builder` seam). Opt-in via
    features.build (or implied by features.fuzzing/poc — see current_policy). Building
    runs untrusted third-party code (configure/make), so it has its own fail-closed
    gate — peer of, not folded into, assert_allows_execution (D5): you can build-and-
    inspect without permitting the TARGET to run. The compile phase is still
    `--network none`, non-root, RO source, ephemeral (the supply-chain containment)."""
    policy = policy or current_policy()
    if not policy.allow_build:
        raise PolicyViolation(
            "building from source is not permitted (enable features.build to compile a "
            "source tree into an instrumented artifact in the sandbox)")


# The default package-registry allowlist for the bounded fetch tier (design §3.5/§8):
# a deny-all-but-these set of hosts a build's FETCH phase may reach. Hosts only — the
# scope is built with the conventional ports (443/80) per host. Operator-extendable via
# settings (features.build_fetch.allowlist); we NEVER fall back to "any host".
DEFAULT_FETCH_ALLOWLIST = (
    "crates.io", "static.crates.io",          # cargo
    "pypi.org", "files.pythonhosted.org",     # pip
    "registry.npmjs.org",                     # npm
    "github.com", "codeload.github.com",      # git/source archives
    "proxy.golang.org", "sum.golang.org",     # go modules
    "deb.debian.org", "security.debian.org",  # distro mirror
)


def assert_allows_build_fetch(policy: AnalysisPolicy | None = None) -> None:
    """Gate the BOUNDED dependency-fetch build phase (design §3.5/§5.3/§8 D6) — the
    HIGHEST residual supply-chain risk in the design, so it is fail-closed and its OWN
    opt-in gate (features.build_fetch), never folded into features.network.

    The fetch phase runs network ON but ONLY to an operator-confirmed ALLOWLIST of
    package registries; every download is hash-pinned into a lockfile + audited
    (EgressEvent). It is a SEPARATE sandbox run from the compile phase, which STILL runs
    `--network none` — so a malicious dependency can be fetched (hash-pinned, recorded)
    but can NEVER run during compile, persist, or exfiltrate. Off ⇒ a fetch build is
    refused (vendored/offline builds are unaffected — they never call this)."""
    policy = policy or current_policy()
    if not policy.allow_build_fetch:
        raise PolicyViolation(
            "bounded dependency fetch is not permitted (enable features.build_fetch to allow a "
            "SEPARATE, audited, allowlisted fetch phase before an offline --network none compile)")


def build_fetch_scope(allowlist=None) -> NetworkScope:
    """A deny-all-but-the-registry-allowlist egress scope for the fetch phase. Like
    remote_scope this never falls back to 'any host' — only the explicit registry hosts
    (with their conventional 443/80 ports) are allowed; everything else is refused at
    `assert_allows_egress`. `allowlist` is a list of hosts (operator-confirmed); empty/
    None uses DEFAULT_FETCH_ALLOWLIST. A host may be given as `host` or `host:port`."""
    hosts = list(allowlist) if allowlist else list(DEFAULT_FETCH_ALLOWLIST)
    allow: set[str] = set()
    for h in hosts:
        h = (h or "").strip()
        if not h:
            continue
        if ":" in h and not h.endswith(":"):
            allow.add(h)
        else:
            host = h.rstrip(":")
            allow.add(f"{host}:443")
            allow.add(f"{host}:80")
    return NetworkScope(allow=frozenset(allow),
                        rationale=f"bounded dependency fetch — {len(hosts)} allowlisted registr(ies)")


def assert_allows_rehost(policy: AnalysisPolicy | None = None) -> None:
    """Gate full-system firmware emulation (booting the whole image). Opt-in via
    features.rehost — the strongest execution capability, so it has its own gate."""
    policy = policy or current_policy()
    if not policy.allow_rehost:
        raise PolicyViolation(
            "firmware rehosting is not permitted (enable features.rehost to boot the firmware "
            "under full-system emulation)")


def assert_allows_remote(policy: AnalysisPolicy | None = None) -> None:
    """Gate connecting to a LIVE remote device (SSH/telnet). Opt-in via features.remote —
    the live-remote tier, where the operator authorizes a specific physical/networked target."""
    policy = policy or current_policy()
    if not policy.allow_remote:
        raise PolicyViolation(
            "remote-device access is not permitted (enable features.remote to connect to an "
            "operator-authorized SSH/telnet target)")


def assert_allows_fuzz_remote(policy: AnalysisPolicy | None = None) -> None:
    """Gate running a fuzz campaign on a user-owned REMOTE Docker host (the
    `RemoteDockerExecutor`, design §5.8b). Opt-in via features.fuzz_remote — a remote
    COMPUTE backend the user owns and explicitly authorizes (the exact posture as
    features.remote: one operator-authorized endpoint, connection details a secret read
    from env/config.toml — never the DB/logs — and the connection audited).

    This is NOT a relaxation of the sandbox boundary: the SAME hardening (`--network
    none` except the gated net-fuzz tier, `--cap-drop ALL`, `--no-new-privileges`,
    `--read-only`, `--user`, resource caps) applies on the remote — hostile bytes only
    ever materialize inside the container, now on a host the user chose. The control
    plane (API/UI) stays bound to 127.0.0.1; the remote is purely compute. Fail-closed:
    a campaign that selects a remote environment is refused unless this is on."""
    policy = policy or current_policy()
    if not policy.allow_fuzz_remote:
        raise PolicyViolation(
            "remote fuzz environments are not permitted (enable features.fuzz_remote to run a "
            "campaign on a user-owned, operator-authorized remote Docker host)")


def remote_scope(host: str, port: int) -> NetworkScope:
    """A deny-all-but-this egress scope for ONE operator-authorized remote device. Unlike
    local_network_scope this does NOT restrict to loopback/private — the operator has named a
    specific host they're authorized to test (the live-remote tier) — but it still pins egress
    to that single host:port and refuses everything else."""
    if not (host or "").strip():
        raise PolicyViolation("remote target needs a host")
    return NetworkScope(allow=frozenset({f"{host}:{int(port)}"}),
                        rationale=f"operator-authorized remote device {host}:{port}")


def egress_scope(policy: AnalysisPolicy | None = None) -> NetworkScope | None:
    return (policy or current_policy()).network


def _host_is_local(host: str) -> bool:
    """True only for loopback/private/link-local IPs or the known local hostnames.
    A bare hostname that isn't a literal local IP is treated as NON-local (refused) —
    Phase 2 never reaches out to resolve/contact a public host."""
    if host in _LOCAL_HOSTNAMES:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    # Defense-in-depth: an IPv4-mapped/transitional IPv6 literal (e.g.
    # `::ffff:169.254.169.254`, 6to4, Teredo) parses as IPv6 with is_link_local
    # False, so the embedded IPv4 (which CAN be link-local cloud-metadata) would
    # otherwise slip past. Reject these mixed forms outright at this tier — a real
    # local target is always expressed as a plain v4 or native v6 literal.
    if isinstance(ip, ipaddress.IPv6Address) and (
        ip.ipv4_mapped is not None or ip.sixtofour is not None or ip.teredo is not None
    ):
        return False
    # Loopback + RFC1918 private only. Link-local is deliberately EXCLUDED so the
    # cloud-metadata endpoint (169.254.169.254) is never reachable — an SSRF vector
    # unrelated to a local web/rehost target. (Python's is_private INCLUDES
    # link-local, so it must be subtracted explicitly.)
    return (ip.is_loopback or ip.is_private) and not ip.is_link_local


def local_network_scope(base_url: str) -> NetworkScope:
    """Build a deny-all-but-this egress scope from a target's base URL, **refusing any
    non-local (public) destination**. This is the structural containment for the
    local-network tier: even with `features.network` on, egress can only ever reach a
    loopback/private target; external hosts require the deferred live-remote tier."""
    u = urlparse(base_url)
    host = u.hostname
    if not host:
        raise PolicyViolation(f"cannot derive an egress scope from {base_url!r}")
    if not _host_is_local(host):
        raise PolicyViolation(
            f"{host!r} is not a loopback/private address — Phase-2 network egress is "
            "restricted to local targets (external hosts need the deferred live-remote tier)")
    port = u.port or (443 if u.scheme == "https" else 80)
    return NetworkScope(allow=frozenset({f"{host}:{port}"}), rationale=f"web surface {base_url}")


def local_tcp_scope(host: str, port: int) -> NetworkScope:
    """Like `local_network_scope` but for a raw host:port (a non-HTTP service on a
    loopback/private device — e.g. a rehosted device's bind shell on some high port).
    **Refuses any non-local destination**, the same structural containment as the web tier."""
    if not (host or "").strip():
        raise PolicyViolation("a TCP scope needs a host")
    if not _host_is_local(host):
        raise PolicyViolation(
            f"{host!r} is not a loopback/private address — local-network egress is "
            "restricted to local targets (external hosts need the live-remote tier)")
    return NetworkScope(allow=frozenset({f"{host}:{int(port)}"}),
                        rationale=f"local service {host}:{port}")


def assert_allows_egress(dest: str | None = None, scope: NetworkScope | None = None,
                         policy: AnalysisPolicy | None = None) -> None:
    """Gate every outbound connection. Fails closed on two independent checks: the
    policy must permit network at all (`features.network`), AND `dest` must be in the
    explicit per-run `scope` allowlist. Feature code calls this; it never branches on
    tier."""
    policy = policy or current_policy()
    if not policy.allow_network:
        raise PolicyViolation(
            "network egress is not permitted (enable features.network for the bounded local-network tier)")
    if scope is None or dest is None or dest not in scope.allow:
        allowed = sorted(scope.allow) if scope else []
        raise PolicyViolation(f"egress to {dest!r} is not in the allowlist {allowed}")
