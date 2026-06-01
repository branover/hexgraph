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
    docs/design-dynamic-surfaces.md."""
    allow: frozenset[str] = frozenset()
    rationale: str = ""


# Graduated, opt-in tiers (docs/design-dynamic-surfaces.md). Each is derived ONLY
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
    allow_network: bool = False    # sandboxes run --network none unless this is on
    allow_rehost: bool = False     # full-system emulation of the firmware (features.rehost)
    allow_remote: bool = False     # connect to ONE live remote device (features.remote)
    tier: int = TIER_STATIC_ONLY
    # The bounded egress scope, when one applies. None == --network none. The scope is
    # built per-target (local_network_scope); the policy only authorizes "network at all".
    network: NetworkScope | None = None


def current_policy() -> AnalysisPolicy:
    # Static-only by default. Enabling PoC/fuzzing flips on execution; enabling
    # `features.network` flips on bounded egress (the local-network tier); enabling
    # `features.rehost` permits full-system emulation. This is the single, explicit place
    # the static-only invariant is relaxed; a settings error fails closed at tier 0.
    try:
        from hexgraph import settings

        exec_on = bool(settings.get("features.fuzzing.enabled") or settings.get("features.poc.enabled"))
        net_on = bool(settings.get("features.network.enabled"))
        rehost_on = bool(settings.get("features.rehost.enabled"))
        remote_on = bool(settings.get("features.remote.enabled"))
        if exec_on or net_on or rehost_on or remote_on:
            # features.remote raises the live-remote tier and inherently permits egress (to the
            # one operator-authorized host — enforced by remote_scope, not by allow_network alone).
            tier = (TIER_LIVE_REMOTE if remote_on else
                    TIER_LOCAL_NETWORK if net_on else TIER_SANDBOXED_EXEC)
            return AnalysisPolicy(static_only=False, allow_execution=exec_on,
                                  allow_network=net_on or remote_on, allow_rehost=rehost_on,
                                  allow_remote=remote_on, tier=tier)
    except Exception:  # noqa: BLE001 — a settings problem must never widen the policy
        pass
    return AnalysisPolicy()


def assert_allows_execution(policy: AnalysisPolicy | None = None) -> None:
    policy = policy or current_policy()
    if not policy.allow_execution:
        raise PolicyViolation("analysis policy is static-only; executing the target is not permitted")


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
