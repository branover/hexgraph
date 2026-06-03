# Security policy

This policy is about vulnerabilities **in HexGraph itself** — the workbench, its sandbox boundary,
its API and UI. It is not about vulnerabilities you discover *with* HexGraph in the targets you
analyze; those belong to whoever owns the target, under whatever disclosure process applies to them.

## The threat model, in one paragraph

HexGraph is a single-user tool you run on your own machine. The API and UI bind to `127.0.0.1` and
nothing else, every target byte is handled inside a disposable, network-less, resource-capped Docker
container, and capability beyond static analysis (executing a target, reaching the network, rehosting
firmware, talking to a remote device) is something you opt into one tier at a time. It is **not** a
hardened, multi-tenant, or internet-facing service, and it isn't meant to be. Do not expose a HexGraph
instance to untrusted users or networks. The Docker-Compose deployment in particular mounts the host's
Docker socket into the app container, which is root-equivalent control of your host's Docker — a
deliberate trade-off for a local tool, documented in the README, and not something to run anywhere
shared.

The bugs we care most about are the ones that break a load-bearing invariant: a sandboxed target
escaping its container or reaching the network when it shouldn't, the policy seam being bypassed so
execution or egress happens without the matching opt-in, the loopback bind being defeated, or a secret
(your API key, an SSH or remote-Docker credential) being written to disk, logged, or returned over the
API.

## Reporting a vulnerability

Please report privately, not in a public issue.

- **Preferred:** use GitHub's private vulnerability reporting — the **Security** tab on the repository,
  then **Report a vulnerability**. This keeps the report and the discussion private until a fix is ready.
- **Or email:** branover@gmail.com.

A useful report says what invariant is broken, how to reproduce it, and what an attacker gains. If you
have a proof of concept, include it — HexGraph is, after all, a tool for writing those.

## What to expect

This is a small project with a single maintainer, so please treat the timelines as good-faith
intentions rather than contractual SLAs. You can expect an acknowledgement within a few days, an
assessment of severity and scope after that, and a fix released as promptly as the severity warrants.
We'll credit you in the release notes unless you'd rather stay anonymous. Coordinated disclosure is
welcome; please give us a reasonable window to ship a fix before going public.

## Supported versions

HexGraph is pre-1.0. Only the latest release (and `main`) receives security fixes; there are no
backports to older tags yet.
