# vulnrouter — a runnable vulnerable web target

An intentionally-vulnerable "router admin" web service in a container — a **real,
runnable target** for HexGraph's dynamic web-surface analysis (Phase 2 `web_recon`
liveness, and the upcoming Phase 3 web PoC). It binds to a **local address only** and
exercises the two bug classes the dynamic track is built for.

⚠ **Deliberately insecure. Run only locally, in the container.**

## Run it
```bash
docker build -t hexgraph-vulnrouter:latest tests/fixtures/vulnrouter
# reach it by its container IP on the docker bridge (a private addr the bounded-egress
# tier permits), or publish to host loopback:
docker run -d --rm --name vr -e ROUTER_FLAG=demo-flag hexgraph-vulnrouter:latest
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' vr
#   → e.g. 172.17.0.2 ; the surface base_url is http://172.17.0.2:8080
```

## Planted bugs (answer key)
| Endpoint | Bug | Trigger |
|---|---|---|
| `POST /api/login` (`token=`) | **Auth bypass** (CWE-287/697) | `_check_token` compares only the first `len(token)` bytes of `ADMIN_TOKEN`, so an **empty token authenticates**. The session cookie it returns then unlocks `/admin/flag`. |
| `GET /admin/flag` | The differential oracle | Returns `FLAG=<ROUTER_FLAG>` only for an authenticated session; an unauthenticated request gets `401`. A bypass that makes this return the flag = proven auth bypass. |
| `POST /api/diag` (`host=`, post-auth) | **Command injection** (CWE-78) | `host` goes into a shell `ping` unsanitised; the endpoint returns **only the command output** (no input reflection), so injected output (`;echo …`) proves *execution*, not echo. |

## How HexGraph validates against it
With `features.network` enabled (the bounded local-network tier), point a `web_app`
surface at the container's `http://<ip>:8080` and run `web_recon`: the sandboxed probe
reaches it over the bridge (a private IP the scope allows), records the endpoints'
liveness, and writes an `EgressEvent` per outbound action. The Phase-3 web PoC will use
the auth-bypass differential and the command-injection output oracle above to produce
*verified* findings. (Validated end-to-end: see the build/web-target PR.)
