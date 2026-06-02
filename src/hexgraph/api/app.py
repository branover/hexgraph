"""FastAPI app on loopback (SPEC §3, §8): JSON API + the React SPA (P4).

Endpoints: health, projects/targets/findings reads, graph JSON, capabilities,
suggestions, runs, task launch + status. The concrete routes live in
`api/routers/` (one APIRouter per resource); this module wires them onto the
app behind the operator-machine trust boundary, then serves the built SPA
(frontend/, `just ui`) at / with a client-side-routing fallback — all assets
local (offline).
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from hexgraph import __version__
from hexgraph.api.loopback import assert_loopback, host_allowed
from hexgraph.api.routers import (
    annotations,
    build,
    campaigns,
    capabilities,
    findings,
    fuzz_env,
    ghidra,
    graph,
    hypotheses,
    projects,
    settings,
    source,
    targets,
    tasks_runs,
)
from hexgraph.config import load_config
from hexgraph.engine.worker import get_worker

_WEB = Path(__file__).resolve().parent.parent / "web"

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


@asynccontextmanager
async def _lifespan(app: FastAPI):
    # Migrate the persistent DB to head (backs up first; adopts legacy/create_all'd DBs).
    from hexgraph.db.migrate import prepare_database

    prepare_database(backup=True)
    await get_worker().start()
    yield
    await get_worker().stop()


def create_app() -> FastAPI:
    app = FastAPI(title="HexGraph", version=__version__, lifespan=_lifespan)

    # --- Operator-machine trust boundary (loopback API has no auth by design) ---
    # 1) Host-header guard: the PRIMARY anti-DNS-rebinding defense. A malicious page that
    #    DNS-rebinds to 127.0.0.1 still carries the ATTACKER'S Host header, which is not
    #    loopback → rejected here before any handler runs. Implemented in-house (not
    #    Starlette's TrustedHostMiddleware) because that matches on `host.split(':')[0]`,
    #    which mangles a bracketed IPv6 loopback `[::1]:8765` → `[` and would lock out the UI
    #    on systems where localhost resolves to ::1. `host_allowed` parses IPv6 correctly and
    #    respects the deliberate non-loopback bind override (widens to allow-all).
    _bind_host = load_config().host

    @app.middleware("http")
    async def _host_guard(request: Request, call_next):
        if not host_allowed(request.headers.get("host", ""), _bind_host):
            return JSONResponse({"detail": "invalid host header"}, status_code=400)
        return await call_next(request)

    # 2) Same-origin (CSRF) guard on state-changing /api/* requests. Browsers set
    #    `Sec-Fetch-Site` automatically. Allow a mutation ONLY when it is `same-origin` (the
    #    SPA's own fetches) or when the header is ABSENT (non-browser clients — though the
    #    CLI/MCP/tests call the engine in-process, not HTTP, so this is belt-and-suspenders).
    #    Everything else — `cross-site` AND `same-site` AND `none` — is rejected. Rejecting
    #    `same-site` is essential: a page on `evil.localhost` resolves to 127.0.0.1 and is
    #    same-SITE to `localhost`, so it would otherwise pass both this guard and the Host
    #    check and flip the sandbox-relaxing feature gates.
    @app.middleware("http")
    async def _same_origin_guard(request: Request, call_next):
        if request.method not in _SAFE_METHODS and request.url.path.startswith("/api/"):
            sfs = request.headers.get("sec-fetch-site")
            if sfs is not None and sfs != "same-origin":
                return JSONResponse(
                    {"detail": f"cross-origin request rejected (Sec-Fetch-Site: {sfs}); same-origin only"},
                    status_code=403,
                )
        return await call_next(request)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    # --- JSON API (one router per resource; see api/routers/) ---
    app.include_router(projects.router)
    app.include_router(targets.router)
    app.include_router(graph.router)
    app.include_router(findings.router)
    app.include_router(hypotheses.router)
    app.include_router(annotations.router)
    app.include_router(settings.router)
    app.include_router(source.router)
    app.include_router(build.router)
    app.include_router(campaigns.router)
    app.include_router(fuzz_env.router)
    app.include_router(tasks_runs.router)
    app.include_router(capabilities.router)
    app.include_router(ghidra.router)

    # --- SPA (built by `frontend/`; served at / with client-side routing fallback) ---
    # MUST come after the API routers so the catch-all `/{full_path}` never shadows them.
    dist = _WEB / "dist"
    if (dist / "index.html").exists():
        if (dist / "assets").is_dir():
            app.mount("/assets", StaticFiles(directory=str(dist / "assets")), name="assets")

        @app.get("/{full_path:path}", include_in_schema=False)
        def spa(full_path: str):
            # All /api, /graph, /health routes are matched above; everything else is
            # the single-page app (so client-side routes like /projects/<id> work).
            return FileResponse(dist / "index.html")

    return app


def run_server(host: str | None = None, port: int | None = None) -> None:
    import uvicorn

    cfg = load_config()
    host = host or cfg.host
    port = port or cfg.port
    assert_loopback(host)  # refuse non-loopback before binding
    print(f"HexGraph serving on http://{host}:{port}  (backend={cfg.llm_backend})")
    uvicorn.run(create_app(), host=host, port=port, log_level="info")
