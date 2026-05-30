"""FastAPI app on loopback (SPEC §3, §8). M1: skeleton + health.

M2 adds the graph endpoint, task launch, and the HTMX UI.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from hexgraph import __version__
from hexgraph.api.loopback import assert_loopback
from hexgraph.config import load_config
from hexgraph.db.session import init_db


@asynccontextmanager
async def _lifespan(app: FastAPI):
    init_db()
    yield


def create_app() -> FastAPI:
    app = FastAPI(title="HexGraph", version=__version__, lifespan=_lifespan)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    return app


def run_server(host: str | None = None, port: int | None = None) -> None:
    import uvicorn

    cfg = load_config()
    host = host or cfg.host
    port = port or cfg.port
    assert_loopback(host)  # refuse non-loopback before binding
    print(f"HexGraph serving on http://{host}:{port}  (backend={cfg.llm_backend})")
    uvicorn.run(create_app(), host=host, port=port, log_level="info")
