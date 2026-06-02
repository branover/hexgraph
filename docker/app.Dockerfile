# HexGraph application image: the frontend SPA + Python backend, packaged to run the
# whole workbench with `docker compose up`. This is the OPTIONAL containerized path; the
# host pip install (`just setup` → `just serve`) remains the primary/dev path.
#
# Build context is the repo root:
#     docker build -f docker/app.Dockerfile -t hexgraph-app:latest .
#
# IMPORTANT — Docker-out-of-Docker: HexGraph spawns its sandbox/build/fuzz/rehost
# containers by talking to a Docker daemon. In the compose deployment the HOST daemon's
# socket is mounted in, so those siblings run on the host (not nested). This image therefore
# ships the docker CLI but NOT a daemon. See docker-compose.yml for the socket-mount
# security note.

# --- Stage 1: build the React SPA into the package's web/dist -----------------
FROM node:20-bookworm-slim AS web
WORKDIR /app
# Install deps first (cache-friendly): the lockfile rarely changes.
COPY frontend/package.json frontend/package-lock.json* ./frontend/
RUN cd frontend && npm install
# Bring in the frontend source + the package tree the vite outDir writes into
# (outDir is ../src/hexgraph/web/dist relative to frontend/), then build.
COPY frontend/ ./frontend/
COPY src/ ./src/
RUN cd frontend && npm run build
# After this the built bundle lives at /app/src/hexgraph/web/dist.

# --- Stage 2: the Python runtime ---------------------------------------------
FROM python:3.12-slim-bookworm AS app

# The docker CLI so the app can launch its sibling sandbox/build/fuzz/rehost containers
# against the mounted host daemon socket. (CLI only — no daemon runs in here.)
RUN apt-get update && apt-get install -y --no-install-recommends \
        docker.io \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/hexgraph

# Copy the project source, including the SPA bundle built in stage 1 (so the editable/
# regular install packages the dist into the wheel and FastAPI serves it).
COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY migrations/ ./migrations/
COPY alembic.ini ./alembic.ini
COPY --from=web /app/src/hexgraph/web/dist ./src/hexgraph/web/dist

# Install the package with the server extra (FastAPI/uvicorn). No analysis libs run in this
# host process — those live only in the sandbox image. No API key is ever baked in.
# Editable install: the package imports from /opt/hexgraph/src, so the migration runner's
# repo_root() (walks up to the pyproject.toml sentinel) resolves /opt/hexgraph/migrations.
RUN pip install --no-cache-dir -e ".[server]"

# Runtime data (SQLite DB + projects) lives under HEXGRAPH_HOME; compose mounts a volume here.
ENV HEXGRAPH_HOME=/data
# Mark this as the official container so the loopback guard accepts the 0.0.0.0 bind that
# Docker's published-port forwarding requires (compose still publishes on host loopback only).
ENV HEXGRAPH_IN_CONTAINER=1 \
    HEXGRAPH_HOST=0.0.0.0 \
    HEXGRAPH_PORT=8765
EXPOSE 8765

COPY docker/app-entrypoint.sh /usr/local/bin/hexgraph-entrypoint
RUN chmod +x /usr/local/bin/hexgraph-entrypoint

ENTRYPOINT ["/usr/local/bin/hexgraph-entrypoint"]
