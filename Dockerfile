# App image for the loopback-only API/UI. Multi-stage: build the React SPA with
# Node, then serve it from the Python image. The analysis *sandbox* is a separate
# image (Dockerfile.sandbox) that this container launches via docker run.

FROM node:20-slim AS ui
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install
COPY frontend/ ./
# tsconfig 'include' is ./src; build emits to ../src/hexgraph/web/dist, so stage
# the python source tree layout for the relative outDir.
RUN mkdir -p /src/hexgraph/web && npm run build

FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
COPY context ./context
COPY migrations ./migrations
COPY alembic.ini ./
# Built SPA from the ui stage.
COPY --from=ui /src/hexgraph/web/dist ./src/hexgraph/web/dist

RUN pip install --no-cache-dir ".[server]"

EXPOSE 8765
CMD ["hexgraph", "serve"]
