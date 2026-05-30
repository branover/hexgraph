# App image for the loopback-only API/UI. The analysis *sandbox* is a separate
# image (Dockerfile.sandbox, M2) that this container launches via docker run.
FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
COPY context ./context

RUN pip install --no-cache-dir ".[server]"

EXPOSE 8765
CMD ["hexgraph", "serve"]
