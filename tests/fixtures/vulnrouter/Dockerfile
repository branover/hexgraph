# Intentionally-vulnerable "router admin" web service — a runnable target for
# HexGraph's dynamic web-surface analysis. Bind to a LOCAL address only.
#   docker build -t hexgraph-vulnrouter:latest tests/fixtures/vulnrouter
#   docker run --rm -e ROUTER_FLAG=... -p 127.0.0.1:8080:8080 hexgraph-vulnrouter:latest
FROM python:3.12-slim
RUN useradd --create-home --uid 1000 router
COPY vulnrouter.py /opt/vulnrouter.py
USER router
EXPOSE 8080
ENV PORT=8080
CMD ["python3", "/opt/vulnrouter.py"]
