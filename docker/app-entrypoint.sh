#!/usr/bin/env sh
# Entrypoint for the HexGraph app container: bring the project DB to the latest schema
# (creating it on first boot, migrating it on later boots — never silently resetting it),
# then start the loopback API/UI. HEXGRAPH_HOME points at the mounted data volume.
set -eu

echo ">> hexgraph: preparing database at ${HEXGRAPH_HOME:-/data} ..."
# `db upgrade` runs prepare_database(): create_all on a fresh DB, alembic upgrade otherwise.
# --no-backup: the volume is the durable store and the op is idempotent; a backup-per-boot
# would just accrete copies inside the volume.
hexgraph db upgrade --no-backup

echo ">> hexgraph: starting server (binds ${HEXGRAPH_HOST:-0.0.0.0}:${HEXGRAPH_PORT:-8765} inside the container) ..."
exec hexgraph serve
