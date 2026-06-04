#!/usr/bin/env bash
#
# setup.sh — bootstrap HexGraph without the `just` task runner.
#
# This is the no-`just` path: it does exactly what `just setup` does — create the
# virtualenv, install the package, build the web UI — and then hands off to the SAME
# interactive setup wizard (`hexgraph setup`) that walks you through the optional
# features and their security implications. If you already have `just`, prefer
# `just setup`; this script is here for people who'd rather not install it.
#
# Usage:
#   ./setup.sh            # build everything, then run the interactive wizard
#   ./setup.sh --yes      # non-interactive: accept the static-only defaults (CI-safe)
# Any arguments are passed straight through to `hexgraph setup` (e.g. --yes, --rebuild).

set -euo pipefail

# Run from the repo root regardless of where the script was invoked from.
cd "$(dirname "$0")"

say() { printf '\n\033[1m>> %s\033[0m\n' "$*"; }
die() { printf '\n\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# --- prerequisites ---------------------------------------------------------
command -v python3 >/dev/null 2>&1 || die "python3 not found. Install Python 3.10+ and re-run."
command -v npm     >/dev/null 2>&1 || die "npm not found. The web UI build needs Node.js + npm (https://nodejs.org). Install them and re-run."

# --- 1/3  virtualenv + package --------------------------------------------
if [ ! -d .venv ]; then
    say "Creating virtualenv (.venv)"
    python3 -m venv .venv
fi
say "Installing the hexgraph package (server + dev extras)"
.venv/bin/pip install -e ".[server,dev]"

# --- 2/3  web UI -----------------------------------------------------------
say "Building the web UI (npm install && npm run build)"
( cd frontend && npm install && npm run build )

# --- 3/3  interactive setup wizard ----------------------------------------
# Same TUI as `just setup`: pick optional features (each shown with its SECURITY
# IMPLICATION) + non-secret config, then it builds the chosen images and inits the DB.
# With no TTY (or --yes/--non-interactive) it applies the static-only baseline without
# prompting, so an unattended run never hangs.
say "Launching the HexGraph setup wizard"
.venv/bin/python -m hexgraph.cli setup "$@"

printf '\n\033[1m✓ Start HexGraph with:\033[0m  .venv/bin/python -m hexgraph.cli serve   →  http://127.0.0.1:8765\n'
printf '  (or, with just installed:  just serve)\n'
