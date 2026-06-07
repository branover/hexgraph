#!/usr/bin/env bash
#
# setup.sh — bootstrap HexGraph (with or without the `just` task runner).
#
# This is the single source of truth for the bootstrap sequence: create the virtualenv,
# install the package, build the web UI, then hand off to the interactive setup wizard
# (`hexgraph setup`) that walks you through the optional features and their security
# implications. `just setup` is a thin wrapper that just calls this script, so the two
# paths can never drift. Run it directly if you'd rather not install `just`.
#
# Usage:
#   ./setup.sh            # build everything, then run the interactive wizard
#   ./setup.sh --yes      # non-interactive: accept the static-only defaults (CI-safe)
# Any arguments are passed straight through to `hexgraph setup` (e.g. --yes, --rebuild).

set -euo pipefail

say() { printf '\n\033[1m>> %s\033[0m\n' "$*"; }
die() { printf '\n\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# Ensure .venv is a *working* virtualenv with pip — idempotent and self-healing.
#
# The guard is deliberately "is there a usable pip?", not "does the directory exist?".
# An interrupted earlier run (Ctrl-C / OOM during `python3 -m venv`) can leave a partial
# .venv behind — the directory and bin/python symlinks present but pip never bootstrapped
# in. A plain `[ -d .venv ]` check would then *skip* creation and the very next line
# (`.venv/bin/pip install …`) would die with ".venv/bin/pip: No such file or directory".
# So treat a venv-without-working-pip as "needs recreating" and rebuild it from scratch.
ensure_venv() {
    if [ -x .venv/bin/python ] && .venv/bin/python -m pip --version >/dev/null 2>&1; then
        return 0  # already a working venv with pip — nothing to do
    fi
    if [ -e .venv ]; then
        say "Recreating .venv (the existing one has no working pip — likely a half-finished earlier run)"
        rm -rf .venv
    else
        say "Creating virtualenv (.venv)"
    fi
    python3 -m venv .venv
    # On some distros `python3-venv` ships without ensurepip wired in, so the venv builds
    # but has no pip. Fail loudly with a fix rather than dying obscurely two lines later.
    [ -x .venv/bin/pip ] || die "created .venv but it has no pip — install your distro's ensurepip/venv support (e.g. 'sudo apt install python3-venv') and re-run."
}

main() {
    # Run from the repo root regardless of where the script was invoked from.
    cd "$(dirname "${BASH_SOURCE[0]}")"

    # --- prerequisites ---------------------------------------------------------
    command -v python3 >/dev/null 2>&1 || die "python3 not found. Install Python 3.11+ and re-run."
    command -v npm     >/dev/null 2>&1 || die "npm not found. The web UI build needs Node.js + npm (https://nodejs.org). Install them and re-run."

    # --- 1/3  virtualenv + package --------------------------------------------
    ensure_venv
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

    printf '\n\033[1m✓ Start HexGraph with:\033[0m  .venv/bin/hexgraph serve   →  http://127.0.0.1:8765\n'
    printf '  (or, with just installed:  just serve)\n'
}

# Run the bootstrap when executed; do nothing when sourced (tests source this file to
# unit-test ensure_venv in isolation, with a stubbed python3, without running the install).
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
