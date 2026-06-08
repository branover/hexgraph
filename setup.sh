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
#   ./setup.sh --refresh  # quick sanity-sync after a `git pull`: rebuild only what's STALE
#                         #   vs the current source and KEEP your config (reinstall if the
#                         #   version changed, rebuild the SPA if stale, rebuild stale images,
#                         #   re-affirm the MCP registration, regenerate the VR skill, migrate
#                         #   the DB). No prompts, no settings changes, no new features.
# Any OTHER arguments are passed straight through to `hexgraph setup` (e.g. --yes, --rebuild).

# We use bash-only features below (BASH_SOURCE, the source-vs-exec guard). The shebang
# already selects bash for `./setup.sh`, but re-exec under bash if someone runs it as
# `sh setup.sh` so it doesn't die on a "Bad substitution".
if [ -z "${BASH_VERSION:-}" ]; then exec bash "$0" "$@"; fi

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

# --- refresh (sanity-sync) -------------------------------------------------------------
# A fast, non-interactive re-sync to the current source that KEEPS your configuration. The
# venv reinstall (only on a version change) and the SPA rebuild (only if stale) live here —
# the same division of labour as the full bootstrap (this script owns venv+deps+SPA; the
# wizard owns images+DB+MCP+skill). The heavy lifting after that is `hexgraph setup --refresh`.
is_refresh() { for a in "$@"; do [ "$a" = "--refresh" ] && return 0; done; return 1; }

_pkg_version_installed() {
    .venv/bin/python -c "import importlib.metadata as m; print(m.version('hexgraph'))" 2>/dev/null || true
}
_pkg_version_source() {
    # the `version = "X.Y.Z"` line in pyproject.toml (first match)
    sed -nE 's/^version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' pyproject.toml | head -n1
}

# Rebuild the SPA only if the built bundle is missing or stale vs frontend sources. Prefer the
# `just ui-check` recipe (single source of truth) when `just` is present; otherwise inline the
# same check so the no-`just` path still works.
_refresh_ui() {
    if command -v just >/dev/null 2>&1; then
        just ui-check
        return
    fi
    local dist="src/hexgraph/web/dist/index.html"
    if [ ! -f "$dist" ] || [ -n "$(find frontend/src -type f -newer "$dist" -print -quit 2>/dev/null)" ]; then
        say "Rebuilding the web UI (bundle missing or stale)"
        ( cd frontend && npm install && npm run build )
    else
        say "Web UI bundle is current"
    fi
}

do_refresh() {
    say "HexGraph refresh — sanity-syncing to the latest source (configuration unchanged)"
    ensure_venv
    local inst src
    inst="$(_pkg_version_installed)"
    src="$(_pkg_version_source)"
    if [ -z "$inst" ] || [ "$inst" != "$src" ]; then
        say "Reinstalling the package (installed=${inst:-none} → source=${src:-?})"
        .venv/bin/pip install -q -e ".[server,dev]"
    else
        say "Package up to date (v$inst) — skipping reinstall"
    fi
    if command -v npm >/dev/null 2>&1; then
        _refresh_ui
    else
        say "npm not found — skipping UI rebuild (install Node.js to refresh the SPA)"
    fi
    # Hand off to the wizard's refresh: stale images, MCP registration, VR skill, DB.
    .venv/bin/python -m hexgraph.cli setup --refresh
    printf '\n\033[1m✓ Refresh complete.\033[0m  Start HexGraph with:  .venv/bin/hexgraph serve   →  http://127.0.0.1:8765\n'
    printf '  (or, with just installed:  just serve)\n'
}

main() {
    # Run from the repo root regardless of where the script was invoked from.
    cd "$(dirname "${BASH_SOURCE[0]}")"

    # Quick sanity-sync path — no prompts, keeps config. (python3 required; npm optional.)
    if is_refresh "$@"; then
        command -v python3 >/dev/null 2>&1 || die "python3 not found. Install Python 3.11+ and re-run."
        do_refresh
        return 0
    fi

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
