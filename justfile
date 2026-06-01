# HexGraph — developer commands. Default backend is the mock: no key, no network.
#
# Quick start (just two commands):
#     just setup     # one-shot: venv + deps + web UI + sandbox image + DB init
#     just serve     # start the app at http://127.0.0.1:8765
#
# Run `just` (or `just --list`) to see every recipe, grouped by purpose.
# `just` is the task runner — install it without sudo via:
#     curl --proto '=https' --tlsv1.2 -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin
# (or `snap install just`), and ensure ~/.local/bin is on PATH.

# ---------------------------------------------------------------------------
# Configurable variables (override on the command line, e.g. `just port=8766 serve`)
# ---------------------------------------------------------------------------
py             := ".venv/bin/python"          # venv interpreter
pip            := ".venv/bin/pip"             # venv pip
host           := env_var_or_default("HEXGRAPH_HOST", "127.0.0.1")  # loopback only — do not change (product invariant)
port           := env_var_or_default("HEXGRAPH_PORT", "8765")       # API/UI port (ambient HEXGRAPH_PORT or `just port=… serve` wins)
sandbox_image  := "hexgraph-sandbox:latest"   # analysis sandbox image tag
firmae_image   := "hexgraph-firmae:latest"    # FirmAE rehosting image tag
qemu_image     := "hexgraph-qemu:latest"      # qemu+KVM rehosting image tag
iotgoat_url    := "https://github.com/OWASP/IoTGoat/releases/download/v1.0/IoTGoat-x86.img.gz"

# The mock backend is the dev/CI default: no key, no network, zero token spend.
export HEXGRAPH_LLM_BACKEND := env_var_or_default("HEXGRAPH_LLM_BACKEND", "mock")

# Default recipe: show the grouped menu when you run a bare `just`.
default:
    @just --list

# ===========================================================================
# setup — the core path a brand-new user needs (run these first)
# ===========================================================================

# ★ One command to get running: install deps, build the web UI + sandbox image, init the DB.
[group('setup')]
setup: install ui
    @echo ""
    @echo ">> Building the analysis sandbox image (needs Docker)…"
    @docker version >/dev/null 2>&1 \
        && just sandbox-build \
        || echo "  (!) Docker not running — recon/decompile need it. Start Docker, then: just sandbox-build"
    @{{py}} -m hexgraph.cli init >/dev/null 2>&1 || true
    @echo ""
    @echo "✓ HexGraph is ready.  Start it with:  just serve   →  http://{{host}}:{{port}}"

# Create the virtualenv (.venv). Rerun only if you delete .venv.
[group('setup')]
venv:
    python3 -m venv .venv

# Install the hexgraph package (server + dev extras) into the venv.
# Rerun after changing dependencies in pyproject.toml.
[group('setup')]
install: venv
    {{pip}} install -e ".[server,dev]"

# ===========================================================================
# run — start the app
# ===========================================================================

# Start the loopback-only API/UI at http://127.0.0.1:8765 (mock backend by default).
[group('run')]
serve:
    HEXGRAPH_HOST={{host}} HEXGRAPH_PORT={{port}} {{py}} -m hexgraph.cli serve

# ===========================================================================
# build — front-end SPA + analysis sandbox image
# ===========================================================================

# REBUILD WHEN you change anything under frontend/ — the served UI is the built
# bundle in src/hexgraph/web/dist, not the live source.
# Build the React SPA into the package (needs Node/npm).
[group('build')]
ui:
    cd frontend && npm install && npm run build

# REBUILD WHEN you change Dockerfile.sandbox or the sandbox toolchain — NOT when you
# edit/add a probe under sandbox/probes/ (probes are mounted from the install at runtime,
# so probe changes need no rebuild). with_ghidra=1 is an opt-in heavy build.
# Build the analysis sandbox Docker image (needs Docker; with_ghidra=1 bundles Ghidra headless).
[group('build')]
sandbox-build with_ghidra="0":
    docker build -f Dockerfile.sandbox --build-arg WITH_GHIDRA={{with_ghidra}} -t {{sandbox_image}} .

# ===========================================================================
# test — the offline suites (mock backend, $0)
# ===========================================================================

# Run the full offline test suite (mock). Docker-gated tests auto-skip without the sandbox image. The merge gate.
[group('test')]
test:
    {{py}} -m pytest -q

# Scored real-key detection test (opt-in): needs ANTHROPIC_API_KEY + the sandbox image; cassette-backed so CI replays at $0.
[group('test')]
test-live:
    {{py}} -m pytest -q tests/test_p8_realkey.py -k real_key -rs

# REBUILD WHEN you change a fixture source under tests/fixtures/.
# (Re)build the test target binaries/firmware under tests/fixtures (needs a C toolchain).
[group('test')]
fixtures:
    tests/fixtures/build.sh
    tests/fixtures/vuln_fw/build.sh
    tests/fixtures/eval_fw/build.sh

# ===========================================================================
# demo — the full offline loop (doubles as a smoke test)
# ===========================================================================

# Full offline loop on bundled fixtures (mock, no key/network), exits 0. Needs Docker; doubles as a smoke test.
[group('demo')]
demo:
    {{py}} -m hexgraph.demo

# ===========================================================================
# rehosting (OPTIONAL, HEAVY — only needed to boot/assess real firmware)
# ===========================================================================
# These build privileged emulation images and are NOT part of normal setup.
# Enable the feature first: `hexgraph config set features.rehost.enabled true`.

# PREREQS to RUN the result: Docker with --privileged + /dev/net/tun. REBUILD WHEN you change docker/firmae/.
# Build the FirmAE rehosting image (vendor firmware blobs).
[group('rehosting (optional, heavy)')]
firmae-build:
    docker build -f docker/firmae/Dockerfile -t {{firmae_image}} .

# PREREQS to RUN the result: hardware virtualization — Docker with --device /dev/kvm. REBUILD WHEN you change docker/qemu/.
# Build the qemu+KVM rehosting image (full-OS disk images).
[group('rehosting (optional, heavy)')]
qemu-build:
    docker build -f docker/qemu/Dockerfile -t {{qemu_image}} .

# Stand up the live vulnrouter web target + a project (guided engagement; needs rehost/network features).
[group('rehosting (optional, heavy)')]
vulnrouter:
    {{py}} scripts/vulnrouter_engagement.py

# PREREQS: the qemu image built (`just qemu-build`) + Docker with /dev/kvm. fw=<path> uses your own image.
# Fetch IoTGoat (x86 full-OS disk image → qemu rehoster), rehost it, register its live web surface.
[group('rehosting (optional, heavy)')]
iotgoat fw="":
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -n "{{fw}}" ]; then
        {{py}} scripts/rehost_engagement.py "{{fw}}" --name "IoTGoat"
    else
        case "{{iotgoat_url}}" in
            *.gz) dl=/tmp/IoTGoat.img.gz; img=/tmp/IoTGoat.img;;
            *)    dl=/tmp/IoTGoat.img;    img=/tmp/IoTGoat.img;;
        esac
        echo "downloading IoTGoat → $dl (override with fw=<path> or iotgoat_url=<url>)"
        curl -fSL "{{iotgoat_url}}" -o "$dl"
        [ "$dl" != "$img" ] && gunzip -f "$dl" || true
        {{py}} scripts/rehost_engagement.py "$img" --name "IoTGoat"
    fi

# ===========================================================================
# maintenance
# ===========================================================================

# Remove the venv and Python caches. Destructive — asks for confirmation.
[group('maintenance')]
[confirm("Remove .venv and all caches? [y/N]")]
clean:
    rm -rf .venv .pytest_cache **/__pycache__ *.egg-info src/*.egg-info
