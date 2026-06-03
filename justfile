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
app_image      := env_var_or_default("HEXGRAPH_APP_IMAGE", "hexgraph-app:latest")       # full app (frontend+backend) image tag
sandbox_image  := "hexgraph-sandbox:latest"   # analysis sandbox image tag
build_image    := env_var_or_default("HEXGRAPH_BUILD_IMAGE", "hexgraph-build:latest")  # build-from-source image tag
fuzz_image     := env_var_or_default("HEXGRAPH_FUZZ_IMAGE", "hexgraph-fuzz:latest")    # coverage-guided fuzz image tag
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

# The wizard lets you choose which optional features to enable (each shown with its SECURITY
# IMPLICATION) + non-secret config, optionally register HexGraph's MCP server with a coding agent
# + install the VR skill, then builds the chosen images + inits the DB. CI-safe: with no TTY (or
# `just setup yes=1`) it applies the static-only baseline + the sandbox image WITHOUT prompting
# (and skips the MCP/skill install), so an unattended `just setup` never hangs.
# ★ Bootstrap venv+deps+SPA, then run the interactive setup wizard (the one command to get running).
[group('setup')]
setup yes="0": install ui
    #!/usr/bin/env bash
    set -euo pipefail
    echo ""
    if [ "{{yes}}" = "1" ] || [ ! -t 0 ]; then
        # No interactive terminal (CI) or explicit yes=1 → non-interactive baseline.
        {{py}} -m hexgraph.cli setup --non-interactive
    else
        {{py}} -m hexgraph.cli setup
    fi
    echo ""
    echo "✓ Start HexGraph with:  just serve   →  http://{{host}}:{{port}}"

# Create the virtualenv (.venv). Rerun only if you delete .venv.
[group('setup')]
[private]
venv:
    python3 -m venv .venv

# Rerun after changing dependencies in pyproject.toml.
# Install the hexgraph package (server + dev extras) into the venv.
[group('setup')]
install: venv
    {{pip}} install -e ".[server,dev]"

# ===========================================================================
# run — start the app
# ===========================================================================

# Ensures the served SPA is CURRENT first (ui-check rebuilds it only if stale) — a plain
# `just serve` used to silently ship an OLD bundle when frontend/ had changed since the
# last build, hiding new UI (the Campaigns tab, assurance chips, …) until you ran `just ui`.
# Start the loopback-only API/UI at http://127.0.0.1:8765 (mock backend by default).
[group('run')]
serve: ui-check
    HEXGRAPH_HOST={{host}} HEXGRAPH_PORT={{port}} {{py}} -m hexgraph.cli serve

# Rebuild the SPA only if the built bundle is MISSING or STALE vs frontend/ sources —
# so a plain `just serve` always ships current UI without paying a full npm build when
# nothing changed. Run `just ui` to force an unconditional rebuild.
[group('run')]
[private]
ui-check:
    #!/usr/bin/env bash
    set -euo pipefail
    dist="src/hexgraph/web/dist/index.html"
    if [ ! -f "$dist" ]; then
        echo ">> SPA bundle missing — building it (just ui)…"
        just ui
        exit 0
    fi
    # Any frontend source/config newer than the built bundle ⇒ the bundle is stale.
    newer=$(find frontend -type f \
        \( -path 'frontend/src/*' -o -name 'index.html' -o -name 'package.json' \
           -o -name 'package-lock.json' -o -name 'vite.config.*' -o -name 'tsconfig*.json' \) \
        -newer "$dist" -not -path 'frontend/node_modules/*' -print -quit 2>/dev/null || true)
    if [ -n "$newer" ]; then
        echo ">> SPA bundle is STALE ($newer changed since last build) — rebuilding (just ui)…"
        just ui
    else
        echo ">> SPA bundle is current."
    fi

# ===========================================================================
# build — front-end SPA + analysis sandbox image
# ===========================================================================

# REBUILD WHEN you change anything under frontend/ — the served UI is the built
# bundle in src/hexgraph/web/dist, not the live source.
# Build the React SPA into the package (needs Node/npm).
[group('build')]
ui:
    cd frontend && npm install && npm run build

# REBUILD WHEN you change docker/sandbox.Dockerfile or the sandbox toolchain — NOT when you
# edit/add a probe under sandbox/probes/ (probes are mounted from the install at runtime,
# so probe changes need no rebuild). with_ghidra=1 is an opt-in heavy build.
# Build the analysis sandbox Docker image (needs Docker; with_ghidra=1 bundles Ghidra headless).
[group('build')]
sandbox-build with_ghidra="0":
    docker build -f docker/sandbox.Dockerfile --build-arg WITH_GHIDRA={{with_ghidra}} -t {{sandbox_image}} .

# OPT-IN, gated by features.build. REBUILD WHEN you change docker/build.Dockerfile or the build
# toolchain — NOT when you edit build_probe.py (probes are mounted from the install at
# runtime). This DEDICATED image (clang/LLVM + sanitizers + SanCov + AFL++ compilers) is
# the recorded base_image a BuildSpec compiles in; it is NOT the shared sandbox image.
# WORKTREE DISCIPLINE: build a PRIVATE tag and point HEXGRAPH_BUILD_IMAGE at it — never
# clobber a shared tag: `HEXGRAPH_BUILD_IMAGE=hexgraph-build:wt-<topic> just build-image`.
# Build the build-from-source image (needs Docker; with_cross=1 adds cross gcc/binutils + qemu-user for firmware cross-compile).
[group('build')]
build-image with_cross="0":
    docker build -f docker/build.Dockerfile --build-arg WITH_CROSS={{with_cross}} -t {{build_image}} .

# OPT-IN, gated by features.fuzzing/poc. REBUILD WHEN you change docker/fuzz.Dockerfile or the
# fuzz toolchain — NOT when you edit fuzz_probe.py / afl_probe.py (probes are mounted
# from the install at runtime). This DEDICATED image (AFL++ LTO/CmpLog + libFuzzer +
# llvm-symbolizer + afl-cov/llvm-cov + gdb + qemu-user) is what a coverage-guided fuzz
# CAMPAIGN runs in; it is NOT the shared sandbox image. WORKTREE DISCIPLINE: build a
# PRIVATE tag and point HEXGRAPH_FUZZ_IMAGE at it — never clobber a shared tag:
#   `HEXGRAPH_FUZZ_IMAGE=hexgraph-fuzz:wt-<topic> just fuzz-build`.
# Build the coverage-guided fuzz image (needs Docker; AFL++ + libFuzzer + llvm-symbolizer).
[group('build')]
fuzz-build:
    docker build -f docker/fuzz.Dockerfile -t {{fuzz_image}} .

# The host pip install (`just setup`) remains the primary/dev path; this is for running the
# whole thing in a container. Multi-stage: Node builds the SPA, Python installs the package with
# the bundle. REBUILD WHEN you change app source, frontend/, or docker/app.Dockerfile.
# Build the full HexGraph app image (frontend SPA + backend + docker CLI) for `docker compose up`.
[group('build')]
app-build:
    docker build -f docker/app.Dockerfile -t {{app_image}} .

# Mounts the host Docker socket so the app spawns its sandbox/build/fuzz sibling containers on
# the host daemon — see the security note in docker-compose.yml.
# Start HexGraph via docker-compose at http://{{host}}:{{port}} (published on host loopback only).
[group('run')]
up:
    docker compose up --build

# Stop the docker-compose stack (keeps the named data volume).
[group('run')]
down:
    docker compose down

# ===========================================================================
# test — the offline suites (mock backend, $0)
# ===========================================================================

# Run the full offline test suite (mock). Docker-gated tests auto-skip without the sandbox image. The merge gate.
[group('test')]
test:
    {{py}} -m pytest -q

# CI gate: FAIL FAST if Docker/the sandbox image is absent, then run the full suite.
# A green OFFLINE `just test` validates NONE of the live egress/exec/rehost/remote paths
# (they silently skip) — this recipe refuses to "pass" without them. Build the image first
# with `just sandbox-build`. Override with allow_no_docker=1 only to deliberately run offline.
[group('test')]
[private]
test-ci allow_no_docker="0":
    #!/usr/bin/env bash
    set -euo pipefail
    if [ "{{allow_no_docker}}" != "1" ]; then
        if ! docker version >/dev/null 2>&1; then
            echo "✗ test-ci: Docker is not available — the security-critical live tests" >&2
            echo "  (vulnrouter RCE/auth-bypass, web_discover, SSH remote, rehost) would SILENTLY" >&2
            echo "  skip, so a 'green' run proves nothing about the egress/exec/rehost/remote paths." >&2
            echo "  Start Docker + run 'just sandbox-build', or 'just test-ci allow_no_docker=1' to override." >&2
            exit 1
        fi
        if ! docker image inspect {{sandbox_image}} >/dev/null 2>&1; then
            echo "✗ test-ci: the {{sandbox_image}} image is missing — live tests would skip." >&2
            echo "  Build it with: just sandbox-build" >&2
            exit 1
        fi
    fi
    {{py}} -m pytest -q -rs

# Scored real-key detection test (opt-in): needs ANTHROPIC_API_KEY + the sandbox image; cassette-backed so CI replays at $0.
[group('test')]
[private]
test-live:
    {{py}} -m pytest -q tests/test_p8_realkey.py -k real_key -rs

# REBUILD WHEN you change a fixture source under tests/fixtures/.
# (Re)build the test target binaries/firmware under tests/fixtures (needs a C toolchain).
[group('test')]
[private]
fixtures:
    tests/fixtures/build.sh
    tests/fixtures/vuln_fw/build.sh
    tests/fixtures/eval_fw/build.sh

# ===========================================================================
# demo — the full offline loop (doubles as a smoke test)
# ===========================================================================

# campaign (MockFuzzer) → verified PoC + assurance ladder → spawn follow-up → graph. Mock LLM,
# no key/network, $0; needs only the base sandbox image (Docker) for recon/unpack.
# Narrated offline loop (ingest → instrumented build → fuzz → verified PoC → graph); also a smoke test.
[group('demo')]
demo:
    {{py}} -m hexgraph.demo

# Seed the rich SCREENSHOT-SHOWCASE project (mock, offline, $0, no Docker) into HEXGRAPH_HOME:
# one engagement exercising the firmware tree, dynamic surfaces, source/coverage, the
# assurance ladder, a finished mock fuzz campaign, and a wide edge variety — for the README
# hero shots + the per-feature doc captures. `--reset` rebuilds it. Then `just serve` to view,
# or `just capture` to regenerate docs/images/. Enables fuzzing/poc/network/build features.
[group('demo')]
[private]
showcase *args:
    HEXGRAPH_FUZZER=mock {{py}} scripts/seed_showcase.py {{args}}

# Seed the four GRAPH-PRESENTATION complexity tiers (SMALL/MEDIUM/LARGE/PATHOLOGICAL) into
# HEXGRAPH_HOME — the reusable A/B fixture for the graph redesign's before/after Playwright
# captures (docs/design/design-graph-presentation.md §9). Mock, offline, $0, deterministic. `--reset`
# rebuilds; `--tier large` seeds one. Then `just serve` and open each "Graph tier — …" project.
[group('demo')]
[private]
graph-tiers *args:
    HEXGRAPH_FUZZER=mock {{py}} scripts/seed_graph_tiers.py {{args}}

# Regenerate the committed docs/images/*.png from the showcase project (Playwright, dark
# theme, 1440x900). Seeds the showcase into a throwaway HEXGRAPH_HOME, serves it on a spare
# port, captures the hero + per-feature shots, and tears down. Needs the dev-only Playwright
# browser: `.venv/bin/pip install playwright && .venv/bin/playwright install chromium`.
[group('demo')]
[private]
capture:
    HEXGRAPH_FUZZER=mock {{py}} scripts/capture_screenshots.py

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
