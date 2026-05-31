# HexGraph — developer commands. Default backend is the mock: no key, no network.
#
# Quick start (just two commands):
#     make setup     # one-shot: venv + deps + web UI + sandbox image
#     make serve     # start the app at http://127.0.0.1:8765
#
.DEFAULT_GOAL := help
PY ?= .venv/bin/python
PIP ?= .venv/bin/pip
export HEXGRAPH_LLM_BACKEND ?= mock

.PHONY: help setup install venv ui sandbox-build test demo test-live fixtures serve vulnrouter firmae-build iotgoat clean

help: ## Show this help
	@echo "HexGraph — get started with:  make setup  &&  make serve"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

setup: install ui ## ★ One command: install deps, build the web UI, and the sandbox image
	@echo ""
	@echo ">> Building the analysis sandbox image (needs Docker)…"
	@docker version >/dev/null 2>&1 \
		&& $(MAKE) --no-print-directory sandbox-build \
		|| echo "  (!) Docker not running — recon/decompile need it. Start Docker, then: make sandbox-build"
	@$(PY) -m hexgraph.cli init >/dev/null 2>&1 || true
	@echo ""
	@echo "✓ HexGraph is ready.  Start it with:  make serve   →  http://127.0.0.1:8765"

# --- granular targets (composed by `setup`; referenced by CI/docs) ---

venv: ## Create the virtualenv
	python3 -m venv .venv

install: venv ## Install the Python package (server + dev extras) into the venv
	$(PIP) install -e ".[server,dev]"

ui: ## Build the React SPA into the package (needs Node/npm)
	cd frontend && npm install && npm run build

WITH_GHIDRA ?= 0
sandbox-build: ## Build the analysis sandbox Docker image (WITH_GHIDRA=1 to include Ghidra headless)
	docker build -f Dockerfile.sandbox --build-arg WITH_GHIDRA=$(WITH_GHIDRA) -t hexgraph-sandbox:latest .

serve: ## Start the loopback-only API/UI (http://127.0.0.1:8765)
	$(PY) -m hexgraph.cli serve

vulnrouter: ## Stand up the live vulnrouter web target + a project pointed at it (Claude engagement)
	$(PY) scripts/vulnrouter_engagement.py

firmae-build: ## Build the FirmAE rehosting image (heavy; needs privileged Docker + /dev/net/tun to run)
	docker build -f docker/firmae/Dockerfile -t hexgraph-firmae:latest .

IOTGOAT_URL ?= https://github.com/OWASP/IoTGoat/releases/download/v1.0/IoTGoat-rpi-2.img.gz
iotgoat: ## Fetch IoTGoat (FW=<path> to use your own), rehost it, register its live web surface
	@if [ -z "$(FW)" ]; then \
		echo "downloading IoTGoat → /tmp/IoTGoat.img.gz (override with FW=<path>)"; \
		curl -fSL "$(IOTGOAT_URL)" -o /tmp/IoTGoat.img.gz && gunzip -f /tmp/IoTGoat.img.gz; \
		$(PY) scripts/rehost_engagement.py /tmp/IoTGoat.img --name "IoTGoat"; \
	else \
		$(PY) scripts/rehost_engagement.py "$(FW)" --name "IoTGoat"; \
	fi

test: ## Run the test suite against the mock backend (offline)
	$(PY) -m pytest -q

demo: ## Full offline loop on bundled fixtures (mock backend, no key/network), exit 0
	$(PY) -m hexgraph.demo

test-live: ## Scored real-key detection test (needs ANTHROPIC_API_KEY + sandbox image; cassette-backed)
	$(PY) -m pytest -q tests/test_p8_realkey.py -k real_key -rs

fixtures: ## (Re)build the test target binaries/firmware under tests/fixtures
	tests/fixtures/build.sh
	tests/fixtures/vuln_fw/build.sh
	tests/fixtures/eval_fw/build.sh

clean: ## Remove venv and caches
	rm -rf .venv .pytest_cache **/__pycache__ *.egg-info src/*.egg-info
