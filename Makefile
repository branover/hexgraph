# HexGraph — developer commands. Default backend is the mock: no key, no network.
.DEFAULT_GOAL := help
PY ?= .venv/bin/python
PIP ?= .venv/bin/pip
export HEXGRAPH_LLM_BACKEND ?= mock

.PHONY: help venv install test demo fixtures sandbox-build serve clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

venv: ## Create the virtualenv
	python3 -m venv .venv

install: venv ## Install the package (server + dev extras) into the venv
	$(PIP) install -e ".[server,dev]"

test: ## Run the test suite against the mock backend
	$(PY) -m pytest -q

demo: ## Full offline loop on bundled fixtures (mock backend, no key/network), exit 0
	$(PY) -m hexgraph.demo

test-live: ## Scored real-key detection test (needs ANTHROPIC_API_KEY + sandbox image; ~cents, cassette-backed)
	$(PY) -m pytest -q tests/test_p8_realkey.py -k real_key -rs

fixtures: ## (Re)build the test target binaries/firmware under tests/fixtures
	tests/fixtures/build.sh
	tests/fixtures/vuln_fw/build.sh

sandbox-build: ## Build the analysis sandbox Docker image (add WITH_GHIDRA=1 to include Ghidra)
	docker build -f Dockerfile.sandbox -t hexgraph-sandbox:latest .

ui: ## Build the React SPA into the package (needs Node/npm)
	cd frontend && npm install && npm run build

serve: ## Start the loopback-only API/UI (lands in M1-T5)
	$(PY) -m hexgraph.cli serve

clean: ## Remove venv and caches
	rm -rf .venv .pytest_cache **/__pycache__ *.egg-info src/*.egg-info
