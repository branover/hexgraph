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

install: venv ## Install the package (dev extras) into the venv
	$(PIP) install -e ".[dev]"

test: ## Run the test suite against the mock backend
	$(PY) -m pytest -q

demo: ## Full offline loop on bundled fixtures (mock backend, no key/network), exit 0
	@echo "make demo lands in M2 — ingest -> recon -> finding -> graph -> spawn"
	@exit 1

fixtures: ## (Re)build the test target binaries/firmware under tests/fixtures
	@echo "tests/fixtures/build.sh lands in M2-T8"
	@exit 1

sandbox-build: ## Build the analysis sandbox Docker image
	@echo "Dockerfile.sandbox lands in M2-T1"
	@exit 1

serve: ## Start the loopback-only API/UI (lands in M1-T5)
	$(PY) -m hexgraph.cli serve

clean: ## Remove venv and caches
	rm -rf .venv .pytest_cache **/__pycache__ *.egg-info src/*.egg-info
