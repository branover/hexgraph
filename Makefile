# This project uses `just` now (see justfile). Run `just` to list recipes.
.DEFAULT_GOAL := notice
.PHONY: notice
notice:
	@echo "This project uses 'just' now — run 'just' to see recipes (or 'just --list')."
