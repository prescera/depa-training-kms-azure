# Copyright (c) iSPIRT Foundation.
# Licensed under the MIT license.

SHELL := /bin/bash
PORT ?= 18010
VENV ?= .venv-integration
PYTHON ?= python3

.PHONY: help build typecheck test test-integration sandbox-up sandbox-down check-common deploy-acl clean
.DEFAULT_GOAL := help

help: ## Show targets
	@grep -E '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "%-18s %s\n", $$1, $$2}'

node_modules: package-lock.json
	npm ci --no-audit --no-fund
	@touch node_modules

build: node_modules ## Type-check and build dist/bundle.json (+ dist/bundle_digest.txt)
	npm run build

typecheck: node_modules ## Type-check app and tests
	npm run typecheck

test: node_modules ## Unit tests (jest, Node shim of the CCF runtime)
	npm test

$(VENV)/bin/pytest: test/integration/requirements.txt
	$(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install -q -r test/integration/requirements.txt
	@touch $@

test-integration: $(VENV)/bin/pytest ## Two-sandbox end-to-end tests (needs Docker and the sibling repo)
	cd test/integration && ../../$(VENV)/bin/pytest -q -p no:cacheprovider

sandbox-up: ## Start a local CCF sandbox with this app on PORT (PORT=$(PORT))
	scripts/sandbox-up.sh $(PORT)

sandbox-down: ## Remove the local sandbox on PORT
	scripts/sandbox-down.sh $(PORT)

check-common: ## Fail if shared code differs from the sibling repository
	scripts/check-common.sh

deploy-acl: ## Deploy dist/bundle.json to ACL (ACL_NAME/ACL_URL, ACL_TOKEN)
	scripts/deploy-acl.sh

clean: ## Remove build outputs and local sandbox workspaces
	rm -rf dist workspace $(VENV)
