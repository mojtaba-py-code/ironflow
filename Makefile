# IronFlow developer tasks.  Run `make` for the list.

.DEFAULT_GOAL := help
.PHONY: help install install-dev lint format typecheck test test-fast coverage \
        security check clean build docker docker-run run-example serve scaffold

PYTHON ?= python
PKG    := ironflow

help:  ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	 | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

install:  ## Install the package with the common extras
	$(PYTHON) -m pip install -e ".[columnar,excel,api]"

install-dev:  ## Install everything, including dev tooling
	$(PYTHON) -m pip install -e ".[dev,columnar,excel,remote,api]"
	pre-commit install || true

lint:  ## Lint (ruff)
	$(PYTHON) -m ruff check .

format:  ## Auto-format and auto-fix
	$(PYTHON) -m ruff check --fix .
	$(PYTHON) -m ruff format .

typecheck:  ## Static type check (mypy)
	$(PYTHON) -m mypy

test:  ## Full test suite
	$(PYTHON) -m pytest -q

test-fast:  ## Skip the integration-marked tests
	$(PYTHON) -m pytest -q -m "not integration"

coverage:  ## Test suite with a coverage report
	$(PYTHON) -m pytest --cov=$(PKG) --cov-report=term-missing --cov-report=html -q
	@echo "HTML report: htmlcov/index.html"

security:  ## Scan for committed secrets and vulnerable dependencies
	$(PYTHON) scripts/check_secrets.py
	$(PYTHON) -m ruff check --select S .
	-$(PYTHON) -m pip_audit --strict --desc

check: lint typecheck test security  ## Everything CI runs

clean:  ## Remove build and cache artefacts
	rm -rf build dist *.egg-info src/*.egg-info htmlcov .coverage coverage.xml
	rm -rf .pytest_cache .mypy_cache .ruff_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +

build: clean  ## Build the wheel and sdist
	$(PYTHON) -m pip install --quiet build
	$(PYTHON) -m build

docker:  ## Build the container image
	docker build -f docker/Dockerfile -t ironflow:latest .

docker-run:  ## Bring up the local stack (PostgreSQL + API + scheduler)
	docker compose -f docker/docker-compose.yml up --build

scaffold:  ## Create a pipelines/ directory with a worked example
	$(PYTHON) -m $(PKG) config init

run-example:  ## Dry-run the bundled example pipeline
	$(PYTHON) -m $(PKG) pipeline run example --dry-run

serve:  ## Start the API and dashboard on http://127.0.0.1:8080
	$(PYTHON) -m $(PKG) serve
