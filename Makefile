.PHONY: build test test-env shell shell-env \
        doc8 ruff mypy clean-dev clean-test clean pre-commit

VERSION := 0.1.3
SHELL := /bin/bash
# Makefile for project
VENV := .venv/bin/activate
UNAME_S := $(shell uname -s)

# -----------------------------------------------------------------------
# Docker-based testing (the ONLY way to run tests)
# -----------------------------------------------------------------------

build:
	docker compose build

# List all available environments in the Docker container
list-envs: build
	docker compose run --rm tox -l

test: build
	docker compose run --rm tox

# Usage: make docker-test-env ENV=py312
test-env: build
	@if [ -z "$(ENV)" ]; then \
		echo "Usage: make docker-test-env ENV=py312"; \
		exit 1; \
	fi
	docker compose run --rm tox -e $(ENV)

shell: build
	docker compose run --rm --entrypoint bash tox

# Usage: make docker-shell-env ENV=py312
shell-env: build
	@if [ -z "$(ENV)" ]; then \
		echo "Usage: make docker-shell-env ENV=py312"; \
		exit 1; \
	fi
	docker compose run --rm --entrypoint bash tox -e $(ENV)

# -----------------------------------------------------------------------
# Code quality (run locally)
# -----------------------------------------------------------------------

doc8:
	doc8

ruff:
	ruff check src/ --fix

mypy:
	mypy src/

# ----------------------------------------------------------------------------
# Documentation
# ----------------------------------------------------------------------------

# Build documentation using Sphinx and zip it
build-docs:
	source $(VENV) && sphinx-source-tree
	source $(VENV) && sphinx-build -n -b text docs builddocs
	source $(VENV) && sphinx-build -n -a -b html docs builddocs
	cd builddocs && zip -r ../builddocs.zip . -x ".*" && cd ..

rebuild-docs:
	source $(VENV) && sphinx-apidoc . --full -o docs -H 'safezip' -A 'Artur Barseghyan <artur.barseghyan@gmail.com>' -f -d 20
	cp docs/conf.py.distrib docs/conf.py
	cp docs/index.rst.distrib docs/index.rst

build-docs-epub:
	$(MAKE) -C docs/ epub

build-docs-pdf:
	$(MAKE) -C docs/ latexpdf

auto-build-docs:
	source $(VENV) && sphinx-autobuild docs docs/_build/html

# Serve the built docs on port 5001
serve-docs:
	source $(VENV) && cd builddocs && python -m http.server 5001

compile-requirements:
	source $(VENV) && uv pip compile --all-extras -o docs/requirements.txt pyproject.toml

compile-requirements-upgrade:
	source $(VENV) && uv pip compile --all-extras -o docs/requirements.txt pyproject.toml --upgrade

# ----------------------------------------------------------------------------
# Pre-commit
# ----------------------------------------------------------------------------

pre-commit-install:
	pre-commit install

pre-commit: pre-commit-install
	pre-commit run --all-files

# ----------------------------------------------------------------------------
# Installation
# ----------------------------------------------------------------------------

create-venv:
	uv venv

# Install the project
install: create-venv
	source $(VENV) && uv pip install -e .[all]

# ----------------------------------------------------------------------------
# Security
# ----------------------------------------------------------------------------

create-secrets:
	source $(VENV) && detect-secrets scan > .secrets.baseline

detect-secrets:
	source $(VENV) && detect-secrets scan --baseline .secrets.baseline

# -----------------------------------------------------------------------
# Housekeeping
# -----------------------------------------------------------------------

clean-dev:
	find . -name "*.orig" -exec rm -rf {} +
	find . -name "__pycache__" -exec rm -rf {} +
	rm -rf dist/ src/safezip.egg-info/ .cache/ .mypy_cache/ .ruff_cache/

clean-test:
	find . -name "*.pyc" -exec rm -rf {} +
	rm -rf .coverage .pytest_cache/ htmlcov/

clean: clean-dev clean-test

update-version:
	@echo "Updating version in pyproject.toml and __init__.py"
	@if [ "$(UNAME_S)" = "Darwin" ]; then \
		gsed -i 's/^version = "[0-9.]\+"/version = "$(VERSION)"/' pyproject.toml; \
		gsed -i 's/__version__ = "[0-9.]\+"/__version__ = "$(VERSION)"/' src/safezip/__init__.py; \
	else \
		sed -i 's/^version = "[0-9.]\+"/version = "$(VERSION)"/' pyproject.toml; \
		sed -i 's/__version__ = "[0-9.]\+"/__version__ = "$(VERSION)"/' src/safezip/__init__.py; \
	fi

# ----------------------------------------------------------------------------
# Release
# ----------------------------------------------------------------------------

package-build:
	source $(VENV) && python -m build .

check-package-build:
	source $(VENV) && twine check dist/*

release:
	source $(VENV) && twine upload dist/* --verbose

test-release:
	source $(VENV) && twine upload --repository testpypi dist/* --verbose

# ----------------------------------------------------------------------------
# Other
# ----------------------------------------------------------------------------

%:
	@:
