default: help

.PHONY: test
test: ## Run application tests
	pytest --ignore=.venv --doctest-modules --doctest-glob='threat_modeling/*.py' -v -n 4 --cov-report term-missing --cov=threat_modeling --cov-fail-under 100

.PHONY: lint
lint: ## Run code linters and type checker
	black tests threat_modeling examples
	flake8 --exclude .venv --max-line-length 88
	mypy --strict --ignore-missing-imports --package threat_modeling

.PHONY: check
check: ## Run linters and tests
	make lint
	make test

.PHONY: docs
docs: ## Build project documentation in live reload for editing
	make -C docs/ clean
	sphinx-apidoc -f -o docs/source threat_modeling
	sphinx-autobuild docs/ docs/_build/html

.PHONY: help
help: ## Print this message and exit
	@printf "threat-modeling: Makefile for development, documentation and testing.\n"
	@printf "Subcommands:\n\n"
	@awk 'BEGIN {FS = ":.*?## "} /^[0-9a-zA-Z_-]+:.*?## / {printf "\033[36m%s\033[0m : %s\n", $$1, $$2}' $(MAKEFILE_LIST) \
		| sort \
		| column -s ':' -t
