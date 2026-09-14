.DEFAULT_GOAL := help

RUNTESTS := Build/Scripts/runTests.sh

.PHONY: help up down shell cgl cgl-fix fix phpstan rector test test-unit test-functional test-mutation test-fuzz test-e2e test-coverage test-coverage-path lint ci docs

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Environment
up: ## Start DDEV + install TYPO3 v14
	ddev start && ddev install-v14

down: ## Stop DDEV
	ddev stop

shell: ## Open container shell
	ddev ssh

# Quality
cgl: ## Check code style (dry-run)
	$(RUNTESTS) -s cgl

cgl-fix: ## Fix code style
	composer ci:cgl

fix: cgl-fix ## Alias for cgl-fix

phpstan: ## Run PHPStan static analysis
	$(RUNTESTS) -s phpstan

rector: ## Run Rector dry-run
	composer ci:test:php:rector

lint: ## PHP syntax check
	$(RUNTESTS) -s lint

# Testing
test: test-unit test-functional ## Run unit + functional tests via runTests.sh

test-unit: ## Run unit tests (containerized)
	$(RUNTESTS) -s unit

test-functional: ## Run functional tests (containerized)
	$(RUNTESTS) -s functional

test-fuzz: ## Run fuzz tests (containerized)
	$(RUNTESTS) -s fuzz

test-mutation: ## Run mutation tests (containerized)
	$(RUNTESTS) -s mutation

test-coverage: ## Run unit tests with line coverage (Xdebug)
	$(RUNTESTS) -s unitCoverage

test-coverage-path: ## Run unit tests with path + branch coverage (Xdebug)
	$(RUNTESTS) -s unitCoveragePath

test-coverage-functional: ## Run functional tests with coverage (Xdebug)
	$(RUNTESTS) -s functionalCoverage

test-e2e: ## Run Playwright E2E tests (requires DDEV up)
	npm run test:e2e

# CI
ci: ## Run all CI checks locally
	@echo "Running code style check..."
	@composer ci:test:php:cgl
	@echo "Running PHPStan..."
	@composer ci:test:php:phpstan
	@echo "Running unit tests..."
	@composer ci:test:php:unit
	@echo "Running fuzz tests..."
	@composer ci:test:php:fuzz
	@echo "All CI checks passed!"

# Documentation
docs: ## Render documentation
	docker run --rm --pull always -v "$(shell pwd)":/project -t ghcr.io/typo3-documentation/render-guides:latest --config=Documentation
