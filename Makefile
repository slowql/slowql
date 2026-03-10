.PHONY: help install test coverage lint format type-check build clean all check

help:
	@echo "SlowQL Development Commands"
	@echo "=========================="
	@echo "install    - Install dev dependencies"
	@echo "test       - Run test suite"
	@echo "coverage   - Run tests with coverage"
	@echo "lint       - Run linters"
	@echo "format     - Auto-format code"
	@echo "type-check - Run mypy"
	@echo "build      - Build package"
	@echo "clean      - Clean build artifacts"
	@echo "check      - Run lint + type-check + test (no formatting)"
	@echo "all        - Format + lint + type-check + test"

install:
	pip install -e '.[dev]'

test:
	pytest -v

coverage:
	pytest --cov=src/slowql --cov-report=html --cov-report=term

lint:
	ruff check src/ tests/

format:
	ruff format src/ tests/
	ruff check --fix src/ tests/

type-check:
	mypy src/

build:
	python -m build

clean:
	rm -rf build/ dist/ *.egg-info htmlcov/ .pytest_cache/ .coverage
	find . -type d -name __pycache__ -exec rm -rf {} +

check: lint type-check test
	@echo "All checks passed!"

all: format lint type-check test
	@echo "All checks passed!"
