.PHONY: help install test coverage lint format type-check security build docs clean all

help:
    @echo "SlowQL Development Commands"
    @echo "=========================="
    @echo "install    - Install dev dependencies"
    @echo "test       - Run test suite"
    @echo "coverage   - Run tests with coverage"
    @echo "lint       - Run linters"
    @echo "format     - Auto-format code"
    @echo "type-check - Run mypy"
    @echo "security   - Run security scans"
    @echo "build      - Build package"
    @echo "docs       - Build documentation"
    @echo "clean      - Clean build artifacts"
    @echo "all        - Run all checks"

install:
    pip install -e '.[dev]'
    pre-commit install

test:
    pytest -v

coverage:
    pytest --cov=slowql --cov-report=html --cov-report=term

lint:
    ruff check slowql/ tests/

format:
    black slowql/ tests/
    ruff check --fix slowql/ tests/

type-check:
    mypy slowql/

security:
    pip-audit
    bandit -r slowql/

build:
    python -m build

docs:
    mkdocs build

clean:
    rm -rf build/ dist/ *.egg-info htmlcov/ .pytest_cache/ .coverage
    find . -type d -name __pycache__ -exec rm -rf {} +

all: format lint type-check test security
    @echo "✅ All checks passed!"
