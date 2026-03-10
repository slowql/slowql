# Contributing to SlowQL

Thank you for your interest in contributing!

## Setup

    git clone https://github.com/makroumi/slowql.git
    cd slowql
    python -m venv .venv
    source .venv/bin/activate
    pip install -e ".[dev]"

## Development Workflow

1. Fork the repository
2. Create a feature branch (git checkout -b feat/my-feature)
3. Write tests for new code
4. Run checks before submitting:

    make check    # lint + type-check + test (no formatting)
    make all      # format + lint + type-check + test

## Code Style

- Formatting: ruff format (automatic via make format)
- Linting: ruff check
- Type hints: Required, checked via mypy
- Line length: 100 characters

## Commit Messages

Follow Conventional Commits (https://www.conventionalcommits.org/):

- feat: new feature
- fix: bug fix
- docs: documentation
- chore: maintenance

## Pull Requests

- Include a clear description
- Reference related issues
- Ensure CI passes before requesting review

## Adding Rules

Rules live in src/slowql/rules/ organized by dimension:

    src/slowql/rules/
    +-- security/       # SEC-* rules
    +-- performance/    # PERF-* rules
    +-- cost/           # COST-* rules
    +-- reliability/    # REL-* rules
    +-- compliance/     # COMP-* rules
    +-- quality/        # QUAL-* rules

Each rule needs:
- Rule class in the appropriate module
- Tests in tests/unit/test_rules.py
- Registration in catalog.py via get_all_rules()
