# Contributing to SlowQL

Thank you for your interest in contributing to SlowQL! 

Our full contribution and development documentation is hosted online at [slowql.dev/docs/development/setup/](https://slowql.dev/docs/development/setup/) and is also available in the `docs/development` directory of this repository.

Please consult these documents based on the type of contribution you are planning:
- **Local Setup**: See [`docs/development/setup.md`](docs/development/setup.md)
- **Adding Analysis Rules**: See [`docs/development/adding-rules.md`](docs/development/adding-rules.md)
- **Testing Guidelines**: See [`docs/development/testing.md`](docs/development/testing.md)
- **General Workflow & Style**: See [`docs/development/contributing.md`](docs/development/contributing.md)

## Quick Start

```bash
git clone https://github.com/makroumi/slowql.git
cd slowql
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Ensure everything works
pytest
ruff check .
mypy src/slowql
```

We look forward to your contributions!