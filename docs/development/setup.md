# Development Setup

To contribute upstream to SlowQL, you must configure a native enterprise development environment locally. The project heavily relies on modern Python static typing and strict formatting gates.

## System Prerequisites

- Python 3.11 or greater
- Git version 2.20+
- An active UNIX-like shell (Linux, macOS, or WSL2)

## Installation Workflow

1. **Clone the Source Engine**
   Ensure you fork the repository prior to cloning down your working copy:
   ```bash
   git clone https://github.com/slowql/slowql.git
   cd slowql
   ```

2. **Isolate the Environment**
   We strongly mandate operating entirely inside a virtual environment to prevent dependency collisions with global Python binaries:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   ```

3. **Install Dependencies via Hatchling**
   SlowQL utilizes `hatchling` via the `pyproject.toml` definition. Install the project completely in editable mode targeting the `dev` tag:
   ```bash
   pip install -e ".[dev]"
   ```
   *This bootstraps `pytest`, `ruff`, `mypy`, `sqlglot`, and other essential CI tools locally.*

4. **Initialize Security Hooks (Mandatory)**
   All pull requests must pass formatting logic locally. Initialize `pre-commit` to attach our formatting gates directly to your local Git commits:
   ```bash
   pre-commit install
   ```

## Verifying the Sandbox

Ensure your dependencies resolved perfectly by executing the primary testing pipeline natively:

```bash
pytest
ruff check .
mypy src/slowql --strict
```

If all three executions return zero errors, your development sandbox is officially validated.

## IDE Configuration

### Visual Studio Code
To prevent syntax collisions across contributors, define the following variables inside your local `.vscode/settings.json`:

```json
{
    "python.defaultInterpreterPath": "${workspaceFolder}/.venv/bin/python",
    "[python]": {
        "editor.defaultFormatter": "charliermarsh.ruff",
        "editor.formatOnSave": true,
        "editor.codeActionsOnSave": {
            "source.fixAll": "explicit",
            "source.organizeImports": "explicit"
        }
    },
    "python.analysis.typeCheckingMode": "strict",
    "mypy-type-checker.args": [
        "--config-file=pyproject.toml"
    ]
}
```

This guarantees that native `ruff` formatting and `mypy` assertions execute structurally prior to submitting Pull Requests.
