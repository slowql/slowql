# Installation

As an embedded enterprise analyzer, SlowQL provides native deployment trajectories tailored for local developer laptops, headless CI/CD runners, and Docker ecosystems.

## Prerequisites

- **Python**: `3.11` or newer.
- Operating System: Multi-platform (Linux, macOS, Windows).

---

## Install from PyPI (Recommended)

The standard track for local development is via Python's package manager.

```bash
pip install slowql
```

### Feature Extras
By default, the core engine installs cleanly via `sqlglot` keeping its footprint nominal. To unlock auxiliary integrations, append the designated extra tags:

- **LSP Integration**: `pip install "slowql[lsp]"` (Injects `pygls` routing to power the VS Code and Neovim Editor plugins).
- **Terminal UI**: `pip install "slowql[interactive]"` (Injects `readchar` to allow manual terminal overrides).
- **The Kitchen Sink**: `pip install "slowql[all]"` (Loads all features seamlessly).

---

## Install via Docker (GHCR)

To enforce strict version immutability in CI/CD pipelines without resolving Python environments natively, pull the GitHub Container Registry image:

```bash
docker pull ghcr.io/makroumi/slowql:latest
```

**Executing against workspace geometries:**
```bash
docker run --rm -v $(pwd):/workspace -w /workspace ghcr.io/makroumi/slowql:latest \
  --non-interactive \
  --fail-on high \
  --dialect postgresql \
  schemas/*.sql
```

---

## Contributing & Source Construction

To install SlowQL exclusively for modifying the rule engine, or interacting with the `tests/` suites directly:

```bash
# Clone the central project
git clone https://github.com/makroumi/slowql.git
cd slowql

# Install natively in explicitly editable mode targeting Developer tooling
pip install -e ".[dev]"
```
*(The `dev` bundle ships with `pytest`, `mypy`, `ruff`, and testing stubs)*.

---

## Verifying the Installation 

Confirm whether the parsing binaries are accurately bound to your `$PATH`:

```bash
slowql --version
# Outputs: SlowQL Version 1.6.2
```
