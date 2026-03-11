# SlowQL

SlowQL is a static analyzer for SQL.

It scans SQL files and detects patterns associated with production incidents, performance regressions, security vulnerabilities, and data integrity risks.

The analyzer runs locally, requires **no external services**, and is suitable for development workflows, CI pipelines, and automated quality gates.

---

<!-- Distribution -->

<p align="center">
  <a href="https://github.com/makroumi/slowql/releases"><img src="https://img.shields.io/github/v/release/makroumi/slowql?logo=github&label=release&color=4c1" alt="Release"></a>
  <a href="https://pypi.org/project/slowql/"><img src="https://img.shields.io/pypi/v/slowql?logo=pypi&logoColor=white&label=PyPI&color=3775A9" alt="PyPI"></a>
  <a href="https://pypi.org/project/slowql/"><img src="https://img.shields.io/pypi/pyversions/slowql?logo=python&logoColor=white&label=Python" alt="Python"></a>
  <a href="https://hub.docker.com/r/makroumi/slowql"><img src="https://img.shields.io/docker/v/makroumi/slowql?logo=docker&logoColor=white&label=Docker&color=2496ED" alt="Docker"></a>
  <a href="https://github.com/makroumi/slowql/pkgs/container/slowql"><img src="https://img.shields.io/badge/GHCR-available-181717?logo=github&logoColor=white" alt="GHCR"></a>
</p>

<p align="center">
  <a href="https://hub.docker.com/r/makroumi/slowql"><img src="https://img.shields.io/docker/pulls/makroumi/slowql?logo=docker&logoColor=white&label=Docker%20pulls" alt="Docker Pulls"></a>
  <a href="https://pypistats.org/packages/slowql"><img src="https://img.shields.io/pypi/dm/slowql?logo=pypi&logoColor=white&label=PyPI%20downloads" alt="PyPI Downloads"></a>
</p>

---

<!-- Build & Quality -->

<p align="center">
  <a href="https://github.com/makroumi/slowql/actions/workflows/ci.yml"><img src="https://github.com/makroumi/slowql/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://codecov.io/gh/makroumi/slowql"><img src="https://codecov.io/gh/makroumi/slowql/graph/badge.svg" alt="Coverage"></a>
  <a href="https://github.com/astral-sh/ruff"><img src="https://img.shields.io/badge/lint-ruff-46a758?logo=ruff&logoColor=white" alt="Ruff"></a>
  <a href="http://mypy-lang.org/"><img src="https://img.shields.io/badge/types-mypy-blue?logo=python&logoColor=white" alt="Mypy"></a>
  <a href="https://github.com/makroumi/slowql/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"></a>
</p>

---

<!-- Community -->

<p align="center">
  <a href="https://github.com/makroumi/slowql/stargazers"><img src="https://img.shields.io/github/stars/makroumi/slowql?style=social" alt="Stars"></a>
  <a href="https://github.com/makroumi/slowql/issues"><img src="https://img.shields.io/github/issues/makroumi/slowql?logo=github" alt="Issues"></a>
  <a href="https://github.com/makroumi/slowql/discussions"><img src="https://img.shields.io/github/discussions/makroumi/slowql?logo=github" alt="Discussions"></a>
  <a href="https://github.com/makroumi/slowql/graphs/contributors"><img src="https://img.shields.io/github/contributors/makroumi/slowql?logo=github&color=success" alt="Contributors"></a>
</p>

---

<p align="center">
  <img src="assets/slowql.gif" alt="SlowQL CLI demo" width="850">
</p>

---

# Overview

SlowQL analyzes SQL source code and detects patterns associated with:

- security vulnerabilities
- performance regressions
- reliability issues
- inefficient query patterns
- compliance risks
- code quality problems

The analyzer works entirely offline and performs static inspection of SQL queries without executing them.

Typical use cases include:

- developer workflows
- CI/CD quality checks
- SQL governance in repositories
- automated query review

---

# Installation

### pipx (recommended)

```bash
pipx install slowql
```

### pip

```bash
pip install slowql
```

Requirements:

- Python 3.11+
- Linux / macOS / Windows

Verify installation:

```bash
slowql --version
```

---

# Quick Start

Analyze a SQL file:

```bash
slowql queries.sql
```

Analyze a directory:

```bash
slowql --input-file sql/
```

Run in CI mode:

```bash
slowql --non-interactive --input-file sql/ --export json
```

---

# Example

Input SQL:

```sql
SELECT * FROM users WHERE email LIKE '%@gmail.com';
DELETE FROM logs;
```

Output:

```
CRITICAL  REL-DATA-001   DELETE without WHERE clause
HIGH      PERF-IDX-002   Leading wildcard prevents index usage
MEDIUM    PERF-SCAN-001  SELECT * may trigger full scans
```

---

# Rule Coverage

SlowQL currently ships with **171 rules** across six dimensions.

| Dimension | Rules |
|-----------|------|
| Security | 45 |
| Performance | 39 |
| Quality | 30 |
| Cost | 20 |
| Reliability | 19 |
| Compliance | 18 |

Each issue contains:

- rule identifier
- severity
- dimension
- location in source
- contextual snippet
- remediation guidance

Severity levels:

```
critical
high
medium
low
info
```

---

# CLI Usage

Basic usage:

```bash
slowql queries.sql
slowql --input-file sql/
```

Export reports:

```bash
slowql --export json
slowql --export json html csv
slowql --out reports/
```

CI mode:

```bash
slowql --non-interactive
slowql --fail-on high
```

Query comparison:

```bash
slowql --compare
```

---

# Safe Autofix

Some rules support automated remediation.

Examples:

| Rule | Fix |
|-----|-----|
| QUAL-NULL-001 | `= NULL` → `IS NULL` |
| QUAL-NULL-001 | `!= NULL` → `IS NOT NULL` |
| QUAL-STYLE-002 | `EXISTS (SELECT *)` → `EXISTS (SELECT 1)` |

Preview fixes:

```bash
slowql --diff
```

Apply fixes:

```bash
slowql --fix
```

Backup files are created automatically before modification.

---

# Output Formats

SlowQL supports multiple output formats.

### JSON

Machine-readable format for CI systems.

### HTML

Self-contained report suitable for sharing or archiving.

### CSV

Spreadsheet-friendly export.

---

# Configuration

SlowQL automatically discovers configuration files.

Supported files:

```
slowql.yaml
.slowql.yaml
```

Example configuration:

```yaml
enabled_dimensions:
  - security
  - performance

disabled_rules:
  - PERF-SCAN-001

fail_on: high
```

---

# Pre-commit Hook

SlowQL can be used as a pre-commit hook to analyze SQL files automatically before they are committed. 

Add the following to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/makroumi/slowql
    rev: v2.0.0 # replace with actual version
    hooks:
      - id: slowql
        # Optional: override default arguments
        args: ["--non-interactive", "--fail-on", "medium"]
```

---

# CI Integration

SlowQL supports automated quality gates.

Example GitHub Actions workflow:

```yaml
name: SQL Analysis

on: [push, pull_request]

jobs:
  slowql:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - run: pip install slowql

      - run: slowql --non-interactive --input-file sql/ --export json
```

Fail build on critical issues:

```bash
slowql --fail-on critical
```

---

# Docker

Run SlowQL without installing Python.

```bash
docker run --rm -v "$PWD:/work" makroumi/slowql \
  slowql --input-file /work/sql
```

---

# Architecture

Project structure:

```
src/slowql/
  analyzers/
  rules/
  parser/
  core/
  reporters/
  cli/
```

Core components:

| Component | Description |
|-----------|-------------|
| parser | SQL parsing and AST generation |
| engine | rule execution and orchestration |
| analyzers | dimension-specific rule groups |
| rules | detection logic |
| reporters | output formats |
| cli | command-line interface |

SQL parsing and AST generation are powered by **sqlglot**.

---

# Development

Clone the repository:

```bash
git clone https://github.com/makroumi/slowql.git
cd slowql
```

Create development environment:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Run tests:

```bash
pytest
```

Static checks:

```bash
ruff check .
mypy src/slowql
```

---

# Contributing

Contributions are welcome.

Typical workflow:

1. Fork repository
2. Create feature branch
3. Add tests
4. Submit pull request

See `CONTRIBUTING.md` for full guidelines.

---

# License

Apache License 2.0.

See `LICENSE` for details.

---

# Support

Issues:  
https://github.com/makroumi/slowql/issues

Discussions:  
https://github.com/makroumi/slowql/discussions

---

<p align="center">
<a href="#slowql">Back to top</a>
</p>