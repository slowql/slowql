# SlowQL

SlowQL is a **production-focused offline SQL static analyzer** designed to catch security vulnerabilities, performance regressions, reliability issues, compliance risks, cost inefficiencies, and code quality problems before they reach production.

It performs safe static analysis of your SQL source code, requiring **no database connection**. SlowQL is built for modern engineering teams, supporting CI/CD pipelines, pre-commit hooks, GitHub Actions, SARIF output, and automated fixes.

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
  <a href="https://github.com/sponsors/makroumi"><img src="https://img.shields.io/badge/Sponsor-GitHub%20Sponsors-ea4aaa?logo=githubsponsors&logoColor=white" alt="Sponsor"></a>
  <a href="https://snyk.io/test/github/makroumi/slowql"><img src="https://snyk.io/test/github/makroumi/slowql/badge.svg" alt="Known Vulnerabilities"></a>
</p>

---

<p align="center">
  <img src="assets/slowql.gif" alt="SlowQL CLI demo" width="850">
</p>

---

## Why SlowQL

- **Offline-First Analysis**: Catch bugs without ever connecting to a live database.
- **Deep Visibility**: 171 built-in rules covering performance, security, and reliability.
- **Schema-Aware**: Optionally validate against your DDL files to catch missing tables and columns.
- **Safe Autofix**: Automatically remediate common anti-patterns with one command.
- **Native Context**: Native workflow integrations including pre-commit, GitHub Actions, SARIF, and foundational LSP/VS Code support.
- **Actionable Reporting**: Results through console output, GitHub annotations, SARIF, and exported JSON/HTML reports.

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

Requirements: Python 3.11+, Linux / macOS / Windows.

---

# Quick Start

Analyze a SQL file:
```bash
slowql queries.sql
```

Analyze with schema validation:
```bash
slowql queries.sql --schema schema.sql
```

Run in CI mode with failure thresholds:
```bash
slowql --non-interactive --input-file sql/ --fail-on high --format github-actions
```

Preview and apply safe fixes:
```bash
slowql queries.sql --diff
slowql queries.sql --fix --fix-report fix-report.json
```

---

# Schema-Aware Validation

SlowQL can perform optional schema-aware validation by inspecting your DDL files. This allows the analyzer to catch structural issues that generic static analysis might miss.

- **Tables/Columns**: Detect references to non-existent tables or columns.
- **Index Suggestions**: Identify filtered columns that lack corresponding indexes.

```bash
# Pass a single DDL file
slowql queries.sql --schema database/schema.sql

# Fail CI if schema issues are found
slowql migrations/ --schema schema.sql --fail-on critical
```

### Example Schema Findings
- `SCHEMA-TBL-001`: Table referenced but not defined in schema.
- `SCHEMA-COL-001`: Column referenced but not present in table definition.
- `SCHEMA-IDX-001`: Missing index suggested for highly-filtered column.

---

# Rule Coverage

SlowQL ships with **171 rules** across six core dimensions:

| Dimension | Focus | Rules |
|-----------|-------|-------|
| Security | SQL injection, permission risks, sensitive data | 45 |
| Performance | Full scans, leading wildcards, N+1 patterns | 39 |
| Quality | Style, readability, anti-patterns | 30 |
| Cost | Inefficient cloud-warehouse patterns | 20 |
| Reliability | Null handling, data integrity, lock risks | 19 |
| Compliance | GDPR, PII handling, data sovereignty | 18 |

---

# CLI Usage

### Primary Flags
- `--input-file` : Path to SQL file or directory.
- `--schema`: Path to DDL schema file.
- `--fail-on`: Set exit failure threshold (`critical`, `high`, `medium`, `low`, `info`, `never`).
- `--non-interactive`: Suppress spinners and interactive prompts.

### Output Control
- `--format`: Controls the primary output stream (`console`, `github-actions`, `sarif`).
- `--export`: Writes detailed reports to disk (`json`, `html`, `csv`).
- `--out /`: Directory for exported reports.

### Exit Codes
- `0`: No issues found or issues below failure threshold.
- `2`: Issues found meet or exceed the `--fail-on` threshold.
- `3`: Runtime error or tool failure.

---

# Configuration

SlowQL automatically discovers configuration from `slowql.toml`, `.slowql.toml`, `slowql.yaml`, `.slowql.yaml`, or `pyproject.toml` (under `[tool.slowql]`).

```yaml
# slowql.yaml example
severity:
  fail_on: high
  warn_on: medium

analysis:
  dialect: postgresql
  enabled_dimensions:
    - security
    - performance
    - reliability
  disabled_rules:
    - PERF-SCAN-001

schema:
  path: db/schema.sql

output:
  format: console
  verbose: false
  show_fixes: true

cost:
  cloud_provider: none

compliance:
  frameworks:
    - gdpr
```

---

# CI Integration

### GitHub Action (Official)

```yaml
- uses: makroumi/slowql-action@v1
  with:
    path: "./sql/**/*.sql"
    schema: "db/schema.sql"
    fail-on: high
    format: github-actions
```

### Direct CLI Usage

```yaml
- name: SlowQL Analysis
  run: |
    pip install slowql
    # Direct CLI usage with schema validation
    slowql --non-interactive --input-file sql/ --schema db/schema.sql --fail-on high --format github-actions
```

---

# Architecture

SlowQL is designed as a modular pipeline for SQL analysis:

- **Parser**: Leverages [sqlglot](https://github.com/tobymao/sqlglot) for robust SQL AST generation.
- **Engine**: Orchestrates rule execution and cross-query analysis.
- **Analyzers**: Domain-specific logic controllers (Security, Perf, etc.).
- **Inspector**: Handles schema loading and metadata resolution.
- **Reporters**: Transforms results into actionable formats (SARIF, HTML, etc.).

---

# Development

```bash
git clone https://github.com/makroumi/slowql.git
pip install -e ".[dev]"

# Run comprehensive test suite
pytest

# Static analysis
ruff check .
mypy src/slowql
```

---

# License & Support

- **License**: Apache License 2.0.
- **Issues**: [GitHub Issues](https://github.com/makroumi/slowql/issues)
- **Discussions**: [Community Discussions](https://github.com/makroumi/slowql/discussions)

---

<p align="center">
<a href="#slowql">Back to top</a>
</p>
