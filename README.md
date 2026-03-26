# SlowQL

SlowQL is a **production-focused offline SQL static analyzer** that catches security vulnerabilities, performance regressions, reliability issues, compliance risks, cost inefficiencies, and code quality problems before they reach production.

It performs safe static analysis of your SQL source code with **no database connection required**. SlowQL ships with **279 built-in rules** covering **14 SQL dialects**, and is built for modern engineering teams supporting CI/CD pipelines, pre-commit hooks, GitHub Actions, SARIF output, LSP, and automated fixes.

---

<!-- Distribution -->

<p align="center">
  <a href="https://github.com/makroumi/slowql/releases"><img src="https://img.shields.io/github/v/release/makroumi/slowql?logo=github&label=release&color=4c1" alt="Release"></a>
  <a href="https://pypi.org/project/slowql/"><img src="https://img.shields.io/pypi/v/slowql?logo=pypi&logoColor=white&label=PyPI&color=3775A9" alt="PyPI"></a>
  <a href="https://pypi.org/project/slowql/"><img src="https://img.shields.io/pypi/pyversions/slowql?logo=python&logoColor=white&label=Python" alt="Python"></a>
  <a href="https://hub.docker.com/r/makroumi/slowql"><img src="https://img.shields.io/docker/v/makroumi/slowql?logo=docker&logoColor=white&label=Docker&color=2496ED" alt="Docker"></a>
  <a href="https://github.com/makroumi/slowql/pkgs/container/slowql"><img src="https://img.shields.io/badge/GHCR-available-181717?logo=github&logoColor=white" alt="GHCR"></a>
  <a href="https://marketplace.visualstudio.com/items?itemName=Makroumi.slowql-vscode"><img src="https://img.shields.io/visual-studio-marketplace/v/Makroumi.slowql-vscode?logo=visualstudiocode&logoColor=white&label=VS%20Code&color=007ACC" alt="VS Code"></a>
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

**Offline-First Analysis.** Catch bugs without ever connecting to a live database. SlowQL works entirely on SQL source files, making it safe to run anywhere.

**Custom Rule Engine.** Define your own organizational SQL conventions via YAML rules or Python plugins. Custom rules integrate seamlessly with the built-in catalog and support full reporting and suppression.

**279 Built-in Rules.** Covers security, performance, reliability, compliance, cost, and quality. Each rule includes impact documentation, fix guidance, and severity classification.

**Cross-File SQL Analysis.** Detect breaking changes across multiple files. SlowQL understands relationships between DDL, views, and procedures, flagging when a schema change in one file (e.g., `DROP COLUMN`) breaks a query in another.

**dbt & Jinja Support.** Natively parses dbt models and SQL templates containing Jinja tags (`{{ ref() }}`, `{% if %}`, `{% for %}`). Enforces dbt best practices including missing references and hardcoded schema detection.

**Migration Framework Support.** Natively supports **Alembic**, **Django migrations**, **Flyway**, **Liquibase**, **Prisma Migrate**, and **Knex**. SlowQL understands the ordering, dependencies, and context of migration files to catch destructive changes before they break your existing queries.

**14 SQL Dialects.** Dialect-aware analysis for PostgreSQL, MySQL, SQL Server (T-SQL), Oracle, SQLite, Snowflake, BigQuery, Redshift, ClickHouse, DuckDB, Presto, Trino, Spark, and Databricks. Universal rules fire on all dialects; dialect-specific rules only fire when relevant.

**Schema-Aware Validation.** Optionally validate against your DDL files to catch missing tables, columns, and suggest indexes.

**Safe Autofix.** Conservative, exact-text-replacement fixes with `FixConfidence.SAFE`. No guessing, no heuristic rewrites. Preview with `--diff`, apply with `--fix`.

**CI/CD Native.** GitHub Actions, SARIF, pre-commit hooks, JSON/HTML/CSV exports. Exit codes based on severity thresholds.

**Editor Integration.** VS Code extension via [slowql-vscode](https://marketplace.visualstudio.com/items?itemName=Makroumi.slowql-vscode) and foundational LSP server for other editors.

**Application Code SQL Extraction.** Automatically extract and analyze SQL strings embedded in **Python**, **TypeScript/JavaScript**, **Java**, **Go**, and **Ruby** files. SlowQL uses language-specific heuristics (ASID-based for Python, regex for others) to find SQL, even inside f-strings and template literals, and flags potential injection risks in dynamic constructions.

---

## Installation

### pipx (recommended)

```bash
pipx install slowql
```

### pip

```bash
pip install slowql
```

### Docker

```bash
docker run --rm -v $(pwd):/src makroumi/slowql /src/queries.sql
```

Requirements: Python 3.11+, Linux / macOS / Windows.

---

## Quick Start

slowql queries.sql
```

Analyze application code (extracts SQL strings automatically):
```bash
slowql src/app.py src/services/
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

## Schema-Aware Validation

SlowQL performs optional schema-aware validation by inspecting your DDL files. This catches structural issues that generic static analysis misses.

**Tables and Columns.** Detect references to non-existent tables or columns.

**Index Suggestions.** Identify filtered columns that lack corresponding indexes.

```bash
slowql queries.sql --schema database/schema.sql
slowql migrations/ --schema schema.sql --fail-on critical
```

Schema findings:

| Rule | Description |
|------|-------------|
| `SCHEMA-TBL-001` | Table referenced but not defined in schema |
| `SCHEMA-COL-001` | Column referenced but not present in table definition |
| `SCHEMA-IDX-001` | Missing index suggested for filtered column |

---

## Rule Coverage

SlowQL ships with **279 rules** across six dimensions:

| Dimension | Focus | Rules |
|-----------|-------|------:|
| Security | SQL injection, privilege escalation, credential exposure, SSRF | 61 |
| Performance | Full scans, indexing, joins, locking, sorting, pagination | 56 |
| Reliability | Data loss prevention, transactions, race conditions, idempotency | 35 |
| Quality | Naming, complexity, null handling, modern SQL, style, dbt | 40 |
| Cost | Cloud warehouse optimization, storage, compute, network | 33 |
| Compliance | GDPR, HIPAA, PCI-DSS, SOX, CCPA | 18 |

### Dialect-Specific Rules

107 rules are dialect-aware, firing only on the relevant database engine:

| Dialect | Specific Rules | Examples |
|---------|---------------:|---------|
| PostgreSQL | 12 | `pg_sleep` detection, `SECURITY DEFINER` without `search_path`, `CREATE INDEX` without `CONCURRENTLY` |
| MySQL | 15 | `LOAD DATA LOCAL INFILE`, `utf8` vs `utf8mb4`, `ORDER BY RAND()`, MyISAM detection |
| T-SQL (SQL Server) | 22 | `OPENROWSET`, `sp_OACreate`, `@@IDENTITY`, `MERGE` without `HOLDLOCK`, `SET NOCOUNT ON` |
| Oracle | 10 | `UTL_HTTP`/`UTL_FILE`, `EXECUTE IMMEDIATE` injection, `CONNECT BY` without `NOCYCLE` |
| Snowflake | 8 | `COPY INTO` credentials, `VARIANT` in `WHERE`, `CLONE` without `COPY GRANTS` |
| BigQuery | 6 | `SELECT *` cost, `DISTINCT` on `UNNEST`, repeated subqueries |
| SQLite | 6 | `ATTACH DATABASE` file access, `PRAGMA foreign_keys = OFF`, `AUTOINCREMENT` overhead |
| Redshift | 7 | `COPY` with embedded credentials, `COPY` without `MANIFEST`, `DISTSTYLE ALL` |
| ClickHouse | 7 | `url()` SSRF, mutations, `SELECT` without `FINAL`, `JOIN` without `GLOBAL` |
| DuckDB | 3 | `COPY` without `FORMAT`, large `IN` lists, old-style casts |
| Presto / Trino | 4 | Implicit cross-joins, `INSERT OVERWRITE` without partition, `ORDER BY` without `LIMIT` |
| Spark / Databricks | 5 | `BROADCAST` on large table, UDF in `WHERE`, `CACHE TABLE` without filter |

The remaining 165 rules are universal and fire on all dialects.

---

## Safe Autofix

SlowQL provides conservative, zero-risk autofixes for rules where the replacement is 100% semantically equivalent:

```bash
slowql queries.sql --diff
slowql queries.sql --fix
slowql queries.sql --fix --fix-report fixes.json
```

Autofix principles:

1. Only exact text replacements. No schema inference, no heuristic rewrites.
2. Every fix is tagged with `FixConfidence.SAFE`, meaning the output is functionally identical to the input.
3. A `.bak` backup is always created before writing.
4. Fixes can be previewed as a unified diff before applying.

Examples of safe autofixes:

| Rule | Before | After |
|------|--------|-------|
| `QUAL-NULL-001` | `WHERE x = NULL` | `WHERE x IS NULL` |
| `QUAL-STYLE-002` | `EXISTS (SELECT * FROM t)` | `EXISTS (SELECT 1 FROM t)` |
| `QUAL-MYSQL-003` | `LOCK IN SHARE MODE` | `FOR SHARE` |
| `QUAL-TSQL-001` | `SET ANSI_NULLS OFF` | `SET ANSI_NULLS ON` |
| `QUAL-ORA-002` | `SELECT 1 FROM DUAL` | `SELECT 1` |

---

## Inline Suppression

Rules can be silenced on a per-line, per-block, or per-file basis using directives written directly in SQL comments. No configuration file changes are required.

```sql
SELECT * FROM archive;  -- slowql-disable-line PERF-SCAN-001

-- slowql-disable-next-line SEC-INJ-001
SELECT id, token FROM sessions WHERE id = $1;

-- slowql-disable PERF-SCAN
SELECT * FROM event_stream;
SELECT * FROM session_log;
-- slowql-enable PERF-SCAN

-- slowql-disable-file REL-001
```

| Directive | Scope |
|---|---|
| `-- slowql-disable-line RULE-ID` | Current line only |
| `-- slowql-disable-next-line RULE-ID` | Next non-blank line |
| `-- slowql-disable RULE-ID` | Open block until matching `enable` or EOF |
| `-- slowql-enable RULE-ID` | Closes an open block |
| `-- slowql-disable-file RULE-ID` | Entire file |

The rule ID may be an exact identifier, a prefix, comma-separated values, or omitted entirely to suppress all rules for that scope. Matching is case-insensitive.

---

## Baseline Mode (Diff Mode)

Baseline Mode allows you to adopt SlowQL on an existing, chaotic codebase without drowning in thousands of initial warnings. This is similar to SonarQube's "New Code Period."

1. **Create a baseline:** Store all your current issues in a `.slowql-baseline` file.
   ```bash
   slowql queries/ --update-baseline
   ```

2. **Run against the baseline:** Now, SlowQL will only flag **new** issues introduced *after* the baseline was created.
   ```bash
   slowql queries/ --baseline
   ```

Because issues are fingerprinted via content hashes, standard edits like appending blank lines won't suddenly "un-suppress" your baseline issues. See the full [Baseline Docs](docs/usage/baseline.md) for CI/CD setup.

---

## Git-Aware Analysis

In CI environments, running static analysis over thousands of files on every commit is slow and unnecessary. SlowQL supports git-aware analysis to cleanly skip untouched files.

```bash
# Only analyze files that are changed, staged, or untracked
slowql . --git-diff

# Analyze files changed since branching off main
slowql . --since main
```

---

## CLI Usage

### Primary Flags
```
--input-file       Path to SQL file or directory
--schema           Path to DDL schema file
--baseline         Path to baseline file (suppress known issues)
--update-baseline  Update/create the baseline file
--fail-on          Failure threshold: critical, high, medium, low, info, never
--non-interactive  Suppress spinners and interactive prompts
--git-diff         Only analyze files changed in the current workspace
--since            Analyze files changed since a specific git revision (e.g. main)
--cache-dir        Directory to store cache files (default: .slowql_cache)
--no-cache         Disable query result caching
--clear-cache      Clear cache directory before analysis
--jobs, -j         Number of parallel workers for analyzing multiple files. (0 = auto)
```

### Output Control
```
--format                        Primary output: console, github-actions, sarif
--export                        Export to disk: json, html, csv, sarif
--out                           Directory for exported reports
--diff                          Preview safe autofix diff
--fix                           Apply safe autofixes (single file, creates .bak)
--fix-report                    Write JSON report of fixes
--list-rules                    List all 279 rules with severity, dimension, and dialect
--list-rules --filter-dimension Filter by dimension (security, performance, etc.)
--list-rules --filter-dialect   Filter by dialect (postgresql, mysql, etc.)
--explain RULE-ID               Show full documentation for a specific rule
```

### Exit Codes
```
0    No issues found or issues below failure threshold
2    Issues found meet or exceed --fail-on threshold
3    Runtime error or tool failure
```

---

## Configuration

SlowQL discovers configuration from `slowql.toml`, `.slowql.toml`, `slowql.yaml`, `.slowql.yaml`, or `pyproject.toml` (under `[tool.slowql]`).

```yaml
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
  severity_overrides:
    PERF-SCAN-001: info
    QUAL-NULL-001: critical

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

## CI Integration

### GitHub Action (Official)

```yaml
- uses: makroumi/slowql-action@v1
  with:
    path: "./sql/**/*.sql"
    schema: "db/schema.sql"
    fail-on: high
    format: github-actions
```

### Direct CLI in CI

```yaml
- name: SlowQL Analysis
  run: |
    pip install slowql
    slowql --non-interactive --input-file sql/ --schema db/schema.sql --fail-on high --format github-actions
```

### Pre-commit

```yaml
repos:
  - repo: https://github.com/makroumi/slowql
    rev: v1.6.2
    hooks:
      - id: slowql
        args: [--fail-on, high]
```

---

## VS Code Extension

Install [slowql-vscode](https://marketplace.visualstudio.com/items?itemName=Makroumi.slowql-vscode) from the VS Code Marketplace for real-time SQL analysis in your editor. The extension uses the SlowQL LSP server for diagnostics.

---

### Query Complexity Scoring

SlowQL now provides a numerical complexity score (0-100) for every analyzed query, helping teams enforce quality policies and track complexity trends.

- **Structural Analysis:** Scores are calculated based on joins, subqueries, and aggregations.
- **Trend Tracking:** Persistent tracking of queries allows you to see if complexity is increasing or decreasing over time.
- **Visual Spectrum:** A new "Query Complexity Spectrum" in the terminal output highlights the most complex queries at a glance.

#### Configuration

You can enable/disable complexity scoring and set thresholds for "optimal", "complex", and "critical" queries in your `.slowql.yml`:

```yaml
complexity:
  enabled: true
  threshold_optimal: 40
  threshold_complex: 70
```

## Architecture

SlowQL is a modular pipeline:

```
SQL Files → Parser (sqlglot) → AST → Analyzers → Rules → Issues → Reporters
                                 ↑                          ↓
                           Schema Inspector            AutoFixer
                           (DDL parsing)           (safe text fixes)
```

**Parser.** Uses [sqlglot](https://github.com/tobymao/sqlglot) for multi-dialect SQL parsing. Handles statement splitting, dialect detection, and AST generation.

**Engine.** Orchestrates parsing, analyzer execution, schema validation, and result aggregation.

**Analyzers.** Six domain-specific analyzers (Security, Performance, Reliability, Compliance, Cost, Quality), each loading rules from the catalog.

**Custom Rules.** Dynamic plugin system that loads user-defined rules from YAML files (regex-based) or Python modules (AST-based) at runtime.

**Rules.** 279 detection rules implemented as `PatternRule` (regex), `ASTRule` (sqlglot AST traversal), or custom `Rule` subclasses.

**Schema Inspector.** Parses DDL files into a schema model. Enables table/column existence checks and index suggestions.

**Reporters.** Console (rich TUI), GitHub Actions annotations, SARIF 2.1.0, JSON, HTML, CSV.

**AutoFixer.** Conservative text-based fix engine. Span-based and exact-text replacements only.

---

## Development

```bash
git clone https://github.com/makroumi/slowql.git
pip install -e ".[dev]"

pytest
ruff check .
mypy src/slowql
```

---

## License

Apache License 2.0. See [LICENSE](LICENSE).

**Issues:** [github.com/makroumi/slowql/issues](https://github.com/makroumi/slowql/issues)

**Discussions:** [github.com/makroumi/slowql/discussions](https://github.com/makroumi/slowql/discussions)

---

<p align="center">
<a href="#slowql">Back to top</a>
</p>