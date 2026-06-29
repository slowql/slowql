# SlowQL Documentation

**SlowQL** is a next-generation SQL static analyzer written in Rust. It detects security vulnerabilities, performance regressions, reliability risks, cost inefficiencies, compliance violations, and code quality problems in SQL files and application source code.

SlowQL runs entirely offline without connecting to any database.

## Key Properties

- **Zero false positives in proven mode.** Verified against 28 open-source repositories including Django, Rails, ClickHouse, Vitess, Citus, and TimescaleDB.
- **Three confidence levels.** `proven` (act without review), `contextual` (verify before acting), `advisory` (style hints).
- **Context-aware.** Automatically classifies files as application code, migrations, tests, seeds, framework internals, or documentation.
- **282+ built-in rules** across security, performance, reliability, quality, cost, and compliance.
- **14 SQL dialects.** PostgreSQL, MySQL, T-SQL, Oracle, SQLite, Snowflake, BigQuery, Redshift, ClickHouse, DuckDB, Presto, Trino, Spark, Databricks.
- **Fast.** Scans 171k queries in 14 seconds. Typical repos under 1 second.

## Getting Started

- [Installation](getting-started/installation.md)
- [Quick Start](getting-started/quick-start.md)
- [Configuration](getting-started/configuration.md)

## Usage

- [CLI Reference](usage/cli-reference.md)
- [CI/CD Integration](usage/ci-cd-integration.md)
- [Baseline Mode](usage/baseline.md)
- [Inline Suppression](usage/suppression.md)
- [Application Code Extraction](usage/app-code-extraction.md)
- [Cross-File Analysis](usage/cross-file-analysis.md)

## Architecture

- [System Design](architecture/system-design.md)
- [Context Awareness](architecture/context-awareness.md)
- [Rule System](architecture/rule-system.md)

## Rules

- [Rule Overview](rules/overview.md)

## Development

- [Contributing](development/contributing.md)
- [Adding Rules](development/adding-rules.md)
- [Testing](development/testing.md)
