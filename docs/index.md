# Built for Modern SQL Workflows

![SlowQL Demo](assets/slowql.gif)

**SlowQL** is the ultimate, next-generation SQL static analyzer designed to detect security vulnerabilities, performance bottlenecks, and compliance violations instantly, before they reach production. 

Unlike traditional linters that only format SQL, SlowQL builds a full Abstract Syntax Tree (AST) using `sqlglot` to semantically understand your queries.

---

## Key Features

- **272 Auto-Discovered Rules**: Comprehensive coverage strictly categorized across six dimensions: Security, Performance, Cost, Reliability, Compliance, and Quality.
- **Dialect Guardians**: Native support for **14 SQL dialects** (PostgreSQL, MySQL, T-SQL, Snowflake, BigQuery, etc.). Rules only trigger for the dialects they explicitly target, eliminating false positives natively.
- **Safe Autofix**: Automatically and safely format and fix bad SQL (`--fix` and `--diff`), with atomic `.bak` file generation guaranteeing operational safety.
- **Rich Output Pipelines**: Ships with a cyberpunk-inspired terminal UI for human operability, alongside native SARIF and JSON exporters for automated pipelines.
- **Migration Framework Support**: Natively supports Alembic, Django, Flyway, Liquibase, Prisma, and Knex with full dependency and ordering awareness.
- **Language Server Protocol (LSP)**: Instant execution diagnostics exposed directly in VS Code via the embedded `slowql-lsp` background server.

---

## Why SlowQL?

### No Database Connection Required
SlowQL parses SQL fully offline via AST structure trees. Execution pipelines do not require functioning database clusters, credential routing, or valid schema definitions to identify missing `WHERE` clauses or `SELECT *` anti-patterns.

### Speed First
Written purely in Python 3.11+ and optimized heavily on multi-threaded generators, SlowQL processes tens of thousands of complex queries near instantly.

### Seamless Extensibility
Write custom rules in Python seamlessly without directly modifying the core engine logic. Teams can parse the AST manually, yield a raw `Issue` model, and SlowQL inherently resolves the formatting, routing, and serialized reporting.

---

## Getting Started

Ready to formally secure and optimize your database architectures?

- [**Quick Start**](getting-started/quick-start.md) - Deploy your first analysis environment in 5 minutes.
- [**CI/CD Integration**](usage/ci-cd-integration.md) - Enforce headless pipelines within GitHub Actions or GitLab.
- [**Rule Overview**](rules/overview.md) - Browse the exact boundaries of all 272 security and performance assertions.
