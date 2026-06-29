<div align="center">

<img src="assets/logo.png" alt="SlowQL Logo" style="width: 600px; height: 200px; object-fit: cover; object-position: center;" />

<br/>

**Next-generation SQL static analyzer. Written in Rust.**

Zero false positives in proven mode. Tested against 28 open-source repositories.

<p align="center">
  <a href="https://github.com/slowql/slowql/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/License-AGPL--3.0-blue.svg" />
  </a>
  <a href="https://github.com/slowql/slowql/releases">
    <img src="https://img.shields.io/github/v/release/slowql/slowql?logo=github&label=Release&color=4c1" />
  </a>
  <a href="https://github.com/slowql/slowql/actions/workflows/ci.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/slowql/slowql/ci.yml?label=CI&logo=githubactions" />
  </a>
  <a href="https://github.com/slowql/slowql/stargazers">
    <img src="https://img.shields.io/github/stars/slowql/slowql?logo=github&label=Stars" />
  </a>
</p>

</div>

## What SlowQL Does

SlowQL scans SQL files and application source code for security vulnerabilities, performance regressions, reliability risks, cost inefficiencies, compliance violations, and code quality problems. It runs offline without connecting to any database.

## Key Properties

- **Zero false positives in proven mode.** Verified against Django, Rails, Prisma, Hasura, Supabase, ClickHouse, Vitess, Citus, TimescaleDB, and 19 other open-source projects.
- **Three confidence levels.** `proven` (structurally verified, act without review), `contextual` (accurate with context, verify before acting), `advisory` (style hints and best practices).
- **Context-aware.** Automatically classifies files as application code, migrations, tests, seeds, framework internals, or documentation. Rules are filtered by context to eliminate noise.
- **Fast.** Scans 171k queries (ClickHouse) in 14 seconds. Scans typical application repos in under 1 second (Ryzen i7 U4700, 12GB RAM)
- **Offline.** No database connection, no network, no telemetry.

## Installation

### From source (requires Rust toolchain)

```bash
git clone https://github.com/slowql/slowql.git
cd slowql
cargo install --path .
```

### Docker
``` Bash
docker run --rm -v $(pwd):/src ghcr.io/slowql/slowql /src
```

## Quick Start
``` Bash
# Scan a directory (default: proven mode, zero false positives)
slowql src/

# Scan a single SQL file
slowql queries.sql

# Scan with schema validation
slowql src/ --schema db/schema.sql

# Show all findings including hints
slowql src/ --min-confidence advisory

# CI mode with failure threshold
slowql src/ --fail-on high --format github-actions
```

## Confidence Modes
SlowQL uses three confidence levels to separate verified defects from style suggestions.

| Mode      | Flag                               | What it shows                                                                                   |
| --------- | ---------------------------------- | ----------------------------------------------------------------------------------------------- |
| Proven    | `default`                          | Only structurally verified findings. Zero false positives by design.                            |
| Contextual | `--min-confidence contextual`      | Adds context-dependent findings. Accurate when schema and usage context are available.            |
| Advisory  | `--min-confidence advisory`      | Adds style hints, dead code detection, and best-practice suggestions.                           |

``` Bash
# Proven mode (default) - safe for CI gates
slowql src/

# Contextual mode - for code review
slowql src/ --min-confidence contextual

# Advisory mode - for comprehensive audit
slowql src/ --min-confidence advisory
```

## What It Catches
| Dimension | Rules | Examples |
| --------- | ----- | -------- |
| Security  | 61    | SQL injection, privilege escalation, credential exposure, SSRF |
| Performance | 73 | Full table scans, missing indexes, unbounded queries, N+1 joins |
| Reliability | 44 | DELETE without WHERE, missing transactions, race conditions |
| Quality | 52 | Null comparison errors, naming issues, dead code, complexity |
| Cost | 33 | Cloud warehouse optimization, partition pruning, storage waste |
| Compliance | 18 | GDPR, HIPAA, PCI-DSS, SOX, CCPA patterns |

## Supported Languages and Formats
### SQL files
Direct analysis of `.sql` files. Supports 14 SQL dialects.

### Application Code
Extracts SQL strings from source code and analyzes them:

- **Python** - triple-quoted strings, f-strings, cursor.execute()
- **TypeScript/JavaScript** - template literals, db.query(), knex.raw()
- **Java/Kotlin** - prepareStatement(), createNativeQuery()
- **Go** - db.Query(), db.Exec()
- **Ruby** - connection.execute(), heredocs
- **C#** - connection.Execute()
- **MyBatis XML** - mapper files with dynamic SQL tags

### Framework Support
- **Migrations**: Alembic, Django, Flyway, Liquibase, Prisma, Knex
- **dbt**: ref() resolution, Jinja template stripping
- **ORMs**: Detects query builder patterns vs raw SQL

## SQL Dialects
Dialect-aware analysis for 14 database engines:

- PostgreSQL
- MySQL
- SQL Server (T-SQL)
- Oracle
- SQLite
- Snowflake
- BigQuery
- Redshift
- ClickHouse
- DuckDB
- Presto
- Trino
- Spark
- Databricks

107 rules are dialect-specific. 175 rules are universal.

## Context Classification
SlowQL automatically classifies each file by its role in the project:

| **Context** | **Effect** |
|---------|--------|
| `application` | Full rule analysis |
| `migration` | Only security and reliability rules |
| `test` | Only security and reliability rules |
| `seed` | Only security and reliability rules |
| `example` | Only security and reliability rules |
| `framework_internal` | Only security and reliability rules, with deny list |
| `ddl_schema` | Only security, reliability, and compliance rules |
| `dbt_model` | Full analysis minus unbounded SELECT |
| `adhoc` | Full analysis minus context-dependent rules |

No configuration needed. Context is inferred from file paths and content patterns.

## Schema-Aware Validation
Validate queries against your DDL files:
``` Bash
slowql src/ --schema db/schema.sql
```

| **Rule** | **Description** |
|------|-------------|
| `SCHEMA-TBL-001` | Table referenced but not defined in schema |
| `SCHEMA-COL-001` | Column referenced but not in table definition |

## Safe Autofix
Conservative, exact-text-replacement fixes. No heuristic rewrites.
``` Bash
# Preview fixes
slowql queries.sql --diff

# Apply fixes (creates .bak backup)
slowql queries.sql --fix

# Apply and write report
slowql queries.sql --fix --fix-report fixes.json
```

| **Rule** | **Before** | **After** |
|------|--------|-------|
| `QUAL-NULL-001` | `WHERE x = NULL` | `WHERE x IS NULL` |
| `QUAL-STYLE-002` | `EXISTS (SELECT * FROM t)` | `EXISTS (SELECT 1 FROM t)` |

## Inline Suppression
Suppress rules directly in SQL comments:
``` SQL
SELECT * FROM archive;  -- slowql-disable-line PERF-SCAN-001

-- slowql-disable-next-line SEC-INJ-001
SELECT id FROM sessions WHERE id = $1;

-- slowql-disable PERF-SCAN
SELECT * FROM logs;
-- slowql-enable PERF-SCAN

-- slowql-disable-file
```

## Baseline Mode
Adopt SlowQL on existing codebases without drowning in warnings:
``` Bash
# Create baseline of current issues
slowql src/ --update-baseline .slowql-baseline

# Only report new issues
slowql src/ --baseline .slowql-baseline
```

## Git-Aware Analysis
Only analyze changed files:
``` Bash
slowql . --git-diff
slowql . --since main
```

## Output formats
| **Format** | **Flag** | **Use case** |
|------|------|--------|
| Console | `default` | Human-readable terminal output |
| JSON | `--format json` | CI/CD pipelines, custom tooling |
| SARIF | `--format sarif` | GitHub Code Scanning, IDE integration |
| GitHub Actions | `--format github-actions` | PR annotations |

Export to files:
``` Bash
slowql src/ --export json --export html --export csv --out reports/
```

## Configuration
SlowQL discovers configuration from `slowql.yaml`, `slowql.toml`, `.slowql.yaml`, `.slowql.toml`, or `pyproject.toml` (under `[tool.slowql]`).

``` YAML
analysis:
  dialect: postgresql
  enabled_dimensions:
    - security
    - performance
    - reliability
    - cost
    - quality
  disabled_rules: []
  # min_confidence: proven

severity:
  fail_on: high

compliance:
  frameworks:
    - gdpr

schema:
  path: db/schema.sql
  ```

Generate a starter config:
``` Bash
slowql --init
```
  
## Custom Rules
Define organization-specific rules in YAML:
 ``` YAML
  rules:
  - id: ORG-001
    name: "Require tenant_id filter"
    severity: high
    dimension: security
    pattern: "SELECT.*FROM\\s+orders\\b(?!.*tenant_id)"
    message: "All queries on orders table must filter by tenant_id"
```

Load with config:
``` YAML
analysis:
  custom_rules: .slowql-rules.yaml
```

## CI integration
### GitHub Actions
``` YAML
- name: SlowQL Analysis
  run: |
    slowql src/ --fail-on high --format github-actions
```

### Pre-commit
``` YAML
repos:
  - repo: https://github.com/slowql/slowql
    rev: v2.0.0
    hooks:
      - id: slowql
        args: [--fail-on, high]
```

## CLI Reference
``` text
Usage: slowql [OPTIONS] [FILES]...

Arguments:
  [FILES]...  Input SQL files or directories

Options:
  -d, --dialect <DIALECT>          SQL dialect
  -s, --schema <SCHEMA>            Path to DDL schema file
      --format <FORMAT>            Output format [console, json, sarif, github-actions]
      --export <EXPORT>            Export results to file (json, html, csv, sarif)
      --out <OUT>                  Output directory for exports [default: reports]
      --fail-on <FAIL_ON>          Fail at or above this severity
      --diff                       Preview safe autofix diff
      --fix                        Apply safe autofixes (.bak backup created)
      --baseline <BASELINE>        Path to baseline file
      --update-baseline <PATH>     Create or update baseline file
      --list-rules                 List all available rules
      --explain <RULE>             Show documentation for a specific rule
      --git-diff                   Only analyze files changed in git
      --since <REV>                Analyze files changed since a git revision
      --min-confidence <LEVEL>     Minimum confidence: proven, contextual, advisory
      --include-nonprod            Include test/example/seed contexts in output
      --compare                    Detect similar queries across files
      --init                       Create a slowql.yaml config file
      --verbose                    Enable verbose output
  -h, --help                       Print help
  -V, --version                    Print version
```

### Exit Codes
| **Code** | **Meaning** |
|------|---------|
| 0 | No issues found (or below threshold) |
| 1 | Issues found at medium or low severity |
| 2 | Issues found at high severity |
| 3 | Issues found at critical severity |

## Explore Rules
``` Bash
# List all rules
slowql --list-rules

# Filter by dimension
slowql --list-rules --filter-dimension security

# Filter by dialect
slowql --list-rules --filter-dialect postgresql

# Explain a specific rule
slowql --explain PERF-SCAN-001
```

## Architecture
``` text
Files -> Walker -> Context Classifier -> Parser -> Rule Engine -> Issues -> Reporter
                                           |           |             |
                                      Extractor    Schema        Autofix
                                    (app code)   Validator     (safe only)
``` 
- **Walker**: Traverses directories, filters by supported extensions
- **Context Classifier**: Classifies files by role (application, test, migration, etc.)
- **Parser**: Splits SQL statements, detects dialect, extracts tables/columns
- **Extractor**: Pulls SQL from Python, TypeScript, Java, Go, Ruby, C#, MyBatis XML
- **Rule Engine**: 282+ rules across 6 dimensions with confidence levels
- **Schema Validator**: Optional DDL-based table/column existence checks
- **Autofix**: Conservative text-replacement fixes with backup
- **Reporter**: Console, JSON, SARIF, GitHub Actions, HTML, CSV

## Verified Against
SlowQL v2.0.0 was hardened against these open-sourrce repositories with zero false positives in proven mode:
(AMD Ryzen i7 U4700 12GB RAM)

| **Repository** | **Queries** | **Time** |
|---|---|---|
| ClickHouse | 171,533 | 14s |
| graphql-engine | 84,101 | 54s |
| citus | 64,468 | 5s |
| timescaledb | 30,775 | 2.5s |
| spark | 19,892 | 2s |
| sqlfluff | 14,979 | 1s |
| vitess | 2,312 | 0.5s |
| postgrest | 2,322 | 0.4s |
| mybatis-3 | 1,703 | 0.3s |
| metabase | 1,310 | 0.5s |
| supabase | 817 | 0.3s |
| django | 201 | 0.2s |
| rails | 164 | 0.2s |
| prisma-engines | 167 | 0.1s |
| sqlmap | 142 | 0.1s |
| + 13 more

## Development
``` Bash
git clone https://github.com/slowql/slowql.git
cd slowql
cargo build
cargo test
```
625 tests covering rules, extractors, context classification, CLI, and integration scenarios.

## License
AGPL-3.0. See [LICENSE](LICENSE).

Copyright (C) 2025-2026 [El Mehdi Makroumi](https://github.com/makroumi).
