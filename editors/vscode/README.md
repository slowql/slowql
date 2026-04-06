# SlowQL for VS Code

Static SQL analysis with 282 built-in rules across 14 SQL dialects. Catches security vulnerabilities, performance regressions, reliability issues, compliance risks, cost inefficiencies, and code quality problems as you type. No database connection required.

## Features

**282 rules across six dimensions:**

| Dimension | What it catches |
|-----------|----------------|
| Security | SQL injection, hardcoded credentials, privilege escalation, SSRF |
| Performance | Full scans, missing indexes, N+1 patterns, locking issues |
| Reliability | Data loss risk, race conditions, missing transactions |
| Quality | NULL comparison errors, implicit joins, naming issues |
| Cost | Cloud warehouse anti-patterns, unnecessary scans |
| Compliance | GDPR, HIPAA, PCI-DSS, SOX violations |

**14 SQL dialects with dialect-specific rules:**

PostgreSQL, MySQL, SQL Server (T-SQL), Oracle, SQLite, Snowflake, BigQuery, Redshift, ClickHouse, DuckDB, Presto, Trino, Spark, Databricks.

107 rules are dialect-aware and only fire on the relevant engine. 175 universal rules fire on all dialects.

**Schema-aware validation.** Point SlowQL at your DDL files to detect references to non-existent tables, columns, and get index suggestions.

## Quick Start

1. Install SlowQL with LSP support:

        pip install "slowql[lsp]"

2. Install this extension from the VS Code Marketplace.

3. Open any .sql file. Diagnostics appear in the Problems panel automatically.

The status bar shows SlowQL state: running, error, or disabled.

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| slowql.enable | true | Enable or disable the language server |
| slowql.dialect | (empty, auto) | SQL dialect for dialect-specific rules |
| slowql.command | python | Python executable path |
| slowql.args | ["-m", "slowql.lsp.server"] | Language server arguments |
| slowql.schemaFile | (empty) | Path to DDL file for schema validation |
| slowql.databaseUrl | (empty) | Database connection string for live schema |
| slowql.trace.server | off | Trace LSP communication for debugging |

### Dialect Selection

Set slowql.dialect to your database engine to enable dialect-specific rules. Leave empty for auto-detection.

        {
          "slowql.dialect": "postgresql"
        }

### Schema Validation

Point to your DDL file to catch missing tables and columns:

        {
          "slowql.schemaFile": "db/schema.sql"
        }

Or connect to a live database:

        {
          "slowql.databaseUrl": "postgresql://user:pass@localhost:5432/mydb"
        }

## Commands

Open the Command Palette (Ctrl+Shift+P / Cmd+Shift+P):

| Command | Description |
|---------|-------------|
| SlowQL: Restart Language Server | Restart the background analysis engine |
| SlowQL: Show Status | Show server state, dialect, and rule count |

## Requirements

Python 3.11+ and SlowQL with LSP extras:

        pip install "slowql[lsp]"

If using a virtual environment, set slowql.command to the full path:

        {
          "slowql.command": "/path/to/venv/bin/python"
        }

## Troubleshooting

**Server not starting.** Check the SlowQL output channel (View then Output then SlowQL) for error details. Common causes:

1. slowql[lsp] not installed. Run pip install "slowql[lsp]"
2. Wrong Python path. Set slowql.command to your Python binary.
3. Virtual environment not activated. Use the full path to the venv Python.

**No diagnostics appearing.** Verify the file language is set to SQL (bottom right of VS Code). Check that slowql.enable is true.

## Links

- GitHub: https://github.com/slowql/slowql
- PyPI: https://pypi.org/project/slowql/
- Issues: https://github.com/slowql/slowql/issues
- CLI Documentation: https://github.com/slowql/slowql\#readme
