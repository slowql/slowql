# SlowQL for VS Code

Production-focused offline SQL static analysis for identifying security, performance, and reliability issues as you type.

SlowQL provides instant diagnostics for your SQL queries, powered by the SlowQL Language Server. It requires no database connection, performing all analysis statically and safely.

## Features

SlowQL ships with rules across six core dimensions to ensure your SQL is production-ready:

- **Security**: Detects SQL injection risks, hardcoded credentials, and authentication bypass patterns.
- **Performance**: Highlights `SELECT *`, leading wildcards, missing `LIMIT` on large scans, and function usage on indexed columns.
- **Reliability**: Catches high-risk `DELETE`/`UPDATE` without `WHERE` clauses and missing transaction blocks.
- **Quality**: Identifies `NULL` comparison errors (e.g., `= NULL`), syntax anti-patterns, and style issues.
- **Compliance**: Flags PII access (Email, SSN, Credit Card) and GDPR-related data handling risks.
- **Cost**: Detects expensive cloud-warehouse patterns like full table scans and unintentional `CROSS JOIN`s.
- **Schema-Aware**: Validates query structure against your DDL files to detect non-existent tables, columns, and suggest missing indexes.

## Quick Start

1. **Install SlowQL**: Ensure you have Python 3.11+ and install SlowQL with LSP support:
   ```bash
   pip install "slowql[lsp]"
   ```
2. **Install Extension**: Install this extension from the VS Code Marketplace.
3. **Open SQL**: Open any `.sql` file to start receiving real-time diagnostics in the Problems panel.

## Configuration

Settings available under the `slowql` namespace:

- `slowql.enable`: Toggle the language server (default: `true`).
- `slowql.command`: Path to the Python executable (default: `"python"`).
- `slowql.args`: CLI arguments for the server (default: `["-m", "slowql.lsp.server"]`).

## Commands

Access these from the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`):

- **SlowQL: Restart Language Server**: Restarts the background analysis engine.
- **SlowQL: Show Extension Status**: Provides diagnostics for the extension and server health.

## Requirements

- **Python 3.11+**
- **SlowQL** with LSP extras: `pip install "slowql[lsp]"`

## Links

- [GitHub Repository](https://github.com/makroumi/slowql)
- [Issue Tracker](https://github.com/makroumi/slowql/issues)
- [PyPI Package](https://pypi.org/project/slowql/)

---
*SlowQL is an open-source tool for modern engineering teams. Contributions are welcome!*
