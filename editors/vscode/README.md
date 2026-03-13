# SlowQL for VS Code

Early-stage real-time diagnostics for SQL powered by the SlowQL Language Server.

SlowQL helps you find potential performance issues and anti-patterns in your queries before they hit production. It provides instant feedback in the Problems panel as you type.

## Features

- **Real-time Diagnostics**: Instant feedback on SQL anti-patterns and performance risks.
- **Smart Analysis**: Deep inspection of query structure and schema requirements.
- **Multi-Dialect Support**: Initial support for PostgreSQL and MySQL syntax.
- **Lightweight**: Connects to your local SlowQL installation via LSP.

## Quick Start

1. **Install SlowQL**: Ensure you have Python 3.11+ and install SlowQL with LSP support:
   ```bash
   pip install "slowql[lsp]"
   ```
2. **Install Extension**: Install this extension from the Marketplace.
3. **Open SQL**: Open any `.sql` file to start receiving diagnostics.

## Configuration

Settings available under the `slowql` namespace:

- `slowql.enable`: Toggle the language server (default: `true`).
- `slowql.command`: Language server executable (default: `"python"`).
- `slowql.args`: CLI arguments for the server (default: `["-m", "slowql.lsp.server"]`).

## Requirements

- **Python 3.11+**
- **SlowQL** (installed via pip)

## Links

- [GitHub Repository](https://github.com/makroumi/slowql)
- [Issue Tracker](https://github.com/makroumi/slowql/issues)
- [Documentation](https://github.com/makroumi/slowql)

---
*Note: This is an early-stage diagnostics extension. Features and analysis rules are actively evolving.*
