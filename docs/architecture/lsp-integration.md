# LSP Integration

SlowQL v2.0.0 does not include an LSP server.

The Language Server Protocol integration from the v1.x release has been removed in v2.0.0. The `slowql-lsp` command is not available in this release.

## Planned

LSP integration for VS Code and other editors is planned for a future release of SlowQL.

## Current Alternatives

- Run `slowql src/` from the integrated terminal
- Configure a VS Code task to run SlowQL on save
- Use the pre-commit hook for automatic analysis on commit

See [Editor Setup](../usage/editor-setup.md) for details.
