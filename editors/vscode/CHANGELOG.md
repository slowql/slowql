# Changelog

## [0.2.0]

### Added
- Dialect selection setting (slowql.dialect) with 14 supported dialects
- Status bar item showing server state (running/error/disabled)
- LSP trace setting (slowql.trace.server) for debugging
- Dialect passed to language server via --dialect flag
- Show Output action on server startup failure

### Changed
- Updated to 272 built-in rules (was 171)
- Dialect-specific rules now fire only on matching dialect
- Improved error handling and user-facing messages
- Better config change detection (restarts on dialect change)
- Status bar hidden when non-SQL files are active

### Fixed
- Config args now cloned before modification (prevents mutation across restarts)

## [0.1.1] - 2025-03-14

### Fixed
- Minor stability fixes

## [0.1.0] - 2025-03-13

### Added
- Real-time SQL diagnostics via SlowQL Language Server
- 171 built-in rules across 6 dimensions
- Configurable language server command and arguments
- Restart Language Server command
- Show Extension Status command
- Output channel for server diagnostics
- Schema file and database URL configuration

### Requirements
- Python 3.11+
- SlowQL with LSP extras: pip install slowql[lsp]
