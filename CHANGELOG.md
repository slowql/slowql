# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.6.2] - 2026-03-25

### Fixed
- Synchronized documentation and rule counts across all platforms.
- Updated version metadata in configuration and environment files.

## [1.6.1] - 2026-03-19

### Added
- **Massive Documentation Overhaul (`docs/`)**: Comprehensively rewrote the entire MkDocs hierarchy to strict enterprise standards, permanently eliminating emojis, legacy jargon, and non-deterministic formatting.
- **Architecture Navigation**: Exposed internal orchestration mechanics detailing `system-design`, `parser-engine`, `rule-system`, `export-system`, and `lsp-integration`.
- **Comprehensive Usage Tier**: Expanded CI/CD integration pipelines (GitHub Actions, SARIF payloads) and explicitly documented VS Code Extension installations leveraging internal `pygls` routing.
- **Python API Framework**: Systematized programmatic integrations demonstrating offline `Query` construction natively hooking into `BaseReporter` JSON artifacts.

### Changed
- **Development Contribution Guards**: Restructured local `adding-rules.md` documentation mapping exact `dialects = ("tsql", "snowflake")` arrays and enforcing `ruff`/`mypy` checks sequentially.
- **Version Control Hooks**: Deprecated raw `python -m build` references internally in exchange for defining accurate `hatchling` compilation workflows matching `pyproject.toml`.

### Removed
- **Legacy Purge**: Eradicated deprecated structural documents (e.g., `adding-detectors.md`) generating parsing conflicts during compilation.

---

## [1.6.0] - 2026-03-18

### Added
- **Massive Rule Expansion**: Now ships with **272 rules** (up from 171) completely covering **14 SQL dialects** (PostgreSQL, MySQL, T-SQL, Oracle, Snowflake, BigQuery, Redshift, ClickHouse, DuckDB, Presto, Trino, Spark, Databricks, SQLite).
- **Rule Introspection**: Added `slowql --list-rules` and `slowql --explain RULE-ID` commands.
- **Interactive Setup**: Added `slowql --init` wizard to automatically generate `slowql.yaml` and detect dialects/schemas.
- **Safe Autofix**: Added `--fix` and `--diff` flags with 9 initial zero-risk text replacements (`FixConfidence.SAFE`).
- **Dialect Filtering**: Dialect-specific rules now safely skip when analyzing generic/unknown SQL, eliminating false positives.

### Changed
- **Next-Gen TUI**: Completely revamped the console reporter. Removed emojis, fixed table alignments, and modernized the layout for a clean, professional look.
- **CI/CD Polish**: Suppressed welcome banners and verbose logs in `--non-interactive` mode.
- **VS Code Extension (v0.2.0)**: Added dialect selection settings, status bar integration, and better server state handling.

### Fixed
- Replaced brittle hardcoded test counts with threshold assertions to streamline future rule contributions.
- Fixed an issue where `sqlglot` dialect normalization was case-sensitive.
- Fixed CLI integration for Language Server Protocol (LSP), allowing the server to be correctly launched via `slowql-lsp` standalone binary.
- Fixed test suite failures by adding proper skip decorators for environments without `[lsp]` dependencies.

---

## [1.5.0] - 2026-03-13

### Added
- Conservative autofix foundation.
- `--diff` preview mode in the CLI.
- `--fix` safe apply mode with backup support.
- `--fail-on` severity threshold support.
- `github-actions` output format annotation support.
- `--fix-report` JSON output.
- Source-anchored parser support.
- Remediation mode classification.
- Safe autofixes for `QUAL-NULL-001` and `QUAL-STYLE-002`.

### Changed
- Non-interactive session export now requires explicit `--export-session`.
- Multi-file CLI input improved for automation/pre-commit style use.

---

## [1.3.0] - 2025-12-19

### Added
- Enhanced SQL analyzer with improved security and performance detection.
- New compliance checks for GDPR, HIPAA, and PCI-DSS standards.
- Advanced cost optimization recommendations.
- Extended support for MySQL and PostgreSQL dialects.
- Interactive mode with rich terminal UI (Cyberpunk aesthetic).
- Custom detector framework for extensible analysis.

### Changed
- Improved error handling and user feedback.
- Enhanced CLI output with better formatting based on `rich`.
- Optimized parsing engine for better performance leveraging `sqlglot`.

### Fixed
- Various minor bug fixes and stability improvements.
- Corrected detection patterns for multiple AST edge cases.

---

## [1.0.3] - 2025-12-03

### Added
- Initial release of SlowQL.
- Critical and High severity detectors for core structural SQL flaws.
- CI/CD examples (GitHub, GitLab, Jenkins, Pre-Commit).

### Fixed
- MkDocs strict build errors on initial publication.