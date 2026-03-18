# Changelog

## [1.6.0] - 2026-03-18

### Added
- **Massive Rule Expansion**: Now ships with **272 rules** (up from 171) completely covering **14 SQL dialects** (PostgreSQL, MySQL, T-SQL, Oracle, Snowflake, BigQuery, Redshift, ClickHouse, DuckDB, Presto, Trino, Spark, Databricks, SQLite).
- **Rule Introspection**: Added `slowql --list-rules` and `slowql --explain RULE-ID` commands.
- **Interactive Setup**: Added `slowql --init` wizard to automatically generate `slowql.yaml` and detect dialects/schemas.
- **Safe Autofix**: Added `--fix` and `--diff` flags with 9 initial zero-risk text replacements (FixConfidence.SAFE).
- **Dialect Filtering**: Dialect-specific rules now safely skip when analyzing generic/unknown SQL, eliminating false positives.

### Changed
- **Next-Gen TUI**: Completely revamped the console reporter. Removed emojis, fixed table alignments, and modernized the layout for a clean, professional look.
- **CI/CD Polish**: Suppressed welcome banners and verbose logs in `--non-interactive` mode.
- **VS Code Extension (v0.2.0)**: Added dialect selection settings, status bar integration, and better server state handling.

### Fixed
- Replaced brittle hardcoded test counts with threshold assertions to streamline future rule contributions.
- Fixed an issue where `sqlglot` dialect normalization was case-sensitive.


All notable changes to this project will be documented here.

---

## [1.5.0] - 2026-03-13

### Added
- Conservative autofix foundation
- `--diff` preview mode
- `--fix` safe apply mode with backup support
- `--fail-on` severity threshold support
- `github-actions` output format
- `--fix-report` JSON output
- Source-anchored parser support
- Remediation mode classification
- Safe autofixes for:
  - `QUAL-NULL-001`
  - `QUAL-STYLE-002`

### Changed
- Non-interactive session export now requires explicit `--export-session`
- Multi-file CLI input improved for automation/pre-commit style use

---

## [1.3.0] - 2025-12-19

### Added
- Enhanced SQL analyzer with improved security and performance detection
- New compliance checks for GDPR, HIPAA, and PCI-DSS standards
- Advanced cost optimization recommendations
- Extended support for MySQL and PostgreSQL dialects
- Interactive mode with rich terminal UI
- Custom detector framework for extensible analysis

### Changed
- Improved error handling and user feedback
- Enhanced CLI output with better formatting
- Optimized parsing engine for better performance
- Updated documentation and examples

### Fixed
- Various minor bug fixes and stability improvements
- Corrected detection patterns for edge cases

---

## [1.0.3] - 2025-12-03

### Added
- Initial release of SlowQL
- Critical and High severity detectors
- CI/CD examples (GitHub, GitLab, Jenkins, Pre-Commit)

### Fixed
- MkDocs strict build errors