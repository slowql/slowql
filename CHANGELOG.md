# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Changed
- **Reversed Interactive Default**: `slowql queries.sql` now runs instant analysis with no animation and no dialect selector by default. Use `--interactive` to opt-in to the full animated experience.
- **Dialect Auto-Detection**: Dialect is now resolved from config or CLI `--dialect` flag. The interactive dialect selector only appears with `--interactive`.
- **`--non-interactive` Deprecated**: The flag still works for backward compatibility but is now the default behavior.

---

## [1.6.5] - 2026-04-03

### Added
- **MyBatis Parser Enhancements**: Significantly improved the robustness of the MyBatis XML parser and expanded test coverage for complex nested queries.

### Fixed
- **Internal Quality**: Resolved a suite of linting and style errors across the codebase to maintain strict CI/CD compliance.

---

## [1.6.4] - 2026-03-31

### Added
- **MyBatis Support**: Introduced initial support for analyzing SQL within MyBatis XML mapper files.

### Fixed
- **VS Code Extension Security**: Updated extension dependencies to resolve high-severity security advisories.

---

## [1.6.3] - 2026-03-28

### Added
- **New Rule**: Implemented `UnreachableCodeRule` as a parent-independent check.
- **T-SQL Support**: Added raw-text fallback for analyzing T-SQL procedure bodies.

### Fixed
- **Dialect Aliasing**: CLI now correctly resolves common dialect aliases (e.g., `postgres` -> `postgresql`, `pg` -> `postgresql`, `mssql` -> `tsql`).
- **Clean Output**: Removed internal debug print statements from the analysis pipeline.

### Changed
- **Documentation**: Verified and synchronized rule counts in README to match the actual 272-rule registry.

---

## [1.6.2] - 2026-03-25

### Added
- **Query Complexity Scoring**: Implemented query complexity scoring and trend tracking framework for performance auditing.

### Fixed
- **Import Sorting**: Resolved import sorting issues in `catalog.py`.
- **Sync**: Synchronized documentation and rule counts across all platforms.
- **Metadata**: Updated version metadata in configuration and environment files.

---

## [1.6.1] - 2026-03-19

### Added
- **Severity Migration Framework**: Comprehensive support for tracking rule severity across database migration tools (Alembic, Django, Flyway, Liquibase, Prisma, Knex).
- **Custom Rule Engine**: Implemented support for user-defined YAML and Python plugins.
- **Parallel Processing**: Added parallel batch processing for file analysis, significantly reducing runtime on large repositories.
- **Git-Aware Analysis**: Added `--git-diff` and `--since` flags for analyzing only changed files.
- **Incremental Analysis**: Implemented Baseline/Diff mode for tracking new violations over time.
- **Inline Suppression**: Added the `--slowql-ignore` system for targeted rule suppression within SQL files.
- **Dbt and Jinja Support**: Added support for analyzing Dbt projects and Jinja-templated SQL files.
- **Hash-based Caching**: Implemented file caching to skip analysis for unchanged documents.
- **Safe Autofix Expansion**: Added 2 additional safe autofixes for `CASE ELSE NULL` and `DO LANGUAGE plpgsql`.
- **Massive Documentation Overhaul**: Completely rewritten MkDocs hierarchy with enterprise-standard clarity.

### Changed
- **Development Contribution Guards**: Restructured contribution documentation and enforced sequential CI checks.
- **Build Workflows**: Switched to `hatchling` compilation matching `pyproject.toml`.

### Removed
- **Legacy Components**: Removed deprecated structural documents and obsolete parsers.

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

## [1.4.0] - 2026-03-09

### Added
- **Major Rule Expansion**: Reached 171 rules spanning Security, Performance, Cost, Reliability, and quality dimensions.
- **Batch 3 (Reliability)**: 6 new rules covering data integrity and transaction handling.
- **Batch 4 (Compliance)**: 6 new rules covering GDPR and auditing requirements.
- **Batch 5 (Quality)**: 9 new rules covering style, modern SQL practices, and DRY principles.

### Changed
- **Architecture**: Modularized `catalog.py` into a dimension-based structure for better maintainability.

### Fixed
- Improved `.gitignore` and configuration handling for optional dependencies.

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