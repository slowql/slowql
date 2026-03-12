# Changelog

All notable changes to this project will be documented here.

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


## 1.5.0

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