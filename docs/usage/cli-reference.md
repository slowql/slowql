# CLI Reference

## Syntax

```bash
slowql [OPTIONS] [FILES]...
```

## Arguments

Argument  | Description
[FILES]...| SQL files or directories to analyze. Multiple paths accepted. 

## Analysis Options
**Flag**  | **Description** | **Default**
`-d, --dialect <DIALECT>` | SQL dialect. Auto-detected if not set. | auto
`-s, --schema <SCHEMA>` | Path to DDL schema file for schema-aware validation. | none
`--min-confidence <LEVEL>` | Minimum confidence level to report. Options: `proven`, `contextual`, `advisory`. | `proven`
`--include-nonprod` | Include findings from test, example, seed, and framework contexts. | off
`--fail-on <SEVERITY>` | Exit non-zero when issues at or above this severity are found. Options: `critical`, `high`, `medium`, `low`, `info`, `never`. | none
`--compare` | Enable query comparison mode (detect similar queries across files). | off

## Output Options

**Flag**  | **Description** | **Default**
`--format <FORMAT>` | Output format. Options: `console`, `json`, `sarif`, `github-actions`. | `console`
`--export <FORMAT>` | Export to file. Options: `json`, `html`, `csv`, `sarif`. Repeatable. | none
`--out <DIR>` | Output directory for exported files. | reports
`--verbose` | Enable verbose output including skipped files and context. | off

## Autofix Options

**Flag**  | **Description** | **Default**
`--diff` | Preview safe autofix changes without modifying files. | off
`--fix` | Apply safe autofixes. Creates `.bak` backup before modifying. | off
`--fix-report <PATH>` | Write JSON report of applied fixes. | none

## Baseline Options

**Flag**  | **Description** | **Default**
`--baseline <PATH>` | Path to baseline file. Only report new issues not in baseline. | none
`--update-baseline <PATH>` | Create or update baseline file with current issues. | none

## Rule Options

**Flag**  | **Description** | **Default**
`--list-rules` | List all available rules. | none
`--filter-dimension <DIM>` | Filter `--list-rules` by dimension. | none
`--filter-dialect <DIALECT>` | Filter `--list-rules` by dialect. | none
`--explain <RULE>` | Show documentation for a specific rule. | none

## Git Options

**Flag**  | **Description** | **Default**
`--git-diff` | Only analyze files changed in the current git working tree. | off
`--since <REV>` | Only analyze files changed since a git revision (e.g. `main`, `HEAD~5`). | none

## Cache Options

**Flag**  | **Description** | **Default**
`--no-cache` | Disable caching. | off
`--cache-dir <DIR>` | Directory to store cache files. | `.slowql_cache`
`--clear-cache` | Clear cache before analysis. | off

## Other Options

**Flag**  | **Description** | **Default**
`--init` | Create a slowql.yaml config file in the current directory. | off
`-j, --jobs <N>` | Number of parallel workers. 0 = auto-detect. | auto-detect
`-h, --help` | Print help. | none
`-V, --version` | Print version. | none

## Dialects

`postgresql`, `mysql`, `tsql`, `oracle`, `sqlite`, `snowflake`, `bigquery`, `redshift`, `clickhouse`, `duckdb`, `presto`, `trino`, `spark`, `databricks`

## Exit COdes

**Code**  | **Meaning** 
0 | No issues found or issues below threshold
1 | Issues found at medium or low severity
2 | Issues found at high severity
3 | Issues found at critical severity

## Examples

``` bash
# Scan a directory in proven mode
slowql src/

# Scan with schema validation
slowql src/ --schema db/schema.sql

# CI mode with annotations and SARIF export
slowql src/ --fail-on high --format github-actions --export sarif --out reports/

# Show contextual findings for code review
slowql src/ --min-confidence contextual

# Preview safe autofixes
slowql src/ --diff

# Apply safe autofixes
slowql src/ --fix

# Only analyze changed files
slowql . --git-diff

# Only analyze files changed since branching off main
slowql . --since main

# List security rules for PostgreSQL
slowql --list-rules --filter-dimension security --filter-dialect postgresql

# Explain a rule
slowql --explain SEC-INJ-001
```
