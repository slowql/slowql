# CLI Reference

The SlowQL Command Line Interface (CLI) is the primary method for executing static analysis workflows. Engineered for both interactive human usage and headless CI/CD operations, the CLI exposes the full capabilities of the SlowQL engine.

---

## Execution Syntax

The CLI accepts configuration via explicit flags or positional arguments.

```bash
slowql [OPTIONS] [FILE] [EXTRA_FILES...]
slowql init [--dialect DIALECT] [--fail-on SEVERITY]
```

> [!TIP]
> If no file is provided, SlowQL will default to interactive mode unless `--non-interactive` is passed.

---

## Input & Target Selection

These arguments define the scope of the analysis.

| Flag | Description | Default |
|---|---|---|
| `[file]` | The primary SQL file or directory to parse (positional argument). | None |
| `[extra_files...]` | Additional SQL files. Typically used by systems like `pre-commit` which pass arrays of changed files. | None |
| `--input-file PATH` | Explicitly define the target file (alias for the positional `file` argument). | None |
| `--init`, `init` | Scaffolds a `slowql.yaml` configuration profile in the current directory. Launches an interactive wizard by default, or runs non-interactively if `--dialect` and `--fail-on` arguments are provided. | `False` |
| `--mode` | Editor mode selection: `{auto, paste, compose}`. `auto` detects a TTY terminal and switches to `compose` for multi-line SQL input. | `auto` |

---

## Analysis Configuration

Modify how the parsing engine and rule registry inspect the queries.

| Flag | Description | Default |
|---|---|---|
| `--dialect`, `-d` | Forces a specific SQL dialect parser. Valid options: `postgresql`, `mysql`, `tsql`, `oracle`, `snowflake`, `bigquery`, `redshift`, `clickhouse`, `duckdb`, `presto`, `trino`, `spark`, `databricks`. | *Auto-detected* |
| `--schema`, `-s` | Path to a DDL schema file (`.sql`). Enables schema-aware rules (e.g. validating missing columns or tables). | None |
| `--baseline` | Path to a `.slowql-baseline` file. When provided, SlowQL only reports new issues not found in the baseline. | `None` |
| `--update-baseline` | Analyzes target files and writes all found issues to the specified baseline file, exiting successfully. | `None` |
| `--fail-on` | Threshold for returning a non-zero exit code (Pipeline failure). Options: `{critical, high, medium, low, info, never}`. | `high` |
| `--no-cache` | Disables internal AST caching during the run. Useful for benchmarking or bypassing stale tokens. | `False` |
| `--compare` | Enables query comparison mode for performance profiling between two SQL statements. | `False` |

---

## Output & Formatting

Control how SlowQL serializes and reports identified vulnerabilities.

| Flag | Description | Default |
|---|---|---|
| `--format` | The standard output (STDOUT) reporter. Options: `console` (Rich UI), `github-actions` (native PR annotations), `sarif` (raw JSON). | `console` |
| `--export` | Auto-export formats saved to disk post-analysis. Options: `html`, `csv`, `json`, `sarif`. Multiple formats can be stacked (e.g. `--export json sarif`). | None |
| `--out` | Output directory destination for the generated export files. | `./` |
| `--verbose` | Output granular tracebacks, AST token arrays, and parser internals. | `False` |
| `--export-session`| Dumps the active session history explicitly, highly useful for diagnosing headless CI environments. | `False` |

---

## Safe Autofix System

SlowQL can actively modify your raw SQL files by applying `RemediationMode.SAFE_APPLY` logic.

> [!WARNING]
> Due to the inherent risks of automated code modification, the `--fix` parameter currently only executes on a **single file** at a time. It will safely generate a `.bak` backup copy of the original payload prior to modification.

| Flag | Description |
|---|---|
| `--diff` | Previews the exact textual changes and Git-style diffs for safe fixes in your terminal without touching the disk. |
| `--fix` | Overwrites the target file with safe fixes, generating a `<filename>.bak` backup securely in the same directory. |
| `--fix-report PATH` | Generates a structured JSON receipt detailing exactly which bytes were mutated during the fix execution. |

---

## Rule Introspection

Inspect the internal metadata of the 272 built-in rules without executing analysis.

| Flag | Description |
|---|---|
| `--list-rules` | Outputs a tabular grid of every active rule loaded into the registry. |
| `--explain RULE_ID` | Renders the complete documentation, rationale, and remediation guidance for a specific Issue ID (e.g. `slowql --explain PERF-SCAN-001`). |
| `--filter-dimension`| Filters `--list-rules` tabular output to a specific dimension natively (e.g. `cost`, `security`). |
| `--filter-dialect` | Filters `--list-rules` by a specific datastore capability (e.g. `mysql`). |

---

## Inline Suppression

Rules can be silenced on a per-line, per-block, or per-file basis using directives written directly in SQL comments. This does not require any configuration file changes.

| Directive | Scope |
|---|---|
| `-- slowql-disable-line RULE-ID` | The line the comment appears on |
| `-- slowql-disable-next-line RULE-ID` | The next non-blank, non-comment line |
| `-- slowql-disable RULE-ID` | All lines until a matching `-- slowql-enable` |
| `-- slowql-enable RULE-ID` | Closes an open block suppression |
| `-- slowql-disable-file RULE-ID` | The entire file |

The rule ID may be an exact identifier (`PERF-SCAN-001`), a prefix (`PERF-SCAN`), comma-separated values (`PERF-SCAN-001, SEC-INJ-001`), or omitted entirely to suppress all rules for the given scope. Matching is case-insensitive.

```sql
SELECT * FROM archive;  -- slowql-disable-line PERF-SCAN-001

-- slowql-disable-next-line SEC-INJ-001
SELECT id, token FROM sessions WHERE id = $1;

-- slowql-disable PERF-SCAN-001
SELECT * FROM event_stream;
SELECT * FROM session_log;
-- slowql-enable PERF-SCAN-001
```

See [Inline Suppression](suppression.md) for the full reference.

---


Modify the aesthetic triggers, critical for continuous integration.

| Flag | Description |
|---|---|
| `--non-interactive` | Prevents SlowQL from blocking the runner by pausing for missing user inputs or dialect confirmations. (Now the default whenever input files are given) |
| `--select-dialect` | Forces the CLI to prompt for interactive dialect selection. |
| `--no-intro` | Skips the startup Cyberpunk banner sequence. |
| `--fast` | Deactivates CLI animations and typing layout effects for rapid execution. |
| `--duration SECS` | Overrides the intro animation timing. |

---

## Enterprise Examples

**Headless CI/CD Pipeline Execution:**
```bash
slowql src/**/*.sql \
  --non-interactive \
  --fail-on high \
  --format github-actions \
  --export sarif \
  --out build/security-reports/
```

**Discovering Snowflake Cost Inefficiencies:**
```bash
slowql --list-rules --filter-dialect snowflake --filter-dimension cost
slowql --explain COST-SF-001
```

**Safely applying automated fixes with a JSON receipt:**
```bash
slowql database/migrations/v2.sql --fix --fix-report fix_receipt.json
```
