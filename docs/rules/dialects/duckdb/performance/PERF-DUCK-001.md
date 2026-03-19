# COPY Without FORMAT Specification (PERF-DUCK-001)

**Dimension**: Performance
**Severity**: Medium
**Scope**: Dialect Specific (Duckdb)

## Description
Without FORMAT, DuckDB guesses from the file extension. For URLs, pipes, or extensionless files this can silently fail.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Add FORMAT explicitly: COPY t FROM 'file.csv' (FORMAT CSV). Supported: CSV, PARQUET, JSON.
