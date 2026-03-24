# Large IN List — Use VALUES Table (PERF-DUCK-002)

**Dimension**: Performance
**Severity**: Low
**Scope**: Dialect Specific (Duckdb)

## Description
Large IN lists are evaluated as repeated OR conditions. A VALUES table with a semi-join is more efficient for DuckDB's vectorized engine.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
