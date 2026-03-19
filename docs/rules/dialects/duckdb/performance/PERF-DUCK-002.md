# Large IN List — Use VALUES Table (PERF-DUCK-002)

**Dimension**: Performance
**Severity**: Low
**Scope**: Dialect Specific (Duckdb)

## Description
Large IN lists are evaluated as repeated OR conditions. A VALUES table with a semi-join is more efficient for DuckDB's vectorized engine.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Replace IN (1,2,...,100) with: JOIN (VALUES (1),(2),...,(100)) AS v(id) USING (id).
