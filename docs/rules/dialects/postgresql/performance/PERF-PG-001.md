# ILIKE Disables Index (PERF-PG-001)

**Dimension**: Performance
**Severity**: Medium
**Scope**: Dialect Specific (Postgresql)

## Description
ILIKE performs case-insensitive matching but cannot use standard B-tree indexes. This causes full table scans on large tables. A query on a million-row table with ILIKE can be 1000x slower than with a proper index.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Create a citext column type or a functional index: CREATE INDEX idx ON table (lower(column)). Then use: WHERE lower(column) LIKE lower('value%'). Or use pg_trgm extension with GIN index for arbitrary substring matching.
