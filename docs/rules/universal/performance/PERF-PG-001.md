# ILIKE Disables Index (PERF-PG-001)

**Dimension**: Performance
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
ILIKE performs case-insensitive matching but cannot use standard B-tree indexes. This causes full table scans on large tables. A query on a million-row table with ILIKE can be 1000x slower than with a proper index.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
