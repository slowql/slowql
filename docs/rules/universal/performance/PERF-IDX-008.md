# COALESCE/ISNULL/NVL on Indexed Column (PERF-IDX-008)

**Dimension**: Performance
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
Wrapping a column in COALESCE/ISNULL forces evaluation of every row. WHERE ISNULL(status, 'x') = 'active' cannot use an index on status.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Handle NULL explicitly: WHERE (status = 'active' OR (status IS NULL AND 'x' = 'active')). Or use a filtered index, computed column, or ensure column is NOT NULL.
