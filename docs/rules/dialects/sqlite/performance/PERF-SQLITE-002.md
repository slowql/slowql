# LIKE Without COLLATE NOCASE (PERF-SQLITE-002)

**Dimension**: Performance
**Severity**: Low
**Scope**: Dialect Specific (Sqlite)

## Description
Without COLLATE NOCASE on the column, LIKE queries cannot use indexes and fall back to full table scan.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Define columns with COLLATE NOCASE: CREATE TABLE t (name TEXT COLLATE NOCASE). Or create an index with COLLATE NOCASE.
