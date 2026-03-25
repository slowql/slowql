# LIKE Without COLLATE NOCASE (PERF-SQLITE-002)

**Dimension**: Performance
**Severity**: Low
**Scope**: Universal (All Dialects)

## Description
Without COLLATE NOCASE on the column, LIKE queries cannot use indexes and fall back to full table scan.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
