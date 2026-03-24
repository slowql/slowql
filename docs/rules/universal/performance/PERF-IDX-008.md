# COALESCE/ISNULL/NVL on Indexed Column (PERF-IDX-008)

**Dimension**: Performance
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
Wrapping a column in COALESCE/ISNULL forces evaluation of every row. WHERE ISNULL(status, 'x') = 'active' cannot use an index on status.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
