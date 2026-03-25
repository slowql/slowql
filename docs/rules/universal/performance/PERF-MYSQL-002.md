# ORDER BY RAND() Full Table Sort (PERF-MYSQL-002)

**Dimension**: Performance
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
On 1M rows, ORDER BY RAND() LIMIT 1 still reads and sorts all 1M rows.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
