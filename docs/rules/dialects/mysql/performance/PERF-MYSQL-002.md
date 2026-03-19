# ORDER BY RAND() Full Table Sort (PERF-MYSQL-002)

**Dimension**: Performance
**Severity**: High
**Scope**: Dialect Specific (Mysql)

## Description
On 1M rows, ORDER BY RAND() LIMIT 1 still reads and sorts all 1M rows.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use random offset subquery or maintain a sampling column.
