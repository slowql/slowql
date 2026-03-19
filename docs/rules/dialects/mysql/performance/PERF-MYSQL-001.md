# SELECT FOR UPDATE Without LIMIT (MySQL) (PERF-MYSQL-001)

**Dimension**: Performance
**Severity**: Medium
**Scope**: Dialect Specific (Mysql)

## Description
Locking too many rows blocks concurrent writes.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Add LIMIT to restrict locked rows. Use indexed WHERE clause.
