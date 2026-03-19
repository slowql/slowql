# GROUP BY Implicit Sort (Removed in MySQL 8.0) (PERF-MYSQL-004)

**Dimension**: Performance
**Severity**: Low
**Scope**: Dialect Specific (Mysql)

## Description
Results appear sorted on MySQL 5.x but are unordered on 8.0+. This causes subtle bugs during MySQL version upgrades.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Add explicit ORDER BY if sorted output is needed. If order doesn't matter, add ORDER BY NULL to explicitly disable sorting.
