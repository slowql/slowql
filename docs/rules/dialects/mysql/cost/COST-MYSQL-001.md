# Query Cache Pollution (COST-MYSQL-001)

**Dimension**: Cost
**Severity**: Low
**Scope**: Dialect Specific (Mysql)

## Description
Large result sets evict smaller, frequently-used entries from the query cache, degrading performance for other queries.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Add SQL_NO_CACHE: SELECT SQL_NO_CACHE ... for analytical or one-off queries. Note: query cache is removed in MySQL 8.0+.
