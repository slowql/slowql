# Deprecated SQL_CALC_FOUND_ROWS (QUAL-MYSQL-001)

**Dimension**: Quality
**Severity**: Low
**Scope**: Dialect Specific (Mysql)

## Description
SQL_CALC_FOUND_ROWS disables LIMIT optimisations and forces a full table scan to count all matching rows. It is deprecated and will be removed in a future MySQL version.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Replace with two separate queries: one with LIMIT for the page and one COUNT(*) query for the total. Use covering indexes to make the COUNT(*) query fast.
