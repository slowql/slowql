# SELECT * Wastes Snowflake Credits (COST-SF-001)

**Dimension**: Cost
**Severity**: Medium
**Scope**: Dialect Specific (Snowflake)

## Description
Snowflake stores data in columnar micro-partitions. SELECT * prevents column pruning and forces scanning all partitions. On large tables this multiplies credit consumption and increases query time, directly increasing warehouse cost.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Select only needed columns. Use clustering keys on large tables. Consider materialized views for frequently queried column subsets.
