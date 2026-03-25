# SELECT * Wastes Snowflake Credits (COST-SF-001)

**Dimension**: Cost
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
Snowflake stores data in columnar micro-partitions. SELECT * prevents column pruning and forces scanning all partitions. On large tables this multiplies credit consumption and increases query time, directly increasing warehouse cost.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
