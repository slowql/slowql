# SELECT * on Partitioned Hive Table (COST-PRESTO-001)

**Dimension**: Cost
**Severity**: High
**Scope**: Dialect Specific (Presto)

## Description
Hive tables can have thousands of partitions and hundreds of columns. SELECT * reads everything, multiplying I/O and cost.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
