# SELECT * on Partitioned Hive Table (COST-PRESTO-001)

**Dimension**: Cost
**Severity**: High
**Scope**: Dialect Specific (Trino)

## Description
Hive tables can have thousands of partitions and hundreds of columns. SELECT * reads everything, multiplying I/O and cost.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Specify columns explicitly. Add WHERE on partition columns: WHERE dt = '2024-01-01'. Use SHOW PARTITIONS to understand layout.
