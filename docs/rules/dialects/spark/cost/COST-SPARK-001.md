# Full Scan Without Partition Filter (COST-SPARK-001)

**Dimension**: Cost
**Severity**: Medium
**Scope**: Dialect Specific (Spark)

## Description
A partitioned table with 365 daily partitions will read 365x more data without a partition filter. Databricks charges per DBU.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
