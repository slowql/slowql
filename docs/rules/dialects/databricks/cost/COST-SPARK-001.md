# Full Scan Without Partition Filter (COST-SPARK-001)

**Dimension**: Cost
**Severity**: Medium
**Scope**: Dialect Specific (Databricks)

## Description
A partitioned table with 365 daily partitions will read 365x more data without a partition filter. Databricks charges per DBU.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Always filter on partition columns: WHERE date = '2024-01-01'. Enable spark.sql.sources.partitionOverwriteMode=dynamic for safe overwrites.
