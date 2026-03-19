# INSERT OVERWRITE Without Partition (REL-SPARK-001)

**Dimension**: Reliability
**Severity**: Critical
**Scope**: Dialect Specific (Databricks)

## Description
All existing data in the table is replaced. A query intended to update one partition destroys the entire table unless partitionOverwriteMode=dynamic is set.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Specify partition: INSERT OVERWRITE TABLE t PARTITION (dt='2024-01-01'). Or enable dynamic mode: SET spark.sql.sources.partitionOverwriteMode=dynamic.
