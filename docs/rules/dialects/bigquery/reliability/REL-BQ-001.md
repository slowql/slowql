# DML Without WHERE on BigQuery (REL-BQ-001)

**Dimension**: Reliability
**Severity**: High
**Scope**: Dialect Specific (Bigquery)

## Description
DML on all partitions is expensive. BigQuery does not support ROLLBACK.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Always include WHERE with partition filter: WHERE _PARTITIONDATE = '2024-01-01'.
