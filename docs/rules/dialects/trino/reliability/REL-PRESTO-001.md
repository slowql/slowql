# INSERT OVERWRITE Without Partition (REL-PRESTO-001)

**Dimension**: Reliability
**Severity**: Critical
**Scope**: Dialect Specific (Trino)

## Description
All existing data in the table is replaced. Without partition specification, a query meant to update one day's data destroys the entire table.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Always specify partition: INSERT OVERWRITE table PARTITION (dt='2024-01-01'). Or use INSERT INTO for append-only semantics.
