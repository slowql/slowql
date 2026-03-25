# INSERT OVERWRITE Without Partition (REL-SPARK-001)

**Dimension**: Reliability
**Severity**: Critical
**Scope**: Universal (All Dialects)

## Description
All existing data in the table is replaced. A query intended to update one partition destroys the entire table unless partitionOverwriteMode=dynamic is set.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
