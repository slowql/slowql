# INSERT OVERWRITE Without Partition (REL-PRESTO-001)

**Dimension**: Reliability
**Severity**: Critical
**Scope**: Dialect Specific (Presto)

## Description
All existing data in the table is replaced. Without partition specification, a query meant to update one day's data destroys the entire table.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
