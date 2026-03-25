# MERGE Without HOLDLOCK (REL-TSQL-002)

**Dimension**: Reliability
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Concurrent MERGE statements can both evaluate NOT MATCHED and attempt INSERT, causing duplicate key errors. Or both evaluate MATCHED and overwrite each other's updates.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
