# MERGE Without HOLDLOCK (REL-TSQL-002)

**Dimension**: Reliability
**Severity**: High
**Scope**: Dialect Specific (Tsql)

## Description
Concurrent MERGE statements can both evaluate NOT MATCHED and attempt INSERT, causing duplicate key errors. Or both evaluate MATCHED and overwrite each other's updates.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Add WITH (HOLDLOCK) to the MERGE target: MERGE INTO target WITH (HOLDLOCK) USING ... Or wrap in SERIALIZABLE transaction.
