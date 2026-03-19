# Missing Savepoint in Long Transaction (REL-REC-001)

**Dimension**: Reliability
**Severity**: Info
**Scope**: Universal (All Dialects)

## Description
A failure in step 10 of a 10-step transaction forces rollback of all previous steps. Savepoints allow partial recovery and reduce re-work cost.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use SAVEPOINT after logically complete sub-operations within long transactions. Use ROLLBACK TO SAVEPOINT to recover from partial failures without rolling back the entire transaction.
