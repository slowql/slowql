# Lock Escalation Risk (REL-DEAD-002)

**Dimension**: Reliability
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
SQL Server escalates row locks to table locks after ~5000 locks. Wide UPDATE/DELETE statements lock the entire table, blocking all other operations.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Add selective WHERE with indexed columns. Use TOP/LIMIT for batching. Consider ROWLOCK hint if table lock is not acceptable. Process in smaller batches.
