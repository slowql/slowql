# Lock Escalation Risk (REL-DEAD-002)

**Dimension**: Reliability
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
SQL Server escalates row locks to table locks after ~5000 locks. Wide UPDATE/DELETE statements lock the entire table, blocking all other operations.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
