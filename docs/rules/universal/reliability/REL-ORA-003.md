# PRAGMA AUTONOMOUS_TRANSACTION (REL-ORA-003)

**Dimension**: Reliability
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Data committed in an autonomous transaction survives parent rollback. This breaks the assumption that ROLLBACK undoes all changes, leading to data inconsistency.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
