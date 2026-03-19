# PRAGMA AUTONOMOUS_TRANSACTION (REL-ORA-003)

**Dimension**: Reliability
**Severity**: High
**Scope**: Dialect Specific (Oracle)

## Description
Data committed in an autonomous transaction survives parent rollback. This breaks the assumption that ROLLBACK undoes all changes, leading to data inconsistency.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Only use AUTONOMOUS_TRANSACTION for audit logging where you intentionally want commits to persist. Never use for business data modifications.
