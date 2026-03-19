# Cascade Delete Risk (REL-FK-002)

**Dimension**: Reliability
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
DELETE on parent table with ON DELETE CASCADE can wipe millions of child records in one statement. Often unintended and irreversible without backups.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Check child records before DELETE: SELECT COUNT(*) FROM child_table WHERE parent_id = ?. Use soft delete (is_deleted flag). Disable CASCADE for critical tables. Require explicit confirmation.
