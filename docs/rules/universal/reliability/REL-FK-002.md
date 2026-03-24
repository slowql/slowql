# Cascade Delete Risk (REL-FK-002)

**Dimension**: Reliability
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
DELETE on parent table with ON DELETE CASCADE can wipe millions of child records in one statement. Often unintended and irreversible without backups.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
