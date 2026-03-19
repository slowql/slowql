# Read-Modify-Write Without Lock (REL-RACE-001)

**Dimension**: Reliability
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Read-modify-write without locks causes lost updates. Two concurrent transactions read the same value, both modify, both write — one update is lost. Classic race condition.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use SELECT ... FOR UPDATE to lock rows during read-modify-write. Or use SERIALIZABLE isolation. Better: use atomic UPDATE with single statement.
