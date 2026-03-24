# Read-Modify-Write Without Lock (REL-RACE-001)

**Dimension**: Reliability
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Read-modify-write without locks causes lost updates. Two concurrent transactions read the same value, both modify, both write — one update is lost. Classic race condition.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
