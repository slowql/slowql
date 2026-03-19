# SELECT FOR UPDATE Without NOWAIT (Oracle) (PERF-ORA-001)

**Dimension**: Performance
**Severity**: Medium
**Scope**: Dialect Specific (Oracle)

## Description
Without NOWAIT, the session hangs waiting for row locks.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Add NOWAIT to raise ORA-00054 or SKIP LOCKED (Oracle 11g+).
