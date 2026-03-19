# SELECT FOR UPDATE Without NOWAIT/SKIP LOCKED (PG) (PERF-PG-004)

**Dimension**: Performance
**Severity**: Low
**Scope**: Dialect Specific (Postgresql)

## Description
Without NOWAIT, the query blocks until the lock is released.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Add NOWAIT to fail immediately or SKIP LOCKED to skip locked rows.
