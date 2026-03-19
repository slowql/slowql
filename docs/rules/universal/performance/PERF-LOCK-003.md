# Long Transaction Pattern (PERF-LOCK-003)

**Dimension**: Performance
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Long transactions hold locks for their entire duration, blocking other queries. A 10-second transaction holding a lock can queue up hundreds of waiting requests.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Keep transactions as short as possible. Do all preparation BEFORE BEGIN TRAN. Use optimistic concurrency.
