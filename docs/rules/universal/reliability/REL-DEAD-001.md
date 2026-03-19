# Deadlock Pattern (REL-DEAD-001)

**Dimension**: Reliability
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Deadlocks occur when Transaction A locks Table1 then waits for Table2, while Transaction B locks Table2 then waits for Table1. Both freeze, one must abort.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Always lock tables in consistent alphabetical order across all transactions. Use SELECT ... FOR UPDATE in consistent order. Consider using NOWAIT and retry logic.
