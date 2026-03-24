# Deadlock Pattern (REL-DEAD-001)

**Dimension**: Reliability
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Deadlocks occur when Transaction A locks Table1 then waits for Table2, while Transaction B locks Table2 then waits for Table1. Both freeze, one must abort.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
