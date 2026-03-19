# Non-Deterministic Query (QUAL-TEST-001)

**Dimension**: Quality
**Severity**: Low
**Scope**: Universal (All Dialects)

## Description
Non-deterministic queries are hard to test and reproduce. They can cause flaky tests and unpredictable behavior in production if results depend on the exact millisecond of execution.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Pass time as a parameter from the application layer. Use fixed seeds for random functions. Ensure query results are predictable for the same input state.
