# Missing Retry Logic (REL-RETRY-001)

**Dimension**: Reliability
**Severity**: Info
**Scope**: Universal (All Dialects)

## Description
Transactions fail on transient errors (deadlock, timeout, connection blip). Without retry logic, operations fail permanently when they could succeed on retry.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Implement retry loop with exponential backoff for deadlocks (error 1205) and timeouts. Use TRY...CATCH block. Limit retry attempts (3-5). Log failures for monitoring.
