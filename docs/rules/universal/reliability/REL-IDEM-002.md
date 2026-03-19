# Non-Idempotent UPDATE Pattern (REL-IDEM-002)

**Dimension**: Reliability
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
Relative updates like SET count = count + 1 execute multiple times on retry, causing incorrect totals. Financial calculations become inaccurate, inventory goes negative.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use optimistic locking: UPDATE ... SET count = count + 1, version = version + 1 WHERE id = ? AND version = ?. Or use idempotency keys to track processed operations.
