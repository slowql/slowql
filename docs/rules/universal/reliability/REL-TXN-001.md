# Missing Transaction Rollback Handler (REL-TXN-001)

**Dimension**: Reliability
**Severity**: Info
**Scope**: Universal (All Dialects)

## Description
Without ROLLBACK, a failed transaction may partially commit changes, leaving data in an inconsistent state. This is especially dangerous for multi-step operations like financial transfers.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Always pair BEGIN/COMMIT with a ROLLBACK in error handling. Use savepoints for partial rollbacks in complex transactions. In application code, use try/catch/finally patterns to ensure ROLLBACK on exception.
