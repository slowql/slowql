# Missing Transaction Rollback Handler (REL-TXN-001)

**Dimension**: Reliability
**Severity**: Info
**Scope**: Universal (All Dialects)

## Description
Without ROLLBACK, a failed transaction may partially commit changes, leaving data in an inconsistent state. This is especially dangerous for multi-step operations like financial transfers.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
