# Empty Transaction Block (REL-TXN-003)

**Dimension**: Reliability
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
Empty transactions acquire locks, write to WAL/transaction log, and consume connection slots for no purpose. In high-concurrency systems this adds unnecessary contention.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
