# Empty Transaction Block (REL-TXN-003)

**Dimension**: Reliability
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
Empty transactions acquire locks, write to WAL/transaction log, and consume connection slots for no purpose. In high-concurrency systems this adds unnecessary contention.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Remove the empty BEGIN...COMMIT block, or add the intended DML statements between them.
