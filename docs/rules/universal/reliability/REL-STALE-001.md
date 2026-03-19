# Stale Read Risk (REL-STALE-001)

**Dimension**: Reliability
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
In replicated databases, writes go to primary, reads may hit replicas. SELECT immediately after UPDATE may return old data if replication lag exists.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Wrap write-then-read in transaction. Use read-from-primary hints for critical reads. Use RETURNING/OUTPUT clause to get written data atomically. Accept eventual consistency where appropriate.
