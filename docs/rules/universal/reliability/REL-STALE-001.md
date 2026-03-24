# Stale Read Risk (REL-STALE-001)

**Dimension**: Reliability
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
In replicated databases, writes go to primary, reads may hit replicas. SELECT immediately after UPDATE may return old data if replication lag exists.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
