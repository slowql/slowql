# ORDER BY Without LIMIT on Redshift (PERF-RS-002)

**Dimension**: Performance
**Severity**: Medium
**Scope**: Dialect Specific (Redshift)

## Description
All rows must be sent to the leader node for global sorting. On large tables this can OOM the leader or take very long.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Add LIMIT to bound the result. For analytics, use window functions with PARTITION BY to sort within partitions.
