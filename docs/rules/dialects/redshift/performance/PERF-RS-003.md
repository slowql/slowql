# NOT IN on Redshift (Hash Join Explosion) (PERF-RS-003)

**Dimension**: Performance
**Severity**: Medium
**Scope**: Dialect Specific (Redshift)

## Description
NOT IN forces Redshift to build a hash table of the entire subquery result. With NULLs present, it degrades to a nested loop.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Replace NOT IN (SELECT ...) with NOT EXISTS (SELECT 1 FROM ... WHERE ...) or LEFT JOIN ... WHERE key IS NULL.
