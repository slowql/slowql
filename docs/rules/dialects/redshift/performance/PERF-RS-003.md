# NOT IN on Redshift (Hash Join Explosion) (PERF-RS-003)

**Dimension**: Performance
**Severity**: Medium
**Scope**: Dialect Specific (Redshift)

## Description
NOT IN forces Redshift to build a hash table of the entire subquery result. With NULLs present, it degrades to a nested loop.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
