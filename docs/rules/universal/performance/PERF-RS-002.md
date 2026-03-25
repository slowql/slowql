# ORDER BY Without LIMIT on Redshift (PERF-RS-002)

**Dimension**: Performance
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
All rows must be sent to the leader node for global sorting. On large tables this can OOM the leader or take very long.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
