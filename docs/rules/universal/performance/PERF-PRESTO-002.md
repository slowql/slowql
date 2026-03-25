# ORDER BY Without LIMIT on Distributed Engine (PERF-PRESTO-002)

**Dimension**: Performance
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
All rows are sent to the coordinator node for sorting. This can exhaust coordinator memory and crash the query.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
