# ORDER BY Without LIMIT on Distributed Engine (PERF-PRESTO-002)

**Dimension**: Performance
**Severity**: Medium
**Scope**: Dialect Specific (Trino)

## Description
All rows are sent to the coordinator node for sorting. This can exhaust coordinator memory and crash the query.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Add LIMIT to bound the result. For analytics use window functions with PARTITION BY to sort within partitions.
