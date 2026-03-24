# Large Table Without Partitioning (COST-PARTITION-001)

**Dimension**: Cost
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
Scanning unpartitioned 1B row table costs 100x more than scanning one partition. Partitioning by date reduces cost by 90-99% for time-range queries.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
