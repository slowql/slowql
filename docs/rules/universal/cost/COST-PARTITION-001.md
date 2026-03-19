# Large Table Without Partitioning (COST-PARTITION-001)

**Dimension**: Cost
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
Scanning unpartitioned 1B row table costs 100x more than scanning one partition. Partitioning by date reduces cost by 90-99% for time-range queries.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Partition large tables by date. Most queries filter by date - partition pruning eliminates 99% of data.
