# CACHE TABLE Without Filter (COST-SPARK-002)

**Dimension**: Cost
**Severity**: Medium
**Scope**: Dialect Specific (Spark)

## Description
Caching a 100GB table consumes 100GB of executor memory across the cluster. This evicts other cached data and may cause OOM.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Cache only needed partitions: CACHE TABLE t OPTIONS ('partitionFilter' = "dt = '2024-01-01'"). Or use CACHE LAZY TABLE to defer until first access.
