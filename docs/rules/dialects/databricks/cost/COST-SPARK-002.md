# CACHE TABLE Without Filter (COST-SPARK-002)

**Dimension**: Cost
**Severity**: Medium
**Scope**: Dialect Specific (Databricks)

## Description
Caching a 100GB table consumes 100GB of executor memory across the cluster. This evicts other cached data and may cause OOM.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
