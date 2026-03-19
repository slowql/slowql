# REGEXP on Large Table Without Filter (PERF-BQ-002)

**Dimension**: Performance
**Severity**: Low
**Scope**: Dialect Specific (Bigquery)

## Description
REGEXP on every row consumes slot time and increases cost.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Pre-filter with LIKE or STARTS_WITH. Use partitioned/clustered tables.
