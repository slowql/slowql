# UDF in WHERE Prevents Pushdown (PERF-SPARK-002)

**Dimension**: Performance
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
Without pushdown, Spark reads the entire table/partition from storage. For Parquet/Delta files this bypasses column pruning and row group filtering.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
