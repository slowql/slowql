# UDF in WHERE Prevents Pushdown (PERF-SPARK-002)

**Dimension**: Performance
**Severity**: Medium
**Scope**: Dialect Specific (Databricks)

## Description
Without pushdown, Spark reads the entire table/partition from storage. For Parquet/Delta files this bypasses column pruning and row group filtering.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Replace UDFs with built-in Spark SQL functions which support pushdown. If UDF is necessary, pre-filter with pushable predicates first.
