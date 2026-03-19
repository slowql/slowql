# BROADCAST Hint on Large Table (PERF-SPARK-001)

**Dimension**: Performance
**Severity**: High
**Scope**: Dialect Specific (Spark)

## Description
Broadcasting a table larger than spark.sql.autoBroadcastJoinThreshold (default 10MB) causes OOM. The entire table is serialized and sent to every executor.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Remove BROADCAST hint and let Spark auto-decide. If needed, verify table size is under autoBroadcastJoinThreshold. Use EXPLAIN to confirm join strategy.
