# BROADCAST Hint on Large Table (PERF-SPARK-001)

**Dimension**: Performance
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Broadcasting a table larger than spark.sql.autoBroadcastJoinThreshold (default 10MB) causes OOM. The entire table is serialized and sent to every executor.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
