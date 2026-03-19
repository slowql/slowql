# Parallel Query Hint (PERF-HINT-003)

**Dimension**: Performance
**Severity**: Info
**Scope**: Dialect Specific (Tsql)

## Description
MAXDOP hints override server-level parallelism. MAXDOP 1 forces single-threaded execution. High MAXDOP values can starve other queries of CPU.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use server or database-level MAXDOP settings. Per-query hints are rarely justified.
