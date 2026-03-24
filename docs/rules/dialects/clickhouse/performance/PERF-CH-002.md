# JOIN Without GLOBAL on Distributed Table (PERF-CH-002)

**Dimension**: Performance
**Severity**: Medium
**Scope**: Dialect Specific (Clickhouse)

## Description
Without GLOBAL, each shard executes the right-side subquery independently. For N shards this means N redundant executions.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
