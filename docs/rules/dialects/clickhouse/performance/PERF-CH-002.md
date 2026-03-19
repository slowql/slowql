# JOIN Without GLOBAL on Distributed Table (PERF-CH-002)

**Dimension**: Performance
**Severity**: Medium
**Scope**: Dialect Specific (Clickhouse)

## Description
Without GLOBAL, each shard executes the right-side subquery independently. For N shards this means N redundant executions.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use GLOBAL JOIN or GLOBAL IN for distributed subqueries: SELECT * FROM dist_table GLOBAL JOIN (SELECT ...) USING key.
