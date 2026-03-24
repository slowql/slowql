# ClickHouse Mutation (ALTER UPDATE/DELETE) (PERF-CH-003)

**Dimension**: Performance
**Severity**: Medium
**Scope**: Dialect Specific (Clickhouse)

## Description
Mutations rewrite entire data parts asynchronously. Frequent mutations queue up and consume disk I/O and CPU. They are not transactional and cannot be rolled back.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
