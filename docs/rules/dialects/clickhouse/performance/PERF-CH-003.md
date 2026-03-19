# ClickHouse Mutation (ALTER UPDATE/DELETE) (PERF-CH-003)

**Dimension**: Performance
**Severity**: Medium
**Scope**: Dialect Specific (Clickhouse)

## Description
Mutations rewrite entire data parts asynchronously. Frequent mutations queue up and consume disk I/O and CPU. They are not transactional and cannot be rolled back.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use ReplacingMergeTree or CollapsingMergeTree for logical deletes/updates. Reserve ALTER TABLE mutations for rare bulk corrections.
