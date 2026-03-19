# SELECT Without FINAL on ReplacingMergeTree (REL-CH-001)

**Dimension**: Reliability
**Severity**: High
**Scope**: Dialect Specific (Clickhouse)

## Description
Queries return duplicate rows that should have been deduplicated. Aggregations like COUNT and SUM return inflated values.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Add FINAL keyword: SELECT * FROM table FINAL WHERE ... Note: FINAL forces a merge at query time which adds latency. For high-throughput reads, use OPTIMIZE TABLE periodically.
