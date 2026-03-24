# SELECT Without FINAL on ReplacingMergeTree (REL-CH-001)

**Dimension**: Reliability
**Severity**: High
**Scope**: Dialect Specific (Clickhouse)

## Description
Queries return duplicate rows that should have been deduplicated. Aggregations like COUNT and SUM return inflated values.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
