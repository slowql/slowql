# SELECT * on ClickHouse Columnar Storage (COST-CH-001)

**Dimension**: Cost
**Severity**: High
**Scope**: Dialect Specific (Clickhouse)

## Description
ClickHouse column pruning is one of its key optimizations. SELECT * bypasses this, reading and decompressing every column.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
