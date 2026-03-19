# SELECT * on ClickHouse Columnar Storage (COST-CH-001)

**Dimension**: Cost
**Severity**: High
**Scope**: Dialect Specific (Clickhouse)

## Description
ClickHouse column pruning is one of its key optimizations. SELECT * bypasses this, reading and decompressing every column.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Always specify explicit column names. ClickHouse decompresses only requested columns, dramatically reducing I/O.
