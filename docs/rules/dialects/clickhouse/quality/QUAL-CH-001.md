# ORDER BY Without LIMIT on ClickHouse (QUAL-CH-001)

**Dimension**: Quality
**Severity**: Medium
**Scope**: Dialect Specific (Clickhouse)

## Description
All data is gathered to one node for global sorting. This can exhaust memory and crash the query.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Add LIMIT to bound results. Or use ORDER BY with LIMIT BY for top-N per group patterns.
