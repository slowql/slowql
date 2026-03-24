# SELECT Without PREWHERE (PERF-CH-001)

**Dimension**: Performance
**Severity**: Info
**Scope**: Dialect Specific (Clickhouse)

## Description
Without PREWHERE, ClickHouse reads all columns from disk before filtering. PREWHERE reads only the filter column first, skipping granules that don't match.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
