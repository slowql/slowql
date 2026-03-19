# SELECT Without PREWHERE (PERF-CH-001)

**Dimension**: Performance
**Severity**: Info
**Scope**: Dialect Specific (Clickhouse)

## Description
Without PREWHERE, ClickHouse reads all columns from disk before filtering. PREWHERE reads only the filter column first, skipping granules that don't match.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Move selective filter conditions from WHERE to PREWHERE. ClickHouse auto-optimizes simple conditions, but explicit PREWHERE guarantees it.
