# VARIANT Column in WHERE Without CAST (PERF-SF-001)

**Dimension**: Performance
**Severity**: Medium
**Scope**: Dialect Specific (Snowflake)

## Description
Without CAST, Snowflake scans all micro-partitions.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Cast VARIANT: WHERE data:field::STRING = 'value'.
