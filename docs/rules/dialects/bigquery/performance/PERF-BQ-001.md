# SELECT DISTINCT on UNNEST (PERF-BQ-001)

**Dimension**: Performance
**Severity**: Medium
**Scope**: Dialect Specific (Bigquery)

## Description
UNNEST explodes arrays then DISTINCT shuffles all rows to deduplicate.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use ARRAY_AGG(DISTINCT ...) instead. Filter before UNNEST to reduce volume.
