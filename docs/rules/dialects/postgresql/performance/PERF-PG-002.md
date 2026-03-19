# Unfiltered COUNT(*) — Consider reltuples (PERF-PG-002)

**Dimension**: Performance
**Severity**: Info
**Scope**: Dialect Specific (Postgresql)

## Description
COUNT(*) on a large table without WHERE scans every row.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
For approximate counts use: SELECT reltuples FROM pg_class WHERE relname = 'table'.
