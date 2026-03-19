# NOT IN Subquery (PERF-SCAN-004)

**Dimension**: Performance
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
NOT IN with subquery fails silently with NULLs and disables index usage

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Rewrite as NOT EXISTS or LEFT JOIN ... WHERE col IS NULL
