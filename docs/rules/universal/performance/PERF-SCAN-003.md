# Unbounded SELECT (PERF-SCAN-003)

**Dimension**: Performance
**Severity**: Low
**Scope**: Universal (All Dialects)

## Description
May return millions of rows, overwhelming application memory

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Add LIMIT clause for paginated or exploratory queries
