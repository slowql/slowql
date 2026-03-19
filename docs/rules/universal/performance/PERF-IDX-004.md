# OR in WHERE Clause (PERF-IDX-004)

**Dimension**: Performance
**Severity**: Info
**Scope**: Universal (All Dialects)

## Description
OR conditions can prevent index usage depending on the query planner

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Consider rewriting as UNION ALL of two queries
