# HAVING Without GROUP BY (PERF-AGG-003)

**Dimension**: Performance
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
Without GROUP BY, HAVING filters the entire table as one group. The query returns either 0 or 1 rows, which is rarely intended.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Add the missing GROUP BY clause, or use WHERE instead of HAVING if no aggregation is needed.
