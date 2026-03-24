# HAVING Without GROUP BY (PERF-AGG-003)

**Dimension**: Performance
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
Without GROUP BY, HAVING filters the entire table as one group. The query returns either 0 or 1 rows, which is rarely intended.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
