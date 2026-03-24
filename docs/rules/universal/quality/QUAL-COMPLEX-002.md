# Excessive Subquery Nesting (QUAL-COMPLEX-002)

**Dimension**: Quality
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
Deeply nested subqueries are unreadable and hard to optimize. Each level makes query execution unpredictable. Often indicates poor query design that should use CTEs or temp tables.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
