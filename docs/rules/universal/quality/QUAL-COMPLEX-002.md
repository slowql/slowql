# Excessive Subquery Nesting (QUAL-COMPLEX-002)

**Dimension**: Quality
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
Deeply nested subqueries are unreadable and hard to optimize. Each level makes query execution unpredictable. Often indicates poor query design that should use CTEs or temp tables.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use Common Table Expressions (CTEs) to flatten query structure. Or break into temp tables. Maximum 2-3 levels for readability.
