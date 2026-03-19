# Long Query (Line Count) (QUAL-COMPLEX-005)

**Dimension**: Quality
**Severity**: Info
**Scope**: Universal (All Dialects)

## Description
Queries over 50 lines are hard to understand, review, and debug. Often indicates poor separation of concerns or missing abstraction layers.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Break into multiple queries or CTEs. Use views for complex joins. Extract repeated patterns into functions. Aim for queries under 30 lines.
