# Excessive CASE Nesting (QUAL-COMPLEX-001)

**Dimension**: Quality
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
Deeply nested CASE statements are difficult to understand, test, and debug. Each nesting level doubles the cognitive load. Often indicates business logic that belongs in application layer.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Refactor to lookup table or create a user-defined function. Limit CASE to 2-3 levels maximum. Use early returns in functions.
