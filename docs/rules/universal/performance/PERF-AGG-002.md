# ORDER BY in Subquery (PERF-AGG-002)

**Dimension**: Performance
**Severity**: Low
**Scope**: Universal (All Dialects)

## Description
ORDER BY in subquery is meaningless and wastes sort cost

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Remove ORDER BY from subquery unless paired with LIMIT/TOP
