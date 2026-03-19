# Nested Loop Join Hint (PERF-CURSOR-003)

**Dimension**: Performance
**Severity**: Low
**Scope**: Dialect Specific (Tsql)

## Description
Forced nested loop joins perform O(n*m) comparisons. For large tables, this is catastrophic. The optimizer usually knows better.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Remove join hints and let the optimizer choose. If hint is necessary, document why.
