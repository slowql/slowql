# Nested Loop Join Hint (PERF-CURSOR-003)

**Dimension**: Performance
**Severity**: Low
**Scope**: Dialect Specific (Tsql)

## Description
Forced nested loop joins perform O(n*m) comparisons. For large tables, this is catastrophic. The optimizer usually knows better.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
