# Query Optimizer Hint (PERF-HINT-001)

**Dimension**: Performance
**Severity**: Low
**Scope**: Dialect Specific (Tsql)

## Description
Query hints freeze execution plans. As data grows and distribution changes, hinted plans become suboptimal. Hints hide underlying issues (missing indexes, bad statistics).

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Remove hints and fix root cause: update statistics, add indexes, simplify query.
