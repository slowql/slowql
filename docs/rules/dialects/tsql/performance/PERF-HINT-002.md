# Index Hint (PERF-HINT-002)

**Dimension**: Performance
**Severity**: Low
**Scope**: Dialect Specific (Tsql)

## Description
Index hints force specific index usage regardless of statistics. When data changes, the forced index may become suboptimal, but the hint remains.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Let the optimizer choose indexes. If it chooses wrong, update statistics or create better indexes.
