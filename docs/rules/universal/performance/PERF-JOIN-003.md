# LEFT JOIN With IS NOT NULL Filter (PERF-JOIN-003)

**Dimension**: Performance
**Severity**: Low
**Scope**: Universal (All Dialects)

## Description
The LEFT JOIN preserves unmatched rows, then WHERE immediately removes them. This wastes I/O and prevents join reordering.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Replace LEFT JOIN with INNER JOIN when the WHERE clause filters out NULLs from the right table. The result is identical but the optimizer has more freedom.
