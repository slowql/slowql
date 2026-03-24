# LEFT JOIN With IS NOT NULL Filter (PERF-JOIN-003)

**Dimension**: Performance
**Severity**: Low
**Scope**: Universal (All Dialects)

## Description
The LEFT JOIN preserves unmatched rows, then WHERE immediately removes them. This wastes I/O and prevents join reordering.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
