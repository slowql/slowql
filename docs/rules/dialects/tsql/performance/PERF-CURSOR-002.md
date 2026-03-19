# WHILE Loop Pattern (PERF-CURSOR-002)

**Dimension**: Performance
**Severity**: Medium
**Scope**: Dialect Specific (Tsql)

## Description
WHILE loops in SQL often indicate procedural thinking applied to a set-based language. Each iteration may execute separate queries, multiplying execution time.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Replace WHILE loops with set-based operations. Use recursive CTEs for hierarchical processing.
