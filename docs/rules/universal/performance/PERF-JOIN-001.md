# Cartesian Product (CROSS JOIN) (PERF-JOIN-001)

**Dimension**: Performance
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Produces row count = table1_rows * table2_rows, exponential cost

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Add explicit JOIN condition or use INNER JOIN
