# Implicit Conversion in JOIN Predicate (PERF-TSQL-003)

**Dimension**: Performance
**Severity**: High
**Scope**: Dialect Specific (Tsql)

## Description
Implicit conversion prevents index seeks, forcing table scans.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Ensure JOIN columns have matching data types at the schema level.
